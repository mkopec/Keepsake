package fidohid

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/psanford/tpm-fido/fidoauth"
	"github.com/psanford/uhid"
)

func New(ctx context.Context, name string) (*SoftToken, error) {
	d, err := uhid.NewDevice(name, rdesc)
	if err != nil {
		return nil, err
	}

	d.Data.Bus = busUSB
	d.Data.VendorID = vendorID
	d.Data.ProductID = productID

	// uhid defaults to random binary, which hosts expecting a printable
	// serial number fail to parse.
	if err := d.SetUniq(hex.EncodeToString(mustRand(8))); err != nil {
		return nil, err
	}

	evtChan, err := d.Open(ctx)
	if err != nil {
		return nil, err
	}

	t := SoftToken{
		device:    d,
		evtChan:   evtChan,
		authEvent: make(chan AuthEvent),
	}

	return &t, nil
}

type SoftToken struct {
	device    *uhid.Device
	evtChan   chan uhid.Event
	authEvent chan AuthEvent

	authFunc func()

	// writeMu serializes writes of (possibly multi-packet) messages so that
	// keepalives don't interleave with responses.
	writeMu sync.Mutex

	// mu protects the in-flight transaction state below.
	mu         sync.Mutex
	busy       bool
	busyChanID uint32
	cancelTx   context.CancelFunc
}

type AuthEvent struct {
	chanID uint32
	cmd    CmdType

	// Ctx is cancelled when the host sends CTAPHID_CANCEL for this
	// transaction or after Release is called.
	Ctx context.Context

	// Req is set for U2F (CTAPHID_MSG) requests
	Req *fidoauth.AuthenticatorRequest
	// CBOR is set for CTAP2 (CTAPHID_CBOR) requests
	CBOR  []byte
	Error error
}

func (t *SoftToken) Events() chan AuthEvent {
	return t.authEvent
}

func (t *SoftToken) Run(ctx context.Context) {
	// Channel IDs are random, so programs can't predict each other's, and
	// only the most recent maxChannels are remembered. Every program that
	// can open the device sees all responses, including channel IDs, so
	// this only stops blind interference.
	channels := make(map[uint32]bool)
	var channelOrder []uint32
	allocateChan := func() uint32 {
		for {
			var b [4]byte
			if _, err := rand.Read(b[:]); err != nil {
				panic(err)
			}
			k := binary.BigEndian.Uint32(b[:])
			if k == 0 || k == broadcastChannel || channels[k] {
				continue
			}
			channels[k] = true
			channelOrder = append(channelOrder, k)
			if len(channelOrder) > maxChannels {
				delete(channels, channelOrder[0])
				channelOrder = channelOrder[1:]
			}
			return k
		}
	}

	pktChan := make(chan Packet)
	go parsePackets(ctx, t.evtChan, pktChan)

	for {
		var (
			innerMsg  []byte
			needSize  uint16
			reqChanID uint32
			cmd       CmdType
		)

		var nextSeq byte
		for pkt := range pktChan {
			if !pkt.IsInitial && (pkt.ChannelID != reqChanID || innerMsg == nil) {
				log.Printf("dropping continuation packet for channel 0x%08x", pkt.ChannelID)
				continue
			}
			if !pkt.IsInitial && pkt.SeqNo != nextSeq {
				log.Printf("dropping message with out of order continuation packet")
				innerMsg = nil
				continue
			}
			if pkt.IsInitial {
				if len(innerMsg) > 0 {
					log.Print("new initial packet while pending packets still exist")
				}
				innerMsg = make([]byte, 0, pkt.TotalSize)
				nextSeq = 0
				needSize = pkt.TotalSize
				reqChanID = pkt.ChannelID
				cmd = pkt.Command
			} else {
				nextSeq++
			}
			innerMsg = append(innerMsg, pkt.Data...)
			if len(innerMsg) >= int(needSize) {
				break
			}
		}
		if innerMsg == nil || len(innerMsg) < int(needSize) {
			// the packet channel closed
			return
		}

		innerMsg = innerMsg[:int(needSize)]

		switch cmd {
		case CmdPing:
			err := t.writeMessage(reqChanID, CmdPing, innerMsg)
			if err != nil {
				log.Printf("Write ping resp err: %s", err)
			}
		case CmdCancel:
			t.mu.Lock()
			if t.busy && t.busyChanID == reqChanID {
				t.cancelTx()
			}
			t.mu.Unlock()
		case CmdInit:
			if reqChanID != broadcastChannel && !channels[reqChanID] {
				t.writeError(reqChanID, errInvalidChannel)
				continue
			}
			chanID := allocateChan()

			var nonce [8]byte
			copy(nonce[:], innerMsg)

			resp := newInitResponse(chanID, nonce)

			err := t.writeMessage(reqChanID, CmdInit, resp.Marshal())
			if err != nil {
				log.Printf("Write Init resp err: %s", err)
				continue
			}
		case CmdMsg, CmdCbor:
			if !channels[reqChanID] {
				t.writeError(reqChanID, errInvalidChannel)
				continue
			}
			txCtx, ok := t.beginTx(ctx, reqChanID)
			if !ok {
				t.writeError(reqChanID, errChannelBusy)
				continue
			}

			evt := AuthEvent{
				chanID: reqChanID,
				cmd:    cmd,
				Ctx:    txCtx,
			}
			if cmd == CmdMsg {
				evt.Req, evt.Error = fidoauth.DecodeAuthenticatorRequest(innerMsg)
			} else if len(innerMsg) == 0 {
				evt.Error = fmt.Errorf("empty cbor request")
			} else {
				evt.CBOR = innerMsg
			}

			select {
			case t.authEvent <- evt:
			case <-ctx.Done():
				return
			}
		default:
			log.Printf("unsuppoted cmd: %s %d", cmd, cmd)
			t.writeError(reqChanID, errInvalidCmd)
		}
	}
}

const (
	busUSB = 0x03

	vendorID  = 0x15d9
	productID = 0x0a37

	frameTypeInit = 0x80
	frameTypeCont = 0x00

	CmdPing      CmdType = 0x01 // Echo data through local processor only
	CmdMsg       CmdType = 0x03 // Send U2F message frame
	CmdLock      CmdType = 0x04 // Send lock channel command
	CmdInit      CmdType = 0x06 // Channel initialization
	CmdWink      CmdType = 0x08 // Send device identification wink
	CmdCbor      CmdType = 0x10 // Send encapsulated CTAP CBOR
	CmdCancel    CmdType = 0x11 // Cancel outstanding requests
	CmdKeepalive CmdType = 0x3b // Processing status notification
	CmdSync      CmdType = 0x3c // Protocol resync command
	CmdError     CmdType = 0x3f // Error response

	vendorSpecificFirstCmd = 0x40
	vendorSpecificLastCmd  = 0x7f

	reportLen            = 64
	initialPacketDataLen = reportLen - 7
	contPacketDataLen    = reportLen - 5

	u2fProtocolVersion = 2
	deviceMajor        = 1
	deviceMinor        = 0
	deviceBuild        = 0
	winkCapability     = 0x01
	lockCapability     = 0x02
	cborCapability     = 0x04
	nmsgCapability     = 0x08

	// CTAPHID_ERROR codes
	errInvalidCmd     = 0x01
	errChannelBusy    = 0x06
	errInvalidChannel = 0x0B

	broadcastChannel = 0xffffffff
	maxChannels      = 256

	// CTAPHID_KEEPALIVE status codes
	KeepaliveProcessing = 0x01
	KeepaliveUPNeeded   = 0x02
)

type CmdType uint8

func (c CmdType) IsVendorSpecific() bool {
	return c >= vendorSpecificFirstCmd && c <= vendorSpecificLastCmd
}

func (c CmdType) String() string {
	switch c {
	case CmdPing:
		return "CmdPing"
	case CmdMsg:
		return "CmdMsg"
	case CmdLock:
		return "CmdLock"
	case CmdInit:
		return "CmdInit"
	case CmdWink:
		return "CmdWink"
	case CmdSync:
		return "CmdSync"
	case CmdError:
		return "CmdError"
	case CmdCbor:
		return "CmdCbor"
	case CmdCancel:
		return "CmdCancel"
	case CmdKeepalive:
		return "CmdKeepalive"
	}

	if c >= vendorSpecificFirstCmd && c <= vendorSpecificLastCmd {
		return fmt.Sprintf("CmdVendor<%d>", c)
	}
	return fmt.Sprintf("CmdUnknown<%d>", c)
}

// src: http://www.usb.org/developers/hidpage/HUTRR48.pdf
var rdesc = []byte{
	0x06, 0xd0, 0xf1, //	USAGE_PAGE (FIDO Alliance)
	0x09, 0x01, //				USAGE (U2F HID Authenticator Device)
	0xa1, 0x01, //				COLLECTION (Application)
	0x09, 0x20, //					USAGE (Input Report Data)
	0x15, 0x00, //					LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00, //		LOGICAL_MAXIMUM (255)
	0x75, 0x08, //					REPORT_SIZE (8)
	0x95, 0x40, //					REPORT_COUNT (64)
	0x81, 0x02, //					INPUT (Data,Var,Abs)
	0x09, 0x21, //					USAGE (Output Report Data)
	0x15, 0x00, //					LOGICAL_MINIMUM (0)
	0x26, 0xff, 0x00, //		LOGICAL_MAXIMUM (255)
	0x75, 0x08, //					REPORT_SIZE (8)
	0x95, 0x40, //					REPORT_COUNT (64)
	0x91, 0x02, //					OUTPUT (Data,Var,Abs)
	0xc0, //							END_COLLECTION
}

func parsePackets(ctx context.Context, evtChan chan uhid.Event, pktChan chan Packet) {
	for {
		var (
			evt uhid.Event
			ok  bool
		)

		select {
		case evt, ok = <-evtChan:
			if !ok {
				return
			}
		case <-ctx.Done():
			return
		}

		if evt.Err != nil {
			log.Fatalf("got evt err: %s", evt.Err)
		}

		// Output means the kernel has sent us data
		if evt.Type == uhid.Output {

			r := newPacketReader(bytes.NewReader(evt.Data))
			b1 := make([]byte, 1)
			r.ReadFull(b1) // ignore first byte

			var channelID uint32
			r.Read(binary.BigEndian, &channelID)

			_, err := r.ReadFull(b1)
			if err != nil {
				log.Printf("U2F protocol read error")
				continue
			}
			typeOrSeqNo := b1[0]

			if typeOrSeqNo&frameTypeInit == frameTypeInit {
				typ := typeOrSeqNo
				cmd := typ ^ frameTypeInit

				var totalSize uint16
				r.Read(binary.BigEndian, &totalSize)

				data := make([]byte, initialPacketDataLen)
				_, err := r.ReadFull(data)
				if err != nil {
					log.Printf("U2F protocol read error")
					continue
				}

				p := Packet{
					ChannelID: channelID,
					IsInitial: true,
					Command:   CmdType(cmd),
					TotalSize: totalSize,
					Data:      data,
				}

				select {
				case pktChan <- p:
				case <-ctx.Done():
					return
				}
			} else {
				seqNo := typeOrSeqNo

				data := make([]byte, contPacketDataLen)
				_, err := r.ReadFull(data)
				if err != nil {
					log.Printf("U2F protocol read error")
					continue
				}

				p := Packet{
					ChannelID: channelID,
					SeqNo:     seqNo,
					Data:      data,
				}

				select {
				case pktChan <- p:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

type Packet struct {
	ChannelID uint32
	IsInitial bool
	Command   CmdType
	SeqNo     byte
	TotalSize uint16
	Data      []byte
}

func newPacketReader(r io.Reader) *packetReader {
	return &packetReader{
		r: r,
	}
}

type packetReader struct {
	r   io.Reader
	err error
}

func (r *packetReader) Error() error {
	return r.err
}

func (pr *packetReader) Read(order binary.ByteOrder, data interface{}) error {
	if pr.err != nil {
		return pr.err
	}

	err := binary.Read(pr.r, order, data)
	if err != nil {
		pr.err = err
	}
	return err
}

func (pr *packetReader) ReadFull(b []byte) (int, error) {
	if pr.err != nil {
		return 0, pr.err
	}

	n, err := io.ReadFull(pr.r, b)
	if err != nil {
		pr.err = err
		return n, err
	}
	return n, nil
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}

type frameInit struct {
	ChannelID       uint32
	Command         uint8
	Data            []byte
	TotalPayloadLen uint16
}

func (fi *frameInit) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, fi.ChannelID)
	buf.WriteByte(fi.Command)
	binary.Write(buf, binary.BigEndian, fi.TotalPayloadLen)
	buf.Write(fi.Data)
	if len(fi.Data) < initialPacketDataLen {
		pad := make([]byte, initialPacketDataLen-len(fi.Data))
		buf.Write(pad)
	}

	return buf.Bytes()
}

type frameCont struct {
	ChannelID uint32
	SeqNo     uint8
	Data      []byte
}

func (fi *frameCont) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, fi.ChannelID)
	buf.WriteByte(fi.SeqNo)
	buf.Write(fi.Data)
	if len(fi.Data) < contPacketDataLen {
		pad := make([]byte, contPacketDataLen-len(fi.Data))

		buf.Write(pad)
	}
	return buf.Bytes()
}

type initResponse struct {
	Nonce              [8]byte
	Channel            uint32
	ProtocolVersion    byte
	MajorDeviceVersion byte
	MinorDeviceVersion byte
	BuildDeviceVersion byte
	RawCapabilities    byte
}

func newInitResponse(channelID uint32, nonce [8]byte) *initResponse {
	return &initResponse{
		Nonce:              nonce,
		Channel:            channelID,
		ProtocolVersion:    u2fProtocolVersion,
		MajorDeviceVersion: deviceMajor,
		MinorDeviceVersion: deviceMinor,
		BuildDeviceVersion: deviceBuild,
		RawCapabilities:    cborCapability,
	}
}

func (resp *initResponse) Marshal() []byte {
	buf := new(bytes.Buffer)
	buf.Write(resp.Nonce[:])
	binary.Write(buf, binary.BigEndian, resp.Channel)
	buf.Write([]byte{
		resp.ProtocolVersion,
		resp.MajorDeviceVersion,
		resp.MinorDeviceVersion,
		resp.BuildDeviceVersion,
		resp.RawCapabilities,
	})

	return buf.Bytes()
}

// ChannelID returns the CTAPHID channel of the request.
func (evt AuthEvent) ChannelID() uint32 {
	return evt.chanID
}

// IsCBOR reports whether evt is a CTAP2 (CTAPHID_CBOR) request.
func (evt AuthEvent) IsCBOR() bool {
	return evt.cmd == CmdCbor
}

// beginTx marks the token as busy with a transaction on chanID. It returns
// false if another transaction is already in flight.
func (t *SoftToken) beginTx(ctx context.Context, chanID uint32) (context.Context, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.busy {
		return nil, false
	}

	txCtx, cancel := context.WithCancel(ctx)
	t.busy = true
	t.busyChanID = chanID
	t.cancelTx = cancel
	return txCtx, true
}

// Release ends the transaction started by evt. It must be called once the
// event has been handled, whether or not a response was written.
func (t *SoftToken) Release(evt AuthEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.busy && t.busyChanID == evt.chanID {
		t.cancelTx()
		t.busy = false
	}
}

// WriteResponse writes a U2F response with the given status word.
func (t *SoftToken) WriteResponse(ctx context.Context, evt AuthEvent, data []byte, status uint16) error {
	if status > 0 {
		statusBytes := make([]byte, 2)
		binary.BigEndian.PutUint16(statusBytes, status)
		data = append(data, statusBytes...)
	}
	return t.writeMessage(evt.chanID, evt.cmd, data)
}

// WriteCBOR writes a CTAP2 response: a status byte followed by the CBOR
// encoded body.
func (t *SoftToken) WriteCBOR(evt AuthEvent, status byte, body []byte) error {
	data := append([]byte{status}, body...)
	return t.writeMessage(evt.chanID, CmdCbor, data)
}

// KeepAlive tells the host the request is still being processed.
func (t *SoftToken) KeepAlive(evt AuthEvent, status byte) error {
	return t.writeMessage(evt.chanID, CmdKeepalive, []byte{status})
}

func (t *SoftToken) writeError(chanID uint32, code byte) {
	err := t.writeMessage(chanID, CmdError, []byte{code})
	if err != nil {
		log.Printf("Write error resp err: %s", err)
	}
}

func (t *SoftToken) writeMessage(chanID uint32, cmd CmdType, data []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()

	return writeRespose(t.device, chanID, cmd, data)
}

func writeRespose(d *uhid.Device, chanID uint32, cmd CmdType, data []byte) error {

	initial := true
	pktSize := initialPacketDataLen

	totalSize := uint16(len(data))
	var seqNo uint8
	for initial || len(data) > 0 {
		sliceSize := pktSize
		if len(data) < sliceSize {
			sliceSize = len(data)
		}

		pktData := data[:sliceSize]
		data = data[sliceSize:]

		if initial {
			initial = false
			pktSize = contPacketDataLen
			frame := frameInit{
				ChannelID:       chanID,
				Command:         uint8(cmd) | frameTypeInit,
				Data:            pktData,
				TotalPayloadLen: totalSize,
			}

			payload := frame.Marshal()

			resp := uhid.Input2Request{
				RequestType: uhid.Input2,
				DataSize:    uint16(len(payload)),
			}
			copy(resp.Data[:], payload)

			err := d.WriteEvent(resp)
			if err != nil {
				return err
			}
		} else {
			frame := frameCont{
				ChannelID: chanID,
				SeqNo:     seqNo,
				Data:      pktData,
			}

			payload := frame.Marshal()

			resp := uhid.Input2Request{
				RequestType: uhid.Input2,
				DataSize:    uint16(len(payload)),
			}
			copy(resp.Data[:], payload)

			err := d.WriteEvent(resp)
			if err != nil {
				return err
			}
			seqNo++
		}
	}

	return nil
}
