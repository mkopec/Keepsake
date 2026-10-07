package tpm

import (
	"bytes"
	"testing"
)

func TestParseSeed(t *testing.T) {
	legacy := bytes.Repeat([]byte{7}, seedSizeBytes)
	seed, noDA, err := parseSeed(legacy)
	if err != nil || noDA || !bytes.Equal(seed, legacy) {
		t.Fatalf("legacy seed: %x %v %v", seed, noDA, err)
	}

	seed, noDA, err = parseSeed(append([]byte{keyHandleVersionNoDA}, legacy...))
	if err != nil || !noDA || !bytes.Equal(seed, legacy) {
		t.Fatalf("noDA seed: %x %v %v", seed, noDA, err)
	}

	for _, bad := range [][]byte{nil, legacy[:19], append([]byte{0x02}, legacy...), append(legacy, 1, 2)} {
		if _, _, err := parseSeed(bad); err == nil {
			t.Errorf("accepted invalid seed %x", bad)
		}
	}
}
