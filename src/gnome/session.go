package gnome

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/godbus/dbus/v5"
)

// Session reports whether the user's graphical session is locked, so that
// Keepsake can refuse requests that nobody can confirm. It asks:
//
//   - logind, for the user's session: locked (LockedHint, set by GNOME and
//     other desktops) or inactive (another session is in the foreground,
//     e.g. after switching users);
//   - GNOME Shell's screen shield (org.gnome.ScreenSaver), if it runs.
type Session struct {
	sessionBus *dbus.Conn

	mu        sync.Mutex
	systemBus *dbus.Conn
}

func NewSession(sessionBus *dbus.Conn) *Session {
	return &Session{sessionBus: sessionBus}
}

// Locked reports whether the session is locked or inactive. It returns an
// error only if neither logind nor the screen saver could be asked.
func (s *Session) Locked(ctx context.Context) (bool, error) {
	locked, lerr := s.logindLocked(ctx)
	if lerr == nil && locked {
		return true, nil
	}
	saver, serr := s.screenSaverActive(ctx)
	if serr == nil && saver {
		return true, nil
	}
	if lerr != nil && serr != nil {
		return false, fmt.Errorf("logind: %v; screen saver: %v", lerr, serr)
	}
	return false, nil
}

func (s *Session) logindLocked(ctx context.Context) (bool, error) {
	s.mu.Lock()
	if s.systemBus == nil {
		conn, err := dbus.ConnectSystemBus()
		if err != nil {
			s.mu.Unlock()
			return false, err
		}
		s.systemBus = conn
	}
	conn := s.systemBus
	s.mu.Unlock()

	// "auto" is the caller's session or, for a process outside of a
	// session such as a systemd user service, the user's graphical
	// session.
	obj := conn.Object("org.freedesktop.login1", "/org/freedesktop/login1/session/auto")
	var lockedHint, active bool
	if err := getProperty(ctx, obj, "org.freedesktop.login1.Session", "LockedHint", &lockedHint); err != nil {
		s.resetSystemBus(conn)
		return false, err
	}
	if err := getProperty(ctx, obj, "org.freedesktop.login1.Session", "Active", &active); err != nil {
		return false, err
	}
	return lockedHint || !active, nil
}

func (s *Session) resetSystemBus(conn *dbus.Conn) {
	if conn.Connected() {
		return
	}
	s.mu.Lock()
	if s.systemBus == conn {
		s.systemBus = nil
	}
	s.mu.Unlock()
}

func (s *Session) screenSaverActive(ctx context.Context) (bool, error) {
	if s.sessionBus == nil {
		return false, errors.New("no session bus")
	}
	var has bool
	err := s.sessionBus.BusObject().CallWithContext(ctx, "org.freedesktop.DBus.NameHasOwner", 0, "org.gnome.ScreenSaver").Store(&has)
	if err != nil {
		return false, err
	}
	if !has {
		return false, errors.New("org.gnome.ScreenSaver not running")
	}
	var active bool
	err = s.sessionBus.Object("org.gnome.ScreenSaver", "/org/gnome/ScreenSaver").
		CallWithContext(ctx, "org.gnome.ScreenSaver.GetActive", 0).Store(&active)
	return active, err
}

func getProperty(ctx context.Context, obj dbus.BusObject, iface, name string, v interface{}) error {
	var variant dbus.Variant
	err := obj.CallWithContext(ctx, "org.freedesktop.DBus.Properties.Get", 0, iface, name).Store(&variant)
	if err != nil {
		return err
	}
	return variant.Store(v)
}
