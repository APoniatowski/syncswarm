//go:build !linux && !darwin

package iface

import "io"

// openSerial is unimplemented on platforms without a termios backend (i.e. not
// Linux or Darwin — notably Windows, whose serial API is entirely different). The
// KISS engine (kiss.go) is OS-independent, so a networked RNode is still reachable
// via NewKISSInterface over a TCP connection on any platform; only opening a local
// serial device needs a per-OS backend.
func openSerial(device string, baud int) (io.ReadWriteCloser, error) {
	return nil, ErrNotImplemented
}
