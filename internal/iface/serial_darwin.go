//go:build darwin

package iface

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// openSerial opens a serial device in raw mode at the given baud rate and returns
// it as a byte stream. Darwin implementation via termios. It mirrors the Linux
// backend, with the BSD differences: TIOCGETA/TIOCSETA instead of TCGETS/TCSETS,
// and speeds carried directly in Ispeed/Ospeed (no CBAUD field in the flags).
func openSerial(device string, baud int) (io.ReadWriteCloser, error) {
	if !validBaud(baud) {
		return nil, fmt.Errorf("unsupported baud rate %d", baud)
	}
	// O_NOCTTY: the port must not become our controlling terminal.
	f, err := os.OpenFile(device, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())

	t, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("get termios: %w", err)
	}
	// Raw mode (cfmakeraw): no line processing, 8N1, receiver on, ignore modem
	// control lines.
	t.Iflag &^= unix.IGNBRK | unix.BRKINT | unix.PARMRK | unix.ISTRIP |
		unix.INLCR | unix.IGNCR | unix.ICRNL | unix.IXON
	t.Oflag &^= unix.OPOST
	t.Lflag &^= unix.ECHO | unix.ECHONL | unix.ICANON | unix.ISIG | unix.IEXTEN
	t.Cflag &^= unix.CSIZE | unix.PARENB
	t.Cflag |= unix.CS8 | unix.CREAD | unix.CLOCAL
	t.Ispeed = uint64(baud)
	t.Ospeed = uint64(baud)
	// Blocking read that returns as soon as >=1 byte is available.
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0

	if err := unix.IoctlSetTermios(fd, unix.TIOCSETA, t); err != nil {
		f.Close()
		return nil, fmt.Errorf("set termios: %w", err)
	}
	return f, nil
}
