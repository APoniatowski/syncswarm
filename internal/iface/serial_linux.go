//go:build linux

package iface

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// openSerial opens a serial device in raw mode at the given baud rate and returns
// it as a byte stream. Linux implementation via termios.
func openSerial(device string, baud int) (io.ReadWriteCloser, error) {
	speed, ok := baudConst(baud)
	if !ok {
		return nil, fmt.Errorf("unsupported baud rate %d", baud)
	}
	// O_NOCTTY: the port must not become our controlling terminal.
	f, err := os.OpenFile(device, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())

	t, err := unix.IoctlGetTermios(fd, unix.TCGETS)
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
	t.Cflag &^= unix.CSIZE | unix.PARENB | unix.CBAUD
	t.Cflag |= unix.CS8 | unix.CREAD | unix.CLOCAL | speed
	t.Ispeed = speed
	t.Ospeed = speed
	// Blocking read that returns as soon as >=1 byte is available.
	t.Cc[unix.VMIN] = 1
	t.Cc[unix.VTIME] = 0

	if err := unix.IoctlSetTermios(fd, unix.TCSETS, t); err != nil {
		f.Close()
		return nil, fmt.Errorf("set termios: %w", err)
	}
	return f, nil
}

// baudConst maps a numeric baud rate to its termios speed constant.
func baudConst(baud int) (uint32, bool) {
	switch baud {
	case 1200:
		return unix.B1200, true
	case 2400:
		return unix.B2400, true
	case 4800:
		return unix.B4800, true
	case 9600:
		return unix.B9600, true
	case 19200:
		return unix.B19200, true
	case 38400:
		return unix.B38400, true
	case 57600:
		return unix.B57600, true
	case 115200:
		return unix.B115200, true
	case 230400:
		return unix.B230400, true
	case 460800:
		return unix.B460800, true
	case 921600:
		return unix.B921600, true
	default:
		return 0, false
	}
}
