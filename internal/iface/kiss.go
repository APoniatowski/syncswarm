package iface

import (
	"bufio"
	"fmt"
	"io"
	"sync"
	"time"
)

// KISS framing (the TNC/packet-radio standard) delimits frames on a byte stream —
// exactly what a serial/LoRa modem exposes. A Reticulum RNode, and Meshtastic /
// MeshCore in KISS mode, all speak it, so one implementation lights up every
// serial-attached radio. A frame is:
//
//	FEND, command, <escaped payload>, FEND
//
// where FEND bytes inside the payload are escaped FESC,TFEND and literal FESC as
// FESC,TFESC. The command byte is port<<4 | type; type 0 (data) on port 0 is all
// SyncSwarm uses.
const (
	kissFEND    = 0xC0
	kissFESC    = 0xDB
	kissTFEND   = 0xDC
	kissTFESC   = 0xDD
	kissCmdData = 0x00
)

// kissEncode wraps a payload in a KISS data frame.
func kissEncode(payload []byte) []byte {
	out := make([]byte, 0, len(payload)+4)
	out = append(out, kissFEND, kissCmdData)
	for _, b := range payload {
		switch b {
		case kissFEND:
			out = append(out, kissFESC, kissTFEND)
		case kissFESC:
			out = append(out, kissFESC, kissTFESC)
		default:
			out = append(out, b)
		}
	}
	return append(out, kissFEND)
}

// readKISSFrame reads one KISS frame from r, returning its payload (command byte
// stripped, escapes resolved). Leading garbage and empty (back-to-back FEND)
// frames are skipped, so a mid-stream start still resynchronises on the next
// delimiter.
func readKISSFrame(r *bufio.Reader) ([]byte, error) {
	// Advance to a frame start.
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == kissFEND {
			break
		}
	}
	var frame []byte
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch b {
		case kissFEND:
			if len(frame) == 0 {
				continue // empty frame / doubled delimiter — keep scanning
			}
			return frame[1:], nil // drop the command/port byte
		case kissFESC:
			n, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			switch n {
			case kissTFEND:
				frame = append(frame, kissFEND)
			case kissTFESC:
				frame = append(frame, kissFESC)
			default:
				frame = append(frame, n) // tolerate a malformed escape
			}
		default:
			frame = append(frame, b)
		}
	}
}

// kissInterface is a framed transport over any byte-stream link (a serial port, a
// TCP socket to a networked RNode) using KISS delimiting. It is the shared engine
// behind LoRaInterface and SerialInterface. The medium is address-less broadcast
// RF, so inbound frames carry an empty Addr and Send ignores its addr argument —
// every frame goes to the one attached modem, which transmits it on the air.
type kissInterface struct {
	name string
	kind Kind
	caps Caps
	rwc  io.ReadWriteCloser

	frames    chan InboundFrame
	done      chan struct{}
	closeOnce sync.Once
	wmu       sync.Mutex   // serialises writes to the stream
	duty      *dutyLimiter // nil = unlimited (wired transports, or opted out)
}

// SetDutyCycle limits transmissions to `fraction` of wall time on air over
// `window` (0 window = 1 hour), as licence-free radio bands require. fraction <= 0
// disables limiting. Call before the interface carries traffic.
func (k *kissInterface) SetDutyCycle(fraction float64, window time.Duration) {
	k.wmu.Lock()
	defer k.wmu.Unlock()
	k.duty = newDutyLimiter(fraction, k.caps.Bitrate, window)
}

// newKISSInterface starts framing over rwc. It takes ownership of rwc and closes
// it on Close.
func newKISSInterface(name string, rwc io.ReadWriteCloser, kind Kind, caps Caps) *kissInterface {
	k := &kissInterface{
		name:   name,
		kind:   kind,
		caps:   caps,
		rwc:    rwc,
		frames: make(chan InboundFrame, 64),
		done:   make(chan struct{}),
	}
	go k.readLoop()
	return k
}

func (k *kissInterface) Name() string                { return k.name }
func (k *kissInterface) Kind() Kind                  { return k.kind }
func (k *kissInterface) Caps() Caps                  { return k.caps }
func (k *kissInterface) Frames() <-chan InboundFrame { return k.frames }

func (k *kissInterface) Send(_ string, frame []byte) error {
	if len(frame) > k.caps.MTU {
		return fmt.Errorf("iface %s: frame %d exceeds MTU %d", k.kind, len(frame), k.caps.MTU)
	}
	select {
	case <-k.done:
		return ErrClosed
	default:
	}
	encoded := kissEncode(frame)
	k.wmu.Lock()
	defer k.wmu.Unlock()
	// Regulatory/neighbourly airtime limit: refuse rather than transmit over budget.
	if !k.duty.allow(len(encoded)) {
		return ErrDutyCycleExceeded
	}
	if _, err := k.rwc.Write(encoded); err != nil {
		select {
		case <-k.done:
			return ErrClosed
		default:
			return fmt.Errorf("iface %s: write: %w", k.kind, err)
		}
	}
	return nil
}

func (k *kissInterface) Close() error {
	k.closeOnce.Do(func() {
		close(k.done)
		k.rwc.Close() // unblocks readLoop's Read
	})
	return nil
}

func (k *kissInterface) readLoop() {
	defer close(k.frames)
	r := bufio.NewReader(k.rwc)
	for {
		frame, err := readKISSFrame(r)
		if err != nil {
			return // stream closed or fatal error
		}
		data := make([]byte, len(frame))
		copy(data, frame)
		select {
		case k.frames <- InboundFrame{Addr: "", Data: data}:
		case <-k.done:
			return
		}
	}
}

// NewKISSInterface wraps an already-open byte-stream link (e.g. a TCP connection
// to a networked RNode, or a test pipe) as a KISS interface. Use it when the
// caller owns the transport; NewSerialInterface / NewLoRaInterface open a serial
// device for you.
func NewKISSInterface(name string, rwc io.ReadWriteCloser, kind Kind, caps Caps) Interface {
	return newKISSInterface(name, rwc, kind, caps)
}
