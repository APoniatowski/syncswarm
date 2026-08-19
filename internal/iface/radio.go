package iface

// Radio interfaces are stubs for now. v1 targets IP-ish media (UDP/TCP); these
// lay the seam so that if the mesh model works well we can bridge SyncSwarm into
// existing LoRa mesh ecosystems without reworking the core:
//
//   - Reticulum RNode  — a serial/USB LoRa transceiver speaking RNode framing;
//     bridging here effectively makes SyncSwarm interoperable with Reticulum's
//     physical layer.
//   - Meshtastic       — LoRa mesh firmware; a bridge would ride its channels
//     (likely via its serial/BLE protobuf API) as a low-bitrate interface.
//   - MeshCore         — another LoRa mesh stack; same idea, different framing.
//
// Each will be a real Interface implementation once wired: framing a SyncSwarm
// wire packet down to the medium's tiny MTU (~500 bytes), which is why Pillar 5
// of RETICULUM_ALIGNMENT.md (MTU-driven sizing) is a prerequisite. Until then,
// every method returns ErrNotImplemented and Frames() yields a closed channel so
// callers degrade cleanly rather than block.

// loRaMTU / serialMTU reflect typical LoRa payload and a conservative serial
// frame, recorded now so MTU-driven sizing has real numbers to target.
const (
	loRaMTU   = 500
	serialMTU = 500
)

// closedFrames is a pre-closed channel returned by stub interfaces so a caller
// ranging over Frames() exits immediately instead of blocking forever.
func closedFrames() <-chan InboundFrame {
	ch := make(chan InboundFrame)
	close(ch)
	return ch
}

// LoRaInterface is a stub for a LoRa radio transport (Reticulum RNode /
// Meshtastic / MeshCore bridge). Not yet implemented.
type LoRaInterface struct {
	name   string
	device string // e.g. "/dev/ttyUSB0" or a BLE address — recorded for later
}

// NewLoRaInterface records the target device but does not open it; the backend
// is not implemented yet. It never fails, so wiring code can register a LoRa
// interface today and light it up later.
func NewLoRaInterface(name, device string) *LoRaInterface {
	return &LoRaInterface{name: name, device: device}
}

func (l *LoRaInterface) Name() string { return l.name }
func (l *LoRaInterface) Kind() Kind   { return KindLoRa }
func (l *LoRaInterface) Caps() Caps {
	return Caps{MTU: loRaMTU, Bitrate: 5000, Broadcast: true, FullDuplex: false}
}
func (l *LoRaInterface) Send(string, []byte) error   { return ErrNotImplemented }
func (l *LoRaInterface) Frames() <-chan InboundFrame { return closedFrames() }
func (l *LoRaInterface) Close() error                { return nil }

// SerialInterface is a stub for a KISS/serial link to a radio modem (TNC, packet
// radio). Not yet implemented.
type SerialInterface struct {
	name   string
	device string
	baud   int
}

// NewSerialInterface records the serial device and baud rate but does not open
// the port; the backend is not implemented yet.
func NewSerialInterface(name, device string, baud int) *SerialInterface {
	return &SerialInterface{name: name, device: device, baud: baud}
}

func (s *SerialInterface) Name() string { return s.name }
func (s *SerialInterface) Kind() Kind   { return KindSerial }
func (s *SerialInterface) Caps() Caps {
	return Caps{MTU: serialMTU, Bitrate: 9600, Broadcast: false, FullDuplex: false}
}
func (s *SerialInterface) Send(string, []byte) error   { return ErrNotImplemented }
func (s *SerialInterface) Frames() <-chan InboundFrame { return closedFrames() }
func (s *SerialInterface) Close() error                { return nil }
