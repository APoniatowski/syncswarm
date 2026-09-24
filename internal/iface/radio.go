package iface

import "fmt"

// Radio interfaces bridge SyncSwarm onto serial-attached LoRa modems using KISS
// framing (see kiss.go), so a node can join a mesh over the air rather than IP:
//
//   - Reticulum RNode  — a serial/USB LoRa transceiver in KISS mode; this makes
//     SyncSwarm ride Reticulum's physical layer.
//   - Meshtastic / MeshCore — LoRa mesh firmware; usable as a low-bitrate
//     interface when configured for KISS over serial.
//
// The medium is address-less broadcast RF: announces and path requests flood
// over it exactly like UDP broadcast, which is all the connection-agnostic
// discovery model needs. Frames are sized to the tiny radio MTU by the Link layer
// (Pillar 5, Caps().MTU). A real serial device is opened by openSerial (Linux
// today; other OSes return ErrNotImplemented) — the KISS engine itself is
// OS-independent and also drives a networked RNode via NewKISSInterface.

// loRaMTU / serialMTU are conservative per-frame payload caps: LoRa's airtime
// budget keeps frames small, and a generic KISS TNC is similar.
const (
	loRaMTU   = 500
	serialMTU = 500

	// Common default line rates for the two roles (RNode enumerates fast; a
	// classic TNC is slow). Callers may override.
	defaultLoRaBaud   = 115200
	defaultSerialBaud = 9600
)

// LoRaInterface is a LoRa radio transport over a serial-attached modem (RNode /
// Meshtastic / MeshCore in KISS mode).
type LoRaInterface struct {
	*kissInterface
}

// NewLoRaInterface opens the serial LoRa modem at device (e.g. "/dev/ttyUSB0") at
// baud (0 → a sensible default) and frames traffic over it with KISS. It fails if
// the device cannot be opened or the platform has no serial backend.
func NewLoRaInterface(name, device string, baud int) (*LoRaInterface, error) {
	if baud <= 0 {
		baud = defaultLoRaBaud
	}
	rwc, err := openSerial(device, baud)
	if err != nil {
		return nil, fmt.Errorf("iface lora: open %q: %w", device, err)
	}
	caps := Caps{MTU: loRaMTU, Bitrate: 5000, Broadcast: true, FullDuplex: false}
	return &LoRaInterface{newKISSInterface(name, rwc, KindLoRa, caps)}, nil
}

// SerialInterface is a KISS/serial link to a radio modem (TNC, packet radio).
type SerialInterface struct {
	*kissInterface
}

// NewSerialInterface opens the serial device at baud (0 → a sensible default) and
// frames traffic over it with KISS.
func NewSerialInterface(name, device string, baud int) (*SerialInterface, error) {
	if baud <= 0 {
		baud = defaultSerialBaud
	}
	rwc, err := openSerial(device, baud)
	if err != nil {
		return nil, fmt.Errorf("iface serial: open %q: %w", device, err)
	}
	caps := Caps{MTU: serialMTU, Bitrate: baud, Broadcast: true, FullDuplex: false}
	return &SerialInterface{newKISSInterface(name, rwc, KindSerial, caps)}, nil
}
