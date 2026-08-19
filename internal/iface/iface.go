// Package iface is the connection-agnostic transport seam for SyncSwarm.
//
// Every physical or virtual medium that can move a frame of bytes is exposed as
// an Interface: UDP, TCP, and (as stubs for now) LoRa radio and serial links.
// The rest of the stack — discovery, announces, routing, transfer — is written
// against Interface and never touches a socket directly, so adding a new medium
// is an additive implementation rather than a change to the core.
//
// This is Pillar 1 of RETICULUM_ALIGNMENT.md. v1 targets IP-ish media
// (UDP/TCP/I2P/Bluetooth-over-IP); the radio kinds are stubs that lay the seam
// for a future bridge into Reticulum (RNode), Meshtastic, and MeshCore.
//
// Frames are opaque bytes: this package deliberately does not import
// internal/protocol, so the dependency only ever flows core → iface.
package iface

import "errors"

// ErrNotImplemented is returned by interface kinds that are stubbed (LoRa,
// serial) until their backend is wired in.
var ErrNotImplemented = errors.New("iface: transport not implemented yet")

// ErrClosed is returned by Send after an interface has been closed.
var ErrClosed = errors.New("iface: interface closed")

// Broadcast is the address passed to Send to reach every peer on a
// broadcast-capable medium (UDP, LoRa, AutoInterface). On point-to-point media
// (TCP client) it is treated as "the peer".
const Broadcast = ""

// Kind identifies the medium behind an Interface.
type Kind string

const (
	KindUDP       Kind = "udp"        // datagram, broadcast-capable
	KindTCPServer Kind = "tcp-server" // stream, accepts many peers
	KindTCPClient Kind = "tcp-client" // stream, dials one peer (backbone bridge)
	KindLoRa      Kind = "lora"       // stub: Reticulum RNode / Meshtastic / MeshCore
	KindSerial    Kind = "serial"     // stub: KISS/serial framing to a radio modem
)

// Caps describes a medium's transport properties so the core can size frames,
// cap announce bandwidth, and decide which interfaces are suitable for a given
// packet. All values are approximate.
type Caps struct {
	MTU        int  // max frame payload in bytes (UDP ~1400, TCP large, LoRa ~500)
	Bitrate    int  // approx bits/sec, used to cap announce traffic per interface
	Broadcast  bool // medium supports one-to-many delivery
	FullDuplex bool // medium can send and receive simultaneously
}

// InboundFrame is one received frame plus the medium-specific source address
// (e.g. "203.0.113.4:64512" for IP media). Addr is opaque to the core; it is
// only ever handed back to Send.
type InboundFrame struct {
	Addr string
	Data []byte
}

// Interface is a bidirectional, framed transport over one medium.
//
// Send delivers one frame to addr (Broadcast for one-to-many). Frames yields
// inbound frames until the interface is closed, at which point the channel is
// closed. Implementations must be safe for concurrent Send calls.
type Interface interface {
	Name() string
	Kind() Kind
	Caps() Caps
	Send(addr string, frame []byte) error
	Frames() <-chan InboundFrame
	Close() error
}
