package link

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// maxMessageChunks is the largest chunk count the 16-bit count/index fields can
// represent (a uint16 holds 0..65535), so a message may span at most this many
// chunks.
const maxMessageChunks = 1<<16 - 1

// maxMessageChunk bounds the plaintext carried in one link frame, and is the
// default when the transport MTU is unknown (or large, like a TCP bridge). Over
// a datagram medium the chunk is sized down to the interface MTU by
// maxChunkForMTU so the on-wire frame fits one packet (no IP fragmentation, and
// small enough for radio). Larger payloads are split across frames.
const maxMessageChunk = 32 * 1024

// minMessageChunk floors the MTU-derived chunk so a tiny/misreported MTU can't
// drive the chunk to zero (which would never make progress).
const minMessageChunk = 64

// linkFrameOverhead is the fixed, MTU-independent part of a link data frame:
// packet header + JSON field names + base64-encoded LinkID/Nonce + the AEAD tag.
// Measured at ~234 bytes for an empty chunk; rounded up for margin. The
// remaining, chunk-proportional cost is the base64 expansion of the ciphertext
// (~4/3), which maxChunkForMTU inverts.
const linkFrameOverhead = 300

// maxChunkForMTU returns the largest plaintext chunk whose resulting on-wire link
// frame fits within mtu. The frame is roughly linkFrameOverhead + (4/3)*chunk
// (the JSON/base64 envelope), so we invert that and clamp to
// [minMessageChunk, maxMessageChunk]. A non-positive or large mtu yields the
// default maxMessageChunk.
func maxChunkForMTU(mtu int) int {
	if mtu <= 0 {
		return maxMessageChunk
	}
	budget := (mtu - linkFrameOverhead) * 3 / 4
	if budget < minMessageChunk {
		return minMessageChunk
	}
	if budget > maxMessageChunk {
		return maxMessageChunk
	}
	return budget
}

// maxInflightMessages caps how many partially-received messages a Reassembler
// buffers, so incomplete messages (e.g. from a lossy datagram transport) cannot
// grow memory without bound.
const maxInflightMessages = 256

// msgHeaderLen is the per-frame header: 8-byte message ID, 2-byte chunk index,
// 2-byte chunk count.
const msgHeaderLen = 12

// SendMessage delivers data over the link as one or more framed chunks, so a
// payload larger than a single frame can be sent. Delivery is best-effort: fully
// reliable over an ordered transport (a TCP bridge), lossy over a datagram one
// (a lost chunk drops the whole message — the application layer confirms/retries).
func SendMessage(l *Link, data []byte) error {
	return sendMessageChunks(l.Send, l.mgr.chunkFor(l.peerAddr), data)
}

// sendMessageChunks splits data into <=chunk-byte pieces, frames each with the
// message header, and emits it via send. Shared by SendMessage (raw over a Link)
// and Router.SendMessage (prefixed for the multiplexed path).
func sendMessageChunks(send func([]byte) error, chunk int, data []byte) error {
	if chunk < 1 {
		chunk = 1
	}
	var msgID [8]byte
	if _, err := rand.Read(msgID[:]); err != nil {
		return err
	}
	total := (len(data) + chunk - 1) / chunk
	if total == 0 {
		total = 1 // always send at least one (possibly empty) chunk
	}
	if total > maxMessageChunks {
		// The 16-bit chunk index can't address more pieces; a payload this large
		// over this MTU needs the Resource layer (reliable, 32-bit part index),
		// not a single best-effort link message.
		return fmt.Errorf("link: message %d bytes needs %d chunks at %d-byte MTU chunking, exceeds %d",
			len(data), total, chunk, maxMessageChunks)
	}
	for i := 0; i < total; i++ {
		start := i * chunk
		end := start + chunk
		if end > len(data) {
			end = len(data)
		}
		frame := make([]byte, msgHeaderLen+(end-start))
		copy(frame[0:8], msgID[:])
		binary.BigEndian.PutUint16(frame[8:10], uint16(i))
		binary.BigEndian.PutUint16(frame[10:12], uint16(total))
		copy(frame[msgHeaderLen:], data[start:end])
		if err := send(frame); err != nil {
			return err
		}
	}
	return nil
}

// Reassembler collects message chunks arriving on a link and invokes onMessage
// once every chunk of a message has been received. Feed it via Link.OnData.
type Reassembler struct {
	mu        sync.Mutex
	parts     map[[8]byte]*partial
	onMessage func([]byte)
}

type partial struct {
	total   int
	got     int
	chunks  [][]byte
	started time.Time
}

// partialTTL bounds how long an incomplete message is held. The sub-protocols
// carried here are explicitly best-effort — a dropped chunk is normal, not
// exceptional — so a partial that never completes is an expected outcome and must
// be reclaimed. Without this the table filled with stale entries and, being capped,
// then dropped *every* subsequent message for the life of the link: a file transfer
// over onion-over-Links delivered nothing at all while the sender reported success.
// Generous compared with the round trip a message needs to arrive.
const partialTTL = 30 * time.Second

// NewReassembler returns a Reassembler that calls onMessage with each fully
// reassembled message.
func NewReassembler(onMessage func([]byte)) *Reassembler {
	return &Reassembler{parts: make(map[[8]byte]*partial), onMessage: onMessage}
}

// Feed consumes one link frame. Suitable as a Link.OnData callback.
func (r *Reassembler) Feed(frame []byte) {
	if len(frame) < msgHeaderLen {
		return
	}
	var id [8]byte
	copy(id[:], frame[0:8])
	idx := binary.BigEndian.Uint16(frame[8:10])
	total := binary.BigEndian.Uint16(frame[10:12])
	if total == 0 || idx >= total {
		return
	}
	payload := frame[msgHeaderLen:]

	r.mu.Lock()
	p := r.parts[id]
	if p == nil {
		if len(r.parts) >= maxInflightMessages {
			r.evictLocked()
		}
		if len(r.parts) >= maxInflightMessages {
			r.mu.Unlock()
			return // genuinely saturated with live partials; shed load
		}
		p = &partial{total: int(total), chunks: make([][]byte, total), started: time.Now()}
		r.parts[id] = p
	}
	if p.total != int(total) {
		r.mu.Unlock()
		return // inconsistent framing for this message ID
	}
	if p.chunks[idx] == nil {
		p.chunks[idx] = append([]byte(nil), payload...)
		p.got++
	}
	complete := p.got == p.total
	if complete {
		delete(r.parts, id)
	}
	r.mu.Unlock()

	if complete {
		var out []byte
		for _, c := range p.chunks {
			out = append(out, c...)
		}
		r.onMessage(out)
	}
}

// evictLocked reclaims space in a full partials table: expired entries first, and
// failing that the oldest one.
//
// Dropping the oldest rather than refusing the newcomer matters. Refusing is what
// the code used to do implicitly, and it meant a burst of incomplete messages could
// wedge the reassembler permanently — every later message, however well-formed, was
// turned away by partials that would never complete. The oldest partial is the one
// least likely to still be receiving chunks.
//
// Caller holds r.mu.
func (r *Reassembler) evictLocked() {
	now := time.Now()
	for id, p := range r.parts {
		if now.Sub(p.started) >= partialTTL {
			delete(r.parts, id)
		}
	}
	if len(r.parts) < maxInflightMessages {
		return
	}
	var oldestID [8]byte
	var oldest time.Time
	first := true
	for id, p := range r.parts {
		if first || p.started.Before(oldest) {
			oldestID, oldest, first = id, p.started, false
		}
	}
	if !first {
		delete(r.parts, oldestID)
	}
}
