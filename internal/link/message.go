package link

import (
	"crypto/rand"
	"encoding/binary"
	"sync"
)

// maxMessageChunk bounds the plaintext carried in one link frame. It is well
// under the UDP interface MTU (with room for the AEAD tag and packet framing) and
// fits comfortably on a TCP bridge. Larger payloads are split across frames.
const maxMessageChunk = 32 * 1024

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
	var msgID [8]byte
	if _, err := rand.Read(msgID[:]); err != nil {
		return err
	}
	total := (len(data) + maxMessageChunk - 1) / maxMessageChunk
	if total == 0 {
		total = 1 // always send at least one (possibly empty) chunk
	}
	for i := 0; i < total; i++ {
		start := i * maxMessageChunk
		end := start + maxMessageChunk
		if end > len(data) {
			end = len(data)
		}
		frame := make([]byte, msgHeaderLen+(end-start))
		copy(frame[0:8], msgID[:])
		binary.BigEndian.PutUint16(frame[8:10], uint16(i))
		binary.BigEndian.PutUint16(frame[10:12], uint16(total))
		copy(frame[msgHeaderLen:], data[start:end])
		if err := l.Send(frame); err != nil {
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
	total  int
	got    int
	chunks [][]byte
}

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
			r.mu.Unlock()
			return // shed load rather than grow without bound
		}
		p = &partial{total: int(total), chunks: make([][]byte, total)}
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
