package transfer

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/APoniatowski/syncswarm/internal/discovery"
	"github.com/APoniatowski/syncswarm/internal/encryption"
	"github.com/APoniatowski/syncswarm/internal/fragment"
	"github.com/APoniatowski/syncswarm/internal/protocol"
	"github.com/APoniatowski/syncswarm/internal/storage"
)

// defaultStreamBlockSize is the plaintext size of each independently
// erasure-coded streaming block. Sender memory is bounded to roughly one block
// plus its shards; the receiver holds only the blocks not yet flushed in order.
const defaultStreamBlockSize = 4 * 1024 * 1024 // 4 MiB

// streamAckTimeout bounds how long a confirmed SendStream waits for the
// receiver's end-to-end delivery ack after emitting the whole stream. Generous
// because a large stream may still be reassembling when the last block is sent.
const streamAckTimeout = 30 * time.Second

// stampStreaming copies a fragment's streaming metadata onto its wire packet.
func stampStreaming(pkt *protocol.Packet, frag fragment.Fragment) {
	pkt.Streaming = frag.Streaming
	pkt.BlockIndex = frag.BlockIndex
	pkt.BlockLen = frag.BlockLen
	pkt.Final = frag.Final
}

// SetStreamSink installs a factory that provides an io.WriteCloser to flush a
// received stream into (completed blocks are written in order, then Closed). When
// nil, a streamed transfer is buffered in memory and delivered via the onData
// callback instead — correct, but without the receiver-side memory bound. Call
// before Start.
func (t *Transfer) SetStreamSink(factory func(id [32]byte) io.WriteCloser) {
	t.streamSink = factory
}

// SetStreamBlockSize overrides the streaming block size (non-positive restores
// the default). Call before Start.
func (t *Transfer) SetStreamBlockSize(size int) {
	if size <= 0 {
		size = defaultStreamBlockSize
	}
	t.streamBlockSize = size
}

// SendStream erasure-codes and sends the contents of r to destNode block by
// block, so the sender never buffers the whole payload. It requires a content
// key and an erasure-coding configuration (DataShards/ParityShards). Delivery
// prefers the anonymous forwarded path when hops are configured and eligible
// relays exist, otherwise it falls back to a direct streamed connection (the
// same degradation as SendData). When the caller enabled ConfirmDelivery the
// send blocks until the receiver acknowledges the whole reassembled stream and
// returns an error if that ack does not arrive; otherwise it is fire-and-forget.
//
// Note: when hops are configured but no relay is available, the fallback to a
// direct connection reveals the sender to the recipient — anonymity degrades to
// direct rather than failing, matching SendData.
func (t *Transfer) SendStream(r io.Reader, destNode string) error {
	if t.sealer == nil || t.dataShards <= 0 || t.parityShards <= 0 {
		return fmt.Errorf("streaming requires a content key and erasure coding (DataShards/ParityShards)")
	}
	if destNode == "" {
		return fmt.Errorf("streaming requires a destination node")
	}

	nodes := t.discovery.GetActiveNodes()
	nodes = t.resolveDest(destNode, nodes) // transparent DHT resolution
	var dest *discovery.Node
	for _, n := range nodes {
		if n.ID == destNode {
			dest = n
			break
		}
	}
	if dest == nil {
		return fmt.Errorf("destination node %s is not active", destNode)
	}

	id := sha256.Sum256(append(randomToken(), []byte(time.Now().String())...))

	// Choose the content sealer: per-recipient (sealed to the dest's public key,
	// PQ hybrid when enabled) when the dest is keyed; otherwise the shared-key
	// sealer. Each erasure-coded shard is sealed with it.
	sealer, hybrid, pq := t.contentSealer(dest)

	sc := scheme{
		DataShards:   uint32(t.dataShards),
		ParityShards: uint32(t.parityShards),
		Streaming:    true,
		HybridSealed: hybrid,
		PQ:           pq,
	}

	// Delivery confirmation: register a pending ack and embed a token in the
	// reply block (forwarded) — or rely on the receiver's signed direct ack — so
	// the sender learns when the whole stream has been reassembled and flushed.
	var ackToken []byte
	var ackCh chan struct{}
	if t.confirm {
		ackToken = randomToken()
		ackCh = t.registerAck(id, dest.SignKey, ackToken)
		defer t.unregisterAck(id)
	}

	var sendErr error
	sentForwarded := false
	if t.hopCount > 0 && t.nodePriv != nil && len(dest.PubKey) > 0 {
		// Only commit to the forwarded path when a route can actually be built.
		// r is a single-pass reader, so we cannot start streaming forwarded and
		// then retry direct once bytes are consumed; if there are no eligible
		// relays (e.g. a swarm of just the two endpoints), fall through to the
		// direct path instead of black-holing the stream.
		if fc, err := t.newForwardCtx(dest, nodes, id, sc, ackToken); err == nil && len(fc.relays) > 0 {
			sendErr = t.streamBlocks(r, fc.sendFragment, id, sealer, 0)
			sentForwarded = true
		}
	}
	if !sentForwarded {
		// Strict anonymity: refuse to degrade an anonymous stream to a direct one
		// (which would reveal the sender) when no forwarded route could be built.
		if t.strictAnon && t.hopCount > 0 {
			return fmt.Errorf("strict anonymity: no relay route to %s for %d hops", destNode, t.hopCount)
		}
		sendErr = t.streamDirect(dest, id, sc, r, sealer)
	}
	if sendErr != nil {
		return sendErr
	}

	if t.confirm {
		select {
		case <-ackCh:
			return nil
		case <-time.After(streamAckTimeout):
			return fmt.Errorf("stream to %s not confirmed within %s", destNode, streamAckTimeout)
		case <-t.ctx.Done():
			return fmt.Errorf("transfer canceled")
		}
	}
	return nil
}

// resumableStreamTTL bounds how long an interrupted resumable stream's partial
// state is retained on the receiver awaiting a resume before it is reclaimed.
const resumableStreamTTL = time.Hour

// SendStreamResumable streams r to destNode over a direct connection with resume
// support: the transfer is identified stably by streamID, so if a send is
// interrupted, a later call with the same streamID skips the blocks the receiver
// already holds and continues. r must be an io.ReadSeeker (e.g. a file), and the
// block size must be the same across attempts. Resumable streaming uses the
// direct path (the recipient must be directly reachable); the anonymous forwarded
// path is not supported.
func (t *Transfer) SendStreamResumable(r io.ReadSeeker, destNode, streamID string) error {
	if t.sealer == nil || t.dataShards <= 0 || t.parityShards <= 0 {
		return fmt.Errorf("streaming requires a content key and erasure coding (DataShards/ParityShards)")
	}
	if destNode == "" || streamID == "" {
		return fmt.Errorf("resumable streaming requires a destination and a stream id")
	}

	nodes := t.discovery.GetActiveNodes()
	nodes = t.resolveDest(destNode, nodes)
	var dest *discovery.Node
	for _, n := range nodes {
		if n.ID == destNode {
			dest = n
			break
		}
	}
	if dest == nil {
		return fmt.Errorf("destination node %s is not active", destNode)
	}

	// Stable transfer ID per (sender, dest, streamID) so retries resume the same
	// receiver-side state.
	id := sha256.Sum256([]byte(t.selfID + "|" + destNode + "|" + streamID))

	sealer, hybrid, pq := t.contentSealer(dest)
	sc := scheme{
		DataShards:   uint32(t.dataShards),
		ParityShards: uint32(t.parityShards),
		Streaming:    true,
		Resumable:    true,
		HybridSealed: hybrid,
		PQ:           pq,
	}
	return t.streamDirectResumable(dest, id, sc, r, sealer)
}

// streamDirectResumable is streamDirect plus resume negotiation: the receiver's
// init acknowledgement reports the next block it needs (in ChunkNumber); the
// sender seeks r to that block and streams from there.
func (t *Transfer) streamDirectResumable(dest *discovery.Node, id [32]byte, sc scheme, r io.ReadSeeker, sealer encryption.Sealer) error {
	conn := dialWithRetries(peerDialAddr(dest))
	if conn == nil {
		return fmt.Errorf("failed to connect to node %s", dest.ID)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	meta := &storage.ChunkMeta{ID: id, DestNode: dest.ID}
	initPacket := protocol.NewPacket(protocol.PacketTypeData, nil, "", dest.ID)
	initPacket.ID = id
	initPacket.SourceNode = t.selfID
	applyScheme(initPacket, sc)
	initPacket.Sign(t.signKey)
	if err := protocol.WritePacket(conn, initPacket); err != nil {
		return fmt.Errorf("failed to send streaming init: %w", err)
	}
	ack, err := protocol.ReadPacket(br)
	if err != nil {
		return fmt.Errorf("failed to receive streaming ack: %w", err)
	}

	// Resume from the block the receiver still needs.
	resumeFrom := ack.ChunkNumber
	size := t.streamBlockSize
	if size <= 0 {
		size = defaultStreamBlockSize
	}
	if resumeFrom > 0 {
		if _, err := r.Seek(int64(resumeFrom)*int64(size), io.SeekStart); err != nil {
			return fmt.Errorf("resume seek failed: %w", err)
		}
	}

	return t.streamBlocks(r, func(frag fragment.Fragment) error {
		return t.sendFragmentDirect(conn, br, id, meta, sc, frag)
	}, id, sealer, resumeFrom)
}

// sweepResumableStreams reclaims retained partial resumable streams that have not
// been resumed within resumableStreamTTL.
func (t *Transfer) sweepResumableStreams() {
	ticker := time.NewTicker(resumableStreamTTL / 6)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-resumableStreamTTL)
			t.transfers.Range(func(key, value any) bool {
				st := value.(*transferState)
				if st.scheme.Resumable && st.stream != nil && st.stream.abandonIfIdle(cutoff) {
					t.transfers.Delete(key)
				}
				return true
			})
		}
	}
}

// streamDirect opens one streamed connection and emits every block's fragments
// over it, waiting for per-chunk acks (like the whole-payload direct path).
func (t *Transfer) streamDirect(dest *discovery.Node, id [32]byte, sc scheme, r io.Reader, sealer encryption.Sealer) error {
	conn := dialWithRetries(peerDialAddr(dest))
	if conn == nil {
		return fmt.Errorf("failed to connect to node %s", dest.ID)
	}
	defer conn.Close()
	br := bufio.NewReader(conn)

	meta := &storage.ChunkMeta{ID: id, DestNode: dest.ID}
	initPacket := protocol.NewPacket(protocol.PacketTypeData, nil, "", dest.ID)
	initPacket.ID = id
	initPacket.SourceNode = t.selfID
	applyScheme(initPacket, sc)
	initPacket.Sign(t.signKey)
	if err := protocol.WritePacket(conn, initPacket); err != nil {
		return fmt.Errorf("failed to send streaming init: %w", err)
	}
	if _, err := protocol.ReadPacket(br); err != nil {
		return fmt.Errorf("failed to receive streaming ack: %w", err)
	}

	return t.streamBlocks(r, func(frag fragment.Fragment) error {
		return t.sendFragmentDirect(conn, br, id, meta, sc, frag)
	}, id, sealer, 0)
}

// streamBlocks reads r one block at a time, erasure-codes each block, and emits
// its fragments via send. It uses one block of lookahead so the last block is
// marked Final even when the payload is an exact multiple of the block size.
func (t *Transfer) streamBlocks(r io.Reader, send func(fragment.Fragment) error, id [32]byte, sealer encryption.Sealer, startBlock uint32) error {
	size := t.streamBlockSize
	if size <= 0 {
		size = defaultStreamBlockSize
	}
	buf := make([]byte, size)

	readBlock := func() ([]byte, bool, error) {
		n, err := io.ReadFull(r, buf)
		switch err {
		case nil:
			return append([]byte(nil), buf[:n]...), false, nil // full block; more may follow
		case io.ErrUnexpectedEOF:
			return append([]byte(nil), buf[:n]...), true, nil // short read => last block
		case io.EOF:
			return nil, true, nil // no more data
		default:
			return nil, false, err
		}
	}

	emit := func(blockIndex uint32, data []byte, final bool) error {
		frags, err := t.encodeBlock(id, blockIndex, data, final, sealer)
		if err != nil {
			return err
		}
		for _, f := range frags {
			if err := send(f); err != nil {
				return err
			}
		}
		return nil
	}

	prev, prevFinal, err := readBlock()
	if err != nil {
		return err
	}
	if prev == nil { // empty stream: a single empty final block
		return emit(startBlock, nil, true)
	}

	blockIndex := startBlock
	for {
		if prevFinal {
			return emit(blockIndex, prev, true)
		}
		next, nextFinal, err := readBlock()
		if err != nil {
			return err
		}
		if next == nil { // prev was the last full block
			return emit(blockIndex, prev, true)
		}
		if err := emit(blockIndex, prev, false); err != nil {
			return err
		}
		blockIndex++
		prev, prevFinal = next, nextFinal
	}
}

// encodeBlock Reed-Solomon-encodes one block into sealed shards tagged with
// their block position. A block shorter than dataShards is zero-padded so it can
// still be split; BlockLen carries the true length so the receiver trims it.
func (t *Transfer) encodeBlock(id [32]byte, blockIndex uint32, data []byte, final bool, sealer encryption.Sealer) ([]fragment.Fragment, error) {
	f, err := fragment.NewRSFragmenter(sealer, t.dataShards, t.parityShards)
	if err != nil {
		return nil, err
	}
	blockLen := len(data)
	enc := data
	if len(enc) < t.dataShards {
		padded := make([]byte, t.dataShards)
		copy(padded, enc)
		enc = padded
	}
	frags, _, err := f.Fragment(id, enc)
	if err != nil {
		return nil, err
	}
	for i := range frags {
		frags[i].Streaming = true
		frags[i].BlockIndex = blockIndex
		frags[i].BlockLen = uint32(blockLen)
		frags[i].Final = final
	}
	return frags, nil
}

// streamAssembler reconstructs a streamed transfer block by block and flushes
// completed blocks, in order, to a sink (or an in-memory buffer delivered via
// onData when no sink is configured). Only blocks not yet flushed are held, so
// memory is bounded by the reordering window rather than the whole payload.
type streamAssembler struct {
	mu           sync.Mutex
	t            *Transfer
	id           [32]byte
	dataShards   int
	parityShards int
	sink         io.WriteCloser
	buf          *bytes.Buffer // used when sink is nil
	blocks       map[uint32]*streamBlock
	nextFlush    uint32
	done         bool

	// For the end-to-end delivery ack sent on completion: the anonymous reply
	// block (forwarded transfers) or the origin node (direct transfers).
	replyBlock []byte
	sourceNode string

	hybridSealed bool      // shards sealed to our node key rather than a shared key
	pq           bool      // hybrid sealing uses X25519 + ML-KEM-768
	lastActivity time.Time // last time a fragment was absorbed (for the resume sweep)
}

type streamBlock struct {
	total    uint32
	blockLen int
	final    bool
	received map[uint32]bool
	chunks   map[uint32][]byte
	subParts map[uint32]map[uint32][]byte
	data     []byte // reconstructed block, awaiting in-order flush
	ready    bool
}

func (t *Transfer) newStreamAssembler(pkt *protocol.Packet) *streamAssembler {
	sa := &streamAssembler{
		t:            t,
		id:           pkt.ID,
		dataShards:   int(pkt.DataShards),
		parityShards: int(pkt.ParityShards),
		blocks:       make(map[uint32]*streamBlock),
		replyBlock:   pkt.ReplyBlock,
		sourceNode:   pkt.SourceNode,
		hybridSealed: pkt.HybridSealed,
		pq:           pkt.PQ,
		lastActivity: time.Now(),
	}
	if t.streamSink != nil {
		sa.sink = t.streamSink(pkt.ID)
	}
	if sa.sink == nil {
		sa.buf = &bytes.Buffer{}
	}
	return sa
}

// add records one streamed fragment piece. It returns true once the whole stream
// has been flushed (the final block and everything before it).
func (sa *streamAssembler) add(pkt *protocol.Packet) bool {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	if sa.done {
		return true
	}
	sa.lastActivity = time.Now()

	b := sa.blocks[pkt.BlockIndex]
	if b == nil {
		b = &streamBlock{
			total:    pkt.TotalChunks,
			blockLen: int(pkt.BlockLen),
			final:    pkt.Final,
			received: make(map[uint32]bool),
			chunks:   make(map[uint32][]byte),
			subParts: make(map[uint32]map[uint32][]byte),
		}
		sa.blocks[pkt.BlockIndex] = b
	}
	if b.ready {
		return sa.done // already reconstructed, awaiting or past flush
	}

	if idx, payload, ok := absorbStreamPiece(b, pkt); ok {
		b.chunks[idx] = payload
		b.received[idx] = true
	}

	if uint32(len(b.received)) >= uint32(sa.dataShards) {
		if data, err := sa.reconstructBlock(b); err == nil {
			b.data = data
			b.ready = true
			b.received = nil
			b.chunks = nil
			b.subParts = nil
		}
	}

	sa.flushReady()
	return sa.done
}

// flushReady writes contiguous reconstructed blocks starting at nextFlush and
// finishes the stream once the final block is flushed.
func (sa *streamAssembler) flushReady() {
	for {
		b := sa.blocks[sa.nextFlush]
		if b == nil || !b.ready {
			return
		}
		if sa.sink != nil {
			_, _ = sa.sink.Write(b.data)
		} else {
			sa.buf.Write(b.data)
		}
		final := b.final
		delete(sa.blocks, sa.nextFlush)
		sa.nextFlush++
		if final {
			sa.finish()
			return
		}
	}
}

// resumeFrom returns the next block index the assembler still needs — the resume
// point reported to a sender re-sending a resumable stream.
func (sa *streamAssembler) resumeFrom() uint32 {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	return sa.nextFlush
}

// abandonIfIdle closes the sink of an incomplete stream that has seen no activity
// since cutoff, without delivering — reclaiming a resumable partial that was
// never resumed. Returns true if it abandoned the stream (caller should delete).
func (sa *streamAssembler) abandonIfIdle(cutoff time.Time) bool {
	sa.mu.Lock()
	defer sa.mu.Unlock()
	if sa.done || sa.lastActivity.After(cutoff) {
		return false
	}
	sa.done = true
	if sa.sink != nil {
		_ = sa.sink.Close()
	}
	return true
}

func (sa *streamAssembler) finish() {
	sa.done = true
	sa.t.metrics.IncDelivered()
	sa.t.recordHop(HopDeliver, protocol.HexID(sa.id)[:8])

	if sa.sink != nil {
		_ = sa.sink.Close()
	} else if sa.t.onData != nil {
		// No external sink: deliver the buffered payload via the onData callback.
		data := sa.buf.Bytes()
		go sa.t.onData(data, false)
	}

	// End-to-end delivery acknowledgement (mirrors the whole-payload dispatch):
	// the anonymous reply block for forwarded streams, else a signed ack to the
	// origin for direct streams. A confirmed SendStream waits for this.
	switch {
	case len(sa.replyBlock) > 0:
		go sa.t.sendAckReply(sa.replyBlock)
	case sa.sourceNode != "":
		go sa.t.sendAck(sa.sourceNode, sa.id)
	}
}

func (sa *streamAssembler) reconstructBlock(b *streamBlock) ([]byte, error) {
	sealer := sa.t.recipientOpener(scheme{HybridSealed: sa.hybridSealed, PQ: sa.pq})
	r := fragment.NewRSReassembler(sealer, sa.dataShards, sa.parityShards, b.blockLen)
	for idx, payload := range b.chunks {
		_ = r.Add(fragment.Fragment{TransferID: sa.id, Index: idx, Total: b.total, Payload: payload})
	}
	return r.Reconstruct(sa.id)
}

// absorbStreamPiece reassembles a block's sub-chunks into a complete shard,
// reusing the shared sub-chunk logic over a single block's buffers.
func absorbStreamPiece(b *streamBlock, pkt *protocol.Packet) (idx uint32, payload []byte, ok bool) {
	return absorbSubChunk(b.received, b.subParts, pkt)
}
