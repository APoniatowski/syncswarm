package swarmsync

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"
)

// flakyReadSeeker serves data.Read up to limit bytes, then errors — simulating a
// mid-stream interruption. Seek is supported.
type flakyReadSeeker struct {
	data  []byte
	pos   int
	limit int
}

func (f *flakyReadSeeker) Read(p []byte) (int, error) {
	if f.pos >= f.limit {
		return 0, errors.New("simulated interruption")
	}
	end := f.pos + len(p)
	if end > f.limit {
		end = f.limit
	}
	if end > len(f.data) {
		end = len(f.data)
	}
	n := copy(p, f.data[f.pos:end])
	f.pos += n
	return n, nil
}
func (f *flakyReadSeeker) Seek(off int64, whence int) (int64, error) {
	f.pos = int(off)
	return off, nil
}

// recordingSeeker wraps a bytes.Reader and records the largest resume seek.
type recordingSeeker struct {
	*bytes.Reader
	seekedTo int64
}

func (r *recordingSeeker) Seek(off int64, whence int) (int64, error) {
	if whence == io.SeekStart && off > r.seekedTo {
		r.seekedTo = off
	}
	return r.Reader.Seek(off, whence)
}

// TestResumableStream interrupts a stream partway, then resumes it with the same
// stream ID, and verifies the file completes AND the resume skipped the blocks the
// receiver already had (the sender seeked past block 0).
func TestResumableStream(t *testing.T) {
	const blockSize = 4096
	key := bytes.Repeat([]byte{0x9c}, 32)
	content := bytes.Repeat([]byte("resumable-stream-payload!"), 2000) // ~50 KB, many blocks

	done := make(chan []byte, 8)
	mkSink := func(id [32]byte) io.WriteCloser { return &testStreamSink{done: done} }

	dest := newTestNode(t, Options{NodeID: "dest", Key: key, OnStreamReceived: mkSink})
	sender := newTestNode(t, Options{NodeID: "sender", Key: key, DataShards: 4, ParityShards: 2, StreamBlockSize: blockSize})
	nodes := []*SyncSwarm{dest, sender}
	wireAndStart(t, nodes...)

	// Let discovery settle so the direct dial resolves.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		for _, n := range nodes {
			n.Bootstrap()
		}
		time.Sleep(200 * time.Millisecond)
		// Phase 1: interrupted send (fails after 5 full blocks).
		flaky := &flakyReadSeeker{data: content, limit: 5 * blockSize}
		if err := sender.SendStreamResumable(flaky, dest.NodeID(), "file-1"); err == nil {
			continue // want it to fail; if it "succeeded", discovery wasn't ready — retry
		}

		// Give the receiver a moment to flush what it received.
		time.Sleep(300 * time.Millisecond)

		// Phase 2: resume with the full content and the SAME stream id.
		rs := &recordingSeeker{Reader: bytes.NewReader(content)}
		if err := sender.SendStreamResumable(rs, dest.NodeID(), "file-1"); err != nil {
			t.Fatalf("resume send failed: %v", err)
		}
		select {
		case got := <-done:
			if !bytes.Equal(got, content) {
				t.Fatalf("resumed file mismatch: %d vs %d bytes", len(got), len(content))
			}
			if rs.seekedTo == 0 {
				t.Fatal("resume did not skip any blocks (seekedTo == 0) — it restarted from scratch")
			}
			t.Logf("resumed after seeking to byte %d (block %d)", rs.seekedTo, rs.seekedTo/blockSize)
			return
		case <-time.After(5 * time.Second):
			t.Fatal("resumed stream never completed")
		}
	}
	t.Fatal("timed out establishing the transfer")
}
