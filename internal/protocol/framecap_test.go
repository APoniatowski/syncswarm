package protocol

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestReadPacket_RejectsOversizedDeclaredLength is the guard for the
// pre-allocation DoS: ReadPacket sizes its buffer from a 4-byte length the peer
// declares, before any body arrives, on a connection that is not yet
// authenticated. The cap is therefore the ceiling on what a stranger can make the
// node allocate per connection, and must stay close to what a real frame needs.
func TestReadPacket_RejectsOversizedDeclaredLength(t *testing.T) {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], 64<<20) // what the old cap allowed
	if _, err := ReadPacket(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("a 64 MiB frame was accepted; 4 bytes of input must not commit that much memory")
	}

	binary.BigEndian.PutUint32(hdr[:], maxFrameSize+1)
	if _, err := ReadPacket(bytes.NewReader(hdr[:])); err == nil {
		t.Fatal("a frame above the cap was accepted")
	}

	// The cap must still clear a real fragment (4 MiB payload plus overhead), or
	// large transfers break.
	if maxFrameSize < 5<<20 {
		t.Fatalf("maxFrameSize %d is below a legitimate 4 MiB fragment plus overhead", maxFrameSize)
	}
}
