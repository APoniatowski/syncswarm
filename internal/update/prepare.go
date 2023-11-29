package update

import (
	"encoding/binary"
	"sync"

	"github.com/APoniatowski/syncswarm/internal/encryption"
)

func newKeys(waitgroup *sync.WaitGroup) int {
	waitgroup.Add(1)
	defer waitgroup.Done()
	err := encryption.GenerateKeys(4096)
	if err != nil {
		return 1
	}

	return 0
}

func splitUpdatePayload(data []byte, maxSegmentSize int, headerSize int) [][]byte {
	maxDataSize := maxSegmentSize - headerSize
	var segments [][]byte
	for len(data) > 0 {
		end := maxDataSize
		if end > len(data) {
			end = len(data)
		}
		segments = append(segments, data[:end])
		data = data[end:]
	}
	return segments
}

func createSegmentWithHeader(data []byte, messageID int, totalSegments int, segmentIndex int) []byte {
	// Logic: [messageID (4 bytes)] [totalSegments (4 bytes)] [segmentIndex (4 bytes)]
	header := make([]byte, 12)
	binary.BigEndian.PutUint32(header[0:4], uint32(messageID))
	binary.BigEndian.PutUint32(header[4:8], uint32(totalSegments))
	binary.BigEndian.PutUint32(header[8:12], uint32(segmentIndex))

	// Concatenate the header and the data
	return append(header, data...)
}
