package update

import (
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
