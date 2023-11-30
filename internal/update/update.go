package update

import (
	"log"
	"os"
	"sync"

	"github.com/APoniatowski/syncswarm/internal"
)

func init() {
	// Run discovery checks and get any info
}

func UpdatePayload(payload UpdateService) *NewUpdate {
	return &NewUpdate{
		NewPayload: payload,
	}
}

func (payload *NewUpdate) StartUpdates() int {
	var waitgroup sync.WaitGroup
	go newKeys(&waitgroup)
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalln(err)
		return 1
	}
	// partial dummy data
	payload.NetworkUpdateData = NetworkUpdateData{
		Nodes:      []string{"node1", "node2"},
		Originator: hostname,
		NewPubKey:  "",
		NewPrivKey: "",
	}
	waitgroup.Wait()
	var currentData internal.CurrentData
	// populate data here
	err = payload.NetworkUpdateData.SendUpdate(currentData.PreSharedKey)
	if err != nil {
		log.Fatalln(err)
		return 2
	}
	return 0
}
