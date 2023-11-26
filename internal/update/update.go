package update

import (
	"log"
	"os"
	"sync"
)

func init() {
	// Run discovery checks and get any info:w
}

func StartUpdates() int {
	var waitgroup sync.WaitGroup
	go newKeys(&waitgroup)
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalln(err)
		return 1
	}
	prepUpdate := NetworkUpdateData{
		Nodes:      []string{"node1", "node2"},
		Originator: hostname,
		NewPubKey:  "",
		NewPrivKey: "",
	}
	waitgroup.Wait()
	err = prepUpdate.SendUpdate()
	if err != nil {
		log.Fatalln(err)
		return 2
	}
	return 0
}
