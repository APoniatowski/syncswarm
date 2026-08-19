// Real-time state sync: every node broadcasts an incrementing counter; all nodes
// converge on the latest update.
//
// Run several instances on one host with distinct discovery ports, pointing the
// later ones at the first as a bootstrap peer:
//
//	go run . -dir ./a -disc 64512
//	go run . -dir ./b -disc 64522 -boot 127.0.0.1:64512
package main

import (
	"crypto/sha256"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/APoniatowski/syncswarm/swarmsync"
)

// StateUpdate is the value broadcast between nodes (no unexported fields, so gob
// can encode it).
type StateUpdate struct {
	Counter int
	LastMod time.Time
	Source  string
}

func main() {
	dir := flag.String("dir", "./state-node", "storage dir (holds this node's persistent identity)")
	disc := flag.Int("disc", 0, "discovery UDP port (0 = default 64512)")
	boot := flag.String("boot", "", "comma-separated bootstrap peers, e.g. 127.0.0.1:64512")
	flag.Parse()

	// gob must know the concrete type to decode it into OnVariableReceived.
	gob.Register(StateUpdate{})
	// A demo key shared by all instances; use a real, secret key in production.
	key := sha256.Sum256([]byte("syncswarm-example-shared-key"))

	var mu sync.Mutex
	var latest StateUpdate

	node, err := swarmsync.New(swarmsync.Options{
		StorageDir:     *dir,
		Group:          "ALL", // accept broadcasts
		Key:            key[:],
		DiscoveryPort:  *disc,
		DataPort:       -1, // ephemeral: peers learn it via discovery, so instances can share a host
		BootstrapPeers: splitCSV(*boot),
		OnVariableReceived: func(v interface{}) {
			u, ok := v.(StateUpdate)
			if !ok {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			if u.LastMod.After(latest.LastMod) {
				latest = u
				fmt.Printf("state updated: counter=%d source=%s\n", u.Counter, u.Source)
			}
		},
	})
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	if err := node.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}
	defer node.Stop()
	fmt.Printf("state-sync node %s running (discovery :%d)\n", node.NodeID(), node.DiscoveryPort())

	counter := 0
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		node.Bootstrap() // keep re-announcing so peers converge
		counter++
		u := StateUpdate{Counter: counter, LastMod: time.Now(), Source: node.NodeID()}
		if err := node.SendVariable(u); err != nil {
			log.Printf("broadcast: %v", err)
			continue
		}
		fmt.Printf("broadcast counter=%d\n", counter)
	}
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
