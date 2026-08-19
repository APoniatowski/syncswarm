// Secure send: deliver an encrypted message to a specific node addressed by its
// key-derived NodeID, with confirmed delivery.
//
// Start a recipient (it prints its NodeID):
//
//	go run . -dir ./recipient -disc 64512
//
// Optionally start a relay so the send is onion-routed (anonymous) rather than
// direct:
//
//	go run . -dir ./relay -disc 64522 -boot 127.0.0.1:64512 -relay
//
// Then send to the recipient's NodeID:
//
//	go run . -dir ./sender -disc 64532 -boot 127.0.0.1:64512 \
//	    -to <recipient-node-id> -msg "hello"
package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/APoniatowski/syncswarm/swarmsync"
)

func main() {
	dir := flag.String("dir", "./secure-node", "storage dir (holds this node's persistent identity)")
	disc := flag.Int("disc", 0, "discovery UDP port (0 = default 64512)")
	boot := flag.String("boot", "", "comma-separated bootstrap peers")
	relay := flag.Bool("relay", false, "act as a forwarding relay for others")
	to := flag.String("to", "", "recipient NodeID to send to (empty = listen only)")
	msg := flag.String("msg", "hello from syncswarm", "message to send")
	flag.Parse()

	key := sha256.Sum256([]byte("syncswarm-example-shared-key"))

	node, err := swarmsync.New(swarmsync.Options{
		StorageDir:      *dir,
		Key:             key[:],
		DiscoveryPort:   *disc,
		DataPort:        -1, // ephemeral: peers learn it via discovery, so instances can share a host
		BootstrapPeers:  splitCSV(*boot),
		Relay:           *relay,
		HopCount:        1,         // onion-route through a relay when one exists; else direct
		ConfirmDelivery: *to != "", // sender waits for an authenticated ack
		OnDataReceived: func(data []byte) {
			fmt.Printf("received: %s\n", data)
		},
	})
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	if err := node.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}
	defer node.Stop()
	fmt.Printf("node %s running (discovery :%d)\n", node.NodeID(), node.DiscoveryPort())

	if *to == "" {
		fmt.Println("listening; share the NodeID above with a sender")
		select {}
	}

	// Sender: retry until the recipient is discovered and delivery is confirmed.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		node.Bootstrap()
		time.Sleep(500 * time.Millisecond)
		if err := node.SendTo([]byte(*msg), *to); err != nil {
			continue // recipient not discovered yet, or not yet confirmed
		}
		fmt.Println("delivered and confirmed")
		return
	}
	log.Fatal("timed out; is the recipient running and reachable?")
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
