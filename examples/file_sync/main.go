// File sync: broadcasts files added or changed in a watched directory to all
// other nodes, which write them into their own directory.
//
// Run several instances on one host with distinct discovery ports:
//
//	go run . -dir ./dirA -disc 64512
//	go run . -dir ./dirB -disc 64522 -boot 127.0.0.1:64512
package main

import (
	"crypto/sha256"
	"encoding/gob"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/APoniatowski/syncswarm/swarmsync"
)

// FileMsg is a file's (relative) path and contents, broadcast to peers.
type FileMsg struct {
	Path    string
	Content []byte
}

func main() {
	dir := flag.String("dir", "", "directory to watch and sync (required)")
	disc := flag.Int("disc", 0, "discovery UDP port (0 = default 64512)")
	boot := flag.String("boot", "", "comma-separated bootstrap peers")
	flag.Parse()

	if *dir == "" {
		log.Fatal("-dir is required")
	}
	if err := os.MkdirAll(*dir, 0o755); err != nil {
		log.Fatalf("watch dir: %v", err)
	}

	gob.Register(FileMsg{})
	key := sha256.Sum256([]byte("syncswarm-example-shared-key"))

	node, err := swarmsync.New(swarmsync.Options{
		StorageDir:     filepath.Join(*dir, ".syncswarm"), // identity + chunk store
		Group:          "ALL",
		Key:            key[:],
		DiscoveryPort:  *disc,
		DataPort:       -1, // ephemeral: peers learn it via discovery, so instances can share a host
		BootstrapPeers: splitCSV(*boot),
		OnVariableReceived: func(v interface{}) {
			msg, ok := v.(FileMsg)
			if !ok {
				return
			}
			target := filepath.Join(*dir, filepath.Base(msg.Path))
			if err := os.WriteFile(target, msg.Content, 0o644); err != nil {
				log.Printf("write %s: %v", target, err)
				return
			}
			fmt.Printf("received file %s (%d bytes)\n", msg.Path, len(msg.Content))
		},
	})
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	if err := node.Start(); err != nil {
		log.Fatalf("start: %v", err)
	}
	defer node.Stop()
	fmt.Printf("file-sync node %s watching %s (discovery :%d)\n", node.NodeID(), *dir, node.DiscoveryPort())

	watch(node, *dir)
}

// watch polls the directory and broadcasts new/modified files. A production app
// would use fsnotify instead of polling.
func watch(node *swarmsync.SyncSwarm, dir string) {
	seen := make(map[string]time.Time)
	for {
		node.Bootstrap()
		entries, err := os.ReadDir(dir)
		if err != nil {
			log.Printf("read dir: %v", err)
			time.Sleep(time.Second)
			continue
		}
		for _, e := range entries {
			if e.IsDir() || e.Name() == ".syncswarm" {
				continue
			}
			info, err := e.Info()
			if err != nil {
				continue
			}
			path := filepath.Join(dir, e.Name())
			if last, ok := seen[path]; ok && !info.ModTime().After(last) {
				continue
			}
			content, err := os.ReadFile(path)
			if err != nil {
				continue
			}
			if err := node.SendVariable(FileMsg{Path: e.Name(), Content: content}); err != nil {
				log.Printf("sync %s: %v", e.Name(), err)
				continue
			}
			seen[path] = info.ModTime()
			fmt.Printf("broadcast file %s (%d bytes)\n", e.Name(), len(content))
		}
		time.Sleep(time.Second)
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
