# SyncSwarm Examples

Runnable examples for the [SyncSwarm](../README.md) SDK. Each is a single binary
you run as several instances (on one host or many).

All examples share a fixed demo key (`sha256("syncswarm-example-shared-key")`) so
instances can read each other's messages. **Use a real, secret key in production.**

A node's identity is derived from a persistent key in its `-dir`, so reusing the
same `-dir` keeps its `NodeID` stable across restarts. Each instance prints its
`NodeID` on startup.

## Running multiple instances on one host

Instances can't share a UDP discovery port, so give each a distinct `-disc` port
and point later ones at the first with `-boot`:

```bash
# first node on the default discovery port
go run . -dir ./a -disc 64512

# more nodes, bootstrapping off the first
go run . -dir ./b -disc 64522 -boot 127.0.0.1:64512
```

On separate machines you can use the default ports and just set `-boot` to a
known peer.

## file_sync — directory synchronization

Broadcasts files added or changed in a watched directory to all peers.

```bash
go run . -dir ./dirA -disc 64512
go run . -dir ./dirB -disc 64522 -boot 127.0.0.1:64512
```

Drop a file into `dirA`; it appears in `dirB`.

## realtime_sync — shared state

Each node broadcasts an incrementing counter every 5 seconds; all nodes converge
on the latest update.

```bash
go run . -dir ./a -disc 64512
go run . -dir ./b -disc 64522 -boot 127.0.0.1:64512
```

## secure_send — addressed, encrypted, confirmed delivery

Sends an encrypted message to a specific node addressed by its `NodeID`, waiting
for an authenticated acknowledgement.

```bash
# 1. recipient (prints its NodeID)
go run . -dir ./recipient -disc 64512

# 2. (optional) a relay, so the send is onion-routed / anonymous
go run . -dir ./relay -disc 64522 -boot 127.0.0.1:64512 -relay

# 3. sender — use the recipient's NodeID from step 1
go run . -dir ./sender -disc 64532 -boot 127.0.0.1:64512 \
    -to <recipient-node-id> -msg "hello"
```

With a relay present the send is onion-routed and the recipient can't learn the
sender; with only two nodes it falls back to a direct send.
