package iface

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"net"
	"time"
)

// Bridge authentication: an optional pre-shared-key gate on who may attach a TCP
// bridge.
//
// A bridge listener otherwise accepts every connection, which makes the bridge
// host a privileged position: it sees the discovery metadata of everyone attached
// to it and can selectively drop or delay traffic (SECURITY_AUDIT.md finding 3).
// A PSK does not make the bridge confidential — packets are already signed, and
// payloads are sealed end to end — it decides *who may attach at all*, which is
// what a private deployment needs.
//
// When the PSK is empty the handshake is skipped entirely and the bridge stays
// open, which is the right default for a public seed.
const (
	// bridgeAuthTimeout bounds the whole handshake, so a peer that connects and
	// then says nothing cannot pin a slot open.
	bridgeAuthTimeout = 10 * time.Second
	bridgeNonceLen    = 32

	// The two directions use different labels so a proof cannot be reflected back
	// at its sender. Both nonces are bound into each proof, making a transcript
	// from one connection useless on another.
	bridgeLabelClient = "syncswarm-bridge-v1:client"
	bridgeLabelServer = "syncswarm-bridge-v1:server"
)

func bridgeProof(psk []byte, label string, serverNonce, clientNonce []byte) []byte {
	m := hmac.New(sha256.New, psk)
	m.Write([]byte(label))
	m.Write(serverNonce)
	m.Write(clientNonce)
	return m.Sum(nil)
}

func bridgeNonce() ([]byte, error) {
	n := make([]byte, bridgeNonceLen)
	if _, err := rand.Read(n); err != nil {
		return nil, fmt.Errorf("iface bridge auth: nonce: %w", err)
	}
	return n, nil
}

// bridgeAuthServer runs the accepting side. The dialer speaks first, and nothing
// is sent to a peer that has not opened with a well-formed hello. Two reasons that
// ordering matters:
//
//   - A peer with no key (dialing a bridge it does not know is protected) receives
//     *nothing at all*, so the bridge-liveness check still reports "connected but
//     received no traffic". When the server opened with a challenge instead, a
//     PSK-less client read that challenge as an ordinary frame, marked the bridge
//     active, and the misconfiguration became completely silent.
//   - The server proves itself only after the client has, so an unauthenticated
//     peer cannot harvest server proofs over chosen nonces as an offline oracle.
func bridgeAuthServer(conn net.Conn, r *bufio.Reader, psk []byte) error {
	if len(psk) == 0 {
		return nil
	}
	if err := conn.SetDeadline(time.Now().Add(bridgeAuthTimeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})

	clientNonce, err := readFrame(r)
	if err != nil {
		return fmt.Errorf("iface bridge auth: read client hello: %w", err)
	}
	if len(clientNonce) != bridgeNonceLen {
		return fmt.Errorf("iface bridge auth: bad client nonce length %d", len(clientNonce))
	}
	serverNonce, err := bridgeNonce()
	if err != nil {
		return err
	}
	if err := writeFrame(conn, serverNonce); err != nil {
		return fmt.Errorf("iface bridge auth: send challenge: %w", err)
	}
	got, err := readFrame(r)
	if err != nil {
		return fmt.Errorf("iface bridge auth: read client proof: %w", err)
	}
	want := bridgeProof(psk, bridgeLabelClient, serverNonce, clientNonce)
	if !hmac.Equal(got, want) {
		return fmt.Errorf("iface bridge auth: client failed authentication")
	}
	if err := writeFrame(conn, bridgeProof(psk, bridgeLabelServer, serverNonce, clientNonce)); err != nil {
		return fmt.Errorf("iface bridge auth: send proof: %w", err)
	}
	return nil
}

// bridgeAuthClient runs the dialing side.
func bridgeAuthClient(conn net.Conn, r *bufio.Reader, psk []byte) error {
	if len(psk) == 0 {
		return nil
	}
	if err := conn.SetDeadline(time.Now().Add(bridgeAuthTimeout)); err != nil {
		return err
	}
	defer conn.SetDeadline(time.Time{})

	clientNonce, err := bridgeNonce()
	if err != nil {
		return err
	}
	if err := writeFrame(conn, clientNonce); err != nil {
		return fmt.Errorf("iface bridge auth: send hello: %w", err)
	}
	serverNonce, err := readFrame(r)
	if err != nil {
		return fmt.Errorf("iface bridge auth: read challenge: %w", err)
	}
	if len(serverNonce) != bridgeNonceLen {
		return fmt.Errorf("iface bridge auth: bad server nonce length %d", len(serverNonce))
	}
	if err := writeFrame(conn, bridgeProof(psk, bridgeLabelClient, serverNonce, clientNonce)); err != nil {
		return fmt.Errorf("iface bridge auth: send proof: %w", err)
	}
	got, err := readFrame(r)
	if err != nil {
		return fmt.Errorf("iface bridge auth: read server proof: %w", err)
	}
	if !hmac.Equal(got, bridgeProof(psk, bridgeLabelServer, serverNonce, clientNonce)) {
		return fmt.Errorf("iface bridge auth: server failed authentication")
	}
	return nil
}
