package protocol

import "testing"

// TestRoutedFrameOverhead pins the fixed on-wire cost of a routed packet (header +
// hop-limit byte) so RoutedFrameOverhead stays a safe reserve for MTU sizing: the
// marshaled frame must never exceed the inner size by more than RoutedFrameOverhead.
func TestRoutedFrameOverhead(t *testing.T) {
	const id = "abcdef0123456789abcdef0123456789" // 32-hex node id, as used on the wire
	for _, n := range []int{0, 500, 1400, 65000} {
		inner := make([]byte, n)
		pkt := NewPacket(PacketTypeRouted, EncodeRouted(16, inner), "", id)
		pkt.SourceNode = id
		b, err := pkt.MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		if got := len(b) - n; got > RoutedFrameOverhead {
			t.Fatalf("inner=%d: frame overhead %d exceeds reserve %d", n, got, RoutedFrameOverhead)
		}
	}
}
