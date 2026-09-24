package iface

import "testing"

// TestUDPInterface_SizedMTU verifies the advertised (sizing) MTU and the hard
// send cap are independent: Caps reports the small fragmentation-safe MTU while
// Send still accepts a datagram up to the larger cap.
func TestUDPInterface_SizedMTU(t *testing.T) {
	u, err := NewUDPInterfaceSized("u", "127.0.0.1:0", "", 1400, 9000)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	if got := u.Caps().MTU; got != 1400 {
		t.Fatalf("advertised MTU = %d, want 1400", got)
	}
	// A frame between the advertised MTU and the send cap is accepted (unicast to
	// self so the datagram actually leaves the socket).
	self := u.LocalAddr().String()
	if err := u.Send(self, make([]byte, 4000)); err != nil {
		t.Fatalf("frame within send cap rejected: %v", err)
	}
	// A frame past the send cap is rejected.
	if err := u.Send(self, make([]byte, 9001)); err == nil {
		t.Fatal("frame exceeding send cap should be rejected")
	}
}

func TestUDPInterface_MTUCapDefaultsEqual(t *testing.T) {
	// NewUDPInterfaceMTU sets sizing MTU and send cap to the same value.
	u, err := NewUDPInterfaceMTU("u", "127.0.0.1:0", "", 2000)
	if err != nil {
		t.Fatal(err)
	}
	defer u.Close()
	if got := u.Caps().MTU; got != 2000 {
		t.Fatalf("MTU = %d, want 2000", got)
	}
	if err := u.Send(u.LocalAddr().String(), make([]byte, 2001)); err == nil {
		t.Fatal("frame past MTU should be rejected when cap == MTU")
	}
}
