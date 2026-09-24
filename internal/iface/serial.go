package iface

// standardBauds are the line rates the serial backends accept. Anything else is
// rejected rather than silently mis-configuring the port.
var standardBauds = []int{
	1200, 2400, 4800, 9600, 19200, 38400, 57600, 115200, 230400, 460800, 921600,
}

// validBaud reports whether baud is a supported serial line rate.
func validBaud(baud int) bool {
	for _, v := range standardBauds {
		if v == baud {
			return true
		}
	}
	return false
}
