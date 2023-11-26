package update

import (
	"net"
	"strconv"
)

func (networkUpdate *NetworkUpdateData) ReceiveUpdate() error {
	listening, err := net.ListenPacket("udp", strconv.Itoa(udpPort))
	if err != nil {
		return err
	}
	defer listening.Close()

	for {
		buf := make([]byte, 1024)
		_, _, err := listening.ReadFrom(buf)
		if err != nil {
			return err
		}
	}
}
