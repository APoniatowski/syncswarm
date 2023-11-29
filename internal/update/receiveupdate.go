package update

import (
	"encoding/json"
	"net"
	"strconv"
)

func (networkUpdate *NetworkUpdateData) ReceiveUpdate() error {
	listenAddr, _ := net.ResolveUDPAddr("udp", strconv.Itoa(udpPort))
	conn, _ := net.ListenUDP("udp", listenAddr)
	defer conn.Close()

	buffer := make([]byte, 1024)
	n, _, _ := conn.ReadFromUDP(buffer)

	var receivedData NetworkUpdateData
	//////////////////// Logic below still WIP ////////////////////////////
	err := json.Unmarshal(buffer[:n], &receivedData)
	if err != nil {
		return err
	}
	return nil
}
