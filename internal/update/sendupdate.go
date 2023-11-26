package update

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"
)

func (networkupdate *NetworkUpdateData) SendUpdate() error {
	var waitGroup sync.WaitGroup
	var encryptedData []byte
	var err error
	waitGroup.Add(1)
	go func() {
		encryptedData, err = networkupdate.EncryptUpdateData()
		waitGroup.Done()
	}()
	if err != nil {
		return err
	}
	waitGroup.Wait()
	errMap := make(map[string]error)
	for _, node := range networkupdate.Nodes {
		nodeAddr, err := net.ResolveUDPAddr("udp", node+":"+strconv.Itoa(udpPort))
		if err != nil {
			return err
		}
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			sending, err := net.DialUDP("udp", nil, nodeAddr)
			if err != nil {
				errMap[node] = err
			}
			defer sending.Close()
			if sendConfirmation(sending) {
				_, err = sending.Write(encryptedData)
				if err != nil {
					errMap[node] = err
				}
			}
		}()
		waitGroup.Wait()
	}
	if len(errMap) > 0 {
		for key, value := range errMap {
			fmt.Println(key + ": " + value.Error())
		}
	}
	return nil
}

func (data NetworkUpdateData) EncryptUpdateData() ([]byte, error) {
	var encryptedUpdate []byte
	// encrypt the new network data and convert to bytes using the PreSharedKey
	return encryptedUpdate, nil
}

func sendConfirmation(conn *net.UDPConn) bool {
	var result bool
	for index, request := range confirmationRequests {
		_, err := conn.Write([]byte(request))
		if err != nil {
			return false
		}
		deadline := time.Now().Add(200 * time.Millisecond)
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			return false
		}
		buffer := make([]byte, 1024)
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return false
		}
		if string(buffer[:n]) == expectedResponses[index] {
			result = true
		}
	}

	return result
}
