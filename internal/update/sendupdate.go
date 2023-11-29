package update

import (
	"fmt"
	"net"
	"strconv"
	"sync"
)

func (networkUpdate *NetworkUpdateData) SendUpdate(key *string) error {
	var waitGroup sync.WaitGroup
	var encryptedData []byte
	var err error
	waitGroup.Add(1)
	go func() {
		encryptedData, err = networkUpdate.encryptUpdateData([]byte(*key))
		waitGroup.Done()
	}()
	if err != nil {
		return err
	}
	waitGroup.Wait()
	errMap := make(map[string]error)
	for _, node := range networkUpdate.Nodes {
		if node == networkUpdate.Originator {
			continue
		}
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
