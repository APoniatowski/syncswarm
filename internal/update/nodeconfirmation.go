package update

import (
	"net"
	"time"
)

func sendConfirmation(conn *net.UDPConn) (result bool) {
	for index, request := range confirmationRequests {
		_, err := conn.Write([]byte(request))
		if err != nil {
			result = false
		}
		deadline := time.Now().Add(200 * time.Millisecond)
		err = conn.SetReadDeadline(deadline)
		if err != nil {
			result = false
		}
		buffer := make([]byte, 5) // 5 should be enough
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			result = false
		}
		if n <= 5 {
			if string(buffer[:n]) == expectedResponses[index] {
				result = true
			}
		} else {
			result = false
			break
		}
	}
	return result
}

func receiveConfirmation(conn *net.UDPConn) (result bool) {
	for index, response := range expectedResponses {
		buffer := make([]byte, 5) // 5 should be enough
		n, _, err := conn.ReadFromUDP(buffer)
		if err != nil {
			result = false
		}
		if n <= 5 {

			if string(buffer[:n]) == confirmationRequests[index] {
				result = true
			}
			_, err = conn.Write([]byte(response))
			if err != nil {
				result = false
			}

		} else {
			result = false
			break
		}
	}
	return result
}
