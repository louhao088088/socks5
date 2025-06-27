package server
import (
	"encoding/binary"
	"io"
	"log"		
	"net"
	"strconv"
)
func HandleConnect(conn net.Conn, dstAddr string) error {
	log.Println("CONNECT to", dstAddr)
	remote, err := net.Dial("tcp", dstAddr)
	if err != nil {
		SendFailureResponse(conn, 0x05) // 连接被拒绝
		log.Printf("Failed to connect to %s: %v\n", dstAddr, err)
		return err
	}
	defer remote.Close()
	
	// 发送成功响应
	_, err = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	if err != nil {
		log.Printf("Failed to send success response: %v\n", err)
		return err
	}

	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(conn, remote)
		done <- err
	}()
	go func(){
		_, err := io.Copy(remote, conn)
		done <- err
	}()
	
	<-done
	return nil
}

func stringPort(p []byte) string {
	port := binary.BigEndian.Uint16(p)
	return strconv.Itoa(int(port))
}