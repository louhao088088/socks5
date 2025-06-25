package proxy

import (
	"log"
	"net"
)

// Start 启动代理服务器
func Start(addr string) error {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		log.Printf("Accepted new connection from %s\n", conn.RemoteAddr())
		if err != nil {
			log.Printf("Accept error: %v\n", err)
			continue
		}
		go handleConnection(conn)
	}
}
