package main

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
)

func main() {
	addr := "[::]:8080"
	log.Printf("SOCKS5 proxy listening on %s...\n", addr)
	if err := Start(addr); err != nil {
		log.Fatalf("Failed to start proxy: %v", err)
	}
}

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

func handleConnection(conn net.Conn) {
	defer conn.Close()
	if err := handShake(conn); err != nil {
		log.Printf("Handshake failed: %v\n", err)
		return
	}

	if err := processRequest(conn); err != nil {
		log.Printf("processRequest failed: %v\n", err)
		return
	}

}

// 握手阶段：SOCKS5 协议的版本协商和认证方法协商
func handShake(conn net.Conn) error {
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	VER, NATHU := buf[0], buf[1]
	if VER != 5 {
		return io.ErrUnexpectedEOF
	}

	AUTH := make([]byte, NATHU)
	if _, err := io.ReadFull(conn, AUTH); err != nil {
		return err
	}
	_, err := conn.Write([]byte{0x05, 0x00})

	return err
}

// 处理客户端的 CONNECT 请求
func processRequest(conn net.Conn) error {

	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}

	VER, CMD, RSV, TYPE := buf[0], buf[1], buf[2], buf[3]
	if VER != 5 || CMD != 1 || RSV != 0 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00})
		return io.ErrUnexpectedEOF
	}

	var dstAddr string

	switch {
	case TYPE == 1: // IPV4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return err
		}
		dstAddr = net.IP(addr).String() + ":" + stringPort(port)

	case TYPE == 3: //域名
		domainLen := make([]byte, 1)
		if _, err := io.ReadFull(conn, domainLen); err != nil {
			return err
		}
		domain := make([]byte, domainLen[0])
		if _, err := io.ReadFull(conn, domain); err != nil {
			return err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return err
		}
		dstAddr = string(domain) + ":" + stringPort(port)

	case TYPE == 4: //IPV6
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return err
		}
		dstAddr = net.IP(addr).String() + ":" + stringPort(port)

	default:
		return io.ErrUnexpectedEOF
	}

	log.Println("CONNECT to", dstAddr)
	remote, err := net.Dial("tcp", dstAddr)
	if err != nil {
		conn.Write([]byte{0x05, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return err
	}
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	defer remote.Close()

	go io.Copy(conn, remote)
	go io.Copy(remote, conn)

	select {}

	return nil
}

// 将端口转换为字符串
func stringPort(p []byte) string {
	port := binary.BigEndian.Uint16(p)
	return strconv.Itoa(int(port))
}
