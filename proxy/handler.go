package proxy

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strconv"
)

func handleConnection(conn net.Conn) {
	defer conn.Close()

	if err := handshake(conn); err != nil {
		log.Println("Handshake failed:", err)
		return
	}

	if err := processRequest(conn); err != nil {
		log.Println("Request failed:", err)
	}
}

// 握手阶段：SOCKS5 协议的版本协商和认证方法协商
func handshake(conn net.Conn) error {
	buf := make([]byte, 1024)

	//if _, err := io.ReadFull(conn, buf); err != nil {
	//    return err
	//}
	conn.Read(buf)

	version := buf[0]
	if version != 5 {
		return io.ErrUnexpectedEOF
	}

	// 不认证（method 0x00）
	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

// 处理客户端的 CONNECT 请求
func processRequest(conn net.Conn) error {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}

	version, cmd, _, atyp := header[0], header[1], header[2], header[3]
	if version != 5 || cmd != 1 {
		// 非 CONNECT 请求
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0})
		return io.ErrUnexpectedEOF
	}

	var dstAddr string
	switch atyp {
	case 1: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return err
		}
		port := make([]byte, 2)
		if _, err := io.ReadFull(conn, port); err != nil {
			return err
		}
		dstAddr = net.IP(addr).String() + ":" + stringPort(port)
	case 3: // 域名
		var domainLen [1]byte
		if _, err := conn.Read(domainLen[:]); err != nil {
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
	case 4: // IPv6
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
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0})
		return err
	}
	defer remote.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	go io.Copy(remote, conn)

	go io.Copy(conn, remote)

	select {}

	return nil
}

// 将 2 字节端口转换为字符串
func stringPort(b []byte) string {
	port := binary.BigEndian.Uint16(b)
	return strconv.Itoa(int(port))
}
