package server
import (
	"encoding/binary"
	"io"
	"log"
	"sync"
	"net"
	"time"
)

func HandleUDPAssociate (conn net.Conn, dstAddr string) error {
	log.Println("Handling UDP Associate request...")
	// 解析目标地址
	udpAddr, err := net.ResolveUDPAddr("udp", ":0")
	if err != nil {
		log.Printf("Failed to resolve destination address: %v\n", err)
		SendFailureResponse(conn, 0x01) // 一般SOCKS服务器失败
		return err
	}

	// 创建UDP连接
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		log.Printf("Failed to create UDP connection: %v\n", err)
		SendFailureResponse(conn, 0x01) // 一般SOCKS服务器失败
		return err
	}
	
	actualAddr := udpConn.LocalAddr().(*net.UDPAddr)
	log.Printf("UDP connection established at %s\n", actualAddr)

	// 构建响应包
	response := make([]byte, 10)
	response[0] = 0x05 // SOCKS5版本
	response[1] = 0x00 // 成功
	response[2] = 0x00 // 保留字段
	response[3] = 0x01 // 地址类型：IPv4
	response[4] = 0x00
	response[5] = 0x00 
	response[6] = 0x00
	response[7] = 0x00 // IP地址：0.0.0.0
	binary.BigEndian.PutUint16(response[8:10], uint16(actualAddr.Port)) // BAND 端口号
	if _, err := conn.Write(response); err != nil {
		log.Printf("Failed to send UDP associate response: %v\n", err)
		udpConn.Close()
		return err
	}

	// 将UDP连接与TCP连接关联

	udpAssociation := &UDPAssociation{
		clientAddr: nil,
		udpConn:    udpConn,
		tcpConn:    conn,
		lastActive: time.Now(),
	}

	udpAssociations.Store(conn.RemoteAddr().String(), udpAssociation)

	go ProcessUDPRequest(udpAssociation)


	buf:= make([]byte, 1)

	for {
		conn.SetReadDeadline(time.Now().Add(30 * time.Second)) // 设置读取超时
		_, err = conn.Read(buf)
		if err != nil {
			log.Printf("TCP connection closed: %v\n", err)
			udpAssociations.Delete(conn.RemoteAddr().String())
			udpConn.Close()
			return err
		}
	}
	return nil
}

func StartCleanupTask() {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			now := time.Now()
			udpAssociations.Range(func(key, value interface{}) bool {
				assoc := value.(*UDPAssociation)

				assoc.mutex.RLock()
				FLAG := now.Sub(assoc.lastActive) > 5*time.Minute
				assoc.mutex.RUnlock()

				if FLAG {
					log.Printf("Cleaning up inactive UDP association: %s\n", key)
					udpAssociations.Delete(key)
					assoc.udpConn.Close()
					assoc.tcpConn.Close()
				}
				return true
			})
			
		}
	}()
}

func ProcessUDPRequest(udpassoc *UDPAssociation) {
	log.Println("Processing UDP request...")
	defer udpassoc.udpConn.Close()

	// 读取UDP请求包
	buf := make([]byte, 65536)
	for {
		udpassoc.udpConn.SetReadDeadline(time.Now().Add(5 * time.Minute)) // 设置读取超时
		n, clientAddr, err := udpassoc.udpConn.ReadFromUDP(buf)
		if err != nil {
			//log.Printf("Failed to read UDP request: %v\n", err)
			continue
		}
		
		udpassoc.mutex.Lock()
		if(udpassoc.clientAddr == nil) {
			udpassoc.clientAddr = clientAddr // 保存客户端地
			log.Printf("New UDP association from %s\n", clientAddr)
		} 
		
		udpassoc.lastActive = time.Now() // 更新最后活跃时间
		udpassoc.mutex.Unlock()

		// 解析UDP包
		udpPkg, err := parseUdpPackage(buf[:n])
		if err != nil {
			log.Printf("Failed to parse UDP package: %v\n", err)
			continue
		}

		log.Printf("Received UDP package from %s: %s:%d\n", clientAddr, net.IP(udpPkg.addr), udpPkg.port)

		go relayUDPPacket(udpassoc, udpPkg, clientAddr)
	}
	
}


func relayUDPPacket(assoc *UDPAssociation, packet *UdpPackage, clientAddr *net.UDPAddr) {
	log.Printf("Relaying UDP packet to %s:%d\n", net.IP(packet.addr), packet.port)

	// 构建目标地址
	targetAddr := &net.UDPAddr{
		IP:   net.IP(packet.addr),
		Port: int(packet.port),
	}

	targetConn, err := net.DialUDP("udp", nil, targetAddr)
	if err != nil {
		log.Printf("Failed to dial target UDP address %s: %v\n", targetAddr, err)
		SendFailureResponse(assoc.tcpConn, 0x01) // 一般SOCKS服务器失败
		return
	}
	defer targetConn.Close()

	if _,err := targetConn.Write(packet.data); err != nil {
		log.Printf("Failed to write UDP data to %s: %v\n", targetAddr, err)
		SendFailureResponse(assoc.tcpConn, 0x01) // 一般SOCKS服务器失败
		return
	}
	// 更新最后活跃时间
	assoc.mutex.Lock()
	assoc.lastActive = time.Now()		
	assoc.mutex.Unlock()
	
	// 构建UDP响应包
	response := make([]byte, 65536)
	targetConn.SetReadDeadline(time.Now().Add(30 * time.Second)) // 设置读取超时
	n, err := targetConn.Read(response)
	if err != nil {
		log.Printf("Failed to read UDP response from %s: %v\n", targetAddr, err)
		SendFailureResponse(assoc.tcpConn, 0x01) // 一般SOCKS服务器失败
		return
	}



	responsePacket := buildUDPResponsePacket(packet.atyp, packet.addr, packet.port, response[:n])
	assoc.mutex.RLock()
	if assoc.clientAddr != nil {
		_,err=assoc.udpConn.WriteToUDP(responsePacket,assoc.clientAddr)
		if err != nil{
			log.Printf("Failed to send response to client: %v", err)
		}
	}
	assoc.mutex.RUnlock()


	log.Printf("UDP packet relayed successfully to %s\n", targetAddr)
}


func parseUdpPackage(data []byte) (*UdpPackage, error) {
	if len(data) < 6 {
		return nil, io.ErrUnexpectedEOF
	}
	
	// 解析UDP包
	rsv := binary.BigEndian.Uint16(data[:2])
	frag := data[2]
	atyp := data[3]
	addrLen := 0

	switch atyp {
	case 1: // IPv4
		addrLen = net.IPv4len
	case 3: // 域名
		addrLen = int(data[4]) + 1 // 包含长度字节
	case 4: // IPv6
		addrLen = net.IPv6len
	default:
		return nil, io.ErrUnexpectedEOF
	}

	if len(data) < 6+addrLen {
		return nil, io.ErrUnexpectedEOF
	}

	addr := data[4 : 4+addrLen]
	port := binary.BigEndian.Uint16(data[4+addrLen : 6+addrLen])

	return &UdpPackage{
		rsv:  rsv,
		frag: frag,
		atyp: atyp,
		addr: addr,
		port: port,
		data: data[6+addrLen:],
	}, nil
}

func buildUDPResponsePacket(atyp uint8, dstAddr []byte, dstPort uint16, data []byte) []byte {
	// 构建UDP响应包
	response := make([]byte, 6+len(dstAddr)+len(data))
	binary.BigEndian.PutUint16(response[:2], 0x0000) // RSV
	response[2] = 0x00                                  // FRAG
	response[3] = atyp                                  // ATYP
	copy(response[4:4+len(dstAddr)], dstAddr)
	binary.BigEndian.PutUint16(response[4+len(dstAddr):6+len(dstAddr)], dstPort)
	copy(response[6+len(dstAddr):], data)
	return response
}

type UDPAssociation struct {
	clientAddr	*net.UDPAddr // 客户端地址
	udpConn		*net.UDPConn // UDP连接，用于接收和发送数据
	tcpConn		net.Conn // TCP连接，用于传输UDP数据
	lastActive 	time.Time // 最后活跃时间
	mutex 		sync.RWMutex // 保护并发访问
}

type UdpPackage struct {
	rsv		uint16 // 协议版本
	frag	uint8 // 分片标志
	atyp	uint8 // 地址类型
	addr	[]byte // 地址
	port	uint16 // 端口
	data	[]byte // 数据部分
}	

var (
	udpAssociations sync.Map
)

func SendFailureResponse(conn net.Conn, repCode byte) {
	var response []byte
	switch repCode {
	case 0x01: // 一般SOCKS服务器失败
		response = []byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 0x05: // 连接被拒绝
		response = []byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 0x07: // 命令不支持
		response = []byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	case 0x08: // 地址类型不支持
		response = []byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	default:
		response = []byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	}
	
	conn.Write(response)
	
	// SOCKS5规范要求：发送失败回复后必须在10秒内关闭TCP连接
	// 这里给客户端1秒时间接收回复，然后强制关闭连接
	go func() {
		time.Sleep(1 * time.Second)
		conn.Close()
	}()
}