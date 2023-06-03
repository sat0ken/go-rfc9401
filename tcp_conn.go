package rfc9401

import (
	"fmt"
	"log"
	"net"
)

const clientPort = 37738

func ListenPacket(listenAddr string, port int, chHeader chan TCPHeader) error {
	conn, err := net.ListenPacket("ip:tcp", listenAddr)
	if err != nil {
		log.Fatalf("ListenPacket is err : %v", err)
	}
	defer conn.Close()

	for {
		buf := make([]byte, 1500)
		n, clientAddr, err := conn.ReadFrom(buf)
		if err != nil {
			return err
		}
		tcp := parseTCPHeader(buf[:n], clientAddr.String(), listenAddr)
		// 宛先ポートがクライアントのソースポートであれば
		if byteToUint16(tcp.DestPort) == uint16(port) {
			// fmt.Printf("tcp header is %+v\n", tcp)
			handleTCPConnection(conn, tcp, conn.LocalAddr(), port, chHeader)
		}
	}
}

func Dial(clientAddr string, serverAddr string, port int) (TCPHeader, error) {

	chHeader := make(chan TCPHeader)
	go func() {
		ListenPacket(serverAddr, clientPort, chHeader)
	}()
	conn, err := net.Dial("ip:tcp", serverAddr)
	if err != nil {
		return TCPHeader{}, err
	}
	defer conn.Close()

	// SYNパケットを作る
	syn := TCPHeader{
		TCPDummyHeader: tcpDummyHeader{
			SourceIP: ipv4ToByte(clientAddr),
			DestIP:   ipv4ToByte(serverAddr),
		},
		SourcePort:    uint16ToByte(clientPort),
		DestPort:      uint16ToByte(uint16(port)),
		SeqNumber:     uint32ToByte(209828892),
		AckNumber:     uint32ToByte(0),
		DataOffset:    40,
		DTH:           0,
		Reserved:      0,
		TCPCtrlFlags:  tcpCtrlFlags{SYN: 1},
		WindowSize:    uint16ToByte(65495),
		Checksum:      uint16ToByte(0),
		UrgentPointer: uint16ToByte(0),
		Options:       TCPOptions,
	}

	// SYNパケットを送る
	_, err = conn.Write(syn.toPacket())
	if err != nil {
		return TCPHeader{}, fmt.Errorf("SYN Packet Send error : %s", err)
	}

	fmt.Println("Send SYN Packet")
	// SYNACKを受けて送ったACKを受ける
	ack := <-chHeader
	fmt.Printf("ACK Packet is %+v\n", ack)

	return ack, nil
}

func handleTCPConnection(pconn net.PacketConn, tcpHeader TCPHeader, client net.Addr, port int, ch chan TCPHeader) {

	switch tcpHeader.TCPCtrlFlags.getState() {
	case SYN:
		fmt.Println("receive SYN packet")
		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)
		tcpHeader.SeqNumber = []byte{0x00, 0x00, 0x00, 0x00}
		tcpHeader.TCPCtrlFlags.ACK = 1
		// SYNACKパケットを送信
		_, err := pconn.WriteTo(tcpHeader.toPacket(), client)
		if err != nil {
			log.Fatal(" Write SYNACK is err : %v\n", err)
		}
		fmt.Println("Send SYNACK packet")
	case SYN + ACK:
		fmt.Println("Recv SYNACK packet")
		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		// ACKをいったん保存
		tmpack := tcpHeader.AckNumber
		// ACKに
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)
		tcpHeader.SeqNumber = tmpack
		tcpHeader.DataOffset = 20
		tcpHeader.TCPCtrlFlags.SYN = 0
		tcpHeader.Options = nil
		// ACKパケットを送信
		_, err := pconn.WriteTo(tcpHeader.toPacket(), client)
		if err != nil {
			log.Fatal(" Write SYNACK is err : %v\n", err)
		}
		fmt.Println("Send ACK Packet")
		// ACKまできたのでchannelで一度返す
		ch <- tcpHeader
	case PSH + ACK:
		// Todo: ACKを返す
	case FIN + ACK:
		// Todo: FINACKを返す
	case ACK:
		fmt.Println("Recv ACK packet")
	}
}
