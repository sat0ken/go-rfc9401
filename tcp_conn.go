package rfc9401

import (
	"fmt"
	"log"
	"net"
)

//const clientPort = 37738

const NETWORK_STR = "ip:tcp"

type TcpState struct {
	tcpHeader TCPHeader
	err       error
}

func ListenPacket(listenAddr string, port int, chHeader chan TcpState) error {
	conn, err := net.ListenPacket(NETWORK_STR, listenAddr)
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
		fmt.Printf("tcp.Destport is %d, port is %d\n", byteToUint16(tcp.DestPort), port)
		fmt.Printf("tcp header is %+v\n", tcp)
		if byteToUint16(tcp.DestPort) == uint16(port) {
			// fmt.Printf("tcp header is %+v\n", tcp)
			handleTCPConnection(conn, tcp, conn.LocalAddr(), port, chHeader)
		}
	}
}

func Dial(clientAddr string, serverAddr string, serverpPort int) (TCPHeader, error) {

	clientPort := getRandomClientPort()

	chHeader := make(chan TcpState)
	go func() {
		ListenPacket(serverAddr, clientPort, chHeader)
	}()
	conn, err := net.Dial(NETWORK_STR, serverAddr)
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
		SourcePort:    uint16ToByte(uint16(clientPort)),
		DestPort:      uint16ToByte(uint16(serverpPort)),
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
	// SYNACKに対して受信したACKを受ける
	result := <-chHeader
	if result.err != nil {
		return TCPHeader{}, result.err
	}

	return result.tcpHeader, nil
}

func handleTCPConnection(pconn net.PacketConn, tcpHeader TCPHeader, client net.Addr, port int, ch chan TcpState) {

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
			ch <- TcpState{tcpHeader: TCPHeader{}, err: fmt.Errorf("Send SYNACK err: %v", err)}
		}
		fmt.Println("Send ACK Packet")
		// ACKまできたのでchannelで一度返す
		ch <- TcpState{tcpHeader: tcpHeader, err: nil}
	case PSH + ACK:
		// Todo: ACKを返す
	case FIN + ACK:
		// Todo: ACKを返す
		fmt.Println("Recv FINACK packet")
		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		// ACKをいったん保存
		tmpack := tcpHeader.AckNumber
		// ACKに
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)
		tcpHeader.SeqNumber = tmpack
		tcpHeader.DataOffset = 20
		tcpHeader.TCPCtrlFlags.FIN = 0
		tcpHeader.Options = nil
		// ACKパケットを送信
		_, err := pconn.WriteTo(tcpHeader.toPacket(), client)
		if err != nil {
			ch <- TcpState{tcpHeader: TCPHeader{}, err: fmt.Errorf("Send SYNACK err: %v", err)}
		}
		fmt.Println("Send ACK to FINACK Packet")
		ch <- TcpState{tcpHeader: tcpHeader, err: nil}
	case ACK:
		fmt.Println("Recv ACK packet")
		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		// ACKをいったん保存
		tmpack := tcpHeader.AckNumber
		// ACKに
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)
		tcpHeader.SeqNumber = tmpack
		ch <- TcpState{tcpHeader: tcpHeader, err: nil}
	}
}
