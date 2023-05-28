package rfc9401

import (
	"fmt"
	"log"
	"syscall"
)

const clientPort = 37738

func ListenPacket(fd int, serverAddr string, port int, chHeader chan TCPHeader) error {

	for {
		buf := make([]byte, 1500)
		n, clientAddr, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return err
		}
		addr := clientAddr.(*syscall.SockaddrInet4).Addr
		tcpHeader := ParseHeader(buf[20:n], ipv4ByteToString(addr[:]), serverAddr)
		// 宛先ポートがクライアントのソースポートであれば
		if byteToUint16(tcpHeader.DestPort) == uint16(port) {
			// fmt.Printf("tcp header is %+v\n", tcpHeader)
			handleTCPConnection(fd, tcpHeader, port, chHeader)
		}
	}
}

func Dial(clientAddr string, serverAddr string, port int) (int, TCPHeader, error) {
	// ソケット作成
	send, err := rawsocket()
	if err != nil {
		return -1, TCPHeader{}, err
	}

	addr := syscall.SockaddrInet4{
		Addr: ipv4To4Byte(serverAddr),
		Port: port,
	}

	chHeader := make(chan TCPHeader)
	go func() {
		ListenPacket(send, serverAddr, clientPort, chHeader)
	}()

	// SYNパケットを作る
	syn := TCPHeader{
		TCPDummyHeader: TCPDummyHeader{
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
		TCPCtrlFlags:  TCPCtrlFlags{SYN: 1},
		WindowSize:    uint16ToByte(65495),
		Checksum:      uint16ToByte(0),
		UrgentPointer: uint16ToByte(0),
		Options:       TCPOptions,
	}
	_ = syn

	// SYNパケットを送る
	err = syscall.Sendto(send, SYNPacket, 0, &addr)
	if err != nil {
		return -1, TCPHeader{}, fmt.Errorf("SYN Packet Send error : %s", err)
	}

	fmt.Println("Send SYN Packet")
	// SYNACKを受けて送ったACKを受ける
	ack := <-chHeader

	return send, ack, nil
}

func handleTCPConnection(fd int, tcpHeader TCPHeader, port int, ch chan TCPHeader) {

	addr := syscall.SockaddrInet4{
		Port: port,
	}
	copy(addr.Addr[:], tcpHeader.TCPDummyHeader.DestIP)

	switch tcpHeader.TCPCtrlFlags.getState() {
	case SYN:
		fmt.Println("receive SYN packet")
		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)
		tcpHeader.SeqNumber = []byte{0x00, 0x00, 0x00, 0x00}
		tcpHeader.TCPCtrlFlags.ACK = 1
		// SYNACKパケットを送信
		err := syscall.Sendto(fd, tcpHeader.ToPacket(), 0, &addr)
		if err != nil {
			log.Fatal(" Write SYNACK is err : %v\n", err)
		}
		fmt.Println("send SYNACK packet")
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
		err := syscall.Sendto(fd, tcpHeader.ToPacket(), 0, &addr)
		if err != nil {
			log.Fatal(" Write SYNACK is err : %v\n", err)
		}
		fmt.Println("Send ACK Packet")
		//fmt.Printf("source is %s, dest is %s\n", ipv4ByteToString(tcpHeader.TCPDummyHeader.SourceIP),
		//	ipv4ByteToString(tcpHeader.TCPDummyHeader.DestIP))
		// ACKまできたのでchannelで一度返す
		ch <- tcpHeader
	case PSH + ACK:
		// Todo: ACKを返す
	case FIN + ACK:
		// Todo: FINACKを返す
	}
}
