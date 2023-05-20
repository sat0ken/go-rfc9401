package rfc9401

import (
	"fmt"
	"log"
	"net"
)

func ListenPacket(serverAddr string, port int, chHeader chan TCPHeader) error {
	pconn, err := net.ListenPacket("ip:tcp", serverAddr)
	if err != nil {
		return err
	}

	for {
		buf := make([]byte, 1500)
		n, clientAddr, err := pconn.ReadFrom(buf)
		if err != nil {
			return err
		}
		tcpHeader := ParseHeader(buf[:n], clientAddr.String(), serverAddr)
		// 宛先ポートがサーバがListenしているポートであれば
		if byteToUint16(tcpHeader.DestPort) == uint16(port) {
			handleConnection(pconn, tcpHeader, pconn.LocalAddr(), port, chHeader)
		}
	}
}

func Dial(clientAddr string, serverAddr string, port int) (TCPHeader, error) {

	chHeader := make(chan TCPHeader)
	go func() {
		ListenPacket(serverAddr, 60120, chHeader)
	}()

	conn, err := net.Dial("ip:tcp", serverAddr)
	if err != nil {
		return TCPHeader{}, err
	}
	// SYNパケットを作る
	syn := TCPHeader{
		TCPDummyHeader: TCPDummyHeader{
			SourceIP: ipv4ToByte(clientAddr),
			DestIP:   ipv4ToByte(serverAddr),
		},
		SourcePort:    uint16ToByte(60120),
		DestPort:      uint16ToByte(uint16(port)),
		SeqNumber:     uint32ToByte(1275838710),
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

	// SYNパケットを送る
	_, err = conn.Write(syn.ToPacket())
	if err != nil {
		return TCPHeader{}, err
	}
	fmt.Println("Send SYN Packet")
	// SYNACKを受けて送ったACKを受ける
	ack := <-chHeader

	return ack, nil
}

func handleConnection(pconn net.PacketConn, tcpHeader TCPHeader, client net.Addr, port int, ch chan TCPHeader) {
	switch tcpHeader.TCPCtrlFlags.getState() {
	case SYN:
		// Todo: SYNACKを返す
		fmt.Println("receive SYN packet")

		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)

		tcpHeader.SeqNumber = []byte{0x00, 0x00, 0x00, 0x00}
		tcpHeader.TCPCtrlFlags.ACK = 1
		_, err := pconn.WriteTo(tcpHeader.ToPacket(), client)
		if err != nil {
			log.Fatalf(" Write SYNACK is err : %v\n", err)
		}
		fmt.Println("send SYNACK packet")
	case SYN + ACK:
		// Todo: ACKを返す
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
		_, err := pconn.WriteTo(tcpHeader.ToPacket(), client)
		if err != nil {
			log.Fatalf(" Write SYNACK is err : %v\n", err)
		}
		fmt.Println("Send SYNACK Packet")
		// ACKまできたのでchannelで一度返す
		ch <- tcpHeader
	case PSH + ACK:
		// Todo: ACKを返す
	case FIN + ACK:
		// Todo: FINACKを返す
	}
}
