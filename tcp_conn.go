package rfc9401

import (
	"fmt"
	"log"
	"net"
)

func ListenTCP(localAddr string, port int) error {
	pconn, err := net.ListenPacket("ip:tcp", localAddr)
	if err != nil {
		return err
	}
	defer pconn.Close()
	buf := make([]byte, 1500)
	for {
		n, addr, err := pconn.ReadFrom(buf)
		if err != nil {
			return err
		}
		fmt.Printf("client addr is %s\n", addr)
		tcpheader := ParseHeader(buf[:n])
		tcpheader.handleConnection(pconn, pconn.LocalAddr(), port)
	}
}

func (tcpHeader *TCPHeader) handleConnection(pconn net.PacketConn, addr net.Addr, port int) {
	switch tcpHeader.TCPCtrlFlags.getState() {
	case SYN:
		// Todo: SYNACKを返す
		fmt.Println("receive SYN packet")
		tcpHeader.DestPort = tcpHeader.SourcePort
		// 8080
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)

		tcpHeader.SeqNumber = []byte{0x00, 0x00, 0x00, 0x00}
		tcpHeader.TCPCtrlFlags.ACK = 1
		_, err := pconn.WriteTo(tcpHeader.ToPacket(), addr)
		if err != nil {
			log.Fatalf(" Write SYNACK is err : %v\n", err)
		}
		fmt.Println("send SYNACK packet")
	case SYN + ACK:
		// Todo: ACKを返す
	case PSH + ACK:
		// Todo: ACKを返す
	case FIN + ACK:
		// Todo: FINACKを返す
	}
}

func Dial(address string, port int) error {
	//// TCPパケットを送る
	//conn, err := net.Dial("ip:6", address)
	//if err != nil {
	//	return err
	//}
	// Todo: 3ハンドシェイクの実装
	// SYNパケットを作る
	syn := TCPHeader{
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
		Options:       TCPOPtions,
	}

	fmt.Printf("%x\n", syn.ToPacket())

	return nil
}
