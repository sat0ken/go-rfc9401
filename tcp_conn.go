package rfc9401

import (
	"fmt"
	"net"
)

func ListenTCP(address string, port int) error {
	pconn, err := net.ListenPacket("ip:tcp", address)
	if err != nil {
		return err
	}
	defer pconn.Close()
	buf := make([]byte, 1500)
	for {
		n, _, err := pconn.ReadFrom(buf)
		if err != nil {
			return err
		}
		tcpheader := ParseHeader(buf[:n])
		tcpheader.handleConnection(pconn, pconn.LocalAddr())
	}
}

func (tcpHeader *TCPHeader) handleConnection(pconn net.PacketConn, addr net.Addr) {
	switch tcpHeader.TCPCtrlFlags.getState() {
	case "SYN":
		// Todo: SYNACKを返す
		tcpHeader.DestPort = tcpHeader.SourcePort
		// 8080
		tcpHeader.SourcePort = []byte{0x1f, 0x90}
		tcpHeader.AckNumber = tcpHeader.SeqNumber
		tcpHeader.SeqNumber = []byte{0x00, 0x00, 0x00, 0x00}
		tcpHeader.TCPCtrlFlags.ACK = 1
		fmt.Println("send SYNACK packet")
		pconn.WriteTo(tcpHeader.ToPacket(), addr)
	case "SYNACK":
		// Todo: ACKを返す
	case "PSHACK":
		// Todo: ACKを返す
	case "FINACK":
		// Todo: FINACKを返す
	}
}
