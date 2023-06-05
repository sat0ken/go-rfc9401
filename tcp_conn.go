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
	tcpData   []byte
	err       error
}

func Dial(clientAddr string, serverAddr string, serverpPort int) (TCPHeader, error) {

	clientPort := getRandomClientPort()

	chHeader := make(chan TcpState)
	go func() {
		Listen(serverAddr, clientPort, chHeader)
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
		DataOffset:    20,
		DTH:           0,
		Reserved:      0,
		TCPCtrlFlags:  tcpCtrlFlags{SYN: 1},
		WindowSize:    uint16ToByte(65495),
		Checksum:      uint16ToByte(0),
		UrgentPointer: uint16ToByte(0),
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

func Listen(listenAddr string, port int, chHeader chan TcpState) error {
	conn, err := net.ListenPacket(NETWORK_STR, listenAddr)
	if err != nil {
		log.Fatalf("Listen is err : %v", err)
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

func handleTCPConnection(pconn net.PacketConn, tcpHeader TCPHeader, client net.Addr, port int, ch chan TcpState) {

	switch tcpHeader.TCPCtrlFlags.getState() {
	case SYN:
		fmt.Println("receive SYN packet")
		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)
		tcpHeader.SeqNumber = uint32ToByte(2142718385)
		tcpHeader.DataOffset = 20
		tcpHeader.TCPCtrlFlags.ACK = 1
		// SYNACKパケットを送信
		_, err := pconn.WriteTo(tcpHeader.toPacket(), client)
		if err != nil {
			log.Fatal(" Write SYNACK is err : %v\n", err)
		}
		fmt.Println("Send SYNACK packet, wait ACK Packet...")
	case SYN + ACK:
		fmt.Println("Recv SYNACK packet")
		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		// ACKをいったん保存
		tmpack := tcpHeader.AckNumber
		// ACKに
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)
		tcpHeader.SeqNumber = tmpack
		// Option+12byte
		tcpHeader.DataOffset = 20
		tcpHeader.TCPCtrlFlags.SYN = 0
		// ACKパケットを送信
		_, err := pconn.WriteTo(tcpHeader.toPacket(), client)
		if err != nil {
			ch <- TcpState{tcpHeader: TCPHeader{}, err: fmt.Errorf("Send SYNACK err: %v", err)}
		}
		fmt.Println("Send ACK Packet")
		// ACKまできたのでchannelで一度返す
		ch <- TcpState{tcpHeader: tcpHeader, err: nil}
	case PSH + ACK:
		fmt.Println("Recv PSHACK packet")
		var tcpdata []byte
		var isexistTCPData bool
		if tcpHeader.Data != nil {
			isexistTCPData = true
			tcpdata = tcpHeader.Data
		}
		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		// ACKをいったん保存
		tmpack := tcpHeader.AckNumber
		// ACKに
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, uint32(len(tcpHeader.Data)))
		tcpHeader.SeqNumber = tmpack
		tcpHeader.DataOffset = 20
		tcpHeader.TCPCtrlFlags.PSH = 0
		tcpHeader.Data = nil
		// ACKパケットを送信
		_, err := pconn.WriteTo(tcpHeader.toPacket(), client)
		if err != nil {
			ch <- TcpState{tcpHeader: TCPHeader{}, err: fmt.Errorf("Send SYNACK err: %v", err)}
		}
		fmt.Println("Send ACK to PSHACK Packet")
		// TCPのデータがなければACKを送ったのでchannelで返す
		if !isexistTCPData {
			ch <- TcpState{tcpHeader: tcpHeader, err: nil}
		} else {
			if port == int(byteToUint16(tcpHeader.SourcePort)) && port == 18000 {
				fmt.Println("Send PSHACK Packet From server")
				// サーバならHTTPレスポンスを返す
				tcpHeader.DTH = 1
				resultHeader, _, err := tcpHeader.Write(CreateHttpResp("hello\n"))
				if err != nil {
					ch <- TcpState{tcpHeader: TCPHeader{}, err: err}
				}
				ch <- TcpState{tcpHeader: resultHeader, err: nil}
			} else {
				ch <- TcpState{tcpHeader: tcpHeader, tcpData: tcpdata, err: nil}
			}

		}
	case FIN + ACK:
		fmt.Println("Recv FINACK packet")
		tcpHeader.DestPort = tcpHeader.SourcePort
		tcpHeader.SourcePort = uint16ToByte(uint16(port))
		// ACKをいったん保存
		tmpack := tcpHeader.AckNumber
		// ACKにSEQを
		tcpHeader.AckNumber = addAckNumber(tcpHeader.SeqNumber, 1)
		// SEQにACKを
		tcpHeader.SeqNumber = tmpack
		tcpHeader.DataOffset = 20
		tcpHeader.TCPCtrlFlags.FIN = 0
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
