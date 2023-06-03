package rfc9401

import (
	"bytes"
	"fmt"
	"net"
)

/*
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |D|     |C|E|U|A|P|R|S|F|                               |
| Offset|T| Rsr |W|C|R|C|S|S|Y|I|            Window             |
|       |H| vd  |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           [Options]                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               :
:                             Data                              :
:                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
	URG = 0x20
	ECR = 0x40
	CWR = 0x80
)

var SYNPacket = []byte{
	0x93, 0x6a, 0x46, 0xa0, 0x0c, 0x81, 0xbc, 0x1c,
	0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0xff, 0xd7,
	0xca, 0x69, 0x00, 0x00, 0x02, 0x04, 0xff, 0xd7,
	0x04, 0x02, 0x08, 0x0a, 0x31, 0x07, 0xb1, 0xe8,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07,
}

var TCPOptions = []byte{
	0x02, 0x04, 0xff, 0xd7, 0x04, 0x02, 0x08, 0x0a,
	0x31, 0x07, 0xb1, 0xe8, 0x00, 0x00, 0x00, 0x00,
	0x01, 0x03, 0x03, 0x07,
}

type TCPHeader struct {
	TCPDummyHeader tcpDummyHeader
	SourcePort     []byte
	DestPort       []byte
	SeqNumber      []byte
	AckNumber      []byte
	DataOffset     uint8
	DTH            uint8
	Reserved       uint8
	TCPCtrlFlags   tcpCtrlFlags
	WindowSize     []byte
	Checksum       []byte
	UrgentPointer  []byte
	Options        []byte
	Data           []byte
}

type tcpDummyHeader struct {
	SourceIP []byte
	DestIP   []byte
	Protocol []byte
	Length   []byte
}

type tcpCtrlFlags struct {
	CWR uint8
	ECR uint8
	URG uint8
	ACK uint8
	PSH uint8
	RST uint8
	SYN uint8
	FIN uint8
}

func (ctrlFlags *tcpCtrlFlags) parseTCPCtrlFlags(packet uint8) {
	ctrlFlags.CWR = packet & 0x80 >> 7
	ctrlFlags.ECR = packet & 0x40 >> 6
	ctrlFlags.URG = packet & 0x20 >> 5
	ctrlFlags.ACK = packet & 0x10 >> 4
	ctrlFlags.PSH = packet & 0x08 >> 3
	ctrlFlags.RST = packet & 0x04 >> 2
	ctrlFlags.SYN = packet & 0x02 >> 1
	ctrlFlags.FIN = packet & 0x01
}

func parseTCPHeader(packet []byte, clientAddr string, serverAddr string) (tcpHeader TCPHeader) {
	// SourceのIPアドレスとDestinationのIPアドレスをダミーヘッダにセット
	tcpHeader.TCPDummyHeader.SourceIP = ipv4ToByte(serverAddr)
	tcpHeader.TCPDummyHeader.DestIP = ipv4ToByte(clientAddr)

	// TCPヘッダをセット
	tcpHeader.SourcePort = packet[0:2]
	tcpHeader.DestPort = packet[2:4]
	tcpHeader.SeqNumber = packet[4:8]
	tcpHeader.AckNumber = packet[8:12]
	tcpHeader.DataOffset = packet[12] >> 2
	tcpHeader.DTH = packet[12] & 0x08
	tcpHeader.Reserved = packet[12] & 0x07
	tcpHeader.TCPCtrlFlags.parseTCPCtrlFlags(packet[13])
	tcpHeader.WindowSize = packet[14:16]
	tcpHeader.Checksum = packet[16:18]
	tcpHeader.UrgentPointer = packet[18:20]
	tcpHeader.Options = packet[20:tcpHeader.DataOffset]
	// TCPデータがあればセット
	if int(tcpHeader.DataOffset) < len(packet) {
		tcpHeader.Data = packet[tcpHeader.DataOffset:]
	}

	return tcpHeader
}

func (ctrlFlags *tcpCtrlFlags) getState() int {
	if ctrlFlags.SYN == 1 && ctrlFlags.ACK == 0 {
		return SYN
	} else if ctrlFlags.SYN == 1 && ctrlFlags.ACK == 1 {
		return SYN + ACK
	} else if ctrlFlags.PSH == 1 && ctrlFlags.ACK == 1 {
		return PSH + ACK
	} else if ctrlFlags.FIN == 1 && ctrlFlags.ACK == 1 {
		return FIN + ACK
	} else if ctrlFlags.ACK == 1 && ctrlFlags.SYN == 0 || ctrlFlags.FIN == 0 || ctrlFlags.PSH == 0 {
		return ACK
	}
	return 0
}

func (ctrlFlags *tcpCtrlFlags) toPacket() (flags uint8) {

	if ctrlFlags.CWR == 1 {
		flags += CWR
	}
	if ctrlFlags.ECR == 1 {
		flags += ECR
	}
	if ctrlFlags.URG == 1 {
		flags += URG
	}
	if ctrlFlags.ACK == 1 {
		flags += ACK
	}
	if ctrlFlags.PSH == 1 {
		flags += PSH
	}
	if ctrlFlags.RST == 1 {
		flags += RST
	}
	if ctrlFlags.SYN == 1 {
		flags += SYN
	}
	if ctrlFlags.FIN == 1 {
		flags += FIN
	}

	return flags
}

func (tcpheader *TCPHeader) toPacket() (packet []byte) {
	var b bytes.Buffer

	b.Write(tcpheader.SourcePort)
	b.Write(tcpheader.DestPort)
	b.Write(tcpheader.SeqNumber)
	b.Write(tcpheader.AckNumber)

	offset := tcpheader.DataOffset << 2
	// 死亡フラグが立ってたら4bit目を立てるので8(=1000)を足す
	if tcpheader.DTH == 1 && tcpheader.Reserved == 0 {
		offset += 0x08
	}
	b.Write([]byte{offset})
	b.Write([]byte{tcpheader.TCPCtrlFlags.toPacket()})
	b.Write(tcpheader.WindowSize)
	// checksumを計算するために0にする
	tcpheader.Checksum = []byte{0x00, 0x00}
	b.Write(tcpheader.Checksum)
	b.Write(tcpheader.UrgentPointer)
	if tcpheader.Options != nil {
		b.Write(tcpheader.Options)
	}
	packet = b.Bytes()
	// checksumを計算
	var calc []byte
	// TCPダミーヘッダをセット
	if tcpheader.Data == nil {
		calc = tcpheader.TCPDummyHeader.toPacket(len(packet))
	} else {
		calc = tcpheader.TCPDummyHeader.toPacket(len(tcpheader.Data) + len(packet))
	}
	// TCPヘッダを追加
	calc = append(calc, packet...)
	// https://atmarkit.itmedia.co.jp/ait/articles/0401/29/news080_2.html
	// TCPのチェックサムを計算する場合は、先頭にこの擬似的なヘッダが存在するものとして、TCPヘッダ、TCPペイロードとともに計算する。
	// IPアドレスの情報はIPヘッダ中から抜き出してくる。
	// ペイロード長が奇数の場合は、最後に1byteの「0」を補って計算する（この追加する1byteのデータは、パケット長には含めない）。
	if tcpheader.Data != nil {
		if len(tcpheader.Data)%2 != 0 {
			calc = append(calc, tcpheader.Data...)
			calc = append(calc, 0x00)
		} else {
			calc = append(calc, tcpheader.Data...)
		}
	}

	checksum := calcChecksum(calc)

	// 計算したchecksumをセット
	packet[16] = checksum[0]
	packet[17] = checksum[1]
	// TCPデータをセット
	if tcpheader.Data != nil {
		packet = append(packet, tcpheader.Data...)
	}

	return packet
}

func (dummyHeader *tcpDummyHeader) toPacket(length int) []byte {
	var b bytes.Buffer
	b.Write(dummyHeader.SourceIP)
	b.Write(dummyHeader.DestIP)
	//　0x06 = TCP
	b.Write([]byte{0x00, 0x06})
	b.Write(uint16ToByte(uint16(length)))
	return b.Bytes()
}

// PSHACKでデータを送る
func (tcpheader *TCPHeader) Write(data []byte) (TCPHeader, error) {
	chHeader := make(chan TcpState)
	go func() {
		ListenPacket(ipv4ByteToString(tcpheader.TCPDummyHeader.SourceIP),
			int(byteToUint16(tcpheader.SourcePort)), chHeader)
	}()

	tcpheader.TCPCtrlFlags.PSH = 1
	// Optionめんどいから消す
	tcpheader.Options = nil
	tcpheader.DataOffset = 20
	// TCPデータをセット
	tcpheader.Data = data

	conn, err := net.Dial(NETWORK_STR, ipv4ByteToString(tcpheader.TCPDummyHeader.DestIP))
	if err != nil {
		return TCPHeader{}, fmt.Errorf("connection err : %v", err)
	}
	defer conn.Close()

	// PSHACKパケットを送信
	_, err = conn.Write(tcpheader.toPacket())
	if err != nil {
		return TCPHeader{}, fmt.Errorf("send data err : %v\n", err)
	}

	fmt.Println("Send PSHACK packet")

	// PSHACKを受けて送ったACKを受ける
	result := <-chHeader
	if result.err != nil {
		return TCPHeader{}, err
	}

	fmt.Printf("ACK State header is %+v\n", result.tcpHeader)

	return result.tcpHeader, nil
}

func (tcpheader *TCPHeader) Close() error {
	chHeader := make(chan TcpState)
	go func() {
		ListenPacket(ipv4ByteToString(tcpheader.TCPDummyHeader.SourceIP),
			int(byteToUint16(tcpheader.SourcePort)), chHeader)
	}()

	tcpheader.TCPCtrlFlags.FIN = 1
	conn, err := net.Dial(NETWORK_STR, ipv4ByteToString(tcpheader.TCPDummyHeader.DestIP))
	if err != nil {
		return fmt.Errorf("connection err : %v", err)
	}
	defer conn.Close()

	// FINACKパケットを送信
	_, err = conn.Write(tcpheader.toPacket())
	if err != nil {
		return fmt.Errorf("send fin err : %v\n", err)
	}
	fmt.Println("Send FINACK packet")
	// channelで結果を受ける
	result := <-chHeader
	if result.err != nil {
		return result.err
	}
	close(chHeader)

	return nil
}

func (tcpheader *TCPHeader) Wait() {
	chHeader := make(chan TcpState)
	go func() {
		ListenPacket(ipv4ByteToString(tcpheader.TCPDummyHeader.SourceIP),
			int(byteToUint16(tcpheader.SourcePort)), chHeader)
	}()

	result := <-chHeader

	fmt.Printf("wait result is %+v\n", result.tcpHeader)
}
