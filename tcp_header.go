package rfc9401

import (
	"bytes"
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

type TCPHeader struct {
	SourcePort    []byte
	DestPort      []byte
	SeqNumber     []byte
	AckNumber     []byte
	DataOffset    uint8
	DTH           uint8
	Reserved      uint8
	TCPCtrlFlags  TCPCtrlFlags
	WindowSize    []byte
	Checksum      []byte
	UrgentPointer []byte
	Options       []byte
}

type TCPCtrlFlags struct {
	CWR uint8
	ECR uint8
	URG uint8
	ACK uint8
	PSH uint8
	RST uint8
	SYN uint8
	FIN uint8
}

func (ctrlFlags *TCPCtrlFlags) ParseTCPCtrlFlags(packet uint8) {
	ctrlFlags.CWR = packet & 0x80 >> 7
	ctrlFlags.ECR = packet & 0x40 >> 6
	ctrlFlags.URG = packet & 0x20 >> 5
	ctrlFlags.ACK = packet & 0x10 >> 4
	ctrlFlags.PSH = packet & 0x08 >> 3
	ctrlFlags.RST = packet & 0x04 >> 2
	ctrlFlags.SYN = packet & 0x02 >> 1
	ctrlFlags.FIN = packet & 0x01
}

func ParseHeader(packet []byte) (tcpHeader TCPHeader) {
	tcpHeader.SourcePort = packet[0:2]
	tcpHeader.DestPort = packet[2:4]
	tcpHeader.SeqNumber = packet[4:8]
	tcpHeader.AckNumber = packet[8:12]
	tcpHeader.DataOffset = packet[12] >> 2
	tcpHeader.DTH = packet[12] & 0x08
	tcpHeader.Reserved = packet[12] & 0x07
	tcpHeader.TCPCtrlFlags.ParseTCPCtrlFlags(packet[13])
	tcpHeader.WindowSize = packet[14:16]
	tcpHeader.Checksum = packet[16:18]
	tcpHeader.UrgentPointer = packet[18:20]
	tcpHeader.Options = packet[20:tcpHeader.DataOffset]

	return tcpHeader
}

func (ctrlFlags *TCPCtrlFlags) getState() string {
	if ctrlFlags.SYN == 1 && ctrlFlags.ACK == 0 {
		return "SYN"
	} else if ctrlFlags.SYN == 1 && ctrlFlags.ACK == 1 {
		return "SYNACK"
	} else if ctrlFlags.PSH == 1 && ctrlFlags.ACK == 1 {
		return "PSHACK"
	} else if ctrlFlags.FIN == 1 && ctrlFlags.ACK == 1 {
		return "FINACK"
	} else if ctrlFlags.ACK == 1 && ctrlFlags.SYN == 0 || ctrlFlags.FIN == 0 || ctrlFlags.PSH == 0 {
		return "ACK"
	}
	return ""
}

func (ctrlFlags *TCPCtrlFlags) ToPacket() (flags uint8) {

	if ctrlFlags.CWR == 1 {
		flags += 0x80
	}
	if ctrlFlags.ECR == 1 {
		flags += 0x40
	}
	if ctrlFlags.URG == 1 {
		flags += 0x20
	}
	if ctrlFlags.ACK == 1 {
		flags += 0x10
	}
	if ctrlFlags.PSH == 1 {
		flags += 0x08
	}
	if ctrlFlags.RST == 1 {
		flags += 0x04
	}
	if ctrlFlags.SYN == 1 {
		flags += 0x02
	}
	if ctrlFlags.FIN == 1 {
		flags += 0x01
	}

	return flags
}

func (tcpheader *TCPHeader) ToPacket() (packet []byte) {
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
	b.Write([]byte{tcpheader.TCPCtrlFlags.ToPacket()})
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
	checksum := calcChecksum(packet)

	// 計算したchecksumをセット
	packet[16] = checksum[0]
	packet[17] = checksum[1]

	return packet
}
