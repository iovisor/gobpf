package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"syscall"
	"time"
	"unsafe"

	"github.com/iovisor/gobpf/bcc"
)

const (
	PROTOCOL_FUNC  = "protocol_count"
	PROTOCOL_COUNT = "./net_protocol.c"
	LOOP           = 1
)

func ReadBPFFile(file string) (string, error) {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func Htons(i uint16) uint16 {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

func OpenRawSock(index int) (int, error) {
	sock, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(Htons(syscall.ETH_P_ALL)))
	if err != nil {
		return 0, err
	}
	sll := syscall.SockaddrLinklayer{
		Ifindex:  index,
		Protocol: Htons(syscall.ETH_P_ALL),
	}
	if err := syscall.Bind(sock, &sll); err != nil {
		return 0, err
	}
	return sock, nil
}
func ProtocolCount(cSource string) {
	source, err := ReadBPFFile(cSource)
	if err != nil {
		fmt.Errorf("read BPF file error: %v", err)
		return
	}
	m := bcc.NewModule(source, []string{})
	defer m.Close()

	socketFilter, err := m.LoadSocketFilter(PROTOCOL_FUNC)
	if err != nil {
		fmt.Errorf("socket filter %s not found, err: %v", PROTOCOL_FUNC, err)
		return
	}

	fd, err := OpenRawSock(LOOP)
	if err != nil {
		fmt.Errorf("unable to open a raw socket: %s", err)
		return
	}
	defer syscall.Close(fd)

	if err := m.AttachSocketFilter(fd, socketFilter); err != nil {
		fmt.Errorf("failed trying to attach socket filter: %s", err)
		return
	}

	table := bcc.NewTable(m.TableId("countmap"), m)
	var tcp, udp, icmp, leafInt, keyInt uint32
	hostEndian := bcc.GetHostByteOrder()
	for {
		iter := table.Iter()
		for iter.Next() {
			key, leaf := iter.Key(), iter.Leaf()
			if err := binary.Read(bytes.NewBuffer(key), hostEndian, &keyInt); err != nil {
				continue
			}
			if err := binary.Read(bytes.NewBuffer(leaf), hostEndian, &leafInt); err != nil {
				continue
			}
			switch keyInt {
			case syscall.IPPROTO_TCP:
				tcp = leafInt
			case syscall.IPPROTO_UDP:
				udp = leafInt
			case syscall.IPPROTO_ICMP:
				icmp = leafInt
			}
		}
		fmt.Printf("TCP: %v, UDP: %v, ICMP: %v\n", tcp, udp, icmp)
		time.Sleep(5 * time.Second)
	}
}

func main() {
	ProtocolCount(PROTOCOL_COUNT)
}
