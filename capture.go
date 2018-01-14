package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"golang.org/x/sys/unix"
	"log"
	"net"
	"unsafe"
)

var (
	filter      string = "ether proto 0x888e"
	snapshotLen int32  = 9000
)

type ListenInterface struct {
	fd     int
	handle *pcap.Handle
}

const ETHER_ADDR_LEN = 0x6

// Setup the given device to joing the EAP(OL) link layer multicast group.
func joinMulticastGroup(device *string) (fd int) {
	iface, err := net.InterfaceByName(*device)
	if err != nil {
		log.Fatal(err)
	}

	fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_PAE)
	if err != nil {
		log.Fatal(err)
	}

	mreq := unix.PacketMreq{
		Ifindex: int32(iface.Index),
		Type:    unix.PACKET_MR_MULTICAST,
		Alen:    ETHER_ADDR_LEN,
		Address: [8]uint8{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03},
	}

	_, _, errNo := unix.Syscall6(
		unix.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(unix.SOL_PACKET),
		uintptr(unix.PACKET_ADD_MEMBERSHIP),
		uintptr(unsafe.Pointer(&mreq)),
		unix.SizeofPacketMreq,
		0,
	)
	if errNo > 0 {
		log.Fatal(errNo)
	}

	sockAddrLinkLayer := unix.RawSockaddrLinklayer{
		Family:   unix.AF_PACKET,
		Protocol: unix.ETH_P_PAE,
		Ifindex:  int32(iface.Index),
	}

	_, _, errNo = unix.Syscall(
		unix.SYS_BIND,
		uintptr(fd),
		uintptr(unsafe.Pointer(&sockAddrLinkLayer)),
		unsafe.Sizeof(sockAddrLinkLayer),
	)
	if errNo > 0 {
		log.Fatal(errNo)
	}

	return fd
}

// setupCaptureDevice opens the given device name for live capture.
// It will only capture packets coming into the interface from the network.
func setupCaptureDevice(device *string, promiscuous *bool) ListenInterface {
	handle, err := pcap.OpenLive(*device, snapshotLen, *promiscuous, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		log.Fatal(err)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	fd := joinMulticastGroup(device)

	return ListenInterface{
		fd:     fd,
		handle: handle,
	}
}

// Emit a captured packet onto the wire through the given pcap handle.
// No modifications are being done to the packet, this is a 1:1 mirror.
func emitPacket(packet gopacket.Packet, destination *pcap.Handle) {
	err := destination.WritePacketData(packet.Data())
	if err != nil {
		log.Fatal(err)
	}
}
