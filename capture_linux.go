package main

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"net"
	"unsafe"
)

// Setup the given device to join the EAP(OL) link layer multicast group.
func joinMulticastGroup(device string) (fd int) {
	iface, err := net.InterfaceByName(device)
	if err != nil {
		log.WithFields(logrus.Fields{"interface": device}).Fatal(err)
	}

	fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, unix.ETH_P_PAE)
	if err != nil {
		log.WithFields(logrus.Fields{"interface": device}).Fatal(err)
	}

	mreq := unix.PacketMreq{
		Ifindex: int32(iface.Index),
		Type:    unix.PACKET_MR_MULTICAST,
		Alen:    hwAddressLength,
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
		log.WithFields(logrus.Fields{"interface": device, "error": errNo}).Fatal("Could not join EAP link-layer multicast group")
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
		log.WithFields(logrus.Fields{"interface": device, "error": errNo}).Fatal("Error binding interface to socket")
	}

	return fd
}
