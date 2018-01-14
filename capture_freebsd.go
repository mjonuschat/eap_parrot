package main

import (
	"golang.org/x/sys/unix"
	"log"
	"syscall"
	"unsafe"
)

// Data structure needed by the SIOCADDMULTI ioctl call.
// Based upon the code found in the diagnostic and test
// utility for multicast sockets shipped with FreeBSD:
// https://github.com/freebsd/freebsd/blob/2f4b735c66deb54490042a818e8fd26fa46818f1/usr.sbin/mtest/mtest.c#L759
type IfReq struct {
	Name   [16]byte
	Len    uint8
	Family uint8
	Index  uint16
	Type   uint8
	Nlen   uint8
	Alen   uint8
	Slen   uint8
	Data   [8]byte
}

// Setup the given device to join the EAP(OL) link layer multicast group.
func joinMulticastGroup(device *string) (fd int) {
	var ifname [16]byte
	copy(ifname[:], *device)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP)
	if err != nil {
		log.Fatalf("Error opening socket for interface %s", *device)
	}

	ifReq := IfReq{
		Name:   ifname,
		Len:    unix.SizeofSockaddrDatalink,
		Family: unix.AF_LINK,
		Index:  0,
		Type:   0,
		Nlen:   0,
		Alen:   ETHER_ADDR_LEN,
		Slen:   0,
		Data:   [8]uint8{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03},
	}

	_, _, errNo := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCADDMULTI),
		uintptr(unsafe.Pointer(&ifReq)),
	)
	if errNo == syscall.EADDRINUSE {
		log.Printf("Interface %s is already listing for multicast EAP packets...", *device)
	} else if errNo > 0 {
		log.Fatalf("Interface %s could not be configured to receive EAP packets: %s", *device, errNo)
	}

	return fd
}
