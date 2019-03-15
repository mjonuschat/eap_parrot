package main

import (
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	"syscall"
	"unsafe"
)

// Data structure needed by the SIOCADDMULTI ioctl call.
type IfReq struct {
	Name [16]byte
	// struct sockaddr {
	Len    uint8
	Family uint8
	Data   [8]byte
	// } ifr_addr
}

// Setup the given device to join the EAP(OL) link layer multicast group.
func joinMulticastGroup(device string) (fd int) {
	var ifname [16]byte
	copy(ifname[:], device)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		log.WithFields(logrus.Fields{"device": device}).Fatal("Error opening socket")
	}

	ifReq := IfReq{
		Name:   ifname,
		Len:    unix.SizeofSockaddrDatalink,
		Family: unix.AF_UNSPEC,
		Data:   [8]uint8{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03},
	}

	_, _, errNo := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(unix.SIOCADDMULTI),
		uintptr(unsafe.Pointer(&ifReq)),
	)
	if errNo == syscall.EADDRINUSE {
		log.WithFields(logrus.Fields{"device": device}).Debug("Already a member in the EAP link-layer multicast group")
	} else if errNo > 0 {
		log.WithFields(logrus.Fields{"device": device}).Fatal("Could not join EAP link-layer multicast group")
	}

	return fd
}
