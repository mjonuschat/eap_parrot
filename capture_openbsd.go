package main

import (
	"unsafe"

	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// Data structure needed by the SIOCADDMULTI ioctl call.
type IfReq struct {
	Name [16]byte
	unix.RawSockaddr
}

// Setup the given device to join the EAP(OL) link layer multicast group.
func joinMulticastGroup(device string) (fd int) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		log.WithFields(logrus.Fields{"device": device}).Fatal("Error opening socket")
	}

	var ifReq IfReq
	copy(ifReq.Name[:len(ifReq.Name)-1], device) // like strlcpy(), keep \0 terminated
	ifReq.Len = byte(unsafe.Sizeof(ifReq.RawSockaddr))
	ifReq.Family = unix.AF_UNSPEC
	// Data is signed or unsigned depending on platform (C char)
	type unsignedData = [unsafe.Sizeof(ifReq.Data)]byte
	*(*unsignedData)(unsafe.Pointer(&ifReq.Data)) = unsignedData{0x01, 0x80, 0xc2, 0x00, 0x00, 0x03}

	err = unix.IoctlSetInt(fd, unix.SIOCADDMULTI, int(uintptr(unsafe.Pointer(&ifReq))))
	if err == unix.EADDRINUSE {
		log.WithFields(logrus.Fields{"device": device}).Debug("Already a member in the EAP link-layer multicast group")
	} else if err != nil {
		log.WithFields(logrus.Fields{"device": device}).Fatal("Could not join EAP link-layer multicast group")
	}

	return fd
}
