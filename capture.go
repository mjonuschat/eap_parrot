package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
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
