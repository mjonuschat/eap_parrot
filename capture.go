package main

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
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
		log.WithFields(logrus.Fields{"interface": *device}).Fatal(err)
	}
	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		log.WithFields(logrus.Fields{"interface": *device}).Fatal(err)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.WithFields(logrus.Fields{"interface": *device}).Fatal(err)
	}

	fd := joinMulticastGroup(device)

	return ListenInterface{
		fd:     fd,
		handle: handle,
	}
}

// Decide if we want to forward a packet from the router.
// We might want to ignore START and LOGOFF packets emitted by the AT&T CPE.
func handleRouterPacket(packet gopacket.Packet, ignoreStart *bool, ignoreLogoff *bool) bool {
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		eapol, _ := eapolLayer.(*layers.EAPOL)
		if *ignoreStart && eapol.Type == layers.EAPOLTypeStart {
			log.Debug("Ignoring START packet from Router")
			return false
		}
		if *ignoreLogoff && eapol.Type == layers.EAPOLTypeLogOff {
			log.Debug("Ignoring LOGOFF packet from Router")
			return false
		}
	}

	return true
}

// Emit a captured packet onto the wire through the given pcap handle.
// No modifications are being done to the packet, this is a 1:1 mirror.
func emitPacket(packet gopacket.Packet, destination *pcap.Handle) {
	err := destination.WritePacketData(packet.Data())
	if err != nil {
		log.Fatal(err)
	}
}
