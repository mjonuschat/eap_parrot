package main

import (
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
)

// ListenInterface contains the data structures for packet sniffing/copying.
type ListenInterface struct {
	fd     int
	handle *pcap.Handle
}

const hwAddressLength = 0x6
const bpfEapFilter = "ether proto 0x888e"

// setupCaptureDevice opens the given device name for live capture.
// It will only capture packets coming into the interface from the network.
func setupCaptureDevice(device string) ListenInterface {
	var filter = bpfEapFilter
	if config.Network.VlanID >= 0 {
		filter = fmt.Sprintf("%s or (vlan %d and %s)", filter, config.Network.VlanID, filter)
	}
	handle, err := pcap.OpenLive(device, 9000, config.Network.Promiscuous, pcap.BlockForever)
	if err != nil {
		log.WithFields(logrus.Fields{"interface": device}).Fatal(err)
	}
	err = handle.SetDirection(pcap.DirectionIn)
	if err != nil {
		log.WithFields(logrus.Fields{"interface": device}).Fatal(err)
	}

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.WithFields(logrus.Fields{"interface": device}).Fatal(err)
	}

	fd := joinMulticastGroup(device)

	return ListenInterface{
		fd:     fd,
		handle: handle,
	}
}

// Decide if we want to forward a packet from the router.
// We might want to ignore START and LOGOFF packets emitted by the AT&T CPE.
func handleRouterPacket(packet gopacket.Packet) bool {
	if eapolLayer := packet.Layer(layers.LayerTypeEAPOL); eapolLayer != nil {
		eapol, _ := eapolLayer.(*layers.EAPOL)
		if config.Ignore.Start && eapol.Type == layers.EAPOLTypeStart {
			log.Debug("Ignoring START packet from Router")
			return false
		}
		if config.Ignore.Logoff && eapol.Type == layers.EAPOLTypeLogOff {
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
