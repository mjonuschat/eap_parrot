package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"log"
)

var (
	filter      string = "ether proto 0x888e"
	snapshotLen int32  = 9000
)

// setupCaptureDevice opens the given device name for live capture.
// It will only capture packets coming into the interface from the network.
func setupCaptureDevice(device *string, promiscuous *bool) *pcap.Handle {
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

	return handle
}

// Emit a captured packet onto the wire through the given pcap handle.
// No modifications are being done to the packet, this is a 1:1 mirror.
func emitPacket(packet gopacket.Packet, destination *pcap.Handle) {
	err := destination.WritePacketData(packet.Data())
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	ifWan := flag.String("if-wan", "eth1", "interface of the AT&T ONT/WAN")
	ifRouter := flag.String("if-router", "eth2", "interface of the AT&T router")
	promiscuous := flag.Bool("promiscuous", false, "place interfaces into promiscuous mode")

	debug := flag.Bool("debug", false, "enable debug-level logging")

	flag.Parse()

	// Open devices
	wanHandle := setupCaptureDevice(ifWan, promiscuous)
	rtrHandle := setupCaptureDevice(ifRouter, promiscuous)

	// Close devices on shutdown
	defer wanHandle.Close()
	defer rtrHandle.Close()

	// Use the handle as a packet source to process all packets
	wanSource := gopacket.NewPacketSource(wanHandle, wanHandle.LinkType())
	rtrSource := gopacket.NewPacketSource(rtrHandle, rtrHandle.LinkType())

	for {
		select {
		case packet := <-wanSource.Packets():
			if *debug {
				fmt.Println(*ifWan, packet.Dump())
			} else if *debug {
				fmt.Println(*ifWan, packet.String())
			}
			emitPacket(packet, rtrHandle)
		case packet := <-rtrSource.Packets():
			if *debug {
				fmt.Println(*ifRouter, packet.Dump())
			} else if *debug {
				fmt.Println(*ifRouter, packet.String())
			}
			emitPacket(packet, wanHandle)
		}
	}
}
