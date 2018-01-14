package main

import (
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"golang.org/x/sys/unix"
)

func main() {
	ifWan := flag.String("if-wan", "eth1", "interface of the AT&T ONT/WAN")
	ifRouter := flag.String("if-router", "eth2", "interface of the AT&T router")
	promiscuous := flag.Bool("promiscuous", false, "place interfaces into promiscuous mode instead of multicast")

	debug := flag.Bool("debug", false, "enable debug-level logging")
	debugPackets := flag.Bool("debug-packets", false, "print packets in hex format to assist with debugging")

	flag.Parse()

	// Open devices
	wanInterface := setupCaptureDevice(ifWan, promiscuous)
	rtrInterface := setupCaptureDevice(ifRouter, promiscuous)

	// Close devices on shutdown
	defer wanInterface.handle.Close()
	defer unix.Close(wanInterface.fd)
	defer rtrInterface.handle.Close()
	defer unix.Close(rtrInterface.fd)

	// Use the handle as a packet source to process all packets
	wanSource := gopacket.NewPacketSource(wanInterface.handle, wanInterface.handle.LinkType())
	rtrSource := gopacket.NewPacketSource(rtrInterface.handle, rtrInterface.handle.LinkType())

	for {
		select {
		case packet := <-wanSource.Packets():
			if *debugPackets {
				fmt.Println(*ifWan, packet.Dump())
			} else if *debug {
				fmt.Println(*ifWan, packet.String())
			}
			emitPacket(packet, rtrInterface.handle)
		case packet := <-rtrSource.Packets():
			if *debugPackets {
				fmt.Println(*ifRouter, packet.Dump())
			} else if *debug {
				fmt.Println(*ifRouter, packet.String())
			}
			emitPacket(packet, wanInterface.handle)
		}
	}
}
