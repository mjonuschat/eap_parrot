package main

import (
	"flag"
	"github.com/google/gopacket"
	"github.com/sirupsen/logrus"
	"github.com/sirupsen/logrus/hooks/syslog"
	"golang.org/x/sys/unix"
	"io/ioutil"
)

var log = logrus.New()

func logPacket(device string, packet gopacket.Packet, verbose bool) {
	packetString := packet.String()
	if verbose {
		packetString = packet.Dump()
	}
	log.WithFields(logrus.Fields{"interface": device, "packet": packetString}).Debug("Received EAP/EAPOL packet")
}

// Configure logging
func initLogging(logToSyslog bool, debug bool) {
	log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	if debug {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}
	if logToSyslog {
		hook, err := syslog.NewSyslogHook("", "", 7, "")
		if err != nil {
			log.Error("Unable to connect to local syslog daemon")
		} else {
			log.AddHook(hook)
			log.Out = ioutil.Discard
		}
	}
}

func main() {
	ifWan := flag.String("if-wan", "eth1", "interface of the AT&T ONT/WAN")
	ifRouter := flag.String("if-router", "eth2", "interface of the AT&T router")
	vlanID := flag.Int("vlan", -1, "copy packet for this VLAN ID")
	promiscuous := flag.Bool("promiscuous", false, "place interfaces into promiscuous mode instead of multicast")

	ignoreStart := flag.Bool("ignore-start", false, "ignore EAPOL Start packets from router")
	ignoreLogoff := flag.Bool("ignore-logoff", false, "ignore EAPOL Logoff packets from router")

	debug := flag.Bool("debug", false, "enable debug-level logging")
	debugPackets := flag.Bool("debug-packets", false, "print packets in hex format to assist with debugging")
	logToSyslog := flag.Bool("syslog", false, "log to syslog")

	flag.Parse()

	initLogging(*logToSyslog, *debug || *debugPackets)

	log.Info("eap_parrot starting up...")
	// Open devices
	wanInterface := setupCaptureDevice(ifWan, promiscuous, vlanID)
	rtrInterface := setupCaptureDevice(ifRouter, promiscuous, vlanID)

	// Close devices on shutdown
	shutdownHandler := func() {
		defer wanInterface.handle.Close()
		defer unix.Close(wanInterface.fd)
		defer rtrInterface.handle.Close()
		defer unix.Close(rtrInterface.fd)
	}
	logrus.RegisterExitHandler(shutdownHandler)

	// Use the handle as a packet source to process all packets
	wanSource := gopacket.NewPacketSource(wanInterface.handle, wanInterface.handle.LinkType())
	rtrSource := gopacket.NewPacketSource(rtrInterface.handle, rtrInterface.handle.LinkType())

	for {
		select {
		case packet := <-wanSource.Packets():
			logPacket(*ifWan, packet, *debugPackets)
			emitPacket(packet, rtrInterface.handle)
		case packet := <-rtrSource.Packets():
			logPacket(*ifRouter, packet, *debugPackets)
			if handleRouterPacket(packet, ignoreStart, ignoreLogoff) {
				emitPacket(packet, wanInterface.handle)
			}
		}
	}

	logrus.Exit(0)
}
