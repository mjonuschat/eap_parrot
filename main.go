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

func logPacket(device string, packet gopacket.Packet) {
	packetString := packet.String()
	if config.Logging.DebugPackets {
		packetString = packet.Dump()
	}
	log.WithFields(logrus.Fields{"interface": device, "packet": packetString}).Debug("Received EAP/EAPOL packet")
}

// Configure logging
func initLogging() {
	log.Formatter = &logrus.TextFormatter{FullTimestamp: true}
	if config.Logging.Debug || config.Logging.DebugPackets {
		log.SetLevel(logrus.DebugLevel)
	} else {
		log.SetLevel(logrus.InfoLevel)
	}
	if config.Logging.Syslog {
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
	configFile := flag.String("config", "/etc/eap_parrot.toml", "Full path to the config file")

	flag.Parse()

	initConfiguration(*configFile)
	initLogging()

	log.Info("eap_parrot starting up...")
	// Open devices
	wanInterface := setupCaptureDevice(config.Network.Wan)
	rtrInterface := setupCaptureDevice(config.Network.Router)

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
			logPacket(config.Network.Wan, packet)
			emitPacket(packet, rtrInterface.handle)
		case packet := <-rtrSource.Packets():
			logPacket(config.Network.Router, packet)
			if handleRouterPacket(packet) {
				emitPacket(packet, wanInterface.handle)
			}
		}
	}

	logrus.Exit(0)
}
