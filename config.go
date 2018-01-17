package main

import (
	"github.com/BurntSushi/toml"
	"github.com/sirupsen/logrus"
)

// EAPParrotConfig is the main configuration structure which holds the nested configuration segments.
type EAPParrotConfig struct {
	Network Network
	Logging Logging
	Ignore  IgnorePackets
}

// IgnorePackets holds the configuration for which packets from the CPE are being ignored.
type IgnorePackets struct {
	Start  bool `toml:"start"`
	Logoff bool `toml:"logoff"`
}

// Logging defines loglevels, packet tracing and log destination.
type Logging struct {
	Syslog       bool `toml:"syslog"`
	Debug        bool `toml:"debug"`
	DebugPackets bool `toml:"debug_packets"`
}

// Network defines the configuration used to listen for EAP/EAPOL packets
type Network struct {
	Wan         string `toml:"wan_interface"`
	Router      string `toml:"router_interface"`
	VlanID      int    `toml:"vlan_id"`
	Promiscuous bool   `toml:"promiscuous_mode"`
}

var config EAPParrotConfig

func initConfiguration(configFile string) {
	if _, err := toml.DecodeFile(configFile, &config); err != nil {
		log.WithFields(logrus.Fields{"config": configFile}).Fatal(err)
	}
}
