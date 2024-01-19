package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	// TODO: Figure out what are good values for most of these
	promisc = true
	snapLen = 262144
	dev     = "wlp170s0"
)

func main() {
	fmt.Println("dhcp-tools")

	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("could not find devices, err: %v\n", err)
	}

	found := false
	for _, d := range devs {
		if d.Name == dev {
			found = true
			break
		}
	}

	if !found {
		log.Fatalf("target interface not found")
	}

	handle, err := pcap.OpenLive(dev, snapLen, promisc, pcap.BlockForever)
	if err != nil {
		log.Fatalf("could not open live, err: %v\n", err)
	}
	log.Println("handle created")

	defer handle.Close()

	err = handle.SetBPFFilter("port  67 or port 68")
	if err != nil {
		log.Fatalf("could not set BF Filter, err: %v\n", err)
	}
	log.Println("filter set")

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for p := range source.Packets() {
		log.Println("packet read")

		for _, l := range p.Layers() {
			if l.LayerType() == layers.LayerTypeDHCPv4 {
				log.Println("DHCP Layer read")

				var d layers.DHCPv4
				err := d.DecodeFromBytes(l.LayerContents(), gopacket.NilDecodeFeedback)
				if err != nil {
					log.Fatalf("could not decode packet, err: %v\n", err)
				}

				log.Println(d.Options.String())
				log.Println(d.ClientIP.String())
				log.Println(string(d.ServerName))
				// prettyPrint(&d)
			}
		}
	}
}

func prettyPrint(d *layers.DHCPv4) {
	dhcp, err := json.MarshalIndent(d, "", "\t")
	if err != nil {
		return
	}
	log.Println(string(dhcp))

}
