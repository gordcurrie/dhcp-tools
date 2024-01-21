package sniff

import (
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gordcurrie/dhcp-tools/internal/gui"
)

const (
	promisc = true  // try and capture everything
	snapLen = 65535 // max uint16
)

func Sniff(iface string) {
	handle, err := pcap.OpenLive(iface, snapLen, promisc, pcap.BlockForever)
	if err != nil {
		log.Fatalf("could not open live, err: %v\n", err)
	}

	defer handle.Close()

	err = handle.SetBPFFilter("port  67 or port 68")
	if err != nil {
		log.Fatalf("could not set BF Filter, err: %v\n", err)
	}
	log.Println("awaiting packets...")

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	for p := range source.Packets() {
		for _, l := range p.Layers() {
			if l.LayerType() == layers.LayerTypeDHCPv4 {
				var d layers.DHCPv4
				err := d.DecodeFromBytes(l.LayerContents(), gopacket.NilDecodeFeedback)
				if err != nil {
					log.Printf("error: could not decode packet, err: %v\n", err)
				}

				gui.RenderPacket(d)
			}
		}
	}
}
