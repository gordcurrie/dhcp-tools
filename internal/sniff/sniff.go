package sniff

import (
	"log"
	"os"
	"path/filepath"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gordcurrie/dhcp-tools/internal/env"
	"github.com/gordcurrie/dhcp-tools/internal/gui"
)

const (
	promisc  = false                 // promiscuous mode
	snapLen  = 65535                 // max uint16
	bFFliter = "port  67 or port 68" // dhcp traffic should be all over port 67 or 68
)

func Sniff(iface string, capture bool) {
	var capturesPath string
	var err error
	if capture {
		capturesPath, err = env.GetCapturesPath()
		if err != nil {
			log.Fatalf("error: could not get captures path, err: %v\n", err)
		}
	}

	handle, err := pcap.OpenLive(iface, snapLen, promisc, pcap.BlockForever)
	if err != nil {
		log.Fatalf("error: could not open live, err: %v\n", err)
	}

	defer handle.Close()

	err = handle.SetBPFFilter(bFFliter)
	if err != nil {
		log.Fatalf("error: could not set BF Filter, err: %v\n", err)
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
				fileHandle := gui.RenderPacket(d)

				if capture {
					path := filepath.Join(capturesPath, fileHandle+".dat")
					err = os.WriteFile(path, p.Data(), 0644)
					if err != nil {
						log.Printf("error: could not decode packet, err: %v\n", err)
					}
				}
			}
		}
	}
}

func Send(iface, file string) {
	capturesPath, err := env.GetCapturesPath()
	if err != nil {
		log.Fatalf("error: could not get captures path, err: %v\n", err)
	}

	path := filepath.Join(capturesPath, file)

	dat, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("error: could not get captures path, err: %v\n", err)
	}

	handle, err := pcap.OpenLive(iface, snapLen, promisc, pcap.BlockForever)
	if err != nil {
		log.Fatalf("error: could not open live, err: %v\n", err)
	}
	defer handle.Close()

	err = handle.WritePacketData(dat)
	if err != nil {
		log.Fatalf("error: could not write live, err: %v\n", err)
	}

	log.Printf("sending %s on %s", file, iface)

}
