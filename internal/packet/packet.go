package packet

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gordcurrie/dhcp-tools/internal/env"
	"github.com/gordcurrie/dhcp-tools/internal/gui"
	"github.com/gordcurrie/dhcp-tools/internal/options"
)

const (
	promisc = false                 // promiscuous mode
	snapLen = 65535                 // max uint16
	bpf     = "port  67 or port 68" // Berkeley Packt Filter format, dhcp traffic should be all over port 67 or 68
)

func Sniff(iface string, capture bool) error {
	var capturesPath string
	var err error
	if capture {
		capturesPath, err = env.GetCapturesPath()
		if err != nil {
			return err
		}
	}

	handle, err := pcap.OpenLive(iface, snapLen, promisc, pcap.BlockForever)
	if err != nil {
		return err
	}

	defer handle.Close()

	err = handle.SetBPFFilter(bpf)
	if err != nil {
		return err
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

				if capture {
					fileHandle := genFileName(d)
					path := filepath.Join(capturesPath, fileHandle+".dat")
					err = os.WriteFile(path, p.Data(), 0644)
					if err != nil {
						log.Printf("error: could not decode packet, err: %v\n", err)
					}
				}
			}
		}
	}

	return nil
}

func genFileName(d layers.DHCPv4) string {
	var hostname string
	var messageType string
	if len(d.Options) > 0 {
		for _, op := range d.Options {
			if op.Type == layers.DHCPOptHostname {
				hostname = options.ToString(op)
			}
			if op.Type == layers.DHCPOptMessageType {
				messageType = options.ToString(op)
			}
		}
	}

	return fmt.Sprintf("%s_%s_%s", hostname, messageType, time.Now().Format("2006-01-02-15:04:05.06"))
}

func Send(iface, file string) error {
	capturesPath, err := env.GetCapturesPath()
	if err != nil {
		return err
	}

	path := filepath.Join(capturesPath, file)

	dat, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	handle, err := pcap.OpenLive(iface, snapLen, promisc, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	log.Printf("sending %s on %s", file, iface)

	err = handle.WritePacketData(dat)
	if err != nil {
		return err
	}
	return nil
}
