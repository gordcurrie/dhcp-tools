package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gordcurrie/dhcp-tools/options"
	"github.com/jedib0t/go-pretty/v6/table"
)

const (
	promisc = true  // try and capture everything
	snapLen = 65535 // max uint16
	// dev     = "wlp170s0" // TODO: change this
	dev = "eth0"
)

func main() {
	log.Println("dhcp-tools")

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

				t := table.NewWriter()
				t.SetOutputMirror(os.Stdout)
				t.AppendRow(table.Row{"Time:", time.Now().Format(time.RFC3339)})
				t.AppendRow(table.Row{"IP:", d.ClientIP.String() + " -> " + d.NextServerIP.String()})
				t.AppendRow(table.Row{"OP:", d.Operation})
				t.AppendRow(table.Row{"HardwareType:", d.HardwareType})
				t.AppendRow(table.Row{"HardwareLen:", d.HardwareLen})
				t.AppendRow(table.Row{"HardwareOpts:", d.HardwareOpts})
				t.AppendRow(table.Row{"Xid:", d.Xid})
				t.AppendRow(table.Row{"Secs:", d.Secs})
				t.AppendRow(table.Row{"Flags:", d.Flags})
				t.AppendRow(table.Row{"ClientIP:", d.ClientIP})
				t.AppendRow(table.Row{"YourClientIP:", d.YourClientIP})
				t.AppendRow(table.Row{"NextServerIP:", d.NextServerIP})
				t.AppendRow(table.Row{"RelayAgentIP:", d.RelayAgentIP})
				t.AppendRow(table.Row{"ClientHWAddr:", d.ClientHWAddr})
				t.AppendRow(table.Row{"ServerName:", fmt.Sprintf("%s", d.ServerName)})
				t.AppendRow(table.Row{"File:", fmt.Sprintf("%s", d.File)})

				t.AppendSeparator()
				if len(d.Options) > 0 {
					t.AppendRow(table.Row{"Options:"})

					for _, op := range d.Options {
						t.AppendRow(table.Row{"", "Option:", fmt.Sprintf("%s (%d)", op.Type.String(), op.Type), options.ToString(op)})
					}
				}

				t.Render()
			}
		}
	}
}
