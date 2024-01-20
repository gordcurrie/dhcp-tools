package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/jedib0t/go-pretty/v6/table"
)

const (
	promisc = true       // try and capture everything
	snapLen = 65535      // max uint16
	dev     = "wlp170s0" // TODO: change this
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
						t.AppendRow(table.Row{"", "Option:", fmt.Sprintf("%s (%d)", op.Type.String(), op.Type), OptionData(op)})
					}
				}

				t.Render()
			}
		}
	}
}

// String returns a string version of a DHCP Option.
func OptionData(o layers.DHCPOption) string {
	switch o.Type {

	case layers.DHCPOptHostname, layers.DHCPOptMeritDumpFile, layers.DHCPOptDomainName, layers.DHCPOptRootPath,
		layers.DHCPOptExtensionsPath, layers.DHCPOptNISDomain, layers.DHCPOptNetBIOSTCPScope, layers.DHCPOptXFontServer,
		layers.DHCPOptXDisplayManager, layers.DHCPOptMessage, layers.DHCPOptDomainSearch, layers.DHCPOptClassID: // string
		return fmt.Sprintf("%s", o.Data)

	case layers.DHCPOptMessageType: // msgType
		return msgType(o.Data)

	case layers.DHCPOptSubnetMask, layers.DHCPOptServerID, layers.DHCPOptBroadcastAddr,
		layers.DHCPOptSolicitAddr, layers.DHCPOptRequestIP, layers.DHCPOptRouter, layers.DHCPOptDNS: // net.IP
		return toIP(o.Data)

	case layers.DHCPOptT1, layers.DHCPOptT2, layers.DHCPOptLeaseTime, layers.DHCPOptPathMTUAgingTimeout,
		layers.DHCPOptARPTimeout, layers.DHCPOptTCPKeepAliveInt: // uint32
		return fourBytes(o.Data)

	case layers.DHCPOptMaxMessageSize: // uint16
		return twoBytes(o.Data)

	case layers.DHCPOptParamsRequest: // option params
		return optionParams(o.Data)

	case layers.DHCPOptClientID: // mac address
		return toMac(o.Data)

	default:
		return fmt.Sprintf("%b", o.Data)
	}
}

const invalid = "INVALID"

func msgType(data []byte) string {
	if len(data) != 1 {
		return invalid
	}
	return fmt.Sprintf("%s", layers.DHCPMsgType(data[0]))
}

func toMac(data []byte) string {
	mac := net.HardwareAddr(data)
	return mac.String()
}

func toIP(data []byte) string {
	if len(data) < 4 {
		return invalid
	}

	return fmt.Sprintf("%s", net.IP(data))
}

func fourBytes(data []byte) string {
	if len(data) != 4 {
		return invalid
	}

	return fmt.Sprintf("%d", uint32(data[0])<<24|uint32(data[1])<<16|uint32(data[2])<<8|uint32(data[3]))
}

func twoBytes(data []byte) string {
	if len(data) != 2 {
		return invalid
	}

	return fmt.Sprint(uint16(data[0])<<8 + uint16(data[1]))
}

func optionParams(data []byte) string {
	buf := &bytes.Buffer{}
	for i, v := range data {
		buf.WriteString(fmt.Sprintf("%s (%v)", layers.DHCPOpt(v).String(), v))
		if i+1 != len(data) {
			buf.WriteString(",\n")
		}
	}
	return buf.String()
}
