package gui

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gordcurrie/dhcp-tools/internal/options"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/manifoldco/promptui"
)

func RenderSelect() string {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("could not find devices, err: %v\n", err)
	}

	devNames := []string{}
	for _, d := range devs {
		devNames = append(devNames, d.Name)
	}

	promt := promptui.Select{
		Label: "Select Interface",
		Items: devNames,
	}

	_, iface, err := promt.Run()

	if err != nil {
		log.Printf("failed to read select err: %v\n", err)
		return ""
	}

	return iface
}

func RenderPacket(d layers.DHCPv4) {
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
