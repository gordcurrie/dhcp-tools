package gui

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gordcurrie/dhcp-tools/internal/options"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rivo/tview"
)

func RenderSelect() string {
	iface := ""
	devs, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("could not find devices, err: %v\n", err)
	}

	app := tview.NewApplication()
	list := tview.NewList()
	list.ShowSecondaryText(false)
	list.SetBorder(true)
	list.SetTitle("Select Interface:")
	list.SetWrapAround(true)
	list.SetBackgroundColor(tcell.ColorBlack)
	list.SetMainTextColor(tcell.ColorWhite)
	list.SetSelectedTextColor(tcell.ColorGray)
	for _, d := range devs {
		list.AddItem(d.Name, "", 0, nil)
	}
	list.SetSelectedFunc(func(i int, name string, _ string, _ rune) {
		iface = name
		app.Stop()
	})

	if err := app.SetRoot(list, true).EnableMouse(true).Run(); err != nil {
		panic(err)
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
