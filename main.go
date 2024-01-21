package main

import (
	"log"

	"github.com/gordcurrie/dhcp-tools/internal/gui"
	"github.com/gordcurrie/dhcp-tools/internal/sniff"
)

func main() {
	log.Println("dhcp-tools")

	iface := gui.RenderSelect()

	sniff.Sniff(iface)
}
