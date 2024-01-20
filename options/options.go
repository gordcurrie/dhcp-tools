package options

import (
	"bytes"
	"fmt"
	"net"

	"github.com/google/gopacket/layers"
)

// String returns a string version of a DHCP Option.
func ToString(o layers.DHCPOption) string {
	switch o.Type {

	case layers.DHCPOptHostname, layers.DHCPOptMeritDumpFile, layers.DHCPOptDomainName, layers.DHCPOptRootPath,
		layers.DHCPOptExtensionsPath, layers.DHCPOptNISDomain, layers.DHCPOptNetBIOSTCPScope, layers.DHCPOptXFontServer,
		layers.DHCPOptXDisplayManager, layers.DHCPOptMessage, layers.DHCPOptDomainSearch, layers.DHCPOptClassID: // string
		return fmt.Sprintf("%s", o.Data)

	case layers.DHCPOptMessageType: // msgType
		return toMsgType(o.Data)

	case layers.DHCPOptSubnetMask, layers.DHCPOptServerID, layers.DHCPOptBroadcastAddr,
		layers.DHCPOptSolicitAddr, layers.DHCPOptRequestIP, layers.DHCPOptRouter, layers.DHCPOptDNS: // net.IP
		return toIP(o.Data)

	case layers.DHCPOptT1, layers.DHCPOptT2, layers.DHCPOptLeaseTime, layers.DHCPOptPathMTUAgingTimeout,
		layers.DHCPOptARPTimeout, layers.DHCPOptTCPKeepAliveInt: // uint32
		return toUint32(o.Data)

	case layers.DHCPOptBootfileSize, layers.DHCPOptDatagramMTU,
		layers.DHCPOptInterfaceMTU, layers.DHCPOptMaxMessageSize: // uint16
		return toUint16(o.Data)

	case layers.DHCPOptParamsRequest: // option params
		return optionParams(o.Data)

	case layers.DHCPOptClientID: // mac address
		return toMac(o.Data)

	default:
		return fmt.Sprintf("%b", o.Data)
	}
}

const invalid = "INVALID"

func toMsgType(data []byte) string {
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

func toUint32(data []byte) string {
	if len(data) != 4 {
		return invalid
	}

	return fmt.Sprintf("%d", uint32(data[0])<<24|uint32(data[1])<<16|uint32(data[2])<<8|uint32(data[3]))
}

func toUint16(data []byte) string {
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
