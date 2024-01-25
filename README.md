# dhcp-tools

## Clone

`git clone git@github.com:gordcurrie/dhcp-tools.git`

## Setup

1. Install libpcap-dev on linux `sudo apt-get install libpcap-dev`

## Useage

### Sudo

Needs to be run as root to be able to capture packets.

### Sniff

Sniffs available packets for DHCP traffic.

`sudo dhcp-tools sniff`

Pass optional `-o` `--output` flag with a path to output file to store output.

`sudo dhcp-tools sniff -o ./test.txt`
