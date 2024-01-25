# dhcp-tools

## Setup

1. Install libpcap-dev on linux `sudo apt-get install libpcap-dev`

## Useage

### Sniff

Sniffs available packets for DHCP traffic.

`sudo dhcp-tools sniff`

Pass optional `-o` `--output` flag with a path to output file to store output.

`sudo dhcp-tools sniff -o ./test.txt`
