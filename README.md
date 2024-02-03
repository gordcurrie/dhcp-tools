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

Pass optional `-c` `--capture` flag will capture files in `$HOME/.dhcp-tools/captures`

`sudo dhcp-tools sniff -c`

### Send

Sends a selected previously captured packet on the selected interface.

`sudo dhcp-tools send`

### Clear

Deletes all files in the captures directory.

`sudo dhcp-tools clear`
