# dhcp-tools

[![codecov](https://codecov.io/gh/gordcurrie/dhcp-tools/graph/badge.svg?token=LW1TN6I2WJ)](https://codecov.io/gh/gordcurrie/dhcp-tools)
[![Build](https://github.com/gordcurrie/dhcp-tools/actions/workflows/go.yml/badge.svg)](https://github.com/gordcurrie/dhcp-tools/actions/workflows/go.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/gordcurrie/dhcp-tools)](https://goreportcard.com/report/github.com/gordcurrie/dhcp-tools)

![dhcp-tools](https://github.com/gordcurrie/gifs/blob/main/dhcp-tools.gif)

## Clone

`git clone git@github.com:gordcurrie/dhcp-tools.git`

## Setup

1. Install libpcap-dev on linux `sudo apt-get install libpcap-dev`

## Build

`go build`

## Useage

### Sudo

Needs to be run as root to be able to capture packets.

### Sniff

Sniffs available packets for DHCP traffic.

`sudo ./dhcp-tools sniff`

Pass optional `-c` `--capture` flag will capture files in `$HOME/.dhcp-tools/captures`

`sudo ./dhcp-tools sniff -c`

### Send

Sends a selected previously captured packet on the selected interface.

`sudo ./dhcp-tools send`

### Clear

Deletes all files in the captures directory.

`sudo ./dhcp-tools clear`

### NOTE

This guide assumes you are building from source. If you wish to `go install` you will have to ensure that the path to the binary is included in sudo's $PATH.
