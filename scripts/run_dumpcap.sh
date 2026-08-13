#!/bin/bash

dumpcap -i wlan1 -f 'type mgt' -w /home/superroot/projects/Wi-Fi-Sniffer/pcap_files/$1.pcap