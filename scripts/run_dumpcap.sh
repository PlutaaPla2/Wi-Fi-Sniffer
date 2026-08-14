#!/bin/bash

dumpcap -i wlan1 -f 'type mgt' -w ../pcap_files/$(date +%Y%m%d-%H%M)-$1.pcap