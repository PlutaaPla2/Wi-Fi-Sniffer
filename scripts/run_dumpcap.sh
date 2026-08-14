#!/bin/bash

dumpcap -i wlan1 -f 'type mgt' -w ../pcap_files/$1.pcap