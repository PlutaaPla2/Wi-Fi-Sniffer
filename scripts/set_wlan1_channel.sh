#!/bin/bash

sudo iw dev wlan1 set channel $1
iw dev wlan1 info