#!/bin/bash

sudo iw dev wlan0 scan | grep -E "SSID|freq|channel|signal"