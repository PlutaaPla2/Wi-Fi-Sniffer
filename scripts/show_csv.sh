#!/bin/bash

FILENAME="$1"

column -s, -t < $FILENAME | less -#2 -N -S
