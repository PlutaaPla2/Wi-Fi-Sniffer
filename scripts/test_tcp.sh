#!/bin/bash

IP="${1:-127.0.0.1}"
PORT="${2:-5000}"

nc -vz $IP $PORT