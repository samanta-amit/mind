#!/bin/bash
echo 'Measure latency - RDMA RC read'
ib_read_lat -d $1 -s 8 -o 1 -n 10000000
ib_read_lat -d $1 -s 16 -o 1 -n 10000000
ib_read_lat -d $1 -s 32 -o 1 -n 10000000
ib_read_lat -d $1 -s 64 -o 1 -n 10000000
ib_read_lat -d $1 -s 96 -o 1 -n 10000000
ib_read_lat -d $1 -s 128 -o 1 -n 10000000
ib_read_lat -d $1 -s 160 -o 1 -n 10000000
ib_read_lat -d $1 -s 192 -o 1 -n 10000000
ib_read_lat -d $1 -s 256 -o 1 -n 10000000
