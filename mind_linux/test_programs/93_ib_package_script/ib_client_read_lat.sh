#!/bin/bash
echo 'Measure latency - RDMA RC read'
ib_read_lat -d $1 -s 32 -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 64 -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 128 -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 256 -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 512 -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 1K -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 2K -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 4K -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 8K -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 16K -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 32K -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 64K -n 10000000 $2
sleep 10
ib_read_lat -d $1 -s 128K -n 10000000 $2
