#!/bin/bash
echo 'Measure latency - RDMA RC write'
custom_bin/ib_write_lat -d $1 -s 8 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 16 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 32 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 64 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 96 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 128 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 160 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 192 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 256 -I 1 -n 10000000 $2
