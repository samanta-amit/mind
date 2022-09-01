#!/bin/bash
echo 'Measure latency - RDMA RC write'
custom_bin/ib_write_lat -d $1 -s 32 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 64 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 128 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 256 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 512 -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 1K -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 2K -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 4K -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 8K -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 16K -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 32K -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 64K -I 1 -n 10000000 $2
sleep 10
custom_bin/ib_write_lat -d $1 -s 128K -I 1 -n 10000000 $2
