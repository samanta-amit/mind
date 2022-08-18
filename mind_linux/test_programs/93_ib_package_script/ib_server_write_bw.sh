#!/bin/bash
echo 'Measure throughput - RDMA RC write'
ib_write_bw -d $1 -s 32 -n 100000000 --cpu_util
ib_write_bw -d $1 -s 128 -n 100000000 --cpu_util
ib_write_bw -d $1 -s 512 -n 100000000 --cpu_util
ib_write_bw -d $1 -s 1K -n 100000000 --cpu_util
ib_write_bw -d $1 -s 2K -n 100000000 --cpu_util
ib_write_bw -d $1 -s 4K -n 100000000 --cpu_util
ib_write_bw -d $1 -s 8K -n 100000000 --cpu_util
ib_write_bw -d $1 -s 16K -n 100000000 --cpu_util
ib_write_bw -d $1 -s 32K -n 100000000 --cpu_util
