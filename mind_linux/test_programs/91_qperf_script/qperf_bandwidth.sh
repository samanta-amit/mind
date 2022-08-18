#!/bin/bash
qperf -cm1 -t 60 -m 32 -cp1 -v 10.10.10.102 tcp_bw udp_bw rc_rdma_read_bw rc_rdma_write_bw >> qperf.log
qperf -cm1 -t 60 -m 128 -cp1 -v 10.10.10.102 tcp_bw udp_bw rc_rdma_read_bw rc_rdma_write_bw >> qperf.log
qperf -cm1 -t 60 -m 512 -cp1 -v 10.10.10.102 tcp_bw udp_bw rc_rdma_read_bw rc_rdma_write_bw >> qperf.log
qperf -cm1 -t 60 -m 1k -cp1 -v 10.10.10.102 tcp_bw udp_bw rc_rdma_read_bw rc_rdma_write_bw >> qperf.log
qperf -cm1 -t 60 -m 2k -cp1 -v 10.10.10.102 tcp_bw udp_bw rc_rdma_read_bw rc_rdma_write_bw >> qperf.log
qperf -cm1 -t 60 -m 4k -cp1 -v 10.10.10.102 tcp_bw udp_bw rc_rdma_read_bw rc_rdma_write_bw >> qperf.log
qperf -cm1 -t 60 -m 8k -cp1 -v 10.10.10.102 tcp_bw udp_bw rc_rdma_read_bw rc_rdma_write_bw >> qperf.log
