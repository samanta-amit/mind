#!/bin/bash
qperf -cm1 -t 20 -m 32 -lcp1 -v 10.10.10.102 tcp_lat udp_lat rc_rdma_read_lat rc_rdma_write_lat >> qperf.log
qperf -cm1 -t 20 -m 128 -lcp1 -v 10.10.10.102 tcp_lat udp_lat rc_rdma_read_lat rc_rdma_write_lat >> qperf.log
qperf -cm1 -t 20 -m 512 -lcp1 -v 10.10.10.102 tcp_lat udp_lat rc_rdma_read_lat rc_rdma_write_lat >> qperf.log
qperf -cm1 -t 20 -m 1k -lcp1 -v 10.10.10.102 tcp_lat udp_lat rc_rdma_read_lat rc_rdma_write_lat >> qperf.log
qperf -cm1 -t 20 -m 2k -lcp1 -v 10.10.10.102 tcp_lat udp_lat rc_rdma_read_lat rc_rdma_write_lat >> qperf.log
qperf -cm1 -t 20 -m 4k -lcp1 -v 10.10.10.102 tcp_lat udp_lat rc_rdma_read_lat rc_rdma_write_lat >> qperf.log
qperf -cm1 -t 20 -m 8k -lcp1 -v 10.10.10.102 tcp_lat udp_lat rc_rdma_read_lat rc_rdma_write_lat >> qperf.log

