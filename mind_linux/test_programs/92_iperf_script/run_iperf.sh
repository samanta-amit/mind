#!/bin/bash
for ((i = 0; i < $1; ++i)) ; do
	echo $i
	iperf3 -c 10.10.10.102 -p $((60001+$i)) -O 5 -V -i 10 -t 65 -b 100000M -l 60K -u&
done
#iperf3 -c 10.10.10.102 -p 60002 -O 3 &
#iperf3 -c 10.10.10.102 -p 60003 -O 3 &
#iperf3 -c 10.10.10.102 -p 60004 -O 3 &
#iperf3 -c 10.10.10.102 -p 60005 -O 3 &
