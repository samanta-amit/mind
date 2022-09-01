#!/bin/bash
## sudo ip addr add 10.10.10.101/24 dev enp175s0
# sudo ifconfig enp175s0 mtu 9000
# sudo ifconfig enp175s0 up
sudo ip addr add 10.10.10.224/32 dev enp216s0f1
sudo ip link set dev enp216s0f1 mtu 9000
sudo ip link set dev enp216s0f1 up
sudo ip route add 10.10.10.0/24 dev enp216s0f1

## Now directly assigned to memory node 1
# sudo ip addr add 10.10.11.11/32 dev enp59s0f0
# sudo ifconfig enp59s0f0 mtu 9000
# sudo ifconfig enp59s0f0 up
# sudo ip route add 10.10.11.0/24 dev enp59s0f0
