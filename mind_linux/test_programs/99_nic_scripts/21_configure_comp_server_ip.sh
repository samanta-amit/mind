#!/bin/bash
# sudo ip addr add 10.10.10.102/32 dev enp23s0f0
# sudo ifconfig enp23s0f0 mtu 9000
# sudo ifconfig enp23s0f0 up
# sudo ifconfig enp23s0f1 mtu 9000
# sudo ifconfig enp23s0f1 up
# sudo ifconfig enp37s0f0 mtu 9000
# sudo ifconfig enp37s0f0 up
sudo ip addr add 10.10.10.212/32 dev enp89s0f1
sudo ip link set dev enp89s0f1 mtu 9000
sudo ip link set dev enp89s0f1 up
sudo ip route add 10.10.10.0/24 dev enp89s0f1
sh 13_register_vm_arp.sh enp89s0f1

## Direct link
# sudo ifconfig enp37s0f1 mtu 9000
# sudo ifconfig enp37s0f1 up
#
# sh 13_register_vm_arp.sh enp23s0f0
#
# sudo ip route add 10.10.10.0/24 dev enp23s0f0
