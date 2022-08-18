#!/bin/bash
sudo ip addr add 10.10.10.103/24 dev enp175s0f4
sudo ifconfig enp175s0f4 mtu 9000
sudo ifconfig enp175s0f4 up
ping -c 3 10.10.10.101
# sudo arp -i enp175s0f4 -s 10.10.10.102 0c:42:a1:41:8a:93
ping -c 3 10.10.10.102
# sudo arp -i enp175s0f4 -s 10.10.10.202 00:22:aa:44:66:01
# ping -c 3 10.10.10.202
sudo ibv_devinfo
