#!/bin/bash
sudo ip addr add 10.10.10.51/24 dev ens11
sudo ifconfig ens11 mtu 9000
sudo ifconfig ens11 up
# local host and vm
# ping -c 3 10.10.10.201
ping -c 3 10.10.10.221
ping -c 3 10.10.10.101
# remote host and vms
sudo arp -i ens11 -s 10.10.10.102 0c:42:a1:41:8a:93
ping -c 3 10.10.10.102
sudo arp -i ens11 -s 10.10.10.202 00:22:aa:44:66:01
ping -c 3 10.10.10.202
sudo ibv_devinfo
