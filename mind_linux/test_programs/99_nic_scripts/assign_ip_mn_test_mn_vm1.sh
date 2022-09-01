#!/bin/bash
sudo ip addr add 10.10.21.221/32 dev ens10
sudo ifconfig ens10 mtu 9000
sudo ifconfig ens10 up

# local host and vm
# ping -c 3 10.10.10.101
sudo ip route add 10.10.21.0/24 dev ens10
sudo arp -i ens10 -s 10.10.21.51 00:22:aa:44:55:6c
ping -c 3 10.10.21.51	# switch vm
# ping -c 3 10.10.10.201  # compute vm (may not be used anymore)

# remote host and vms
# sudo arp -i ens10 -s 10.10.10.102 0c:42:a1:41:8a:93
# ping -c 3 10.10.10.102

# switch controller
# sudo arp -i ens10 -s 10.10.10.1 00:02:00:00:03:00
# ping -c 3 10.10.10.1
sudo ibv_devinfo
