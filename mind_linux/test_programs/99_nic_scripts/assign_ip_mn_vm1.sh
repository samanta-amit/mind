#!/bin/bash
sudo ip addr add 10.10.10.221/24 dev ens10
sudo ifconfig ens10 mtu 9000
sudo ifconfig ens10 up

# local host and vm
# sudo arp -i ens10 -s 10.10.10.101 0c:42:a1:3d:c1:84
# ping -c 3 10.10.10.101
# ping -c 3 10.10.10.51	# switch vm
# ping -c 3 10.10.10.201  # compute vm (may not be used anymore)

# remote host and vms
# sudo arp -i ens9 -s 10.10.10.102 0c:42:a1:41:8a:93
# ping -c 3 10.10.10.102

# switch controller
sudo arp -i ens10 -s 10.10.10.1 00:02:00:00:03:00
sudo arp -i ens10 -s 10.10.10.201 04:3f:72:a2:b4:a2
sudo arp -i ens10 -s 10.10.10.202 04:3f:72:a2:b4:a3
sudo arp -i ens10 -s 10.10.10.203 04:3f:72:a2:b5:f2
sudo arp -i ens10 -s 10.10.10.204 04:3f:72:a2:b5:f3
sudo arp -i ens10 -s 10.10.10.205 0c:42:a1:41:8b:5a
sudo arp -i ens10 -s 10.10.10.206 0c:42:a1:41:8b:5b
sudo arp -i ens10 -s 10.10.10.207 04:3f:72:a2:b0:12
sudo arp -i ens10 -s 10.10.10.208 04:3f:72:a2:b0:13
ping -c 3 10.10.10.1
sudo ibv_devinfo
