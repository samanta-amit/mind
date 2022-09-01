#!/bin/bash
sudo ip addr add 10.10.10.205/24 dev ens9
sudo ifconfig ens9 mtu 9000
sudo ifconfig ens9 up

# blueflame
export MLX5_POST_SEND_PREFER_BF=1
export MLX5_SHUT_UP_BF=0
unset MLX5_SHUT_UP_BF

# sudo export MLX5_POST_SEND_PREFER_BF=1
# sudo export MLX5_SHUT_UP_BF=0
# sudo unset MLX5_SHUT_UP_BF

# local host and vm
# ping -c 3 10.10.10.101
# sh 13_register_vm_arp.sh ens9
sudo arp -i ens9 -s 10.10.10.1 00:02:00:00:03:00
sudo arp -i ens9 -s 10.10.10.221 04:3f:72:a2:b7:3a
sudo arp -i ens9 -s 10.10.10.201 04:3f:72:a2:b4:a2 & sudo arp -i ens9 -s 10.10.10.202 04:3f:72:a2:b4:a3 & sudo arp -i ens9 -s 10.10.10.203 04:3f:72:a2:b5:f2 & sudo arp -i ens9 -s 10.10.10.204 04:3f:72:a2:b5:f3 & sudo arp -i ens9 -s 10.10.10.205 0c:42:a1:41:8b:5a & sudo arp -i ens9 -s 10.10.10.206 0c:42:a1:41:8b:5b & sudo arp -i ens9 -s 10.10.10.207 04:3f:72:a2:b0:12 & sudo arp -i ens9 -s 10.10.10.208 04:3f:72:a2:b0:13 & wait
sudo ibv_devinfo
