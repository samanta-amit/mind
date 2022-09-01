sudo ip link set dev ens8f0 up
sudo ip addr add 10.10.10.201/24 dev ens8f0
sudo arp -s -i ens8f0 10.10.10.212 04:3f:72:a2:b4:3b
