#!/bin/bash
sudo iptables -I FORWARD 1 -o virbr0 -d 192.168.122.101 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
sudo iptables -I FORWARD 2 -o virbr0 -d 192.168.122.102 -m state --state NEW,RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -A PREROUTING -p tcp -i eno4 --dport 20024 -j DNAT --to-destination 192.168.122.101:22
sudo iptables -t nat -A PREROUTING -p tcp -i eno4 --dport 20023 -j DNAT --to-destination 192.168.122.102:22
# port number: 20024 for 122.101, 20023 for 122.102, 20022 for 122.201 (switch VM)
