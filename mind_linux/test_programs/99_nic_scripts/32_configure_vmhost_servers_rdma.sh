#!/bin/bash
sudo mst start
ip link show
# disable ICRC check
sudo mcra mlx5_0 0x5361c.12:1 0
sudo mcra mlx5_0 0x5363c.12:1 0
sudo mcra mlx5_1 0x5361c.12:1 0
sudo mcra mlx5_1 0x5363c.12:1 0
# pfc
sudo mlnx_qos -i ens8f0 --trust dscp
sudo mlnx_qos -i ens8f0 --pfc 0,0,0,1,0,0,0,0
sudo mlnx_qos -i ens8f1 --trust dscp
sudo mlnx_qos -i ens8f1 --pfc 0,0,0,1,0,0,0,0
# performance
i=0
while [ $i -ne 48 ]
do
	echo performance | sudo tee /sys/devices/system/cpu/cpu$i/cpufreq/scaling_governor
	i=$(($i+1))
done
