#!/bin/bash
sudo mst start
# echo 4 | sudo tee /sys/class/infiniband/mlx5_2/device/mlx5_num_vfs
#
# echo 0000:25:00.2 | sudo tee /sys/bus/pci/drivers/mlx5_core/unbind 
# echo 0000:25:00.3 | sudo tee /sys/bus/pci/drivers/mlx5_core/unbind 
# echo 0000:25:00.4 | sudo tee /sys/bus/pci/drivers/mlx5_core/unbind 
# echo 0000:25:00.5 | sudo tee /sys/bus/pci/drivers/mlx5_core/unbind 
#
# sudo ip link set dev enp37s0f0 vf 0 mac 00:22:aa:44:66:01
# sudo ip link set dev enp37s0f0 vf 1 mac 00:22:aa:44:66:02
# sudo ip link set dev enp37s0f0 vf 2 mac 00:22:aa:44:66:03
# sudo ip link set dev enp37s0f0 vf 3 mac 00:22:aa:44:66:04
#
# echo 0000:25:00.2 | sudo tee /sys/bus/pci/drivers/mlx5_core/bind 
# echo 0000:25:00.3 | sudo tee /sys/bus/pci/drivers/mlx5_core/bind 
# echo 0000:25:00.4 | sudo tee /sys/bus/pci/drivers/mlx5_core/bind 
# echo 0000:25:00.5 | sudo tee /sys/bus/pci/drivers/mlx5_core/bind 
#
ip link show
