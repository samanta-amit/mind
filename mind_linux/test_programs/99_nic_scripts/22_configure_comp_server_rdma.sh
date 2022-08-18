#!/bin/bash
# disable ICRC check
sudo mcra mlx5_0 0x5361c.12:1 0
sudo mcra mlx5_0 0x5363c.12:1 0
sudo mcra mlx5_1 0x5361c.12:1 0
sudo mcra mlx5_1 0x5363c.12:1 0
sudo mcra mlx5_2 0x5361c.12:1 0
sudo mcra mlx5_2 0x5363c.12:1 0
sudo mcra mlx5_3 0x5361c.12:1 0
sudo mcra mlx5_3 0x5363c.12:1 0
sudo mcra mlx5_4 0x5361c.12:1 0
sudo mcra mlx5_4 0x5363c.12:1 0
sudo mcra mlx5_5 0x5361c.12:1 0
sudo mcra mlx5_5 0x5363c.12:1 0
# pfc
sudo mlnx_qos -i enp37s0 --trust dscp
sudo mlnx_qos -i enp37s0 --pfc 0,0,0,1,0,0,0,0
sudo mlnx_qos -i enp69s0 --trust dscp
sudo mlnx_qos -i enp69s0 --pfc 0,0,0,1,0,0,0,0
sudo mlnx_qos -i enp23s0f0 --trust dscp
sudo mlnx_qos -i enp23s0f0 --trust dscp
sudo mlnx_qos -i enp23s0f1 --pfc 0,0,0,1,0,0,0,0
sudo mlnx_qos -i enp23s0f1 --trust dscp
sudo mlnx_qos -i enp89s0f0 --pfc 0,0,0,1,0,0,0,0
sudo mlnx_qos -i enp89s0f0 --pfc 0,0,0,1,0,0,0,0
sudo mlnx_qos -i enp89s0f1 --trust dscp
sudo mlnx_qos -i enp89s0f1 --pfc 0,0,0,1,0,0,0,0
