#!/bin/bash
git pull
cd ~/Disaggregated_mem_vLinux && sftp sslee@192.168.122.103:/home/sslee/workspace/Disaggregated_mem_vLinux/vmlinux
gdb vmlinux -ex "target remote :60001"
