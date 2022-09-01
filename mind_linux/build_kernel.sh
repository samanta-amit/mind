#!/bin/bash
echo "Remove kernel logs"
sudo rm /var/log/kern.log
sudo rm /var/log/syslog
echo "Remoce cache"
sudo rm .cache.mk
echo "Start"
#git checkout DEV_multithread_merged
#git pull origin DEV_multithread_merged
taskset --cpu-list 0-11 make bzImage -j23 && sudo make install
#sudo reboot
