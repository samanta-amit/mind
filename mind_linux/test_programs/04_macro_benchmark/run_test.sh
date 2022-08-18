#1: workload either tensorflow or voltdb
#2: num nodes
#3: node id
#4: num log files
#5~#8: log file id

PRE=/home/yanpeng/2020_11_25_$1/partitioned/$1_
SUF=_0

g++ test_program.cpp -O2 -g -o test_program -lpthread

./test_program $2 $3 $4 ${PRE}${5}${SUF} ${PRE}${6}${SUF} ${PRE}${7}${SUF} ${PRE}${8}${SUF}
