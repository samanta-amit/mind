# How to run this test program with N nodes
In node 0:

`make run NUM_NODE=N NODE_ID=0 NUM_THREADS=1`

In the last node (id = N-1):

`make run NUM_NODE=N NODE_ID={N-1} NUM_THREADS=1`
