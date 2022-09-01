nthreads=$1

# make test_multithreading
# make test_lock
make disagg_container
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
./disagg_container $nthreads
