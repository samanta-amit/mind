#include <sys/syscall.h>
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int num_container_threads;

static int pin_to_core(int tid, int core_id) {
    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (core_id < 0 || core_id >= num_cores) {
        printf("pin to core[%d] failed, total cores[%d]\n", core_id, num_cores);
        return -1;
    }
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_t current_thread = pthread_self();
    int err = pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
    printf("thread %d pin to core %d ret[%d]\n", tid, core_id, err);
    usleep(10000);
    return err;
}

static void accept_remote_thread_request(void *arg) {
    int tid = *(int *)arg;
    pin_to_core(tid, tid);
    syscall(548, tid, num_container_threads);
} 

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("please enter number of container threads\n");
        return -1;
    }
    num_container_threads = atoi(argv[1]);

    //init TCP conn only
    if (num_container_threads == 0)
        return syscall(548, 0, 0);

    pthread_t *container_threads = new pthread_t[num_container_threads - 1];
    int *tids = new int[num_container_threads - 1];
    int i = 0;
    for (; i < num_container_threads - 1; ++i) {
        tids[i] = i;
        pthread_create(&container_threads[i], NULL,
            (void *(*)(void *))accept_remote_thread_request, (void *)(&tids[i]));
    }
    accept_remote_thread_request((void *)&i);
    return 0;
}
