// Test program to allocate new memory
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sched.h>
#include "../../include/disagg/config.h"

// === Now the following configurations are placed in ../../include/disagg/config.h ===/
// #define TEST_ALLOC_FLAG TEST_ALLOC_FLAG	// default: 0xef
// #define TEST_INIT_ALLOC_SIZE TEST_INIT_ALLOC_SIZE // default: 16 GB

#define PAGE_SIZE 4096UL
#define NUM_THREAD 2
#define MEM_SIZE_MAX (1024*1024*128)

const int _num_iternation = 20;

// Test configuration
// #define single_thread_test
static pthread_barrier_t i_barrier, s_barrier, e_barrier;	// init, start, end

struct trace_t {
	char *access_type;
	unsigned long *addr;
	char *val;
	unsigned long len;
	char *meta_buf;
	char *data_buf;
	int node_idx;
	int num_nodes;
	int master_thread;
	int thread_id;
};
struct trace_t trace_arg[NUM_THREAD];

struct metadata_t {
	unsigned int node_mask;
};

// int first;
int num_nodes;
int node_id = -1;

static int calc_mask_sum(unsigned int mask)
{
	int sum = 0;
	while (mask > 0)
	{
		if (mask & 0x1)
			sum++;
		mask >>= 1;
	}
	return sum;
}

#if 0
int init(struct trace_t *trace)
{
	if(trace && trace->meta_buf)
	{
		struct metadata_t *meta_ptr = (struct metadata_t *)trace->meta_buf;
		// write itself
		if (trace->master_thread)
		{
			unsigned int node_mask = (1 << (trace->node_idx));
			meta_ptr->node_mask |= node_mask;
		}
		// check nodes
		int i = 0;
		while (calc_mask_sum(meta_ptr->node_mask) < trace->num_nodes)
		{
			if (i % 100 == 0)
				printf("Waiting nodes: %d [0x%x]\n", trace->num_nodes, meta_ptr->node_mask);
#ifdef meta_data_test
			meta_ptr->node_mask |= (1 << (trace->node_idx));	// TEST PURPOSE ONLY
#endif
			usleep(20 * 1000);	// wait 20 ms
			i++;
		}
		printf("All nodes are initialized: %d [0x%x]\n", trace->num_nodes, meta_ptr->node_mask);
		return 0;
	}
	return -1;
}
#endif

int pin_to_core(int core_id)
{
    int num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (core_id < 0 || core_id >= num_cores)
        return -1;

    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);

    pthread_t current_thread = pthread_self();
    return pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);
}

void func(void *arg)
{
	struct trace_t *trace = (struct trace_t*) arg;
	int i;
	// warming up cache
	volatile char dummy_val = 0;
	for (i = 0; i < _num_iternation; i++)
	{
		pthread_barrier_wait(&i_barrier);
		// move data to local DRAM cache
		for (int i = 0; i < trace->len; ++i) {
			dummy_val = trace->data_buf[trace->addr[i]];
			trace->data_buf[trace->addr[i]] = dummy_val;
			dummy_val = trace->val[i];
			trace->val[i] = dummy_val;
		}
		pthread_barrier_wait(&s_barrier);
		for (int i = 0; i < trace->len; ++i) {
			if (trace->access_type[i] == 'r') {
				trace->val[i] = trace->data_buf[trace->addr[i]];
			} else if(trace->access_type[i] == 'w') {
				trace->data_buf[trace->addr[i]] = trace->val[i];
			} else {
				printf("unexpected access type\n");
			}
			if (i % 100000 == 0)
				printf("%d\n", i);
		}
		pthread_barrier_wait(&e_barrier);
	}
	// printf("Counting 30 sec before exit...\n");
	// sleep(30);
}

int load_trace(char *trace_name, struct trace_t *arg) {
	FILE *fp;
	fp = fopen(trace_name, "r");
	if (!fp) {
		printf("fail to open trace file\n");
		return -1;
	}

	fscanf(fp, "%lu\n", &arg->len);
	printf("trace len is: %lu\n", arg->len);
	// clean up there was previous mapping
	if (arg->access_type)
	{
		free(arg->access_type);
		arg->access_type = NULL;
	}

	if (arg->addr)
	{
		free(arg->addr);
		arg->addr = NULL;
	}

	if (arg->val)
	{
		free(arg->val);
		arg->val = NULL;
	}

	arg->access_type = (char *)malloc(sizeof(char) * arg->len);
	arg->addr = (unsigned long *)malloc(sizeof(unsigned long) * arg->len);
	arg->val = (char *)malloc(sizeof(char) * arg->len);

	for (int i = 0; i < arg->len; ++i) {
		fscanf(fp, "%c %lu %hhu\n", &arg->access_type[i], &arg->addr[i], &arg->val[i]);
	}
	return 0;
}

void print_res(char *trace_name, struct trace_t *trace, int iter) {
	FILE *fp;
	char trace_full_name[256] = {0};
	sprintf(trace_full_name, "%s_%03d", trace_name, iter);
	fp = fopen(trace_full_name, "w");
	if (!fp) {
		printf("fail to open res file\n");
		return;
	}

	for (int i = 0; i < trace->len; ++i) {
		fprintf(fp, "%c %lu %hhu\n", trace->access_type[i], trace->addr[i], trace->val[i]);
	}
	fclose(fp);
}

enum
{
	arg_trace_1 = 1,
	arg_trace_2 = 2,
	arg_res_1 = 3,
	arg_res_2 = 4,
	arg_node_cnt = 5,
	arg_node_id = 6,
	arg_total = 7,
};

int main(int argc, char **argv)
{
    int ret, i;
	pthread_t thread[NUM_THREAD];

	if (argc != arg_total)
	{
		fprintf(stderr, "Incomplete args\n");
		return 1;
	}
	// num_nodes = atoi(argv[arg_node_cnt]);
	// node_id = atoi(argv[arg_node_id]);
	// printf("Node[%d]: loading trace...\n", node_id);
	pthread_barrier_init(&i_barrier, NULL, NUM_THREAD + 1);
	pthread_barrier_init(&s_barrier, NULL, NUM_THREAD + 1);
	pthread_barrier_init(&e_barrier, NULL, NUM_THREAD + 1);

	// ====== NOTE ===== 
	// This program should be run on target application mode
	// If we make access to the memory ranges other than this size with TEST_ALLOC_FLAG flag, 
	// it will generate segmentation fault since TEST_ALLOC_FLAG is not allowed for general mmap calls
	// =================
	trace_arg[0].node_idx = trace_arg[1].node_idx = node_id;
	trace_arg[0].num_nodes = trace_arg[1].num_nodes = num_nodes;
	trace_arg[0].master_thread = 1;
	trace_arg[0].thread_id = 0;
	trace_arg[1].master_thread = 0;
	trace_arg[1].thread_id = 1;
	// init ptr
	trace_arg[0].access_type = trace_arg[1].access_type = NULL;
	trace_arg[0].addr = trace_arg[1].addr = NULL;
	trace_arg[0].val = trace_arg[1].val = NULL;
	trace_arg[0].meta_buf = trace_arg[1].meta_buf = NULL;
	trace_arg[0].data_buf = trace_arg[1].data_buf = NULL;
	printf("protocol testing buf addr is: %p\n", trace_arg[0].meta_buf);

	printf("running trace...\n");
	for (i = 0; i < NUM_THREAD; i++)
	{
		if (pthread_create(&thread[i], NULL, (void *)func, &trace_arg[i]))
		{
			printf("Error creating thread [%d]\n", i);
			return 1;
		}
	}

	for (i=0; i<_num_iternation; i++)
	{
		if (trace_arg[0].data_buf)
		{
			free(trace_arg[0].data_buf);
			trace_arg[0].data_buf = trace_arg[1].data_buf = NULL;	
		}
		trace_arg[0].data_buf = trace_arg[1].data_buf = (char *)malloc(MEM_SIZE_MAX * sizeof(int));
		ret = load_trace(argv[arg_trace_1], &trace_arg[0]);
		if (ret) {
			printf("fail to load trace\n");
			return 1;
		}

		ret = load_trace(argv[arg_trace_2], &trace_arg[1]);
		if (ret) {
			printf("fail to load trace\n");
			return 1;
		}
		pthread_barrier_wait(&i_barrier);
		pthread_barrier_wait(&s_barrier);
		pthread_barrier_wait(&e_barrier);
		print_res(argv[arg_res_1], &trace_arg[0], i);
		print_res(argv[arg_res_2], &trace_arg[1], i);
	}

	printf("Counting 30 sec before joining...\n");
	sleep(30);
	for (i = 0; i < NUM_THREAD; i++)
	{
		if (pthread_join(thread[i], NULL))
		{
			printf("Error joining thread [%d]\n", i);
			return 2;
		}
	}
	sleep(10);	// give some time for remote blades
	return 0;
}
