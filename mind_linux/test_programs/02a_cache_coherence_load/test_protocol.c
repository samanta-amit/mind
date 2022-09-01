// Test program to allocate new memory

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#include "../../include/disagg/config.h"

// #define TEST_ALLOC_FLAG TEST_ALLOC_FLAG	// default: 0xef
// #define TEST_INIT_ALLOC_SIZE TEST_INIT_ALLOC_SIZE // default: 16 GB
// #define TEST_METADATA_SIZE 16
#define TEST_SLEEP_PERIOD 10000000
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif
#define MAX_NUM_THREAD 32
#define MAX_NUM_NODES 16

// Test configuration
// #define single_thread_test
#define meta_data_test

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
	int num_threads;
	int test_mode;
};
struct trace_t args[MAX_NUM_THREAD];

struct metadata_t {
	// unsigned int node_mask;
	unsigned int node_mask[MAX_NUM_NODES];
	unsigned int fini_node_pass[MAX_NUM_NODES];
};

enum
{
	test_mode_one_page = 1,
	test_mode_near_page = 2,		// near page over thread, thread having same id will access same page
	test_mode_near_diff_page = 3,	// near page over thread and node, no one will access the same page
	test_mode_far_page = 4, 		// NOTE: still withint a cache directory size
	test_mode_multi_cacheline = 5,
};

// int first;
int num_nodes = 1;
int node_id = -1;
int num_threads = 1;

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

static pthread_barrier_t s_barrier;
static int phase = 0;
#if 0
static int sync_nodes(struct trace_t *trace)
{
	if (trace && trace->meta_buf)
	{
		struct metadata_t *meta_ptr = (struct metadata_t *)trace->meta_buf;
		// write itself
		unsigned int node_mask = (1 << (trace->node_idx));
		if (!phase) // 0 -> 1
			meta_ptr->node_mask |= node_mask;
		else // 1 -> 0
			meta_ptr->node_mask &= (~node_mask);

		// check nodes
		int i = 0;
		while ((!phase && calc_mask_sum(meta_ptr->node_mask) < trace->num_nodes) || (phase && calc_mask_sum(meta_ptr->node_mask) > 0))
		{
			if (i % 200 == 0)
				printf("Waiting nodes: %d [p:%d][0x%x]\n", trace->num_nodes, phase, meta_ptr->node_mask);
// #ifdef meta_data_test
// 			meta_ptr->node_mask |= (1 << (trace->node_idx)); // TEST PURPOSE ONLY
// #endif
			// if (!phase && !(meta_ptr->node_mask & node_mask))
			// 	meta_ptr->node_mask |= node_mask;
			usleep(10000); // wait
			i++;
		}
		printf("All nodes are initialized: %d [0x%x]\n", trace->num_nodes, meta_ptr->node_mask);
		phase = !phase;
		return 0;
	}
	return -1;
}
#endif

// static bool check_ready_nodes(struct metadata_t *meta_ptr, int should_zero)
static unsigned long pass = 0;
static int check_ready_nodes(struct metadata_t *meta_ptr, int cur_pass)
{
	// bool all_done = true;
	int done_cnt = 0;
	for (int j = 0; j < MAX_NUM_NODES; ++j)
	{
		// if ((!should_zero && (meta_ptr->node_mask[j] == 0))
		// 	|| (should_zero && (meta_ptr->node_mask[j] != 0)))
		if (meta_ptr->node_mask[j] <= cur_pass)
		{
			// all_done = false;
			// break;
		}else{
			done_cnt ++;
		}
	}
	// return all_done;
	return (done_cnt >= num_nodes ? 1 : 0);
}

int sync_nodes(struct trace_t *trace)
{
	if(trace && trace->meta_buf)
	{
		struct metadata_t *meta_ptr = (struct metadata_t *)trace->meta_buf;
		// write itself
		if (trace->master_thread)
		{
			printf("Start pass [%lu]\n", pass);
			meta_ptr->node_mask[trace->node_idx] = pass + 1;
			// check nodes
			// int i = 0;
			while (!check_ready_nodes(meta_ptr, pass))
			{
				// if (i % 100 == 0)
				// {
				// 	char node_bits[256] = "";
				// 	for (int j = 0; j < MAX_NUM_NODES; ++j)
				// 		sprintf(node_bits, "%s[%u]", node_bits, meta_ptr->node_mask[j]);
				// 	printf("Waiting nodes [%03d]: %d [pass:%lu -> %u] || [%s]\n",
				// 		   (i / 100) % 100, trace->num_nodes, pass, meta_ptr->node_mask[trace->node_idx], node_bits);
				// }
				// usleep(10000);
				// i++;
			}
			printf("All nodes are initialized: %d [%u]\n", trace->num_nodes, meta_ptr->node_mask[trace->node_idx]);
			usleep(10000);
			phase = !phase;
			// pthread_barrier_wait(&s_barrier);
			// fprintf(stderr, "Start pass [%lu] after barrier\n", pass);
			return 0;
		}else{
			// pthread_barrier_wait(&s_barrier);
			return 0;
		}
	}
	return -1;
}

static char dummy_char = 0xfe;
void load_test_fnc(void *arg)
{
	struct trace_t *trace = (struct trace_t*) arg;
	int j = 0;
	unsigned long i = 0, off_page = 0;
	pthread_barrier_wait(&s_barrier);

#ifdef meta_data_test
	while(1){sync_nodes(trace); pass++;}
#endif

	// access the same page in write mode
	switch (trace->test_mode)
	{
	case test_mode_one_page:
		for (i = 0; i < TEST_SLEEP_PERIOD; i++)
		{
			for (j = 0; j < PAGE_SIZE; j++)
				trace->data_buf[0] = dummy_char;
			if (i % (TEST_SLEEP_PERIOD / 100) == 0)
				printf("Thread[%d]: passed %lu\n", trace->thread_id, i);
		}
		break;
	case test_mode_near_page:
	case test_mode_near_diff_page:
		off_page = PAGE_SIZE * trace->thread_id;
		if (trace->test_mode == test_mode_near_diff_page)
		{
			off_page += (PAGE_SIZE * trace->num_threads * trace->node_idx);
		}
		for (i = 0; i < TEST_SLEEP_PERIOD; i++)
		{
			for (j = 0; j < PAGE_SIZE; j++)
				trace->data_buf[off_page + j] = dummy_char;
			if (i % (TEST_SLEEP_PERIOD / 100) == 0)
				printf("Thread[%d]: passed %lu\n", trace->thread_id, i);
		}
		break;

	default:
		printf("No test was chosen, skip...\n");
	}
	pthread_barrier_wait(&s_barrier);
	return ;
}

enum
{
	arg_node_id = 1,
	arg_num_node = 2,
	arg_thread_num = 3,
	arg_test_mode = 4,
	arg_total = 5,
};

int main(int argc, char **argv)
{
	// const int ALLOC_SIZE = 9999 * 4096;
	//starts from few pages, dense access
    int ret, test_mode;
	char *buf_test = NULL;
	pthread_t run_thread[MAX_NUM_THREAD];
	if (argc != arg_total)
	{
		fprintf(stderr, "Incomplete args\n");
		return 1;
	}
	node_id = atoi(argv[arg_node_id]);
	num_nodes = atoi(argv[arg_num_node]);
	num_threads = atoi(argv[arg_thread_num]);
	test_mode = atoi(argv[arg_test_mode]);
#ifdef meta_data_test
	num_threads = 1;	// only the major thread
#endif
	printf("Node[%d] #Thread[%d]: prepare test...\n", node_id, num_threads);
	pthread_barrier_init(&s_barrier, NULL, num_threads + 1);

	// ======== memory mapping =========
	char *meta_buf = (char *)mmap(NULL, TEST_META_ALLOC_SIZE, PROT_READ | PROT_WRITE, TEST_ALLOC_FLAG, -1, 0);
	if (!meta_buf || meta_buf == (void *)-1)
	{
		printf("Error: cannot allocate buffer [0x%lx]\n", (unsigned long)meta_buf);
		return -1;
	}

	char *data_buf = (char *)mmap(NULL, TEST_MACRO_ALLOC_SIZE, PROT_READ | PROT_WRITE, TEST_ALLOC_FLAG, -1, 0);
	if (!data_buf || data_buf == (void *)-1)
	{
		printf("Error: cannot allocate buffer [0x%lx]\n", (unsigned long)data_buf);
		return -1;
	}
	printf("protocol testing buf addr is: %p\n", data_buf);
	printf("Allocated: Meta [0x%llx - 0x%llx], Data [0x%llx - 0x%llx]\n",
		   (unsigned long long)meta_buf, (unsigned long long)meta_buf + TEST_META_ALLOC_SIZE,
		   (unsigned long long)data_buf, (unsigned long long)data_buf + TEST_MACRO_ALLOC_SIZE);
	// =================

	// set up args
	for (int i = 0; i < num_threads; ++i)
	{
		args[i].node_idx = node_id;
		args[i].meta_buf = meta_buf;
		args[i].data_buf = data_buf;
		args[i].num_nodes = num_nodes;
		args[i].master_thread = (i == 0);
		args[i].thread_id = i;
		args[i].test_mode = test_mode;
		args[i].num_threads = num_threads;
	}

	// launch threads
	for (int i = 0; i < num_threads; ++i)
	{
		if (pthread_create(&run_thread[i], NULL, (void *(*)(void *))load_test_fnc, &args[i]))
		{
			printf("Error creating runner thread %d\n", i);
			return 1;
		}
	}

	if (sync_nodes(&args[0]))
	{
		fprintf(stderr, "Initialization error!\n");
		return -1;
	}
	pthread_barrier_wait(&s_barrier);
	printf("Barrier[start] passed\n");


	//Sync termination
	pthread_barrier_wait(&s_barrier);
	printf("Barrier[end] passed\n");
	sync_nodes(&args[0]);

	// join runner threads
	for (int i = 0; i < num_threads; ++i)
	{
		if (pthread_join(run_thread[i], NULL))
		{
			printf("Error joining thread %d\n", i);
			return 2;
		}
	}
	printf("Test complete... terminate after 10 seconds..\n");
	sleep(10);
	return 0;
}
