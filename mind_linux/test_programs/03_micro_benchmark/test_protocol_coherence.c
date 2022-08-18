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
#include "test_utils.h"

// #define TEST_ALLOC_FLAG TEST_ALLOC_FLAG	// default: 0xef
// #define TEST_INIT_ALLOC_SIZE TEST_INIT_ALLOC_SIZE // default: 16 GB
// #define TEST_METADATA_SIZE 16
// #define TEST_CACHELINE_SIZE (2*1024*1024)
#define TEST_CACHELINE_SIZE (4*1024)
#define PAGE_SIZE 4096LU

// Test configuration
// #define single_thread_test
// #define meta_data_test

static char dummy_src[PAGE_SIZE] = {0xf};
static struct trace_t arg;

// 1: I->S or M (same in latency), 2: S->S, 3: M->M, 4: S->M
enum
{
	mode_idle_to_shared = 1,
	mode_shared_to_shared = 2,
	mode_modified_to_modified = 3,
	mode_shared_to_modified = 4,
	mode_total = 5,
};

enum
{
	direction_read = 1,
	direction_write = 2,
	direction_read_then_write = 3,
};

void access_func(struct trace_t *trace, int direction)
{
	unsigned long offset = 0;
	unsigned long end = trace->num_cache_line * TEST_CACHELINE_SIZE;
	// unsigned long end = 100 * TEST_CACHELINE_SIZE;
	if (!trace->is_main)
	{
		//prepare shared directories
		for (offset = 0; offset < end; offset += TEST_CACHELINE_SIZE)
		{
			if (direction == direction_read || direction == direction_read_then_write)
				memcpy(dummy_src, trace->data_buf + offset, PAGE_SIZE);
			else if (direction == direction_write)
				memcpy(trace->data_buf + offset, dummy_src, PAGE_SIZE);
		}
		// let main thread know that we finished to set up cacheline
		notify_itself(trace);
		check_other_nodes(trace, 0);
	}
	else
	{
		// wait the non-main nodes
		// if (is_main_wait_others)
		// 	check_other_nodes(trace, 1);
		for (offset = 0; offset < end; offset += TEST_CACHELINE_SIZE)
		{
			if (direction == direction_read)
				memcpy(dummy_src, trace->data_buf + offset, PAGE_SIZE);
			else if (direction == direction_write || direction == direction_read_then_write)
				memcpy(trace->data_buf + offset, dummy_src, PAGE_SIZE);
		}
		// notify_itself(trace);
	}
}

void func(void *arg)
{
	struct trace_t *trace = (struct trace_t*)arg;
	int i;

	// main test loop
	switch (trace->test_mode)
	{
	case mode_idle_to_shared:
		if (trace->is_main)
		{
			for (i = 0; i < trace->num_cache_line; i++)
			{
				// write
				memcpy(trace->data_buf + (i * TEST_CACHELINE_SIZE), dummy_src, PAGE_SIZE);
			}
		}
		break;
	case mode_shared_to_shared:
		access_func(trace, direction_read);
		break;
	case mode_modified_to_modified:
		access_func(trace, direction_write);
		break;
	case mode_shared_to_modified:
		access_func(trace, direction_read_then_write);
		break;

	default:
		break;
	}
	printf("Counting 5 sec before exit...\n");
	sleep(5);
}

enum
{
	arg_num_node = 1,
	arg_node_id = 2,
	arg_is_main = 3,
	arg_mode = 4,
	arg_num_cache = 5,
	// We will need more than two nodes for test mode 1~3
	arg_total = 6,
};

int main(int argc, char **argv)
{
	
	// const int ALLOC_SIZE = 9999 * 4096;
	//starts from few pages, dense access
	int num_nodes;
	int node_id = 0;
	int is_main = 0;
	int test_mode = 0;
	int num_cache = 1023;
	int ret;
	unsigned long flags = TEST_ALLOC_FLAG;
	char *buf_test = NULL;
	if (argc != arg_total)
	{
		fprintf(stderr, "Incomplete args\n");
		return 1;
	}
	num_nodes = atoi(argv[arg_num_node]);
	node_id = atoi(argv[arg_node_id]);
	is_main = atoi(argv[arg_is_main]);
	test_mode = atoi(argv[arg_mode]);
	num_cache = atoi(argv[arg_num_cache]);

	// ====== NOTE ===== 
	// If we make access to the memory ranges other than this size with TEST_ALLOC_FLAG flag, 
	// it will generate segmentation fault
	// =================
	arg.node_idx = node_id;
	arg.num_nodes = num_nodes;
	arg.is_main = is_main;
	arg.test_mode = test_mode;
	arg.num_cache_line = num_cache;
	arg.meta_buf = (char *)mmap(NULL, TEST_INIT_ALLOC_SIZE, PROT_READ | PROT_WRITE, TEST_ALLOC_FLAG, -1, 0);
	arg.data_buf = arg.meta_buf + TEST_CACHELINE_SIZE;	// from the second cacheline
	if (!arg.meta_buf || arg.meta_buf == (void *)-1)
	{
		printf("Error: cannot allocate buffer [0x%lx]\n", (unsigned long)arg.meta_buf);
		return -1;
	}
	printf("Allocated: [0x%llx - 0x%llx]\n", (unsigned long long)arg.meta_buf, (unsigned long long)arg.meta_buf + TEST_INIT_ALLOC_SIZE);
	//
	printf("Node[ID: %d / Tot: %d] Mode[%d]: Let's start test\n", node_id, num_nodes, test_mode);
	if (!is_main)
	{
		printf("Initial wait for 10 sec...\n");
		sleep(10);
	}

	func(&arg);

	printf("Test ended\n");
	munmap(arg.meta_buf, TEST_INIT_ALLOC_SIZE);
	return 0;
}
