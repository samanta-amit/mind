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

static int repeat = 3;
static pthread_barrier_t s_barrier, e_barrier, rs_barrier;

#define ACCESS_SIZE (1000 * 1000LU)	// 4 KB * 1 million
#define MAX_THREAD_NUM 32			// 4 for LegoOS, but we can do it up to 16
#define PAGE_SIZE 4096LU
#define REPEAT 1
#define MAX_MEM_NODE 4

struct arg_t {
	struct trace_t args;
	int thread_id;
	int total_threads;
	int repeat;
	unsigned long access_size;
	int thread_per_chunk;
	int chunk_per_thread;
	char *data_buf[MAX_MEM_NODE];
};
struct arg_t args[MAX_THREAD_NUM];
pthread_t threads[MAX_THREAD_NUM];
char dummy_src[PAGE_SIZE] = {0xf};

void mem_access_load_func(void *data)
{
	struct arg_t *arg = (struct arg_t *)data;
	unsigned long start_addr = (arg->access_size / arg->thread_per_chunk) * (arg->thread_id % arg->thread_per_chunk);
	unsigned long end_addr = start_addr + (arg->access_size / arg->thread_per_chunk);
	unsigned long addr;
	int i = 0, j = 0;

	printf("Thread[%d]: 0x%lx - 0x%lx\n", arg->thread_id,
		   (unsigned long)arg->args.data_buf + start_addr,
		   (unsigned long)arg->args.data_buf + end_addr);
	pthread_barrier_wait(&s_barrier);
	pthread_barrier_wait(&rs_barrier);
	for (i = 0; i < arg->repeat; i++)
	{
		if (arg->chunk_per_thread == 1)
		{
			for (addr = start_addr; addr < end_addr; addr += PAGE_SIZE)
			{
				// dummy -> buf
				memcpy(arg->args.data_buf + addr, dummy_src, PAGE_SIZE);
				// j++;
				// __sync_synchronize();
			}
		}else{
			for (j = 0; j < arg->chunk_per_thread; j++)
			{
				for (addr = start_addr; addr < end_addr; addr += PAGE_SIZE)
				{
					// dummy -> buf
					memcpy(arg->data_buf[j] + addr, dummy_src, PAGE_SIZE);
					// __sync_synchronize();
				}
			}
		}
	}
	// __sync_synchronize();
	pthread_barrier_wait(&e_barrier);
	printf("Thread[%d]: ended [j:%d]\n", arg->thread_id, j);
}

int main(int argc, char **argv)
{
	int i, j;
	struct timespec start, end;
	double time_taken;
	char *data_ptr[MAX_MEM_NODE] = {0}, *meta_ptr = NULL;
	unsigned long flags = TEST_ALLOC_FLAG;
	int total_thread_num = MAX_THREAD_NUM;
	int repeat = REPEAT;
	int num_node = 1;
	int node_id = 0;
	int num_memory = 1, mem_chunk = 0;
	int mem_chunk_per_node = 1, thread_per_chunk = MAX_THREAD_NUM, chunks_per_thread = 1;
	unsigned long alloc_size = TEST_INIT_ALLOC_SIZE;

	if (argc > 1 && atoi(argv[1]))
	{
		// if it is local
		flags = MAP_PRIVATE|MAP_ANONYMOUS;
	}

	if (argc > 2)
	{
		// if it is local
		total_thread_num = atoi(argv[2]);
	}
	printf("Total threads: %d\n", total_thread_num);

	if (argc > 3)
	{
		repeat = atoi(argv[3]);
	}
	printf("Repeat counter: %d\n", repeat);

	if (argc > 5)
	{
		node_id = atoi(argv[5]);
	}
	printf("Disagg node id: %d\n", node_id);

	if (argc > 6)
	{
		num_memory = atoi(argv[6]);
	}
	printf("Num memory node: %d\n", num_memory);

	if (argc > 4)
	{
		num_node = atoi(argv[4]);
		if (num_node != 4)
		{
			num_node = 1;
		}
	}
	printf("Total disaggregated nodes: %d\n", num_node);

	//reallocate region size
	if (num_node > 1 || (num_memory > 1))
	{
		int total_chunks = TEST_INIT_ALLOC_SIZE / TEST_SUB_REGION_ALLOC_SIZE;
		// we assume those numbers are divided without any remainings
		mem_chunk_per_node = total_chunks / num_node;
		thread_per_chunk = total_thread_num / mem_chunk_per_node;
		if (thread_per_chunk < 1)
			thread_per_chunk = 1;
		// thread number <= 2
		chunks_per_thread = mem_chunk_per_node / total_thread_num;
		if (chunks_per_thread < 1)
			chunks_per_thread = 1;
		//
		alloc_size = TEST_SUB_REGION_ALLOC_SIZE;
	}
	printf("Memory chunk per node/thread: %d/%d, threads per chunk: %d\n",
		   mem_chunk_per_node, chunks_per_thread, thread_per_chunk);

	// Allocate test memory mappings
	meta_ptr = (char *)mmap(NULL, TEST_META_ALLOC_SIZE, PROT_READ | PROT_WRITE, flags, -1, 0);
	if (!meta_ptr || meta_ptr == (void *)-1)
	{
		printf("Error: cannot allocate buffer [0x%lx]\n", (unsigned long)meta_ptr);
		return -1;
	}
	for (i = 0; i < mem_chunk_per_node; i++)
	{
		data_ptr[i] = (char *)mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, flags, -1, 0);
		if (!data_ptr[i] || data_ptr[i] == (void *)-1)
		{
			printf("Error: cannot allocate buffer [0x%lx]\n", (unsigned long)data_ptr[i]);
			return -1;
		}
	}
	printf("Allocated: Meta [0x%llx - 0x%llx], Data [0x%llx - 0x%llx]\n",
		   (unsigned long long)meta_ptr, (unsigned long long)meta_ptr + TEST_META_ALLOC_SIZE,
		   (unsigned long long)data_ptr[0], 
		   (unsigned long long)data_ptr[mem_chunk_per_node - 1] + alloc_size);

	pthread_barrier_init(&s_barrier, NULL, total_thread_num + 1);
	pthread_barrier_init(&e_barrier, NULL, total_thread_num + 1);
	// let threads know all the remote nodes are initialized
	pthread_barrier_init(&rs_barrier, NULL, total_thread_num + 1);

	printf("\n==Start test==\n");
	j = 0;
	for (i = 0; i < total_thread_num; i++)
	{
		args[i].args.meta_buf = meta_ptr;
		args[i].args.data_buf = data_ptr[mem_chunk];
		args[i].args.num_nodes = num_node;
		args[i].args.node_idx = node_id;
		args[i].access_size = alloc_size; // per node access size
		args[i].thread_id = i;
		args[i].total_threads = total_thread_num;
		args[i].repeat = repeat;
		args[i].thread_per_chunk = thread_per_chunk;
		args[i].chunk_per_thread = chunks_per_thread;
		if (++j >= thread_per_chunk)
		{
			j = 0;
			mem_chunk++;
		}
	}

	mem_chunk = 0;
	if (chunks_per_thread > 1)
	{
		for (i = 0; i < total_thread_num; i++)
		{
			for (j = 0; j < chunks_per_thread; j++)
			{
				args[i].data_buf[j] = data_ptr[mem_chunk++];
			}
		}
	}

	for (i = 0; i < total_thread_num; i++)
	{
		if (pthread_create(&threads[i], NULL, (void *)mem_access_load_func, &args[i]))
		{
			printf("Error: cannot creating thread [%d]\n", i);
			return -2;
		}
	}

	// start time
	pthread_barrier_wait(&s_barrier);
	printf("Passed the initialization barrier\n");
	notify_itself(&args[0].args);
	check_other_nodes(&args[0].args, 0);
	pthread_barrier_wait(&rs_barrier);
	clock_gettime(CLOCK_MONOTONIC, &start);

	// end time
	pthread_barrier_wait(&e_barrier);
	clock_gettime(CLOCK_MONOTONIC, &end);
	time_taken = (end.tv_sec - start.tv_sec) * 1e9;
	time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9;
	printf("Done in (%.9lf sec, %.4lf accesses/sec, total incl. remote)\n\n\n",
		   time_taken, (double)(ACCESS_SIZE * repeat) / time_taken);
	printf("Wait 60 sec for the other threads\n");
	sleep(60);
	munmap(meta_ptr, TEST_META_ALLOC_SIZE);
	munmap(data_ptr, alloc_size);
	return 0;
}
