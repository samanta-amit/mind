// Test program to allocate new memory

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_THREAD_NUM 80

static int repeat = 3;
static int alloc_size = 32 * 1024 * 1024;	//512 MB of space (4 bytes / int)
static int *ptr = (int *)NULL;
pthread_t threads[MAX_THREAD_NUM];
static pthread_barrier_t s_barrier, e_barrier;

enum {
  arg_local_thread_num = 1
};

int access_memory(int *cur_alloc_size)
{
	struct timespec start, end;
	int i, j;
	double time_taken;
	volatile int buf;
	pthread_barrier_wait(&s_barrier);
	while ((*cur_alloc_size) <= alloc_size)
	{
		for (j = 0; j < repeat; j++)
		{
			clock_gettime(CLOCK_MONOTONIC, &start);
			printf("Test [%d / %d] size=%d KB:\t write..",
				j + 1, repeat, (*cur_alloc_size) / 1024 * (int)sizeof(int));
			for (i = 0; i < (*cur_alloc_size); i++)
			{
				// memcpy(&ptr[i], &i, sizeof(int));
				ptr[i] = i;
			}
			printf("read..");
			for (i = 0; i < (*cur_alloc_size); i++)
			{
				// memcpy(&buf, &(ptr[i]), sizeof(int));
				buf = ptr[i];
				if (buf != i)
				{
					printf("E[%d != %d, %d] at 0x%lx", i, buf, ptr[i], (unsigned long)(&ptr[i]));
					fflush(stdout);
				}
				// barrier();
			}

			clock_gettime(CLOCK_MONOTONIC, &end);
			time_taken = (end.tv_sec - start.tv_sec) * 1e9;
			time_taken = (time_taken + (end.tv_nsec - start.tv_nsec)) * 1e-9;
			printf(" Done in (%.9lf sec, %.4lf million entries/sec)\n",
				   time_taken, (double)(*cur_alloc_size) / time_taken / 1000. / 1000.);
		}
		pthread_barrier_wait(&e_barrier);
		pthread_barrier_wait(&s_barrier);
	}
}

int main(int argc, char **argv)
{
	int i = 0, j = 0;
	int cur_alloc_size = 8*1024;
	int local_thread_num = 1;
	void *b;
	if (argc > arg_local_thread_num)
	{
		// if it is local
		local_thread_num = atoi(argv[arg_local_thread_num]);
	}

	printf("Number of threads: %d\n", local_thread_num);
	printf("Test for int: %d variables\n", alloc_size);
	printf("=i(0x%lx) j(0x%lx) alloc_size(0x%lx)\n",
		   (unsigned long)&i, (unsigned long)&j, (unsigned long)&cur_alloc_size);

	// barrier : this main thread + worker threads (=local_thread_num)
	pthread_barrier_init(&s_barrier, NULL, local_thread_num + 1);
	pthread_barrier_init(&e_barrier, NULL, local_thread_num + 1);

	for (i = 0; i < local_thread_num; i++)
	{
		if (pthread_create(&threads[i], NULL, (void *)access_memory, &cur_alloc_size))
		{
			printf("Error: cannot creating thread [%d]\n", i);
			return -2;
		}
	}

	// Main body to generate threads
	while (cur_alloc_size <= alloc_size)
	{
		ptr = (int *)malloc(cur_alloc_size * sizeof(int));
		pthread_barrier_wait(&s_barrier);
		pthread_barrier_wait(&e_barrier);
		if (ptr)
			free(ptr);
		cur_alloc_size *= 4;

		if(cur_alloc_size < 8 * 1024)
		{
			printf(" Memory corrupted!! allocation size become %d\n", cur_alloc_size);
			break;
		}
	}
	pthread_barrier_wait(&s_barrier);	// last barrier after updating cur_alloc_size 
	printf("Test ends...\n");
	sleep(60);
	printf("Try to join...\n");
	for (i = 0; i < local_thread_num; i++) {
		if (pthread_join(threads[i], &b) != 0) {
			printf("Error: cannot join thread [%d]\n", i);
			return -2;
		}
	}
	return 0;
}
