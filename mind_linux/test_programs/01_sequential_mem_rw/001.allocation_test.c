// Test program to allocate new memory

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static int repeat = 3;
static int alloc_size = 128 * 1024 * 1024;	//512 MB of space

int main(int argc, char **argv)
{
	int *ptr = NULL;
	int i = 0, j = 0;
	volatile int buf;
	struct timespec start, end;
	double time_taken;
	int cur_alloc_size = 8*1024;

	printf("Test for int: %d variables\n", alloc_size);
	printf("=i(0x%lx) j(0x%lx) buf(0x%lx) alloc_size(0x%lx)\n",
		   (unsigned long)&i, (unsigned long)&j, (unsigned long)&buf, 
		   (unsigned long)&cur_alloc_size);
	while(cur_alloc_size <= alloc_size)
	{
		ptr = (int *)malloc(cur_alloc_size * sizeof(int));
		for (j = 0; j < repeat; j++)
		{
			clock_gettime(CLOCK_MONOTONIC, &start);
			printf("Test [%d / %d] size=%d KB:\t write..", 
					j + 1, repeat, cur_alloc_size / 1024 * (int)sizeof(int));
			for (i = 0; i < cur_alloc_size; i++)
			{
				// memcpy(&ptr[i], &i, sizeof(int));
				ptr[i] = i;
			}

			printf(" read..");

			for (i = 0; i < cur_alloc_size; i++)
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
			printf(" Done in (%.9lf sec, %.4lf entries/sec)\n", 
					time_taken, (double)cur_alloc_size / time_taken);
		}
		if (ptr)
			free(ptr);
		cur_alloc_size *= 2;

		if(cur_alloc_size < 8 * 1024)
		{
			printf(" Memory corrupted!! allocation size become %d\n", cur_alloc_size);
			break;
		}
	}

	return 0;
}
