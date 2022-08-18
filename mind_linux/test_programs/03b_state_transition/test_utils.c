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

int notify_itself(struct trace_t *trace)
{
    if (trace && trace->meta_buf)
    {
        struct metadata_t *meta_ptr = (struct metadata_t *)trace->meta_buf;
        unsigned int node_mask = (1 << (trace->node_idx));
        int i = 0;
        meta_ptr->node_mask |= node_mask;
        printf("Registered myself\n");
        return 0;
    }
    return -1;
}

int check_other_nodes(struct trace_t *trace, int except_me)
{
    if (trace && trace->meta_buf)
    {
        struct metadata_t *meta_ptr = (struct metadata_t *)trace->meta_buf;
        int i = 0;
        int target_num = trace->num_nodes;
        int cur_num = 0;

        if (except_me)
            target_num--; // except me

        while (1)
        {
            cur_num = calc_mask_sum(meta_ptr->node_mask);
            if (cur_num >= target_num)
                break;

            if (i % 20 == 0)
                printf("Still Waiting nodes: %d [0x%x]\n", trace->num_nodes, meta_ptr->node_mask);
            usleep(50 * 1000);	// wait 50 ms
            // sleep(1);
            i++;
        }
        printf("All nodes are initialized: %d [0x%x]\n", trace->num_nodes, meta_ptr->node_mask);
        usleep(10 * 1000);
        return 0;
    }
    return -1;
}

bool TrueOrFalse(double probability, unsigned int* seedp) {
    return (rand_r(seedp) % 100) < probability;
}

double Revise(double orig, int remaining, bool positive) {
    if (positive) {  //false positive
        return (remaining * orig - 1) / remaining;
    } else {  //false negative
        return (remaining * orig + 1) / remaining;
    }
}

int CyclingIncr(int a, int cycle_size) {
    return ++a == cycle_size ? 0 : a;
}



int GetRandom(int min, int max, unsigned int* seedp)
{
    int ret = (rand_r(seedp) % (max - min)) + min;
    return ret;
}

