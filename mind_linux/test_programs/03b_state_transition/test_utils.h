#ifndef __TEST_UTILS_H__
#define __TEST_UTILS_H__
#include <stdbool.h>

struct trace_t
{
    // char *access_type;
    // unsigned long *addr;
    // char *val;
    unsigned long num_cache_line;
    char *meta_buf;
    char *data_buf;
    int node_idx;
    int num_nodes;
    int is_main;
    int test_mode;
};

struct metadata_t
{
    unsigned int node_mask;
};

int notify_itself(struct trace_t *trace);
int check_other_nodes(struct trace_t *trace, int is_main);
bool TrueOrFalse(double probability, unsigned int* seedp);
double Revise(double orig, int remaining, bool positive);
int CyclingIncr(int a, int cycle_size);
int GetRandom(int min, int max, unsigned int* seedp);

#endif

