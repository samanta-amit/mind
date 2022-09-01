#ifndef __TEST_UTILS_H__
#define __TEST_UTILS_H__

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

#endif
