#ifndef __MN_REQUEST_HANDLER_H__
#define __MN_REQUEST_HANDLER_H__

#include <linux/hash.h>
#include <linux/mm_types.h>
#include <linux/sched/mm.h>
#include <linux/sched.h>
#include <linux/types.h>
#include "file_handler.h"

#define MAX_NUMBER_COMPUTE_NODE 32
#define MN_PID_HASH_BIT         8

struct unique_tgid_node
{
    u32                 utgid;
    struct task_struct  *tsk;
    struct list_head    node;
    int                 ref;        //if it brecome 0, it should be freed

    //DEBUG
    struct file_info finfo;
};

struct node_tgid_hash
{
    u16 node_id;
    u16 tgid;
    struct unique_tgid_node *utgid_node;
    struct hlist_node node;
};

struct task_struct *mn_get_task(u16 sender_id, u16 tgid);
struct task_struct *mn_get_task_by_utgid(u32 utgid);
struct file_info *mn_get_file(u16 sender_id, u16 tgid);

int mn_insert_new_task_mm(u16 sender_id, u16 tgid, struct task_struct* tsk);
int mn_link_to_task_mm(u16 sender_id, u16 tgid, u32 utgid);

// prototype: may be not needed
struct socket;

// main functions for handling requests
int handle_fork(struct mem_header* hdr, void* payload, struct socket *sk, int id);
int handle_exec(struct mem_header* hdr, void* payload);
int handle_exit(struct mem_header* hdr, void* payload, struct socket *sk, int id);
int handle_mmap(struct mem_header* hdr, void* payload, struct socket *sk, int id);
int handle_brk(struct mem_header* hdr, void* payload, struct socket *sk, int id);
int handle_munmap(struct mem_header* hdr, void* payload, struct socket *sk, int id);
int handle_mremap(struct mem_header* hdr, void* payload, struct socket *sk, int id);

int handle_data(struct mem_header* hdr, void* payload);
int handle_pfault(struct mem_header* hdr, void* payload, struct socket *sk, int id);

// RDMA version of main functions for handling requests
int handle_rdma_init(struct mem_header *hdr, void *payload, struct socket *sk, int id);

struct thpool_buffer;
int handle_fork_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb);
int handle_exec_rdma(struct common_header* chdr, void* payload);
int handle_exit_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb);
int handle_mmap_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb);
int handle_brk_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb);
int handle_munmap_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb);
int handle_mremap_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb);


int handle_pfault_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb);
int handle_data_rdma(struct common_header* chdr, void* payload);
int handle_check_rdma(struct common_header* chdr, void* payload);


//debug
int handle_check(struct mem_header* hdr, void* payload);
#endif
