#ifndef __FUTEX_DISAGGREGATION_H__
#define __FUTEX_DISAGGREGATION_H__

//#include <linux/hashtable.h>
//#include <linux/wait.h>

#define TIMEOUT_JIFFY 1
#define MAX_FUTEX_QUEUE_BIT 3
#define MAX_FUTEX_THREAD_PER_BLADE 3
#define COND_WAIT 0
#define COND_WAKE 1
#define COND_WAIT_BITSET 9
#define COND_WAKE_BITSET 10


#define MEMORY_HEADER_ALIGNMENT 8
struct mem_header {
        unsigned int opcode;         // type of payload / message
        unsigned int sender_id;      // id of the sender node
} __attribute__((aligned (MEMORY_HEADER_ALIGNMENT)));
/*
struct pidq_entry {
	unsigned int pid;
	struct list_head node;
};

struct futex_hnode {
	unsigned int tgid;
	unsigned long uaddr;
	wait_queue_head_t wq;
	struct list_head pidq;
	spinlock_t pidq_lk;
	struct hlist_node node;
};

struct cond_hnode {
	unsigned int tgid;
	unsigned int pid;
	atomic_t cond;
	struct hlist_node node;
};
*/

/*
struct mem_header {
        unsigned int opcode;         // type of payload / message
        unsigned int sender_id;      // id of the sender node
};
*/
struct futex_msg_struct {
	unsigned long uaddr;
	int tgid;
	int pid;
	int op;
	int nr;
	int bitset;
	unsigned long psn;
} __attribute__((packed));

struct futex_reply_struct {
	int ret;
} __attribute__((packed));

//long do_disagg_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
//		u32 __user *uaddr2, u32 val2, u32 val3);
//int local_wakeup(int tgid, unsigned long uaddr);
#endif