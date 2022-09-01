#include <linux/slab.h>
#include <linux/poll.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/jhash.h>
#include <linux/init.h>
#include <linux/futex.h>
#include <linux/mount.h>
#include <linux/pagemap.h>
#include <linux/syscalls.h>
#include <linux/signal.h>
#include <linux/export.h>
#include <linux/magic.h>
#include <linux/pid.h>
#include <linux/nsproxy.h>
#include <linux/ptrace.h>
#include <linux/sched/rt.h>
#include <linux/sched/wake_q.h>
#include <linux/sched/mm.h>
#include <linux/hugetlb.h>
#include <linux/freezer.h>
#include <linux/bootmem.h>
#include <linux/fault-inject.h>
#include <linux/delay.h>

#include <asm/futex.h>
#include <linux/kthread.h>

#include "locking/rtmutex_common.h"

#include <disagg/futex_disagg.h>
#include <disagg/print_disagg.h>
#include <disagg/profile_points_disagg.h>
#include <disagg/config.h>
#include <disagg/network_disagg.h>

#include <linux/hashtable.h>
#include <linux/wait.h>

/*
init conn with server
constantly read conn to perform local wakeup
remove local wakeup call in container tcp server
send msg to memroy -> send msg to server
*/

DECLARE_HASHTABLE(futex_hlist, MAX_FUTEX_QUEUE_BIT);
DECLARE_HASHTABLE(cond_hlist, MAX_FUTEX_THREAD_PER_BLADE);
spinlock_t futex_hlist_lk;
spinlock_t cond_hlist_lk;
static atomic_t futex_psn;
static unsigned char futex_server_ip[5] = {10,10,10,221,'\0'};
static int futex_server_port = 8765;
static struct socket *futex_sk;
static spinlock_t send_msg_lock;


static struct futex_hnode *find_queue_by_tgid_addr(u32 tgid, u64 uaddr);
static struct pidq_entry *dequeue_pid(struct futex_hnode *futex_node);
static struct cond_hnode *find_cond_by_id(u32 tgid, u32 pid);

#define FUTEX_RING_BUF_SIZE ((sizeof(struct mem_header) + sizeof(struct futex_msg_struct)) * 100)
static char *msg_buf;
static atomic64_t head;
static atomic64_t tail;

DEFINE_PROFILE_POINT(FTX_wait)
DEFINE_PROFILE_POINT(FTX_wait_awake)
DEFINE_PROFILE_POINT(FTX_wake)
//DEFINE_PROFILE_POINT(FTX_notify_wakeup_global)
DEFINE_PROFILE_POINT(FTX_notify_wait_global)
DEFINE_PROFILE_POINT(FTX_local_wakeup)
DEFINE_PROFILE_POINT(FTX_notify_wait_bitset_global)
DEFINE_PROFILE_POINT(FTX_wake_bitset)

static void pin_to_core(int new_cpu) {
    struct cpumask cpuset;
    cpumask_clear(&cpuset);
	cpumask_set_cpu(new_cpu, &cpuset);
    sched_setaffinity(current->pid, &cpuset);
}

static int local_wakeup(int tgid, unsigned long uaddr) {
    int res = 0;
    struct futex_hnode *hnode;
    struct cond_hnode *cond;
    struct pidq_entry *entry;

    hnode = find_queue_by_tgid_addr(tgid, (u64)uaddr);
    if (!hnode) {
        pr_err("fail to find futex queue\n");
        res = -1;
        goto ret;
    }

    entry = dequeue_pid(hnode);
    if (!entry) {
        pr_err("fail to find pid entry\n");
        res = -1;
        goto ret;
    }

    cond = find_cond_by_id(hnode->tgid, entry->pid);
    if (!cond) {
        pr_err("fail to find cond\n");
        res = -1;
        goto ret;
    }

    atomic_set(&(cond->cond), COND_WAKE);

    wake_up(&(hnode->wq));
    pr_futex("FUTEX_WAKEUP_LOCAL tgid[%d] uaddr[0x%lx]\n", tgid, uaddr);

ret:
    if (entry)
        kfree(entry);
    return res;
}

void futex_net_worker(void) {
    int ret = 0;
    struct socket *accept_socket;
    struct mem_header *hdr = NULL;
    struct futex_msg_struct *msg = NULL;
    void *buf = NULL;

    PROFILE_POINT_TIME(FTX_local_wakeup)

    pin_to_core(FUTEX_NET_WORKER_CPU);

    DECLARE_WAITQUEUE(recv_wait, current);

    ret = tcp_initialize_conn(&futex_sk, create_address(futex_server_ip), futex_server_port);
    if ((ret < 0) || !futex_sk) {
	    pr_err("fail to establish conn for fork msg ret[%d] sock[%lx]\n",
            ret, futex_sk);
        goto out;
    }

    accept_socket = futex_sk;

    msg_buf = kzalloc(FUTEX_RING_BUF_SIZE, GFP_KERNEL);
    if (!msg_buf) {
        ret = -ENOMEM;
        goto out;
    }

    buf = kzalloc(FUTEX_WAKEUP_WORKER_BUF_LEN, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    //poll
    printk("futex net worker started\n");
    //while (num_container_threads < max_container_threads) {
    while (1) {
        add_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);
        while (skb_queue_empty(&accept_socket->sk->sk_receive_queue))
        {
            __set_current_state(TASK_INTERRUPTIBLE);
            schedule_timeout(_RECV_CHECK_TIME_IN_JIFFIES);

            if (kthread_should_stop())
            {
                pr_info(" *** mtp | tcp server handle connection "
                        "thread stopped | connection_handler *** \n");

                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&accept_socket->sk->sk_wq->wait,
                                  &recv_wait);
                sock_release(accept_socket);
                return;
            }

            if (signal_pending(current))
            {
                __set_current_state(TASK_RUNNING);
                remove_wait_queue(&accept_socket->sk->sk_wq->wait,
                                  &recv_wait);
                goto out;
            }
        }
        __set_current_state(TASK_RUNNING);
        remove_wait_queue(&accept_socket->sk->sk_wq->wait, &recv_wait);
        
        ret = tcp_receive(accept_socket, buf, FUTEX_WAKEUP_WORKER_BUF_LEN, MSG_DONTWAIT);
        if (ret > 0) {
            pr_futex("FUTEX_RECV %d byte packet\n", ret);
            long old_tail = atomic64_read(&tail);
            long old_tail_mod = old_tail % FUTEX_RING_BUF_SIZE;
            long new_tail = old_tail + ret;

            while (new_tail - atomic64_read(&head) > FUTEX_RING_BUF_SIZE);

            barrier();

            if (old_tail_mod + ret > FUTEX_RING_BUF_SIZE) {
                long copy1_size = FUTEX_RING_BUF_SIZE - old_tail_mod;
                memcpy(msg_buf + old_tail_mod, buf, copy1_size);
                memcpy(msg_buf, buf + copy1_size, ret - copy1_size);
            } else {
                memcpy(msg_buf + old_tail_mod, buf, ret);
            }

            barrier();

            atomic64_set(&tail, new_tail);
        } else {
            pr_futex("TCP recv 0 byte packet\n");
        }
/*
        if (ret > 0)
        {
            // get header first
            if (ret >= sizeof(*hdr))
            {
                hdr = get_header_ptr(buf);
                //pr_futex("TCP: Received opcode: %u\n", hdr->opcode);

                switch (hdr->opcode)
                {
                case DISAGG_FUTEX:
                    if (ret == sizeof(*hdr) + sizeof(*msg)) {
                        void *payload = get_payload_ptr(buf);
                        msg = payload;

                        PROFILE_START(FTX_local_wakeup);
                        ret = local_wakeup(msg->tgid, msg->uaddr);
                        PROFILE_LEAVE(FTX_local_wakeup);

                        if (ret) {
                            pr_err("local wakeup err[%d]\n", ret);
                        }
                    } else {
                        pr_err("corrupted packet size[%d]\n", ret);
                    }
                    break;
                default:
                    pr_err("TCP: Cannot recognize opcode: %u\n", hdr->opcode);
                    goto out;
                }
            }        
            else
            {
                pr_err("Cannot retrieve a header\n");
            }

            // simple return msg
            // memset(out_buf, 0, len+1);
            // strcat(out_buf, "ACK");
            // tcp_server_send(accept_socket, id, out_buf,
            //                 strlen(out_buf), MSG_DONTWAIT);
            //pr_futex("Response has been sent (Ret code: %d)\n", ret);
        }
        */
    }

out:
    sock_release(accept_socket);
    if (buf)
        kfree(buf);
    buf = NULL;
    printk("futex wakeup worker terminated\n");
    do_exit(0);
}

void futex_wake_worker(void) {
    int ret = 0;
    long futex_msg_size = sizeof(struct mem_header) + sizeof(struct futex_msg_struct);
    struct mem_header *hdr = NULL;
    struct futex_msg_struct *msg = NULL;

    pin_to_core(FUTEX_WAKE_WORKER_CPU);
    
    char *buf = kzalloc(FUTEX_WAKEUP_WORKER_BUF_LEN, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    printk("futex wake worker started\n");
    while (1) {
        long old_head = atomic64_read(&head);
        long old_head_mod = old_head % FUTEX_RING_BUF_SIZE;
        long new_head = old_head + futex_msg_size;

        while (atomic64_read(&tail) < new_head)
            usleep_range(1, 1);
        //pr_futex("old head[%ld] new head[%ld] tail[%ld]\n",
        //    old_head, new_head, atomic64_read(&tail));
        barrier();

        if (old_head_mod + futex_msg_size > FUTEX_RING_BUF_SIZE) {
            long copy1_size = FUTEX_RING_BUF_SIZE - old_head_mod;
            memcpy(buf, msg_buf + old_head_mod, copy1_size);
            memcpy(buf + copy1_size, msg_buf, futex_msg_size - copy1_size);
        } else {
            memcpy(buf, msg_buf + old_head_mod, futex_msg_size);
        }

        barrier();

        atomic64_set(&head, new_head);

        hdr = get_header_ptr(buf);
        switch (hdr->opcode) {
        case DISAGG_FUTEX:
            msg = (struct futex_msg_struct *)get_payload_ptr(buf);
            pr_futex("FUTEX_MSG tgid[%d] uaddr[0x%lx]\n", msg->tgid, msg->uaddr);
            local_wakeup(msg->tgid, msg->uaddr);
            break;
        default:
            pr_err("TCP: Cannot recognize opcode: %u\n", hdr->opcode);
            goto out;
        }
    }

out:
    return ret;
}

void disagg_futex_init(void) {
    hash_init(futex_hlist);
    hash_init(cond_hlist);
    spin_lock_init(&futex_hlist_lk);
    spin_lock_init(&cond_hlist_lk);
    atomic_set(&futex_psn, 0);

    spin_lock_init(&send_msg_lock);
    atomic64_set(&head, 0);
    atomic64_set(&tail, 0);
    barrier();
    kthread_run((void *)futex_net_worker, NULL, "futex_net_worker");
    kthread_run((void *)futex_wake_worker, NULL, "futex_wake_worker");
}
EXPORT_SYMBOL(disagg_futex_init);

static struct futex_hnode *find_queue_by_tgid_addr(u32 tgid, u64 uaddr) {
    struct futex_hnode *res = NULL, *cur;
    u32 key = (tgid << 16) + (uaddr % (1L << 32));

    //pr_futex("target tgid[%d] uaddr[%lu] key[%u]\n", tgid, uaddr, key);
    spin_lock(&futex_hlist_lk);
    hash_for_each_possible(futex_hlist, cur, node, key) {
        //pr_futex("\ttgid[%d] uaddr[%lu] key[%u]\n", cur->tgid, cur->uaddr, (cur->tgid << 16) + (cur->uaddr % (1L << 32)));
        if (cur->tgid == tgid && cur->uaddr == uaddr) {
            res = cur;
            break;
        }
    }
    
    if (!res) {
        res = (struct futex_hnode *)kzalloc(sizeof(struct futex_hnode), GFP_KERNEL);
        if (!res) {
            pr_err("can not allocate futex queue tgid[%u], uaddr[%lu]\n", tgid, uaddr);
            goto ret;
        } else {
            //pr_futex("futex hnode allocated[%p]\n", res);
        }
        res->tgid = tgid;
        res->uaddr = uaddr;
        init_waitqueue_head(&(res->wq));
        INIT_LIST_HEAD(&(res->pidq));
        spin_lock_init(&(res->pidq_lk));
        hash_add(futex_hlist, &(res->node), key);
    } else {
        //pr_futex("futex hnode found[%p]\n", res);
    }

ret:
    spin_unlock(&futex_hlist_lk);
    return res;
}

static int enqueue_pid(struct futex_hnode *futex_node, unsigned int pid) {
    int res = 0;
    struct pidq_entry *pid_entry;

    pid_entry = (struct pidq_entry *)kzalloc(sizeof(struct pidq_entry), GFP_KERNEL);
    if (!pid_entry) {
        pr_err("can not allocate pid entry tgid[%u], pid[%lu]\n", futex_node->tgid, pid);
        res = -1;
        goto ret;
    }
    pid_entry->pid = pid;

    spin_lock(&(futex_node->pidq_lk));
    list_add_tail(&(pid_entry->node), &(futex_node->pidq));
    spin_unlock(&(futex_node->pidq_lk));

ret:
    return res;
}

static struct pidq_entry *dequeue_pid(struct futex_hnode *futex_node) {
    struct pidq_entry *pid_entry;

    spin_lock(&(futex_node->pidq_lk));
    pid_entry = container_of((futex_node->pidq).next, struct pidq_entry, node);
    if (!pid_entry) {
        pr_err("no pid entry in queue tgid[%u]\n", futex_node->tgid);
        goto ret;
    }

    list_del(&(pid_entry->node));

ret:
    spin_unlock(&(futex_node->pidq_lk));
    return pid_entry;
}

static struct cond_hnode *find_cond_by_id(u32 tgid, u32 pid) {
    struct cond_hnode *res = NULL, *cur;
    u32 key = (tgid << 16) + pid;

    spin_lock(&cond_hlist_lk);
    hash_for_each_possible(cond_hlist, cur, node, key) {
        //pr_futex("\ttgid[%d] uaddr[%lu] key[%u]\n", cur->tgid, cur->uaddr, (cur->tgid << 16) + (cur->uaddr % (1L << 32)));
        if (cur->tgid == tgid && cur->pid == pid) {
            res = cur;
            break;
        }
    }
    
    if (!res) {
        res = (struct cond_hnode *)kzalloc(sizeof(struct cond_hnode), GFP_KERNEL);
        if (!res) {
            pr_err("can not allocate cond tgid[%u], pid[%u]\n", tgid, pid);
            goto ret;
        } else {
            //pr_futex("cond hnode allocated[%p]\n", res);
        }
        res->tgid = tgid;
        res->pid = pid;
        atomic_set(&(res->cond), COND_WAIT);
        hash_add(cond_hlist, &(res->node), key);
    } else {
        //pr_futex("cond hnode found[%p]\n", res);
    }

ret:    
    spin_unlock(&cond_hlist_lk);
    return res;    
}

static int send_msg_to_futex_server(u32 msg_type, void *payload, u32 len_payload,
                        void *retbuf, u32 max_len_retbuf)
{
    int ret = 0;
    u32 tot_len;
    void *msg = NULL, *payload_msg;
    struct mem_header* hdr;
    int i = 0;
    unsigned long start_ts, end_ts;
    struct socket *_conn_socket = futex_sk;

    if (!retbuf)
        return -ERR_DISAGG_NET_INCORRECT_BUF;

    spin_lock(&send_msg_lock);
    if (!_conn_socket) {
        pr_err("conn to futex server not initialized\n");
        ret = -1;
        goto out_sendmsg_err;
    }

    // make header and attach payload
    tot_len = len_payload + sizeof(*hdr);
    // recv_buf = kmalloc(_recv_buf_size, GFP_KERNEL);
    msg = kmalloc(tot_len, GFP_KERNEL);
    if (!msg) {
		ret = -ENOMEM;
        goto out_sendmsg_err;
    }

    hdr = get_header_ptr(msg);
	hdr->opcode = msg_type;
    hdr->sender_id = get_local_node_id();

    payload_msg = get_payload_ptr(msg);
	memcpy(payload_msg, payload, len_payload);

    // send request
    ret = tcp_send(_conn_socket, msg, tot_len, MSG_DONTWAIT);
    if (ret < tot_len){
        ret = -ERR_DISAGG_NET_FAILED_TX;
        goto out_sendmsg_err;
    }

    // simply polling response
    /*
    memset(retbuf, 0, max_len_retbuf);
    start_ts = jiffies;
    while (1)
    {
        for (i = 0; i < DISAGG_NET_CTRL_POLLING_SKIP_COUNTER; i++)
        {
            // wait_socket_recv(_conn_socket);
            // if(!skb_queue_empty(&_conn_socket->sk->sk_receive_queue))
            {
                ret = tcp_receive(_conn_socket, retbuf, max_len_retbuf, MSG_DONTWAIT);
                if (ret > 0)
                    goto out_sendmsg;
                // printk(KERN_DEFAULT "Msg received\n");
            }
        }
        end_ts = jiffies;
        if ((end_ts > start_ts) && jiffies_to_msecs(end_ts - start_ts) > DISAGG_NET_TCP_TIMEOUT_IN_MS)
        {
            break;
        }
        // usleep_range(10, 10);
    }
    ret = -ERR_DISAGG_NET_TIMEOUT;
    printk(KERN_ERR "Msg timeout\n");
    */
out_sendmsg:
    // if (msg_type == DISSAGG_CHECK_VMA)
    //     PROFILE_LEAVE(NET_tcp_recv_msg);
out_sendmsg_err:
    // release connection  
    // if (_conn_socket && release_lock){
    //     _is_connected = 0;
    //     tcp_finish_conn(_conn_socket);
    //     _conn_socket = NULL;
    // }

    // if (release_lock)
    spin_unlock(&send_msg_lock);
    // free buffers
    // if (!recv_buf)
    //     kfree(recv_buf);
    if (msg)
        kfree(msg);
    // ret >= 0: size of received data, ret < 0: errors
    // barrier();
    return ret;
}

static int notify_wq_global(unsigned long uaddr, int tgid, int pid, int op, int nr, int bitset) {
    int ret;
    struct futex_msg_struct payload;
    struct futex_reply_struct reply;

    payload.uaddr = uaddr;
    payload.tgid = tgid;
    payload.pid = pid;
    payload.op = op;
    payload.nr = nr;
    payload.bitset = bitset;
    payload.psn = atomic_inc_return(&futex_psn);

    //pr_futex("begin psn[%d]\n", payload.psn);
    ret = send_msg_to_futex_server(DISAGG_FUTEX, &payload, sizeof(payload), &reply, sizeof(reply));
    //pr_futex("end psn[%d]\n", payload.psn);

    if (reply.ret)    // only 0 is success
		ret = reply.ret;   // set error

    return ret;
}

static int notify_wait_bitset_global(unsigned long uaddr, int tgid, int pid, int bitset) {
    return notify_wq_global(uaddr, tgid, pid, COND_WAIT_BITSET, 0, bitset);
}

static int notify_wakeup_bitset_global(unsigned long uaddr, int tgid, int nr, int bitset) {
    return notify_wq_global(uaddr, tgid, 0, COND_WAKE_BITSET, nr, bitset);
}

static int notify_wait_global(unsigned long uaddr, int tgid, int pid) {
    return notify_wq_global(uaddr, tgid, pid, COND_WAIT, 0, 0);
}

static int notify_wakeup_global(unsigned long uaddr, int tgid, int nr) {
    return notify_wq_global(uaddr, tgid, 0, COND_WAKE, nr, 0);
}

long do_disagg_futex(u32 __user *uaddr, int op, u32 val, ktime_t *timeout,
		u32 __user *uaddr2, u32 val2, u32 val3) {
    int res = 0;
	int cmd = op & FUTEX_CMD_MASK;
    int tgid = TEST_PROGRAM_TGID;
    struct futex_hnode *hnode;
    struct cond_hnode *cond;
    struct pidq_entry *entry;

    PROFILE_POINT_TIME(FTX_wait)
    PROFILE_POINT_TIME(FTX_wait_awake)
    PROFILE_POINT_TIME(FTX_notify_wait_global)
    PROFILE_POINT_TIME(FTX_notify_wait_bitset_global)
    PROFILE_POINT_TIME(FTX_wake)
    PROFILE_POINT_TIME(FTX_wake_bitset)

    //pr_futex("do_disagg_futex pid[%d] uaddr[%lu] op[%d] val[%u]\n", current->pid, (u64)uaddr, op, val);
    
    if (cmd == FUTEX_WAIT || cmd == FUTEX_WAIT_BITSET) {
        PROFILE_START(FTX_wait);
        PROFILE_START(FTX_wait_awake);

        hnode = find_queue_by_tgid_addr(tgid, (u64)uaddr);
        if (!hnode) {
            pr_err("fail to find futex queue\n");
            res = -1;
            goto ret;
        }

        enqueue_pid(hnode, current->pid);
        cond = find_cond_by_id(hnode->tgid, current->pid);
        if (!cond) {
            res = -1;
            goto ret;
        }

        if (cmd == FUTEX_WAIT) {
            PROFILE_START(FTX_notify_wait_global);
            notify_wait_global(uaddr, tgid, current->pid);
            PROFILE_LEAVE(FTX_notify_wait_global);
            pr_futex("FUTEX_WAIT tgid[%d] pid[%d] uaddr[0x%lx]\n", tgid, current->pid, (u64)uaddr);
            wait_event_timeout(hnode->wq, atomic_read(&(cond->cond)) == COND_WAKE, FUTEX_WAIT_TIMEOUT_JIFFY);
        } else {
            PROFILE_START(FTX_notify_wait_bitset_global);
            notify_wait_bitset_global(uaddr, tgid, current->pid, val3);    
            PROFILE_LEAVE(FTX_notify_wait_bitset_global);   
            pr_futex("FUTEX_WAIT_BITSET tgid[%d] pid[%d] uaddr[0x%lx]\n", tgid, current->pid, (u64)uaddr);
            wait_event_timeout(hnode->wq, atomic_read(&(cond->cond)) == COND_WAKE, FUTEX_WAIT_TIMEOUT_JIFFY);
        }
        PROFILE_LEAVE(FTX_wait);

        //int wakeup_ret = wait_event_timeout(hnode->wq, true, 1);
        //wait_event(hnode->wq, atomic_read(&(cond->cond)) == COND_WAKE);

        atomic_set(&(cond->cond), COND_WAIT);

        PROFILE_LEAVE(FTX_wait_awake);
        pr_futex("FUTEX_AWAKE tgid[%d] pid[%d] uaddr[0x%lx]\n", tgid, current->pid, (u64)uaddr);
    } else if (cmd == FUTEX_WAKE || cmd == FUTEX_WAKE_BITSET) {
        if (cmd == FUTEX_WAKE) {
            PROFILE_START(FTX_wake);
            notify_wakeup_global(uaddr, tgid, val);
            PROFILE_LEAVE(FTX_wake);
            pr_futex("FUTEX_WAKEUP_NOTIFY tgid[%d] pid[%d] uaddr[0x%lx] n[%d]\n", tgid, current->pid, (u64)uaddr, val);
        } else {
            PROFILE_START(FTX_wake_bitset);
            notify_wakeup_bitset_global(uaddr, tgid, val, val3);
            PROFILE_LEAVE(FTX_wake_bitset);
            pr_futex("FUTEX_WAKEUP_BITSET_NOTIFY tgid[%d] pid[%d] uaddr[0x%lx] n[%d]\n", tgid, current->pid, (u64)uaddr, val);
        }
    } else {
        pr_err("FUTEX_BUG tgid[%d] pid[%d] uaddr[0x%lx] cmd[%d]\n", tgid, current->pid, (u64)uaddr, cmd);
        res = -1;
    }
ret:
    return res;
}