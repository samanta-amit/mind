#include <linux/kernel.h>
#include <linux/smp.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/slab.h>
#include <linux/fork.h>
#include <disagg/fork_disagg.h>
#include <disagg/futex_disagg.h>
#include <disagg/network_disagg.h>
#include <disagg/config.h>

#define TCP_SERVER_CPU 8

static atomic_t num_threads;
static atomic_t num_free_threads;
static atomic_t num_busy_threads;
static volatile int container_init_done = 0;
static volatile int next_tid_to_run = 0;
static LIST_HEAD(fork_req_list);
spinlock_t fork_req_list_lock;
static volatile int num_fork_reqs = 0;

static unsigned char _destip[5] = {10,10,10,1,'\0'};

extern void DEBUG_print_vma(struct mm_struct *);

static void pin_to_core(int new_cpu) {
    struct cpumask cpuset;
    cpumask_clear(&cpuset);
	cpumask_set_cpu(new_cpu, &cpuset);
    sched_setaffinity(current->pid, &cpuset);
}

static int __handle_remote_thread(struct fork_msg_struct *fork_msg) {
    return add_one_fork_req(fork_msg, 1);
}
static int handle_remote_thread(void *hdr, void *payload, struct socket* sk) {
    int ret = 0;
    struct remote_thread_reply_struct reply;
    ret = __handle_remote_thread((struct fork_msg_struct *)payload);
    tcp_send(sk, (const char*)&reply, sizeof(struct remote_thread_reply_struct), MSG_DONTWAIT);
    return ret;
}
/*
static int handle_futex(void *hdr, void *payload, struct socket *sk) {
    int ret = 0;
    struct futex_reply_struct reply;
    struct futex_msg_struct *futex_msg = (struct futex_msg_struct *)payload;
    ret = local_wakeup(futex_msg->tgid, futex_msg->uaddr);
    tcp_send(sk, (const char*)&reply, sizeof(struct futex_reply_struct), MSG_DONTWAIT);
    return ret;    
}
*/

static int send_simple_ack(struct socket *accept_socket, int ret) {
    // TEMPORARY
    const int len = DISAGG_NET_SIMPLE_BUFFER_LEN;
    unsigned char out_buf[DISAGG_NET_SIMPLE_BUFFER_LEN + 1];
    memset(out_buf, 0, len + 1);
    sprintf(out_buf, "ACK %d", ret);
    tcp_send(accept_socket, out_buf, strlen(out_buf), MSG_DONTWAIT);
    return 0;
}

static int send_sock_usage_to_switch(struct socket *accept_socket, u32 msg_type) {
    int ret = 0;
    void *msg = NULL;
    struct mem_header *hdr;
    int i = 0;
    char retbuf[DISAGG_NET_SIMPLE_BUFFER_LEN + 1];

    msg = kmalloc(sizeof(*hdr), GFP_KERNEL);
    if (!msg) {
        ret  = -ENOMEM;
        goto out;
    }
    hdr = get_header_ptr(msg);
    hdr->opcode = msg_type;
    hdr->sender_id = get_local_node_id();
    //there's no payload
    //
    ret = tcp_send(accept_socket, msg, sizeof(*hdr), MSG_DONTWAIT);
    if (ret < sizeof(*hdr)) {
        ret = -ERR_DISAGG_NET_FAILED_TX;
        goto out;
    }

    memset(retbuf, 0, DISAGG_NET_SIMPLE_BUFFER_LEN + 1);
    while (1) {
        for (i = 0; i < DISAGG_NET_CTRL_POLLING_SKIP_COUNTER; i++)
        {
            // wait_socket_recv(_conn_socket);
            // if(!skb_queue_empty(&_conn_socket->sk->sk_receive_queue
            {
                ret = tcp_receive(accept_socket, retbuf, DISAGG_NET_SIMPLE_BUFFER_LEN, MSG_DONTWAIT);
                if (ret > 0) {
                    ret = 0;
                    goto out;
                }
                  // printk(KERN_DEFAULT "Msg received\n");
            }
        }
        usleep_range(10, 10);
    }
    ret = -ERR_DISAGG_NET_TIMEOUT;
    printk(KERN_ERR "Msg timeout\n");

out:
    if (msg)
        kfree(msg);
    return ret;
}

void disagg_container_tcp_server(void *arg) {
    int ret = 0;
    struct socket *accept_socket = NULL;
    struct mem_header *hdr = NULL;
    void *buf = NULL;
    int num_container_threads = 0;
    int max_container_threads = *(int *)arg;
    DECLARE_WAITQUEUE(recv_wait, current);

    pin_to_core(TCP_SERVER_CPU);
    ret = tcp_initialize_conn(&accept_socket, create_address(_destip), _destport);
    if ((ret < 0) || !accept_socket) {
	    pr_info("fail to establish conn for fork msg ret[%d] sock[%lx]\n",
            ret, (unsigned long)accept_socket);
        goto out;
    }

    ret = send_sock_usage_to_switch(accept_socket, DISAGG_CONN_USAGE_REMOTE_FORK);

    buf = kzalloc(DISAGG_NET_MAXIMUM_BUFFER_LEN, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    //poll
    printk("disagg container tcp server started, max_container_threads: %d\n", max_container_threads);
    while (num_container_threads < max_container_threads) {
    //while (1) {
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

        ret = tcp_receive(accept_socket, buf, DISAGG_NET_MAXIMUM_BUFFER_LEN, MSG_DONTWAIT);
        if (ret > 0)
        {
            // get header first
            if (ret >= sizeof(*hdr))
            {
                hdr = get_header_ptr(buf);
                pr_info("TCP: Received opcode: %u\n", hdr->opcode);

                switch (hdr->opcode)
                {
                case DISAGG_REMOTE_THREAD:
                    if (ret >= sizeof(*hdr) + sizeof(struct fork_msg_struct))
                    {
						void *payload = get_payload_ptr(buf);
						struct fork_msg_struct *fork_msg = (struct fork_msg_struct *)payload;
                        int recv = ret;
					    int expected_size = sizeof(struct fork_msg_struct);	//should be short enough
						expected_size += (fork_msg->num_file_mappings - 1) * sizeof(struct file_mapping_info);	// size of VMA list
						expected_size += sizeof(*hdr);	// size of header
						printk("REMOTE THREAD: received %d, expected %d\n", recv, expected_size);
						while (recv < expected_size)
						{
							// continue to recv
							ret = tcp_receive(accept_socket, (void *)((char *)buf + recv),
													 DISAGG_NET_MAXIMUM_BUFFER_LEN - recv,
													 MSG_DONTWAIT);
							if (ret > 0)
							{
								recv += ret;
							}else{
								msleep(1000);	// DEBUG: 1 s
							}
							printk("REMOTE THREAD: received %d, expected %d\n", recv, expected_size);
						}
						ret = handle_remote_thread(hdr, payload, accept_socket);
                    }
                    else
                    {
                        ret = -1;
                        send_simple_ack(accept_socket, ret);
                    }
                    break;
                /*
                case DISAGG_FUTEX:
                    if (ret >= sizeof(*hdr) + sizeof(struct futex_msg_struct)) {
                        void *payload = get_payload_ptr(buf);
                        ret = handle_futex(hdr, payload, accept_socket);
                    } else {
                        ret = -1;
                        send_simple_ack(accept_socket, ret);
                    }
                    break;
                */
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
            pr_info("Response has been sent (Ret code: %d)\n", ret);
        }
        ++num_container_threads;
    }

out:
    sock_release(accept_socket);
    if (buf)
        kfree(buf);
    buf = NULL;
    printk("disagg container tcp server terminated, max_container_threads: %d\n", max_container_threads);
    do_exit(0);
}

void disagg_container_init(int num_container_threads) {
    int *arg = NULL;
    pr_info("enter disagg_container_init\n");
    atomic_set(&num_threads, 0);
    atomic_set(&num_free_threads, 0);
    atomic_set(&num_busy_threads, 0);
    spin_lock_init(&fork_req_list_lock);
    num_fork_reqs = 0;

    //starts a tcp server to poll fork req
    arg = kmalloc(sizeof(int), GFP_KERNEL);
    *arg = num_container_threads;
    kthread_run((void *)disagg_container_tcp_server, (void *)arg, "disagg_container_tcp_server");
}

int add_one_fork_req(struct fork_msg_struct *fork_msg, int alloc) {
    struct fork_msg_struct *entry = NULL;
    struct fork_req_struct *req = NULL;
    int ret = 0;
    if (alloc) {
        size_t tot_size = sizeof(*fork_msg) +
            sizeof(struct file_mapping_info) * (fork_msg->num_file_mappings - 1);
        entry = kzalloc(tot_size, GFP_KERNEL);
        if (!entry) {
            ret = -ENOMEM;
            goto out;
        }
        memcpy(entry, fork_msg, tot_size);
    } else {
        entry = fork_msg;
    }

    spin_lock(&fork_req_list_lock);
    req = kzalloc(sizeof(*req), GFP_KERNEL);
    if (!req) {
        ret = -ENOMEM;
        goto unlock;
    }
    req->fork_msg = entry;
    list_add_tail(&req->node, &fork_req_list);
    ++num_fork_reqs;

unlock:
    spin_unlock(&fork_req_list_lock);
out:
    return ret;
}

static struct fork_msg_struct *pop_one_fork_req(void) {
    struct fork_msg_struct *ret = NULL;
    struct fork_req_struct *req = NULL;
    spin_lock(&fork_req_list_lock);
    if (num_fork_reqs == 0)
        goto out;
    req = container_of(fork_req_list.next, struct fork_req_struct, node);
    list_del(&req->node);
    --num_fork_reqs;
    ret = req->fork_msg;
    kfree(req);
out:
    spin_unlock(&fork_req_list_lock);
    return ret;
}

#define CN_COPY_MM_VALUES(EXR, MM, F)	(EXR->F = MM->F)
static void container_set_up_layout(struct fork_msg_struct* payload,
							 struct mm_struct *mm)
{
	CN_COPY_MM_VALUES(payload, mm, hiwater_rss);
	CN_COPY_MM_VALUES(payload, mm, hiwater_vm);
	CN_COPY_MM_VALUES(payload, mm, total_vm);
	CN_COPY_MM_VALUES(payload, mm, locked_vm);
	CN_COPY_MM_VALUES(payload, mm, pinned_vm);
	CN_COPY_MM_VALUES(payload, mm, data_vm);
	CN_COPY_MM_VALUES(payload, mm, exec_vm);
	CN_COPY_MM_VALUES(payload, mm, stack_vm);
	CN_COPY_MM_VALUES(payload, mm, def_flags);
	CN_COPY_MM_VALUES(payload, mm, start_code);
	CN_COPY_MM_VALUES(payload, mm, end_code);
	CN_COPY_MM_VALUES(payload, mm, start_data);
	CN_COPY_MM_VALUES(payload, mm, end_data);
	CN_COPY_MM_VALUES(payload, mm, start_brk);
	CN_COPY_MM_VALUES(payload, mm, brk);
	CN_COPY_MM_VALUES(payload, mm, start_stack);
	CN_COPY_MM_VALUES(payload, mm, arg_start);
	CN_COPY_MM_VALUES(payload, mm, arg_end);
	CN_COPY_MM_VALUES(payload, mm, env_start);
	CN_COPY_MM_VALUES(payload, mm, env_end);
	CN_COPY_MM_VALUES(payload, mm, mmap_base);
	CN_COPY_MM_VALUES(payload, mm, mmap_legacy_base);
}

static int remove_all_mappings(void) {
    int ret = 0;
    struct vm_area_struct *cur = current->mm->mmap;
	struct vm_area_struct *prev, *next;
	struct mm_struct *mm = current->mm;
	// LIST_HEAD(uf);
	barrier();
	while (cur)
	{
		next = cur->vm_next;
		prev = cur->vm_prev;
        if (vma_is_anonymous(cur) || cur->vm_file) {
            //do not unmap vvar and vdso
            if (unlikely(do_munmap(mm, cur->vm_start,
                    cur->vm_end - cur->vm_start, NULL))) {
	            ret = -ENOMEM;
			    printk(KERN_DEFAULT "Failed to unmap vma: 0x%lx - 0x%lx\n",
				        cur->vm_start, cur->vm_end);
		        BUG();
                break;
		    }
        }
        cur = next;
    }
    return ret;
}

#define BAD_ADDR(x) ((unsigned long)(x) >= TASK_SIZE)
static int map_files_from_fork_msg(struct fork_msg_struct *fork_msg) {
    struct file_mapping_info *file_mapping_info = &(fork_msg->file_mapping_infos);
    int map_idx;
    unsigned long addr;
    printk("%u read only mappings in total\n", fork_msg->num_file_mappings);
    for (map_idx = 0; map_idx < fork_msg->num_file_mappings;
            ++map_idx, ++file_mapping_info) {
        //print
        /*
        pr_info("[%u] %lx-%lx %lx %s\n", map_idx, file_mapping_info->addr,
                file_mapping_info->addr + file_mapping_info->len,
                file_mapping_info->offset, file_mapping_info->filename);
        */
        //open
        struct file *filp = filp_open(file_mapping_info->filename, O_RDONLY, 0);
        if (IS_ERR(filp)) {
            printk("error opening file %s ret[%ld]\n", file_mapping_info->filename, PTR_ERR(filp));
            return PTR_ERR(filp);
        }
        //map
        addr = vm_mmap(filp, file_mapping_info->addr, file_mapping_info->len,
                file_mapping_info->prot, file_mapping_info->flag,
                file_mapping_info->offset);
        if (BAD_ADDR(addr) || addr != file_mapping_info->addr) {
            printk("error mapping file %s ret[%lx]\n",
                    file_mapping_info->filename, addr);
            return (int)addr;
        }
        //TODO do we need to close files?
    }
    return 0;
}

static int enforce_addr_space(struct fork_msg_struct *fork_msg) {
    int ret = 0;
    //clear addr space
    if ((ret = remove_all_mappings()))
        goto out;
    //map files
    if ((ret = map_files_from_fork_msg(fork_msg)))
        goto out;
    //mm meta
    container_set_up_layout(fork_msg, current->mm);
    // clear_child_tid
    current->clear_child_tid = (int *)fork_msg->clear_child_tid;
    //debug
    DEBUG_print_vma(current->mm);
out:
    return ret;
}

static void print_hwcontext_forkmsg(struct fork_msg_struct *fm) {
    struct pt_regs *regs = &fm->regs;
    struct desc_struct *tls_array = fm->tls_array;
    printk("regs info from fork msg:\nr15:\t%lx\nr14:\t%lx\nr13:\t%lx\nr12:\t%lx\nbp:\t%lx\nbx:\t%lx\nr11:\t%lx\nr10:\t%lx\nr9:\t%lx\nr8:\t%lx\nax:\t%lx\ncx:\t%lx\ndx:\t%lx\nsi:\t%lx\ndi:\t%lx\norig_ax:\t%lx\nip:\t%lx\ncs:\t%lx\nflags:\t%lx\nsp:\t%lx\nss:\t%lx\nclone_flags:\t%x\ngsindex:\t%hx\nfsindex:\t%hx\nes:\t%hx\nds:\t%hx\ngsbase:\t%lx\nfsbase:\t%lx\ntls_arr0:\t%llx\ntls_arr1:\t%llx\ntls_arr2:\t%llx\n",
        regs->r15, regs->r14, regs->r13, regs->r12, regs->bp, regs->bx, regs->r11, regs->r10, regs->r9, regs->r8, regs->ax, regs->cx, regs->dx, regs->si, regs->di, regs->orig_ax, regs->ip, regs->cs, regs->flags, regs->sp, regs->ss, fm->clone_flags, fm->gsindex, fm->fsindex, fm->es, fm->ds, fm->gsbase, fm->fsbase, *(u64 *)tls_array, *(((u64 *)tls_array) + 1), *(((u64 *)tls_array) + 2));
}

static void print_hwcontext(struct task_struct *tsk) {
    struct pt_regs *regs = task_pt_regs(tsk);
    struct thread_struct *fm = &tsk->thread;
    struct desc_struct *tls_array = fm->tls_array;
    printk("regs info:\nr15:\t%lx\nr14:\t%lx\nr13:\t%lx\nr12:\t%lx\nbp:\t%lx\nbx:\t%lx\nr11:\t%lx\nr10:\t%lx\nr9:\t%lx\nr8:\t%lx\nax:\t%lx\ncx:\t%lx\ndx:\t%lx\nsi:\t%lx\ndi:\t%lx\norig_ax:\t%lx\nip:\t%lx\ncs:\t%lx\nflags:\t%lx\nsp:\t%lx\nss:\t%lx\ngsindex:\t%hx\nfsindex:\t%hx\nes:\t%hx\nds:\t%hx\ngsbase:\t%lx\nfsbase:\t%lx\ntls_arr0:\t%llx\ntls_arr1:\t%llx\ntls_arr2:\t%llx\n",
        regs->r15, regs->r14, regs->r13, regs->r12, regs->bp, regs->bx, regs->r11, regs->r10, regs->r9, regs->r8, regs->ax, regs->cx, regs->dx, regs->si, regs->di, regs->orig_ax, regs->ip, regs->cs, regs->flags, regs->sp, regs->ss, fm->gsindex, fm->fsindex, fm->es, fm->ds, fm->gsbase, fm->fsbase, *(u64 *)tls_array, *(((u64 *)tls_array) + 1), *(((u64 *)tls_array) + 2));
}

static int enforce_hardware_context(struct fork_msg_struct *fork_msg) {
    struct pt_regs *regs = task_pt_regs(current);
    print_hwcontext(current);
    *regs = fork_msg->regs;
    current->thread.ds = fork_msg->ds;
    current->thread.es = fork_msg->es;
    current->thread.fsindex = fork_msg->fsindex;
    //current->thread.gsindex = fork_msg->gsindex;
    current->thread.fsbase = fork_msg->fsbase;
    //current->thread.gsbase = fork_msg->gsbase;

    //write fsbase to register now, because if there's no context switch
    //kernel won't reset fsbase when returning to user space
    //wrmsrl(MSR_FS_BASE, fork_msg->fsbase);

    //schedule to another CPU instead of enforce fs
    pr_info("disagg container CPU id[%d]\n", smp_processor_id());
    pin_to_core(smp_processor_id() + 1);
    pr_info("disagg container CPU id[%d]\n", smp_processor_id());

    //TODO tls array, FPU, io_bitmap or other
    print_hwcontext_forkmsg(fork_msg);
    print_hwcontext(current);
    return 0;
}

//asmlinkage int sys_disagg_handle_remote_thread(void) {
SYSCALL_DEFINE2(disagg_handle_remote_thread, int, tid, int, num_container_threads) {
    struct fork_msg_struct *fork_msg = NULL;

    if (tid == 0) {
        disagg_container_init(num_container_threads);
        next_tid_to_run = 0;
        container_init_done = 1;
        printk("disagg container init done, %d container threads\n",
            num_container_threads);
        //init only, used by main thread
        if (num_container_threads == 0) {
            return 0;
        }
    } else {
        while (!container_init_done)
            msleep(1);
    }

    atomic_inc_return(&num_threads);
    atomic_inc(&num_free_threads);
    printk("hello from container thread %d\n", tid);

    //smaller tid always work first
    while (next_tid_to_run != tid)
        msleep(1);
    printk("container thread %d starts to accept remote thread\n", tid);

    //pop one fork_req from queue
    while (!fork_msg) {
        fork_msg = pop_one_fork_req();
        if (!fork_msg)
            msleep(1);
    }

    printk("launch remote thread %d\n", tid);

    //addr space
    if (tid == 0)
        enforce_addr_space(fork_msg);
    //hardware context
    enforce_hardware_context(fork_msg);

    if (fork_msg)
        kfree(fork_msg);
    
    //tgid changed
    current->tgid = TEST_PROGRAM_TGID;
    current->is_remote = 1;
    //let next container thread runs
    ++next_tid_to_run;
    //behavior ported from start_thread_common
    force_iret();
    return 0;
}
