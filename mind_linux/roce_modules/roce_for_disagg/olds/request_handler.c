#include "controller.h"
#include "memory_management.h"
#include "request_handler.h"
#include "fault.h"
#include "thpool.h"
#include "file_handler.h"

static struct hlist_head mn_compute_hash[MAX_NUMBER_COMPUTE_NODE][1 << MN_PID_HASH_BIT];
static LIST_HEAD(mn_utgid_list);

/* hash related functions */
u8 hash_ftn(u16 tgid)
{
    u8 key = tgid % (1 << MN_PID_HASH_BIT);
    return key;
}

u32 generate_utgid(u16 sender_id, u16 tgid)
{
    u32 res = (sender_id << 16); 
    return (res | (u32)tgid);
} 

// mn: memory node
extern void init_mn_virtual_address_man(void);
int init_mn_man(void)
{
    int i = 0;
    //TODO: initialize memory management
    //proc_caches_init();

    // initialize compute node hash
    for (i=0; i<MAX_NUMBER_COMPUTE_NODE; i++)
    {
        // if (!mn_compute_hash[i]){
            // mn_compute_hash[i] = (struct hlist_head *)kmalloc(
            //         sizeof(struct hlist_head) * (1 << MN_PID_HASH_BIT), GFP_KERNEL);
        hash_init(mn_compute_hash[i]);
        // }
    }

    init_mn_virtual_address_man();
    
    return 0;
}

/* Functions for handling (node id, tgid) -> (unique tgid) mapping */
struct task_struct *mn_get_task(u16 sender_id, u16 tgid)
{
    struct task_struct *res = NULL;
    struct node_tgid_hash* hnode = NULL;

    if (sender_id >= MAX_NUMBER_COMPUTE_NODE)
    {
        // out of range
        return NULL;
    }

    hash_for_each_possible(mn_compute_hash[sender_id], hnode, node, hash_ftn(tgid))
    {
        if ((hnode->tgid == tgid) && hnode->utgid_node)
            res = hnode->utgid_node->tsk;
    }
    return res;
}

struct task_struct *mn_get_task_by_utgid(u32 utgid)
{
    struct unique_tgid_node *tgnode;
    struct task_struct *res = NULL;

    list_for_each_entry(tgnode, &mn_utgid_list, node)
    {
        if (tgnode->utgid == utgid)
            res = tgnode->tsk;
    }
    return NULL;
}

static void free_task_mm(struct task_struct* tsk)
{
    if(tsk)
    {
        if(tsk->mm)
        {
            mn_mmput(tsk->mm);
            tsk->mm = NULL;
        }
        kfree(tsk); 
    }
}

static struct unique_tgid_node *get_utgid(u16 sender_id, u16 tgid)
{
    struct unique_tgid_node *res = NULL;
    struct node_tgid_hash* hnode = NULL;

    if (sender_id >= MAX_NUMBER_COMPUTE_NODE)
    {
        // out of range
        return NULL;
    }

    hash_for_each_possible(mn_compute_hash[sender_id], hnode, node, hash_ftn(tgid))
    {
        if ((hnode->tgid == tgid) && hnode->utgid_node)
            res = hnode->utgid_node;
    }
    return res;
}

struct file_info *mn_get_file(u16 sender_id, u16 tgid)
{
    struct unique_tgid_node *res = get_utgid(sender_id, tgid);
    if (res)
        return &(res->finfo);
    
    return NULL;
}

static void increase_utgid_ref(u16 sender_id, u16 tgid)
{
    struct unique_tgid_node *utgid = get_utgid(sender_id, tgid);
    if (utgid)
    {
        utgid->ref++;
    }
}

static void get_timestamp(char* buf, unsigned int max_size)
{
    struct timeval t;
    struct tm broken;

    if (max_size < 32 || !buf)
        return;

    do_gettimeofday(&t);
    time_to_tm(t.tv_sec, 0, &broken);
    sprintf(buf, "%d:%d:%d:%06ld", 
            broken.tm_hour, broken.tm_min, 
            broken.tm_sec, t.tv_usec);
}

static void write_vma_log(u32 sender_id, u32 tgid, struct mm_struct *mm)
{
    int i = 0;
    struct file_info *finfo = mn_get_file(sender_id, tgid);
    if (mm && finfo && finfo->file)
    {
        char str_time[32] = {0};
        struct vm_area_struct *cur = mm->mmap;
        get_timestamp(str_time, 32);
        for (; cur; cur = cur->vm_next)
        {
            char str_data[256] = {0};
            sprintf(str_data, "%s, %d, 0x%lx, 0x%lx, 0x%lx, %d, %d\n",
                    str_time, DISSAGG_EXIT, cur->vm_start, cur->vm_end, cur->vm_flags, cur->vm_private_data ? 1 : 0,    // actually accessed / allocated?
                    cur->vm_file ? 1 : 0);  // file mapping?
            write_file(finfo, str_data);
            DEBUG_print_one_vma(cur, i);
            i++;
        }
    }
}

//delete given task from the hash and list
//we need to check there are other nodes using the same task_struct now
void mn_delete_task(u16 sender_id, u16 tgid)
{
    struct node_tgid_hash* hnode = NULL;

    if (sender_id >= MAX_NUMBER_COMPUTE_NODE)
    {
        // out of range
        return;
    }

    hash_for_each_possible(mn_compute_hash[sender_id], hnode, node, hash_ftn(tgid))
    {
        //find target nodes
        if ((hnode->tgid == tgid) && hnode->utgid_node)
        {
            /* 
             * Delete from the list first, then free the object
             * Reference/pointers should be clear as NULL
             */
            hnode->utgid_node->ref--;
            // assumeing serialized access, we do not care about the parallel access
            // or atomic access
            if (hnode->utgid_node->ref > 0)
            {
                pr_info("Decreased reference for - sid: %u, tgid: %u, ref: %d\n",
                    sender_id, tgid, hnode->utgid_node->ref);
                break;
            }

            // write into the file
            write_vma_log((u16)sender_id, (u16)tgid, hnode->utgid_node->tsk->mm);

            //tsk
            if (hnode->utgid_node->tsk)
            {
                free_task_mm(hnode->utgid_node->tsk);
                hnode->utgid_node->tsk = NULL;
            }

            //file
            close_file(&hnode->utgid_node->finfo);

            //utgid
            list_del(&hnode->utgid_node->node);
            kfree(hnode->utgid_node);
            hnode->utgid_node = NULL;

            //hash
            hash_del(&hnode->node);
            kfree(hnode);

            pr_info("Removed task node - sid: %u, tgid: %u\n", sender_id, tgid);
            break;
        }
    }
    return;
}

int clear_mn_man(void){
    int i = 0, j = 0;
    // struct list_head *pos;
    struct unique_tgid_node *utgid_ptr;
    struct node_tgid_hash* tgid_ptr;

    // clear utgid list
    while (mn_utgid_list.next && mn_utgid_list.next != &mn_utgid_list)
    {
        // we do not care about the referece counter here
        utgid_ptr = list_entry(mn_utgid_list.next, struct unique_tgid_node, node);
        list_del(&utgid_ptr->node);

        free_task_mm(utgid_ptr->tsk);
        close_file(&utgid_ptr->finfo);
        kfree(utgid_ptr);
    }

    // clear hash list
    for (i = 0; i < MAX_NUMBER_COMPUTE_NODE; i++)
    {
        if (mn_compute_hash[i]){
            // Assumption: utgid record connected to the hash node is already freed
            for (j = 0; j < HASH_SIZE(mn_compute_hash[i]); j++)
            {
                while(mn_compute_hash[i][j].first)
                {
                    tgid_ptr = container_of(mn_compute_hash[i][j].first, struct node_tgid_hash, node);
                    hash_del(&tgid_ptr->node);
                    kfree(tgid_ptr);
                }
            }
            // kfree(mn_compute_hash[i]);
        }
    }

    return 0;
}

int mn_insert_new_task_mm(u16 sender_id, u16 tgid, struct task_struct* tsk)
{
    u32 utgid;
    struct unique_tgid_node *tgnode;
    struct node_tgid_hash *hnode;

    if (!tsk)
    {
        printk(KERN_DEFAULT "Cannot insert NULL into the list\n");
        return -1;
    }

    // Here we assume that given sender_id, tgid is not existing (already checked)
    utgid = generate_utgid(sender_id, tgid);

    // Make utgid record
    tgnode = kmalloc(sizeof(struct unique_tgid_node), GFP_KERNEL);
    tgnode->utgid = utgid;
    tgnode->tsk = tsk;
    tgnode->ref = 1;    // this is the first reference
    tgnode->finfo.fd = -1;
    tgnode->finfo.file = NULL;
    tgnode->finfo.pos = 0;
    list_add(&tgnode->node, &mn_utgid_list);

    // Make (sender_id, tgid) record
    hnode = kmalloc(sizeof(struct node_tgid_hash), GFP_KERNEL);
    hnode->node_id = sender_id;
    hnode->tgid = tgid;
    hnode->utgid_node = tgnode;
    hash_add(mn_compute_hash[sender_id], &hnode->node, hash_ftn(tgid));

    //NOTE: we used kmalloc instead of kzalloc because we imediately initialized the values
    //TODO: error of OOM

    return 0;
}

int mn_link_to_task_mm(u16 sender_id, u16 tgid, u32 utgid)
{
    // if it was not connected before, increase &mm->mm_users
    return 0;
}

static int __handle_fork(struct mem_header* hdr, void* payload, struct fork_reply_struct *reply){
    struct fork_msg_struct *fork_req = (struct fork_msg_struct*) payload;
    
    int ret = -1;
    struct task_struct *old_tsk;
    struct file_info *finfo = NULL;
    if (!mn_get_task(hdr->sender_id, fork_req->tgid)) // no existing entry
    {
        // 1) initial for from systemd
        old_tsk = mn_get_task(hdr->sender_id, fork_req->prev_tgid);
        if (!old_tsk){  // no prev entry
            ret = mn_create_dummy_task_mm(hdr->sender_id, fork_req->tgid, fork_req->pid); 
            if (!ret)
            {
                pr_info("Dummy task/mm inserted (exec required): sender: %u, tgid: %u, pid: %u\n",
                        (unsigned int)hdr->sender_id, (unsigned int)fork_req->tgid, 
                        (unsigned int)fork_req->pid);
                ret = -ERR_DISAGG_FORK_NO_PREV;
            }
        }else{
            // 2) normal fork
            ret = mn_create_mm_from(hdr->sender_id, fork_req->tgid, fork_req->pid,
                                    old_tsk, fork_req->clone_flags);
            if (!ret)
            {
                pr_info("Copied task/mm inserted: sender: %u, tgid: %u, pid: %u, prev_tgid: %u, prev_pid: %u\n",
                        (unsigned int)hdr->sender_id,
                        (unsigned int)fork_req->tgid, (unsigned int)fork_req->pid,
                        (unsigned int)fork_req->prev_tgid, (unsigned int)fork_req->prev_pid);
            }
        }

        if (!ret)
        {
            finfo = mn_get_file(hdr->sender_id, fork_req->tgid);
            if (finfo)
            {
                open_file(finfo, fork_req->tgid, fork_req->comm);
            }
            else
            {
                pr_info("** Cannot find file info\n");
            }
        }

    }else{
        pr_warn("FORK: try to overwrite existing process: %u\n", (unsigned int)fork_req->tgid);
        ret = -ERR_DISAGG_FORK_THREAD;

        // just increase reference
        increase_utgid_ref(hdr->sender_id, fork_req->tgid);
    }
    reply->ret = ret;
    reply->vma_count = 0;    //TODO: not used for now
    return ret;
}

int handle_fork(struct mem_header* hdr, void* payload, struct socket *sk, int id){
    struct fork_reply_struct reply;
    int ret = __handle_fork(hdr, payload, &reply);
    tcp_server_send(sk, id, (const char*)&reply, sizeof(reply), MSG_DONTWAIT);
    return ret;
}

int handle_fork_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb)
{
	void* out_buf = NULL;
    int ret;
    struct fork_reply_struct reply;
    struct mem_header hdr;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;
    
    ret = __handle_fork(&hdr, payload, &reply);
    out_buf = thpool_buffer_tx(tb);
	// memset(out_buf, 0, DISAGG_NET_SIMPLE_BUFFER_LEN);
	memcpy(out_buf, &reply, sizeof(reply));
	tb_set_tx_size(tb, sizeof(reply));

    pr_debug("Fork - Data via RDMA: ret: %d, vma_cnt: %u\n",
            reply.ret, reply.vma_count);

	return ret;
}

static int __handle_exec(struct mem_header* hdr, void* payload){
    struct exec_msg_struct *exec_req = 
        (struct exec_msg_struct*) payload;
    int ret = -1;

    ret = mn_update_mm(hdr->sender_id, exec_req->tgid, exec_req);
    reopen_file(mn_get_file(hdr->sender_id, exec_req->tgid), 
            exec_req->tgid, exec_req->comm);

    // TODO: do we need check the error here and free the task and mm structures?
    // Maybe when they are killed in computing node, it also be notified
    
    return ret;
}

int handle_exec(struct mem_header* hdr, void* payload){
    return __handle_exec(hdr, payload);
}

int handle_exec_rdma(struct common_header* chdr, void* payload)
{
    struct mem_header hdr;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;

    return __handle_exec(&hdr, payload);
}


static int __handle_exit(struct mem_header* hdr, void* payload, struct exit_reply_struct *reply)
{
    struct exit_msg_struct *exit_req = (struct exit_msg_struct *) payload;
    struct task_struct *tsk = mn_get_task(hdr->sender_id, exit_req->tgid);
    int ret = 0;

    if (tsk)    // Not needed but only for checking ret
    {
        // ret = mn_exit(hdr->sender_id, exec_req->tgid, tsk);
        mn_delete_task(hdr->sender_id, exit_req->tgid);
        reply->ret = ret;
        pr_info("EXIT: tgid: %d\n", (int)exit_req->tgid);
    }else{
        reply->ret = -ERR_DISAGG_EXIT_NO_TASK; // no task found
    }
    
    return ret;
}

int handle_exit(struct mem_header* hdr, void* payload, struct socket *sk, int id)
{
    struct exit_reply_struct reply;
    int ret = __handle_exit(hdr, payload, &reply);
    tcp_server_send(sk, id, (const char*)&reply, sizeof(reply), MSG_DONTWAIT);
    return ret;
}

int handle_exit_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb)
{
    void* out_buf = NULL;
    int ret;
    struct exit_reply_struct reply;
    struct mem_header hdr;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;

    ret = __handle_exit(&hdr, payload, &reply);
    out_buf = thpool_buffer_tx(tb);
	memcpy(out_buf, &reply, sizeof(reply));
	tb_set_tx_size(tb, sizeof(reply));

    pr_debug("EXIT - Data via RDMA [%d]: ret: %d, msg_len: %lu\n",
            ret, reply.ret, sizeof(reply));

	return ret;
}

static int __handle_mmap(struct mem_header* hdr, void* payload, struct mmap_reply_struct *reply){
    struct mmap_msg_struct *mmap_req = (struct mmap_msg_struct *) payload;
    struct task_struct *tsk = mn_get_task(hdr->sender_id, mmap_req->tgid);
    unsigned long addr = -ENOMEM;
    struct file_info *finfo = NULL;

    if (tsk)
    {
        addr = mn_do_mmap(tsk, mmap_req->addr, mmap_req->len, mmap_req->prot,
                          mmap_req->flags, mmap_req->vm_flags, mmap_req->pgoff, 
                          (struct file *)mmap_req->file_id);
        if (IS_ERR_VALUE(addr))
        {
            reply->ret = -1;
        }else{
            reply->ret = 0;
        }
        pr_info("MMAP: tgid: %d, pid: %d, addr: 0x%lx, flag: 0x%lx, len: %lu\n",
                (int)mmap_req->tgid, (int)mmap_req->pid, addr, mmap_req->vm_flags, mmap_req->len);

        // write into the file
        finfo = mn_get_file(hdr->sender_id, mmap_req->tgid);
        if (finfo && finfo->file)
        {
            char str_data[256] = {0};
            char str_time[32] = {0};

            get_timestamp(str_time, 32);
            sprintf(str_data, "%s, %d, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, %d\n",
                    str_time, DISSAGG_MMAP, addr, mmap_req->len, mmap_req->addr,
                    mmap_req->vm_flags, mmap_req->pgoff, (int)mmap_req->file_id);
            write_file(finfo, str_data);
        }
    }else{
        reply->ret = -1;
    }
    reply->addr = addr;
    return IS_ERR_VALUE(addr) ? -1 : 0;
}

int handle_mmap(struct mem_header* hdr, void* payload, struct socket *sk, int id){
    struct mmap_reply_struct reply;
    int ret = __handle_mmap(hdr, payload, &reply);
    tcp_server_send(sk, id, (const char*)&reply, sizeof(reply), MSG_DONTWAIT);
    return ret;
}

int handle_mmap_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb)
{
    void* out_buf = NULL;
    int ret;
    struct mmap_reply_struct reply;
    struct mem_header hdr;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;
    reply.ret = -1;
    reply.addr = 0;

    ret = __handle_mmap(&hdr, payload, &reply);
    out_buf = thpool_buffer_tx(tb);
	memcpy(out_buf, &reply, sizeof(reply));
	tb_set_tx_size(tb, sizeof(reply));

    pr_debug("MMAP - Data via RDMA [%d]: ret: %ld, addr: 0x%lx, msg_len: %lu\n",
            ret, reply.ret, reply.addr, sizeof(reply));

	return ret;
}

static int __handle_brk(struct mem_header* hdr, void* payload, struct brk_reply_struct *reply)
{
    struct brk_msg_struct *brk_req = 
        (struct brk_msg_struct *) payload;
    int ret = -1;
    struct file_info *finfo = NULL;
    struct task_struct *tsk = mn_get_task(hdr->sender_id, brk_req->tgid);
    unsigned long addr = (unsigned long)NULL;

    if (tsk)
    {
        unsigned long prev_brk = tsk->mm->brk;
        addr = mn_do_brk(tsk, brk_req->addr);
        if (IS_ERR_VALUE(addr))
        {
            addr = (unsigned long)NULL;
            ret = -1;
        }else{
            ret = 0;
        }

        // write into the file
        finfo = mn_get_file(hdr->sender_id, brk_req->tgid);
        if (finfo && finfo->file)
        {
            char str_data[256] = {0};
            char str_time[32] = {0};

            get_timestamp(str_time, 32);
            sprintf(str_data, "%s, %d, 0x%lx, 0x%lx\n",
                    str_time, DISSAGG_BRK, brk_req->addr, prev_brk);
            write_file(finfo, str_data);
        }
        // print out inside function
        // pr_info("BRK: addr: 0x%lx\n", addr);
    }
    
    reply->ret = ret;
    reply->addr = addr;
    return ret;
}

int handle_brk(struct mem_header* hdr, void* payload, struct socket *sk, int id)
{
    struct brk_reply_struct reply;
    int ret = __handle_brk(hdr, payload, &reply);
    tcp_server_send(sk, id, (const char*)&reply, sizeof(reply), MSG_DONTWAIT);
    return ret;
}

int handle_brk_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb)
{
    void* out_buf = NULL;
    int ret;
    struct brk_reply_struct reply;
    struct mem_header hdr;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;

    ret = __handle_brk(&hdr, payload, &reply);
    out_buf = thpool_buffer_tx(tb);
	memcpy(out_buf, &reply, sizeof(reply));
	tb_set_tx_size(tb, sizeof(reply));

    pr_debug("BRK - Data via RDMA [%d]: ret: %d, addr: 0x%lx, msg_len: %lu\n",
            ret, reply.ret, reply.addr, sizeof(reply));

	return ret;
}

static int __handle_munmap(struct mem_header* hdr, void* payload, struct munmap_reply_struct *reply)
{
    struct munmap_msg_struct *munmap_req = 
        (struct munmap_msg_struct *) payload;
    
    int ret = -1;
    struct file_info *finfo = NULL;
    struct task_struct *tsk = mn_get_task(hdr->sender_id, munmap_req->tgid);
 
    if (tsk && tsk->mm)
    {
        ret = mn_do_munmap(tsk->mm, munmap_req->addr, munmap_req->len);
        pr_info("MUNMAP: tgid: %d, pid: %d, addr: 0x%lx, len: %lu, res: %d\n", 
                (int)munmap_req->tgid, (int)munmap_req->pid, 
                munmap_req->addr, munmap_req->len, ret);

        // write into the file
        finfo = mn_get_file(hdr->sender_id, munmap_req->tgid);
        if (finfo && finfo->file)
        {
            char str_data[256] = {0};
            char str_time[32] = {0};

            get_timestamp(str_time, 32);
            sprintf(str_data, "%s, %d, 0x%lx, 0x%lx\n",
                    str_time, DISSAGG_MUNMAP, munmap_req->addr, munmap_req->len);
            write_file(finfo, str_data);
        }
    }
    reply->ret = ret;
    return ret;
}

int handle_munmap(struct mem_header* hdr, void* payload, struct socket *sk, int id)
{
    struct munmap_reply_struct reply;
    int ret = __handle_munmap(hdr, payload, &reply);
    tcp_server_send(sk, id, (const char*)&reply, sizeof(reply), MSG_DONTWAIT);
    return ret;
}

int handle_munmap_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb)
{
    void* out_buf = NULL;
    int ret;
    struct munmap_reply_struct reply;
    struct mem_header hdr;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;

    ret = __handle_munmap(&hdr, payload, &reply);
    out_buf = thpool_buffer_tx(tb);
	memcpy(out_buf, &reply, sizeof(reply));
	tb_set_tx_size(tb, sizeof(reply));

    pr_debug("MUNMAP - Data via RDMA [%d]: ret: %d, msg_len: %lu\n",
            ret, reply.ret, sizeof(reply));

	return ret;
}

static int __handle_mremap(struct mem_header* hdr, void* payload, struct mremap_reply_struct *reply)
{
    struct mremap_msg_struct *mremap_req = 
        (struct mremap_msg_struct *) payload;
    
    int ret = -1;
    unsigned long addr = (unsigned long)NULL;
    struct task_struct *tsk = mn_get_task(hdr->sender_id, mremap_req->tgid);
 
    if (tsk && tsk->mm)
    {
        addr = mn_do_mremap(tsk, mremap_req->addr, mremap_req->old_len, 
                            mremap_req->new_len, mremap_req->flags, 
                            mremap_req->new_addr); // return new addr
        if (IS_ERR_VALUE(addr))
        {
            addr = (unsigned long)NULL;
            ret = -1;
        }else
            ret = 0;
        // print out inside function instead of here
        pr_info("MREMAP: tgid: %d, pid: %d, n_addr: 0x%lx, n_len: %lu, res: %d\n",
                (int)mremap_req->tgid, (int)mremap_req->pid, addr, mremap_req->new_len, ret);
    }
    reply->ret = ret;
    reply->new_addr = addr;
    return ret;
}

int handle_mremap(struct mem_header* hdr, void* payload, struct socket *sk, int id)
{
    struct mremap_reply_struct reply;
    int ret = __handle_mremap(hdr, payload, &reply);
    tcp_server_send(sk, id, (const char*)&reply, sizeof(reply), MSG_DONTWAIT);
    return ret;
}

int handle_mremap_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb)
{
    void* out_buf = NULL;
    int ret;
    struct mremap_reply_struct reply;
    struct mem_header hdr;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;

    ret = __handle_mremap(&hdr, payload, &reply);
    out_buf = thpool_buffer_tx(tb);
	memcpy(out_buf, &reply, sizeof(reply));
	tb_set_tx_size(tb, sizeof(reply));

    pr_debug("MREMAP - Data via RDMA [%d]: ret: %d, addr: 0x%lx, msg_len: %lu\n",
            ret, reply.ret, reply.new_addr, sizeof(reply));

	return ret;
}

static int __handle_data(struct mem_header* hdr, void* payload)
{
    struct fault_data_struct *data_req = 
        (struct fault_data_struct*) payload;
    int ret = 0;
    ret = mn_push_data(hdr->sender_id, data_req->tgid, data_req);
    
    return ret;
}

int handle_data(struct mem_header* hdr, void* payload){
    return __handle_data(hdr, payload);
}

int handle_data_rdma(struct common_header* chdr, void* payload)
{
    struct mem_header hdr;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;
    return __handle_data(&hdr, payload);
}

static int __handle_pfault(struct mem_header* hdr, void* payload, struct fault_reply_struct **reply)
{
    struct fault_msg_struct *fault_req = (struct fault_msg_struct *) payload;
    int ret = -1;
    // unsigned long addr = (unsigned long)NULL;
    struct task_struct *tsk = mn_get_task(hdr->sender_id, fault_req->tgid);
    unsigned long data_size = 0;
    unsigned long vm_start = 0;
    unsigned long vm_end = 0;
    unsigned long vm_flags = 0;
    void *data_buf = NULL;
 
    if (tsk && tsk->mm)   // no existing entry
    {
        ret = mn_handle_fault(tsk, fault_req->error_code,
                            fault_req->address, fault_req->flags, 
                            &data_buf, &data_size, &vm_start, &vm_end, &vm_flags);
        pr_debug("PgFault: tgid: %d, pid: %d, addr: 0x%lx, data_size: %lu, res: %d\n",
                 (int)fault_req->tgid, (int)fault_req->pid, fault_req->address, data_size, ret);

        if (ret == DISAGG_FAULT_WRITE || ret == DISAGG_FAULT_READ)
        {
            // write into the file
            struct file_info *finfo = mn_get_file(hdr->sender_id, fault_req->tgid);
            if (finfo && finfo->file)
            {
                char str_data[256] = {0};
                char str_time[32] = {0};

                get_timestamp(str_time, 32);
                sprintf(str_data, "%s, %d, %d, 0x%lx\n",
                        str_time, DISSAGG_PFAULT, ret, fault_req->address);
                write_file(finfo, str_data);
            }
        }
    }else{
        pr_err("PgFault: tgid: %d, pid: %d not exist\n", (int)fault_req->tgid, (int)fault_req->pid);
    }
    // TODO: we can make it as one copy instead of two copies: 
    //          give reply buf instead of tmp buf
    *reply = kzalloc(sizeof(struct fault_reply_struct) + data_size, GFP_KERNEL);
    if (!(*reply))
    {
        ret = -1;
        goto pfault_release;
    }
    (*reply)->ret = ret;    // return code or error
    (*reply)->vm_start = vm_start;
    (*reply)->vm_end = vm_end;
    (*reply)->vm_flags = vm_flags;
    (*reply)->data_size = data_size;
    (*reply)->tgid = fault_req->tgid;
    (*reply)->pid = fault_req->pid;
    (*reply)->address = fault_req->address;
    if (data_size > 0)
        memcpy(&((*reply)->data), data_buf, data_size);
    barrier();
    ret = 0;
    
pfault_release:
    if (data_buf)
        kfree(data_buf);

    return ret;
}

int handle_pfault(struct mem_header* hdr, void* payload, struct socket *sk, int id)
{
    struct fault_reply_struct *reply = NULL;
    int ret = -1;
    
    ret = __handle_pfault(hdr, payload, &reply);

    if (!ret && reply)
    {
        tcp_server_send(sk, id, (const char*)reply, sizeof(*reply) + reply->data_size, MSG_DONTWAIT);
        ret = 0;   // must return 0 if it sent reply
    }

    if (reply)
        kfree(reply);
    
    return ret;
}

int handle_pfault_rdma(struct common_header* chdr, void* payload, struct thpool_buffer *tb)
{
    void* out_buf = NULL;
    int ret = -1;
    struct fault_reply_struct *reply = NULL;
    struct mem_header hdr;
    u32 tot_size = 0;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;

    ret = __handle_pfault(&hdr, payload, &reply);

    if (!ret && reply)
    {
        out_buf = thpool_buffer_tx(tb);

        // we assume that sizeof(*reply) + data_size < THPOOL_TX_SIZE
        // TODO: minimize copy by passing out_buf (and do not kmalloc inside __handle_pfault)
        tot_size = sizeof(*reply) + reply->data_size - sizeof(char);
        if (!reply->data_size)
            tot_size += 4;  // 4-byte alignment
        memcpy(out_buf, (void*)reply, tot_size);
        tb_set_tx_size(tb, tot_size);
        ret = 0;
        barrier();

        pr_debug("PgFault - Data via RDMA [%d]: ret: %d, addr: 0x%lx, msg_len: %u\n",
            ret, reply->ret, reply->address, tot_size);
    }else{
        pr_info("PgFault - Data via RDMA [%d] w/ error\n", ret);
        //ret should be set inside __handle_pfault
    }

    if (reply)
        kfree(reply);

    return ret;
}

static int __handle_check(struct mem_header* hdr, void* payload)
{
    struct exec_msg_struct *exec_req = 
        (struct exec_msg_struct*) payload;
    int ret = -1;

    ret = mn_check_vma(hdr->sender_id, exec_req->tgid, exec_req);
    return ret;
}

int handle_check(struct mem_header* hdr, void* payload)
{
    return __handle_check(hdr, payload);
}

int handle_check_rdma(struct common_header* chdr, void* payload)
{
    struct mem_header hdr;
    hdr.opcode = chdr->opcode;
    hdr.sender_id = chdr->src_nid;

    return __handle_check(&hdr, payload);
}
