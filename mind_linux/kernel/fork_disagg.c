/*
 * Header file of fork and disaggregated fork functions
 */
#include <linux/fork.h>
#include <disagg/fork_disagg.h>
#include <disagg/network_disagg.h>
#include <disagg/exec_disagg.h>
#include <disagg/print_disagg.h>
#include <linux/exec.h>

size_t count_read_only_file_mappings(struct task_struct *tsk) {
    struct vm_area_struct *cur = tsk->mm->mmap;
	struct vm_area_struct *prev, *next;
	//struct mm_struct *mm = tsk->mm;
    size_t ret = 0;

    barrier();
    while (cur) {
		next = cur->vm_next;
		prev = cur->vm_prev;
        if (!vma_is_anonymous(cur) && !(cur->vm_flags & VM_WRITE)) {
            if (cur->vm_file) {
                //must be a real file instead of vvar and vdso
                ++ret;
            }
        }
        cur = next;
    }
    return ret;
}

int fill_fork_msg_mappings(struct fork_msg_struct *fork_msg, struct task_struct *tsk) {
    struct vm_area_struct *cur = tsk->mm->mmap;
	struct vm_area_struct *prev, *next;
	//struct mm_struct *mm = tsk->mm;
    int ret = 0;
    int map_idx = 0;
    struct file_mapping_info *file_mapping_info = &(fork_msg->file_mapping_infos);
    //char buf[MAX_FILE_PATH_NAME];
    char *path = NULL;
    char *buf = kmalloc(MAX_FILE_PATH_NAME, GFP_KERNEL);
    if (!buf) {
        ret = -ENOMEM;
        goto out;
    }

    barrier();
    while (cur) {
		next = cur->vm_next;
		prev = cur->vm_prev;
        if (!vma_is_anonymous(cur) && !(cur->vm_flags & VM_WRITE)) { 
            if (!(cur->vm_file)) {
                pr_info("%lx-%lx is vvar or vdso\n",
                        cur->vm_start, cur->vm_end);
                cur = next;
                continue;
            }
            //filename
            path = dentry_path_raw(cur->vm_file->f_path.dentry, buf, MAX_FILE_PATH_NAME);
            if (IS_ERR(path)) {
                printk("error retrieving file name[%lx]\n", (unsigned long)PTR_ERR(path));
                ret = PTR_ERR(path);
                goto out;
            }
            memset(file_mapping_info->filename, 0, MAX_FILE_PATH_NAME);
            memcpy(file_mapping_info->filename, path, strlen(path));
            //addr & len & offset
            file_mapping_info->addr = cur->vm_start;
            file_mapping_info->len = cur->vm_end - cur->vm_start;
            file_mapping_info->offset = cur->vm_pgoff << PAGE_SHIFT;
            //prot & flag
            file_mapping_info->prot = ((cur->vm_flags | VM_READ) ? PROT_READ : 0)
                | ((cur->vm_flags | VM_EXEC) ? PROT_EXEC : 0);
            file_mapping_info->flag = MAP_PRIVATE | MAP_DENYWRITE | MAP_EXECUTABLE | MAP_FIXED;
            //print it
            pr_info("[%u] %lx-%lx %lx %s\n", map_idx, cur->vm_start, cur->vm_end,
                file_mapping_info->offset, file_mapping_info->filename);
            ++map_idx;
            ++file_mapping_info;
        }
        cur = next;
    }
out:
    if (buf)
        kfree(buf);
    return ret;
}

static void print_hwcontext(struct fork_msg_struct *fm) {
    struct pt_regs *regs = &fm->regs;
    struct desc_struct *tls_array = fm->tls_array;
    printk("regs info:\nr15:\t%lx\nr14:\t%lx\nr13:\t%lx\nr12:\t%lx\nbp:\t%lx\nbx:\t%lx\nr11:\t%lx\nr10:\t%lx\nr9:\t%lx\nr8:\t%lx\nax:\t%lx\ncx:\t%lx\ndx:\t%lx\nsi:\t%lx\ndi:\t%lx\norig_ax:\t%lx\nip:\t%lx\ncs:\t%lx\nflags:\t%lx\nsp:\t%lx\nss:\t%lx\nclone_flags:\t%x\ngsindex:\t%hx\nfsindex:\t%hx\nes:\t%hx\nds:\t%hx\ngsbase:\t%lx\nfsbase:\t%lx\ntls_arr0:\t%llx\ntls_arr1:\t%llx\ntls_arr2:\t%llx\n",
        regs->r15, regs->r14, regs->r13, regs->r12, regs->bp, regs->bx, regs->r11, regs->r10, regs->r9, regs->r8, regs->ax, regs->cx, regs->dx, regs->si, regs->di, regs->orig_ax, regs->ip, regs->cs, regs->flags, regs->sp, regs->ss, fm->clone_flags, fm->gsindex, fm->fsindex, fm->es, fm->ds, fm->gsbase, fm->fsbase, *(u64 *)tls_array, *(((u64 *)tls_array) + 1), *(((u64 *)tls_array) + 2));
}

int fill_fork_msg_hwcontext(struct fork_msg_struct *fork_msg, struct task_struct *tsk) {
    fork_msg->regs = *task_pt_regs(tsk);
    fork_msg->ds = tsk->thread.ds;
    fork_msg->es = tsk->thread.es;
    fork_msg->fsindex = tsk->thread.fsindex;
    fork_msg->gsindex = tsk->thread.gsindex;
    fork_msg->fsbase = tsk->thread.fsbase;
    fork_msg->gsbase = tsk->thread.gsbase;
    memcpy(fork_msg->tls_array, tsk->thread.tls_array,
            sizeof(struct desc_struct) * GDT_ENTRY_TLS_ENTRIES);
    //print it
    printk("%s\n", tsk->comm);
    print_hwcontext(fork_msg);
    return 0;
}

static int send_copy_mm(struct task_struct *tsk, unsigned long clone_flags)
{
    //struct fork_msg_struct payload;
    struct fork_msg_struct *payload;
    struct fork_reply_struct *reply;
    int ret;    //, rdma_ret;
    size_t tot_size;
    unsigned num_file_mappings;

    reply = kmalloc(sizeof(struct fork_reply_struct), GFP_KERNEL);
	if (!reply)
        return -ENOMEM;

    num_file_mappings = count_read_only_file_mappings(tsk);
    tot_size = sizeof(*payload) + (num_file_mappings - 1) * sizeof(struct file_mapping_info);
    payload = kmalloc(tot_size, GFP_KERNEL);
    if (!payload)
        return -ENOMEM;

    payload->pid = tsk->pid;
	payload->tgid = tsk->tgid;
	// payload.parent_tgid = tsk->real_parent->tgid;
    payload->prev_pid = current->pid;
    payload->prev_tgid = current->tgid;
    payload->clone_flags = clone_flags;
    payload->clear_child_tid = (unsigned long)(tsk->clear_child_tid);
	memcpy(payload->comm, tsk->comm, TASK_COMM_LEN);

    payload->num_file_mappings = num_file_mappings;
    fill_fork_msg_mappings(payload, tsk);
    fill_fork_msg_hwcontext(payload, tsk);

pr_info("send fork tgid[%d] pid[%d] size[%lu]\n", payload->pid, payload->tgid, tot_size);

    ret = send_msg_to_memory(DISSAGG_FORK, payload, tot_size, 
                             reply, sizeof(*reply));
    // rdma_ret = send_msg_to_memory_rdma(DISSAGG_FORK, &payload, sizeof(payload),
    //                          reply, sizeof(*reply));
    // ret = rdma_ret;
    printk(KERN_DEFAULT "Fork - Data from CTRL [%d]: ret: %d, vma_cnt: %u [0x%llx]\n",
           ret, reply->ret, reply->vma_count, *(long long unsigned *)(reply));

    if (reply->ret)    // only 0 is success
		ret = reply->ret;   // set error

    kfree(reply);
    return ret; // error for ret < 0
}

/*
 * Currently this function forward request to memory node 
 * while it just use the local functions
 */
static atomic_t test_program_thread_cnt;
atomic_t *get_test_program_thread_cnt(void)
{
    return &test_program_thread_cnt;
}

void init_test_program_thread_cnt(void)
{
    atomic_set(&test_program_thread_cnt, 0);
}

int disagg_fork(unsigned long clone_flags, struct task_struct *tsk)
{
    /* TODO: there will be no sync in here, because copy from
     * existing mm_struct should not be a problem since they
     * only have page table of the local/static/read-only data
     */
    int err = 0;
    int cnt = atomic_inc_return(get_test_program_thread_cnt());
    if (tsk->is_remote)
        pr_syscall("FORK: cnt[%d]\n", cnt);
retry_send_msg:
    if (0/*tsk->is_test && cnt > 1*/)
    {
        err = 0;
    }
    else
    {
        err = send_copy_mm(tsk, 0);
    }

    if (err < 0){
        if (err == -ERR_DISAGG_FORK_NO_PREV)
        {
            // send exec sync
            printk(KERN_ERR "FORK - no existing proc: send exec sync: %s\n", tsk->comm);
            
            // Erase all the write-able: we need to hold mmap_sem
            down_write(&tsk->mm->mmap_sem);
            err = cn_notify_exec(tsk);
            up_write(&tsk->mm->mmap_sem);
        }
        else if (err == -ERR_DISAGG_FORK_THREAD)
        {
            printk(KERN_WARNING "New thread added, %s\n", tsk->comm);
        }
        else if (err == -ERR_DISAGG_FORK_REMOTE_THREAD)
        {
            printk(KERN_WARNING "New remote thread added, %s\n", tsk->comm);
            tsk->run_on_other_node = 1;
        }
        else
        {
            printk(KERN_ERR "Cannot send copy_mm() to memory (%d), %s\n", 
                    err, tsk->comm);
            msleep(250);
            goto retry_send_msg;
        }
    }else{
        // Erase all the write-able: we need to hold mmap_sem
        down_write(&tsk->mm->mmap_sem);
        err = cn_notify_fork(tsk);
        up_write(&tsk->mm->mmap_sem);
    }
    
    // printk(KERN_DEFAULT "Forwarded data to memory node\n");
    // TODO: lock will be needed for accessing tsk->comm
    // TODO: #ifdef CONFIG_DISAGGREGATION_DEBUG   
    // if(tsk && tsk->comm){
    //     printk(KERN_DEFAULT "Copy_mm: %s (uid:%d) -> %s (uid:%d)\n", 
    //             current->comm, (int)current->cred->uid.val,
    //             tsk->comm, (int)tsk->cred->uid.val);
    // }
	//return copy_mm(clone_flags, tsk);
    return err;
}

int disagg_fork_report_only(struct task_struct *tsk)
{
    atomic_inc(get_test_program_thread_cnt());
    return send_copy_mm(tsk, 0);
}

int disagg_fork_for_test(struct task_struct *tsk)
{
    /* TODO: there will be no sync in here, because copy from
     * existing mm_struct should not be a problem since they
     * only have page table of the local/static/read-only data
     */
    int err = 0;
    err = send_copy_mm(tsk, 0);
    if (err < 0)
    {
        if (err == -ERR_DISAGG_FORK_NO_PREV)
        {
            err = 0;
        }
        else if (err == -ERR_DISAGG_FORK_THREAD)
        {
            printk(KERN_WARNING "New thread added, %s\n", tsk->comm);
        }
        else
        {
            printk(KERN_ERR "Cannot send copy_mm() to memory (%d), %s\n",
                   err, tsk->comm);
        }
    }
    return err;
}
EXPORT_SYMBOL(disagg_fork_for_test); // for unit test in RoceModule
