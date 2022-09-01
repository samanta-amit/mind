/*
 * Header file of exec and disaggregated exec functions
 */
#include <linux/exec.h>
#include <disagg/config.h>
#include <disagg/exec_disagg.h>
#include <disagg/network_disagg.h>
#include <disagg/fault_disagg.h>
#include <disagg/cnthread_disagg.h>
#include <disagg/profile_points_disagg.h>
#include <disagg/print_disagg.h>

#include <linux/mm.h>
#include <linux/rmap.h>
#include <linux/mempolicy.h>
#include <asm/pgtable_types.h>
#include <asm/pgtable.h>
#include <asm/mman.h>

int count_vm_field(struct task_struct *tsk)
{
	int tot_num = 0;
	struct vm_area_struct *mpnt;
	for (mpnt = tsk->mm->mmap; mpnt; mpnt = mpnt->vm_next)
	{
		tot_num ++;
	}
	return tot_num;
}

int init_vma_field(struct exec_vmainfo *_vma_buf, struct task_struct *tsk)
{
	int res = 0;
	struct vm_area_struct *mpnt;
	struct exec_vmainfo *vma_buf = _vma_buf;
	for (mpnt = tsk->mm->mmap; mpnt; vma_buf++, mpnt = mpnt->vm_next)
	{
		if (mpnt->vm_start <= tsk->mm->start_stack && tsk->mm->start_stack < mpnt->vm_end)
		{
			// expand stack
			unsigned long stack_size = 8 * 1024 * 1024;	// pre-allocatedc 8 MB
			if (expand_stack(mpnt, mpnt->vm_end - stack_size))
			{
				BUG();
			}
		}
		// TODO: copy other important information
		vma_buf->vm_start = mpnt->vm_start;
		vma_buf->vm_end = mpnt->vm_end;
		vma_buf->vm_flags = mpnt->vm_flags;
		vma_buf->vm_pgoff = mpnt->vm_pgoff;
		vma_buf->rb_substree_gap = mpnt->rb_subtree_gap;
		vma_buf->vm_page_prot = mpnt->vm_page_prot.pgprot;
		// use file pointer as an identifier
		vma_buf->file_id = (unsigned long)(mpnt->vm_file);

		//for multithreading, make switch recard writable file mappings also as anonymous mapping,
		//so that we won't have a permission fault when remotely accessing writable file mappings.
		//another way is to change the permission check rules on the switch
		if (mpnt->vm_flags & VM_WRITE) {

			vma_buf->file_id = 0;
		}

		// printk(KERN_DEFAULT "vma copy to: 0x%lx", (long unsigned int)vma_buf);
		//print out
		printk("vma[%ld] [%lx, %lx] perm[%lx] file[%lx]\n", (long)(vma_buf - _vma_buf),
				vma_buf->vm_start, vma_buf->vm_end, vma_buf->vm_flags, vma_buf->file_id);
	}

	return res;
}

void disagg_print_va_layout(struct mm_struct *mm)
{
	/*
	pr_syscall("** CN-VA layout **\n");
	pr_syscall("-total: %lu pages\n", mm->total_vm);
	pr_syscall("-code: 0x%lx - 0x%lx\n", mm->start_code, mm->end_code);
	pr_syscall("-data: 0x%lx - 0x%lx\n", mm->start_data, mm->end_data);
	pr_syscall("-brk: 0x%lx - 0x%lx\n", mm->start_brk, mm->brk);
	pr_syscall("-stack: 0x%lx\n", mm->start_stack);
	pr_syscall("-arg: 0x%lx - 0x%lx\n", mm->arg_start, mm->arg_end);
	pr_syscall("-env: 0x%lx - 0x%lx\n", mm->env_start, mm->env_end);
	*/
	pr_info("** CN-VA layout **\n");
	pr_info("-total: %lu pages\n", mm->total_vm);
	pr_info("-code: 0x%lx - 0x%lx\n", mm->start_code, mm->end_code);
	pr_info("-data: 0x%lx - 0x%lx\n", mm->start_data, mm->end_data);
	pr_info("-brk: 0x%lx - 0x%lx\n", mm->start_brk, mm->brk);
	pr_info("-stack: 0x%lx\n", mm->start_stack);
	pr_info("-arg: 0x%lx - 0x%lx\n", mm->arg_start, mm->arg_end);
	pr_info("-env: 0x%lx - 0x%lx\n", mm->env_start, mm->env_end);
}

#define CN_COPY_MM_VALUES(EXR, MM, F)	(EXR->F = MM->F)

static void cn_set_up_layout(struct exec_msg_struct* payload,
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

// DEFINE_PROFILE_POINT(exec_send_to_memory)
int cn_copy_vma_to_mn(struct task_struct *tsk, u32 msg_type)
{
struct exec_msg_struct *payload;
    struct exec_reply_struct reply;
	int ret = 0;	//rdma_ret
	size_t tot_size = sizeof(struct exec_msg_struct);
	// PROFILE_POINT_TIME(exec_send_to_memory)

	if (msg_type != DISSAGG_CHECK_VMA)
	{
		ret = count_vm_field(tsk);
		if (ret > 0)
			tot_size += sizeof(struct exec_vmainfo) * (ret-1);
	}
	// printk(KERN_DEFAULT "EXEC - VMA SIZE: %lu", tot_size);

	// calculate number of vmas
	// allocate size: struct size + vmas
    payload = (struct exec_msg_struct*)kmalloc(tot_size, GFP_KERNEL);
	if (!payload)
        return -ENOMEM;
	
	// reply = kmalloc(sizeof(struct exec_reply_struct), GFP_KERNEL);
	// if (!reply)
	// {
	// 	kfree(payload);
	// 	return -ENOMEM;
	// }

    payload->pid = tsk->pid;
	payload->tgid = tsk->tgid;
	memcpy(payload->comm, tsk->comm, TASK_COMM_LEN);
	cn_set_up_layout(payload, tsk->mm);

	// put vma information
	payload->num_vma = (u32)ret;
	if (msg_type != DISSAGG_CHECK_VMA)
		init_vma_field(&payload->vmainfos, tsk);

	// PROFILE_START(exec_send_to_memory);
	ret = send_msg_to_memory(msg_type, payload, tot_size, 
                             &reply, sizeof(reply));
	// if (msg_type == DISSAGG_CHECK_VMA)
	// 	PROFILE_LEAVE(exec_send_to_memory);
	// rdma_ret = ret;
	// rdma_ret = send_msg_to_memory_rdma(msg_type, payload, tot_size,
	// 								   reply, sizeof(*reply));
	// printk(KERN_DEFAULT "EXEC - Data from RDMA [%d]: [0x%llx]\n",
	// 	   rdma_ret, *(long long unsigned *)(reply));

	// Now, ret is the received length (may not for RDMA)
	if (ret < 0)
	{
		printk(KERN_ERR "Cannot send EXEC notification - err: %d [%s]\n", 
				ret, tsk->comm);
		// printk(KERN_ERR "** EXEC - Data from RDMA [%d]: [0x%llx]\n",
		// 		rdma_ret, *(long long unsigned*)(reply));
		goto cn_notify_out;
	}
	ret = 0;

cn_notify_out:
    kfree(payload);
	// kfree(reply);
    return ret;
}

static int exec_copy_page_data_to_mn(u16 tgid, struct mm_struct *mm, unsigned long addr,
									 pte_t *pte)
{
	return cn_copy_page_data_to_mn(tgid, mm, addr, pte, CN_ONLY_DATA, 0, NULL);
}

static int _send_cache_dir_full_check(u16 tgid, u64 vaddr, u16 *state, u16 *sharer,
							  u16 *dir_size, u16 *dir_lock, u16 *inv_cnt, int sync_direction)
{
	struct exec_msg_struct *payload;
	struct exec_reply_struct reply;
	int ret = 0; //rdma_ret
	size_t tot_size = sizeof(struct exec_msg_struct);

	payload = (struct exec_msg_struct *)kmalloc(tot_size, GFP_KERNEL);
	if (!payload)
		return -ENOMEM;

	payload->pid = tgid;
	payload->tgid = tgid;
	payload->brk = sync_direction;
	payload->stack_vm = (unsigned long)vaddr;
	ret = send_msg_to_memory(DISSAGG_CHECK_VMA, payload, tot_size,
							 &reply, sizeof(reply));
	if (ret < 0)
	{
		printk(KERN_ERR "Cannot send %s notification - err: %d\n",
			   __func__, ret);
		goto cn_notify_out;
	}else{
		*state = (u16)(reply.ret >> 16);	//first 16 digit
		*sharer = (u16)(reply.ret & 0xffff); //second 16 digit
		if (dir_size)
			*dir_size = (u16)(reply.vma_count >> 16);
		if (dir_lock)
			*dir_lock = (u16)(reply.vma_count & 0x8000);
		if (inv_cnt)
			*inv_cnt = (u16)(reply.vma_count & 0x7fff);
	}
	ret = 0;

cn_notify_out:
	kfree(payload);
	// kfree(reply);
	return ret;
}
#ifdef PRINT_SWITCH_STATUS
int send_cache_dir_full_check(u16 tgid, u64 vaddr, u16 *state, u16 *sharer,
							  u16 *dir_size, u16 *dir_lock, u16 *inv_cnt, int sync_direction)
{return _send_cache_dir_full_check(tgid, vaddr, state, sharer, dir_size, dir_lock, inv_cnt, sync_direction);}
#else
int send_cache_dir_full_check(u16 tgid, u64 vaddr, u16 *state, u16 *sharer,
							  u16 *dir_size, u16 *dir_lock, u16 *inv_cnt, int sync_direction)
{return 0;}
#endif
EXPORT_SYMBOL(send_cache_dir_full_check);

int send_cache_dir_full_always_check(u16 tgid, u64 vaddr, u16 *state, u16 *sharer,
							  u16 *dir_size, u16 *dir_lock, u16 *inv_cnt, int sync_direction)
{return _send_cache_dir_full_check(tgid, vaddr, state, sharer, dir_size, dir_lock, inv_cnt, sync_direction);}
EXPORT_SYMBOL(send_cache_dir_full_always_check);

int send_cache_dir_check(u16 tgid, u64 vaddr, u16 *state, u16 *sharer, int sync_direction)
{
	return send_cache_dir_full_check(tgid, vaddr, state, sharer, NULL, NULL, NULL, sync_direction);
}
EXPORT_SYMBOL(send_cache_dir_check);

static void print_page_checksum(void *data_ptr, unsigned long addr) {
	unsigned long checksum = 0, *itr;
	for (itr = data_ptr; (char *)itr != ((char *)data_ptr + PAGE_SIZE); ++itr)
		checksum += *itr;
	pr_info("addr[%lx] checksum[%lx]\n", addr, checksum);
}

/* It copy data from file for a particular vma */
static int cn_copy_page_data_to_mn_from_file(u16 tgid,
        struct vm_area_struct *vma, unsigned long addr, off_t off_in_vma) {
    struct fault_data_struct payload;
    struct fault_reply_struct reply;
    int ret = 0;
    size_t data_size = PAGE_SIZE;
    void *data_ptr = NULL;
    long bytes;
    loff_t pos;

    data_ptr = kzalloc(data_size, GFP_KERNEL);
    if (!data_ptr) {
        ret = -ENOMEM;
        goto out;
    }

    payload.pid = tgid;
    payload.tgid = tgid;
    payload.address = addr;
    payload.data_size = (u32)data_size;
    payload.data = data_ptr;

    pos = (vma->vm_pgoff << PAGE_SHIFT) + off_in_vma;
    bytes = kernel_read(vma->vm_file, data_ptr, data_size, &pos);
    if (bytes != data_size) {
        ret = bytes;
		pr_err("fail to read writable file mapping from file\n");
        goto out;
    }

	else {
		print_page_checksum(data_ptr, addr);
	}

//double check
/*
char *check_ptr = kzalloc(data_size, GFP_KERNEL);
if (!check_ptr) {
	ret = -ENOMEM;
    goto out;
}
ssize_t dblen = copy_from_user(check_ptr, (void *)addr, data_size);
if (dblen)
	pr_err("fail to copy from user\n");
print_page_checksum(check_ptr, addr);
//
*/

    ret = send_msg_to_memory_rdma(DISSAGG_DATA_PUSH, &payload, data_size,
                                        &reply, sizeof(reply));
    if (ret < 0) {
        pr_cache("Cannot send page data - err: %d\n", ret);
        goto out;
    }
out:
    if (data_ptr)
        kfree(data_ptr);
	pr_info("page sent from file %lx ret[%d]\n", addr, ret);
    return ret;
}

/* It copy data from its own memory */
int cn_copy_vma_data_to_mn(struct task_struct *tsk, struct vm_area_struct *vma, 
		unsigned long start_addr, unsigned long end_addr, off_t off_in_vma)
{
	// struct fault_data_struct *payload;
    // char *reply;		//dummy buffer for ack
	// int ret = -1;
	// unsigned long offset;
	// size_t data_size = (end_addr - start_addr);
	// size_t tot_size = sizeof(*payload);	// + data_size - sizeof(char);
	pte_t *pte = NULL;	//, pte_val;
	// void *sent_data = NULL;
	// int have_data = 0;

	if (end_addr <= start_addr)
	{
		return 0;	//no data to send
	}

	// if (tot_size >= DISAGG_NET_MAXIMUM_BUFFER_LEN)
	// {
	// 	return -1;	//too big to send
	// }
    /*
    if (!vma_is_anonymous(vma)) {
        //we also needs to unmap and send writable file mappings
        //for procces who want to run on multiple nodes
        return cn_copy_page_data_to_mn_from_file(tsk->tgid, vma,
                start_addr);
    }
    */

	// find pte
	//pr_info("page tried to send: %lx", start_addr);
	pte = find_pte_target(tsk->mm, start_addr);
	if (pte && !pte_none(*pte)) //check for tsk
	{
		// forked, so same address but from the previous tsk (current)
		pte = find_pte_target(current->mm, start_addr);
		if (pte && !pte_none(*pte) && pte_present(*pte)) //check for cur
		{
			// TODO: we will need to grab pte lock before go into cn_copy_page_data_to_mn()
			//		 and unlock it after return from cn_copy_page_data_to_mn()
			return exec_copy_page_data_to_mn(tsk->tgid, tsk->mm, start_addr, pte);
		}
	}

	//if we reach here, then the page can not be sent from memory,
	//which means the mapping of page frame has not been established,
	//which means for file mappings, the file content == the initial content in memory
	//so instead, we can send it from file
	if (vma->vm_file) {
		return cn_copy_page_data_to_mn_from_file(tsk->tgid, vma, start_addr, off_in_vma);
	}
	return 0;	// no pte to send
#if 0
	sent_data = kzalloc(data_size, GFP_KERNEL);
	if (!sent_data)
	{
		return -ENOMEM;
	}

	payload = (struct fault_data_struct*)kzalloc(tot_size, GFP_KERNEL);
	if (!payload)
	{
		kfree(sent_data);
        return -ENOMEM;
	}
	
	// reply = (char*)kmalloc(DISAGG_NET_SIMPLE_BUFFER_LEN, GFP_KERNEL);
	reply = kmalloc(sizeof(struct fault_reply_struct), GFP_KERNEL);
	if (!reply)
	{
		kfree(sent_data);
		kfree(payload);
		return -ENOMEM;
	}

    payload->pid = tsk->pid;
	payload->tgid = tsk->tgid;
	payload->address = start_addr;
	// put vma information
	payload->data_size = (u32)data_size;

	if (data_size > PAGE_SIZE)
	{
		BUG();
	}

	// TODO: copy data for now
	offset = 0;
	// while(start_addr + offset < end_addr)
	{
		//check pages for given tsk->mm
		pte = find_pte_target(tsk->mm, start_addr + offset);
		// printk("EXEC - Loaded page (tsk): pte: 0x%lx\n", 
		// 			pte ? (unsigned long)pte->pte : 0);
		if (pte && !pte_none(*pte))	//check for tsk
		{
			pte = find_pte_target(current->mm, start_addr + offset);
			if (pte && !pte_none(*pte))	//check for cur
			{
				pte_val = *pte;
				pte_val = pte_clear_flags(pte_val, _PAGE_USER);
				set_pte_at(current->mm, start_addr + offset, pte, pte_val);
				barrier();
				flush_tlb_mm_range(current->mm, start_addr + offset, 
									start_addr + offset + PAGE_SIZE, VM_NONE);

				if (pte_present(*pte))
				{
					// printk("EXEC - Loaded page (cur): addr: 0x%lx, val: 0x%lx, pte: 0x%lx\n", 
					// 		start_addr + offset, *((unsigned long*)(start_addr + offset)), 
					// 		pte ? (unsigned long)pte->pte : 0);
					// memcpy((&payload->data) + offset, 
					// 	(char*)(start_addr) + offset, PAGE_SIZE);
					// payload->data = (void*)start_addr;	// page aligned user space memory should be fine
					memcpy(sent_data + offset, (char *)(start_addr) + offset, PAGE_SIZE);
				}else{
					memset(sent_data + offset, 0, PAGE_SIZE);
				}
				have_data = 1;
				// restore pte
				pte_val = pte_set_flags(pte_val, _PAGE_USER);
				set_pte_at(current->mm, start_addr + offset, pte, pte_val);
			}
		}
		flush_tlb_mm_range(current->mm, start_addr, end_addr, VM_NONE);
		offset += PAGE_SIZE;
	}

	if (have_data)
	{
		barrier();
		// only transmit one page
		payload->data = sent_data;
		// only PAGE_SIZE data will be sent regardless of the payload given here
		ret = send_msg_to_memory_rdma(DISSAGG_DATA_PUSH, payload, tot_size,
									reply, DISAGG_NET_SIMPLE_BUFFER_LEN);
		// ret = send_msg_to_memory(DISSAGG_DATA_PUSH, payload, tot_size, 
		//                          reply, DISAGG_NET_SIMPLE_BUFFER_LEN);
		ret = 0;
		// printk(KERN_DEFAULT "DATA - Data from RDMA [%d]: [0x%llx] for vma: 0x%lx - 0x%lx\n",
		// 	   ret, *(long long unsigned *)(reply), start_addr, end_addr);

		// Now, ret is the received length (may not for RDMA)
		if (ret < 0)
		{
			printk(KERN_ERR "Cannot send vma data - err: %d [%s]\n", 
					ret, tsk->comm);
			printk(KERN_ERR "** EXEC - Data from RDMA [%d]: [0x%llx]\n",
					ret, *(long long unsigned*)(reply));
			goto cn_send_vma_data_out;
		}
	}
	ret = 0;

cn_send_vma_data_out:
	kfree(sent_data);
	kfree(payload);
	kfree(reply);
    return ret;
#endif
}

DEFINE_PROFILE_POINT(exec_send_data_over_rdma)
/* It copy data from (maybe) other process's memory */
int cn_copy_page_data_to_mn(u16 tgid, struct mm_struct *mm, unsigned long addr,
							pte_t *pte, int is_target_data, u32 req_qp, void *dma_addr)
{
	struct fault_data_struct payload;
	struct fault_reply_struct reply; //dummy buffer for ack
	int ret;
	size_t data_size = PAGE_SIZE;
	// size_t tot_size = sizeof(payload) + data_size - sizeof(char);
	// pte_t *local_pte = NULL;
	struct page *page = NULL;
	unsigned long *data_ptr = NULL;
	u32 msg_type;
	PROFILE_POINT_TIME(exec_send_data_over_rdma)

	payload.req_qp = 0;
	payload.data = NULL;
	if (is_target_data == CN_ONLY_DATA)
	{
		msg_type = DISSAGG_DATA_PUSH;
	}
	else
	{
		if (is_target_data == CN_TARGET_PAGE)
		{
			msg_type = DISSAGG_DATA_PUSH_TARGET;
			payload.req_qp = req_qp;
		}else{
			msg_type = DISSAGG_DATA_PUSH_OTHER;
		}
		payload.data = dma_addr;
	}
	payload.pid = tgid;	//fake
	payload.tgid = tgid;
	payload.address = addr;
	payload.data_size = (u32)data_size;

	if (!payload.data)
	{
		if (pte && !pte_none(*pte))
		{
			page = pte_page(*pte);
		}
		if (page)
		{
			data_ptr = (unsigned long *)kmap(page);
			payload.data = (void *)data_ptr;
		}
	}

	// get local pte for the mmaping
	// printk("DATA - Loaded page: tgid: %u, addr: 0x%lx, pte: 0x%lx, page: 0x%lx, data_ptr: 0x%lx, l_pte: 0x%lx\n", 
	// 					(unsigned int)tgid, addr, pte ? (unsigned long)pte->pte : 0,
	// 					(unsigned long)page, (unsigned long)data_ptr,
	// 					(unsigned long)local_pte
	// 	  );
	// if (pte && page && data_ptr && local_pte && pte_present(*pte) && pte_present(*local_pte))
	if (payload.data)
	{
		PROFILE_START(exec_send_data_over_rdma);
		// spin_lock(&page->ptl);
		// memcpy(&payload->data, (char*)data_ptr, data_size);
		
		barrier();
		ret = send_msg_to_memory_rdma(msg_type, &payload, PAGE_SIZE,
									  &reply, sizeof(reply));
		PROFILE_LEAVE(exec_send_data_over_rdma);
		// send_page_data_retry:
		// ret = send_msg_to_memory_lock(DISSAGG_DATA_PUSH, payload, tot_size,
		// 							reply, DISAGG_NET_SIMPLE_BUFFER_LEN, 0);

		// pr_cache("DATA - Data from RDMA [%d]: [0x%llx]\n",
		// 		 ret, *(long long unsigned *)(&reply));
		// spin_unlock(&page->ptl);
	}else{
		ret = -EINTR;
	}

	// Now, ret is the received length
	if (ret < 0)
	{
		pr_warn_ratelimited("Cannot send page data - err: %d, type: %d, dma: 0x%lx\n",
							ret, is_target_data, (unsigned long)dma_addr);
		goto cn_send_page_data_out;
	}
	ret = 0;

cn_send_page_data_out:
	if (data_ptr)
		kunmap(page);
    // kfree(payload);
	// kfree(reply);
	//pr_info("page sent from memory %lx\n", addr);
    return ret;
}

// extern unsigned long do_disagg_mmap(struct task_struct *tsk,
// 									unsigned long addr, unsigned long len, unsigned long prot,
// 									unsigned long flags, vm_flags_t vm_flags, unsigned long pgoff,
// 									struct file *file);

/*
 * We assume that caller already holds write lock for mm->mmap_sem
 */
// @is_exec: reset VMAs and clean up all the cachelines for this tgid
static int _cn_notify_exec(struct task_struct *tsk, int is_exec)
{
	int ret = 0;
	if (is_exec)
		ret = cn_copy_vma_to_mn(tsk, DISSAGG_EXEC);

	if (likely(!ret))
	{
		// no error, now all mapping are stored in memory node
		struct vm_area_struct *cur = tsk->mm->mmap;
		struct vm_area_struct *prev, *next;
		struct mm_struct *mm = tsk->mm;
		// LIST_HEAD(uf);

		// barrier();

		while (cur)
		{
			//pr_info("cur[%lx, %lx]\n", cur->vm_start, cur->vm_end);
			next = cur->vm_next;
			prev = cur->vm_prev;
			// printk(KERN_DEFAULT "VMA: tgid[%5u] VA[0x%lx - 0x%lx] Flag[0x%lx] File[%d]\n",
			// 	   tsk->tgid, cur->vm_start, cur->vm_end, cur->vm_flags, cur->vm_file ? 1 : 0);

			// remove existing vma (anonymous & writable)
			if ((vma_is_anonymous(cur) && 
				((cur->vm_flags & VM_WRITE) || // writable page
				 !(cur->vm_flags & (VM_WRITE | VM_READ | VM_EXEC)))) // pages in software DRAM page = no permission
                    || (tsk->is_remote && (cur->vm_flags & VM_WRITE)))
			{
				int sent = -1;
//multithreading does not need a magic vma
/*
				if (tsk->is_test)
				{
					if (!TEST_is_test_vma(cur->vm_start, cur->vm_end))
					{
						// skip small mapping to remove
						goto continue_to_next;
					}
					else
					{
						pr_syscall("== [TEST] MAGIC VMA detected: 0x%lx - 0x%lx [file:%d][flag:0x%lx] ==\n",
								   cur->vm_start, cur->vm_end, cur->vm_file ? 1 : 0, cur->vm_flags);
					}
				}
*/
				//send data to mn
				if (cur->vm_end >= cur->vm_start)
				{
					get_cpu();
					if (cur->vm_end - cur->vm_start > DISAGG_NET_MAX_SIZE_ONCE)
					{
						unsigned long offset = 0;
						while (cur->vm_start + offset < cur->vm_end)
						{
							sent = cn_copy_vma_data_to_mn(tsk, cur, cur->vm_start + offset, 
								min(cur->vm_start + offset + DISAGG_NET_MAX_SIZE_ONCE, 
									cur->vm_end), offset);
							if(sent)
								break;
							offset += DISAGG_NET_MAX_SIZE_ONCE;
						}
					}else{
						sent = cn_copy_vma_data_to_mn(tsk, cur, cur->vm_start, cur->vm_end, 0);
					}
					put_cpu();
				}

				//pr_info("done send vma[%lx, %lx] sent[%d]", cur->vm_start, cur->vm_end, sent);

				// remove previous mappings
				if (!sent) // 0: successfully sent, -EINTR: no pte populated
				{
					if((cur->vm_flags & (VM_SHARED | VM_PFNMAP)))
					{
						//special flags
						pr_syscall("Do-not remove special writable vma: 0x%lx - 0x%lx [file:%d][flag:0x%lx]\n",
								   cur->vm_start, cur->vm_end, cur->vm_file ? 1 : 0, cur->vm_flags);
					}
                    /*
                    else if (cur->vm_file){
						//printk(KERN_WARNING "File VMA must not be removed\n");
						//BUG();
					}
                    */
					// else if (cur->vm_start >= mm->brk)
					// {
					// 	//TODO: before brk region - any special mapping? (same vma flag..)
					// }
					else
					{
						int stack = 0;
						unsigned long address = cur->vm_start;
						unsigned long res_addr = 0;
						unsigned long len = cur->vm_end - cur->vm_start;
						unsigned long vm_flags = (cur->vm_flags & ~(VM_WRITE | VM_READ | VM_EXEC)) | VM_DONTEXPAND;
						if (cur->vm_start <= mm->start_stack && mm->start_stack < cur->vm_end)
						{
								stack = 1;
						}
						//pr_info("start unmap vma [%lx, %lx] stack[%d]", cur->vm_start, cur->vm_end, stack);
						// printk(KERN_DEFAULT "Remove pages in writable vma: 0x%lx - 0x%lx [flag: 0x%lx, pgoff: 0x%lx, stack: %d]\n",
						// 	   cur->vm_start, cur->vm_end, cur->vm_flags, cur->vm_pgoff, stack);
						if (0/*!is_exec && tsk->is_test && TEST_is_test_vma(cur->vm_start, cur->vm_end)*/)
						{
							#if 0
							unsigned long tmp_addr;
							pr_cache("[TEST] Try to clean cacheline for tgid: %u, VA: 0x%lx - 0x%lx\n",
									 tsk->tgid, address, address + len);
							for (tmp_addr = address; tmp_addr < address + len; tmp_addr += CACHELINE_SIZE)
							{
								unsigned long tmp_len = min((unsigned long)CACHELINE_SIZE, address + len - tmp_addr);
								if (!is_owner_address(tsk->tgid, tmp_addr))
								{
									if (unlikely(do_munmap(mm, tmp_addr, tmp_len, NULL)))
									{
										ret = -ENOMEM;
										printk(KERN_DEFAULT "Failed to unmap vma: 0x%lx - 0x%lx\n",
											   cur->vm_start, cur->vm_end);
										BUG();
									}
									cnthread_delete_from_list_no_lock(tsk->tgid, tmp_addr);
									res_addr = mmap_dummy_region(mm, tmp_addr, tmp_len, vm_flags);
									if (unlikely(res_addr != tmp_addr))
									{
										BUG();
									}
								}else{
									// already have configured at the first time (when mmap-ed)
								}
							}
							#endif
						}
						else
						{
							if (unlikely(do_munmap(mm, cur->vm_start, cur->vm_end - cur->vm_start, NULL)))
							{
								ret = -ENOMEM;
								printk(KERN_DEFAULT "Failed to unmap vma: 0x%lx - 0x%lx\n",
										cur->vm_start, cur->vm_end);
								BUG();
							}
							else
							{
								unsigned long tmp_addr;
								pr_cache("Try to clean cacheline for tgid: %u, VA: 0x%lx - 0x%lx\n",
										tsk->tgid, address, address + len);
								for (tmp_addr = address; tmp_addr < address + len; tmp_addr += PAGE_SIZE)
								{
									cnthread_delete_from_list_no_lock(tsk->tgid, tmp_addr);
								}
							}
/*
							if (tsk->is_test) {
								if (address == 0x555555754000) {
									pte_t *pte = find_pte_target(tsk->mm, address);
									pr_info("after unmap page[%lx], pte perm[%d]\n", address, pte ? pte_flags(*pte) : -1);
								}
							}
*/
							res_addr = mmap_dummy_region(mm, address, len, vm_flags);
/*
							if (tsk->is_test) {
								if (address == 0x555555754000) {
									pte_t *pte = find_pte_target(tsk->mm, address);
									pr_info("after dummy map page[%lx], pte perm[%d]\n", address, pte ? pte_flags(*pte) : -1);
								}
							}
*/
							if (likely(res_addr == address))
							{
							// if (likely(!IS_ERR_VALUE(res_addr)))
							// {
								// int res = 0;
								cur = find_vma(mm, address);
								if (unlikely(!cur || (cur && cur->vm_start > address)))
								{
									printk(KERN_ERR "Failed to initialize clean mmap [0x%lx]: 0x%lx, addr: 0x%lx, res_addr: 0x%lx\n",
										address, (unsigned long)cur, cur ? cur->vm_start : 0, res_addr);
									if (cur && cur->vm_prev)
									{
										printk(KERN_ERR "prev vma: 0x%lx - 0x%lx\n",
											cur->vm_prev->vm_start, cur->vm_prev->vm_end);
									}
									BUG();
								}

								if(tsk->is_remote)
									pr_info("dummy vma[%lx, %lx] file[%d] flags[%lx] pgprot[%lx]\n",
									cur->vm_start, cur->vm_end, cur->vm_file ? 1:0, cur->vm_flags, (unsigned long)(cur->vm_page_prot.pgprot));
								// res = anon_vma_prepare(cur);
								// if (unlikely(res))
								// {
								// 	printk(KERN_DEFAULT "Failed to ANON initialize clean mmap: addr: 0x%lx, res: %d\n",
								// 			address, res);
								// 	BUG();
								// }
							}else{
								BUG();
							}
							//pr_info("done creat dummy vma [%lx, %lx]", cur->vm_start, cur->vm_end);

							//
							// unmap_pages_vma(mm, cur);
							// cur->vm_flags &= ~(VM_WRITE);		// remove write permission
						}
					}
				}else{
					pr_syscall("**WARN: cannot send vma data: 0x%lx - 0x%lx [%lu]\n",
							   cur->vm_start, cur->vm_end, cur->vm_end - cur->vm_start);
				}

			}else if(cur->vm_flags & VM_WRITE){
				if (!cur->vm_file){	// print out errorous case only
					pr_syscall("**WARN: non-anon & non-file but wriatble (f:%d): 0x%lx - 0x%lx\n",
							   cur->vm_file ? 1 : 0, cur->vm_start, cur->vm_end);
				}
			}else if(vma_is_anonymous(cur)){
				pr_syscall("**WARN: anon but read-only: 0x%lx - 0x%lx\n",
						   cur->vm_start, cur->vm_end);
				// NOTE: COW has read only PTE but writable VMA
			}
//continue_to_next:
			cur = next;
		}
		//pr_info("done handle all vmas\n");
		// unsigned long tmp_addr;
		// printk(KERN_DEFAULT "Try to clean cacheline for tgid: %u, VA: 0x%lx - 0x%lx\n",
		// 	   tsk->tgid, address, address + len);
		// for (tmp_addr = address; tmp_addr < address + len; tmp_addr += PAGE_SIZE)
		// {
		// 	cnthread_delete_from_list_no_lock(tsk->tgid, tmp_addr);
		// }
		if (is_exec)
		{
			//pr_info("start clean up tsk->tgid[%d] mm[%p]\n", tsk->tgid, mm);
			cnthread_clean_up_non_existing_entry(tsk->tgid, mm);
			//pr_info("done clean up\n");
			// cnthread_delete_all_request(tsk->tgid);
		}
		// barrier();
	}else{
		BUG();
	}

	//pr_info("start print tsk->mm[%p]\n", tsk->mm);
	disagg_print_va_layout(tsk->mm);
	//pr_info("done print\n");
	return ret;
}

int cn_notify_exec(struct task_struct *tsk)
{
	return _cn_notify_exec(tsk, 1);
}

int cn_notify_fork(struct task_struct *tsk)
{
	return _cn_notify_exec(tsk, 0);
}
