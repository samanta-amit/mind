#include <disagg/cnthread_disagg.h>
#include <disagg/kshmem_disagg.h>
#include <disagg/exec_disagg.h>
#include <disagg/fault_disagg.h>
#include <disagg/profile_points_disagg.h>
#include <disagg/network_disagg.h>
#include <disagg/network_fit_disagg.h>
#include <disagg/print_disagg.h>
#include <disagg/config.h>
#include <linux/vmalloc.h>

static LIST_HEAD(kshmem_free_page);
// static struct kshmem_page *__kshmem_headp = NULL;
static unsigned long kshmem_va = 0;
static int kshmem_avail = 0;

unsigned long kshmem_get_start_va(void)
{
    return kshmem_va;
}
EXPORT_SYMBOL(kshmem_get_start_va);

void prealloc_kernel_shared_mem(void)
{
    // Try to grab the last area of vmalloc-able VA
    kshmem_va =
        (unsigned long)vm_map_va_only(
            VMALLOC_END - (2 * DISAGG_KERN_SHMEM_SIZE), VMALLOC_END,
            DISAGG_KERN_SHMEM_SIZE);
    if (!kshmem_va)
    {
        pr_err("Disagg_KernShmem: Cannot initialize virtual address\n");
        // BUG();
    }else{
        pr_info("Disagg_KernShmem: Allocated VA: 0x%lx\n", kshmem_get_start_va());
    }
}

unsigned long send_kshmem_alloc(unsigned long size)
{
    struct kshmem_msg_struct payload;
    struct kshmem_reply_struct *reply;
    int ret = -1;
    unsigned long addr = 0;

    reply = kzalloc(sizeof(struct kshmem_reply_struct), GFP_KERNEL);
    if (!reply)
        return -ENOMEM;

    payload.size = size;
    ret = send_msg_to_memory(DISAGG_KSHMEM_ALLOC, &payload, sizeof(payload),
                             reply, sizeof(struct kshmem_reply_struct));

    if (ret < sizeof(payload))
        ret = -EINTR;
    else if (reply->ret)
    {                     // only 0 is success
        ret = reply->ret; // set error
    }
    else
    {
        ret = 0;
        addr = (unsigned long)reply->addr;
    }
    kfree(reply);

    if (ret)
        return 0;
    else
        return addr;
}

static int _test_kshmem_access(void)
{
    unsigned long alloc_addr = 0;
    unsigned long test_size = 128 * PAGE_SIZE;
    volatile char dummy_buf[8] = "";
    pr_info("KernShmem: tsk[0x%lx] mm[0x%lx] init_mm[0x%lx]\n",
            (unsigned long)current, (unsigned long)current->mm,
            (unsigned long)&init_mm);
    // allocate
    pr_info("KernShmem: alloc test\n");
    alloc_addr = send_kshmem_alloc(test_size);
    if (!alloc_addr)
    {
        return -1;
    }
    pr_info("KernShmem: alloc result [0x%lx - 0x%lx]\n",
            alloc_addr, alloc_addr + test_size);
    // access : simply try the very first page to cause invalidation
    if (alloc_addr != kshmem_get_start_va()) {    // in case of second compute blade
        alloc_addr = kshmem_get_start_va() + PAGE_SIZE;  // false sharing
        *(char*)alloc_addr = 0xf;
    }else{
        dummy_buf[0] = *(char*)alloc_addr;
    }
    // free

    return 0;
}

void init_kernel_shared_mem(void)
{
    // pr_info("Disagg_KernShmem: Init started\n");
    pr_info("Disagg_KernShmem: Local test started\n");
    kshmem_avail = 1;
    kthread_run((void *)_test_kshmem_access, NULL, "KernShmemTester");
}

void *alloc_kshmem(unsigned long size)
{
    return (void *)send_kshmem_alloc(size);
}

void free_kshmem(void *alloc_va)
{
    // NOT IMPLEMENTED
    pr_err("%s haven't been implemented yet\n", __func__);
    return ;
}

int is_kshmem_available(void)
{
    return kshmem_avail;
}

int __always_inline is_kshmem_address(unsigned long addr)
{
    return (kshmem_va && (addr >= kshmem_va) && (addr < kshmem_va + DISAGG_KERN_SHMEM_SIZE));
}

// Reference for unmap: https://elixir.bootlin.com/linux/v4.15/source/arch/x86/mm/highmem_32.c#L91
// Index: idx = type + KM_TYPE_NR * smp_processor_id();
// PTE: kmap_pte-idx