#ifndef __KSHMEM_DISAGGREGATION_H__
#define __KSHMEM_DISAGGREGATION_H__

#include <linux/sched.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#define DISAGG_KERN_TGID 0xffff     // first 16 bit of 64 bit kernel VA

struct kshmem_msg_struct
{
	unsigned long size;
} __packed;

struct kshmem_reply_struct
{
    u32 ret;
    u64 addr;
}__packed;

#endif //__KSHMEM_DISAGGREGATION_H__