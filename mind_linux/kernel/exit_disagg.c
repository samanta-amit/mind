/*
 * Header file of fork and disaggregated fork functions
 */
#include <disagg/network_disagg.h>
#include <disagg/exit_disagg.h>
#include <disagg/cnthread_disagg.h>
#include <disagg/config.h>
#include <disagg/print_disagg.h>
#include <linux/exec.h>

static int send_exit_mm(struct task_struct *tsk, unsigned long clone_flags)
{
    struct exit_msg_struct payload;
    struct exit_reply_struct *reply;
    int ret;

    reply = kmalloc(sizeof(struct exit_reply_struct), GFP_KERNEL);
	if (!reply)
        return -ENOMEM;

    payload.pid = tsk->pid;
	payload.tgid = tsk->tgid;
    payload.flag = clone_flags;

    ret = send_msg_to_memory(DISSAGG_EXIT, &payload, sizeof(payload), 
                             reply, sizeof(*reply));

    // ret = send_msg_to_memory_rdma(DISSAGG_EXIT, &payload, sizeof(payload), 
    //                         reply, sizeof(*reply));
	printk(KERN_DEFAULT "EXIT - Data from CTRL [%d]: ret: %d [0x%llx]\n",
		ret, reply->ret, *(long long unsigned*)(reply));

	if (ret >= 0)
		ret = reply->ret;   // set error

    kfree(reply);
    return ret;
}

int disagg_clear_req_buffer(struct task_struct *tsk)
{
    cnthread_delete_all_request(tsk->tgid);
    return 0;
}

/*
 * Currently this function forward request to memory node 
 * while it just use the local functions
 */
int disagg_exit(struct task_struct *tsk)
{
    int err;
    int cnt = atomic_dec_return(get_test_program_thread_cnt());
    unsigned long exit_flag = EXIT_FIRST_TRY;

    if (tsk->is_remote)
        pr_syscall("EXIT: cnt[%d]\n", cnt);

    if (tsk->is_remote)
    {
        if (cnt > 0)
            err = 0;
        else {
retry_send_exit:
            err = send_exit_mm(tsk, exit_flag);
            if (err == -ERR_DISAGG_REMOTE_WAIT_EXIT) {
                pr_info("remote tgroup wait exit\n");
                ssleep(MIND_EXIT_RETRY_IN_SEC);
                exit_flag = EXIT_RETRY;
                goto retry_send_exit;
            }
        }
    }else{
        err  = send_exit_mm(tsk, 0);
    }

    if (err < 0){
		printk(KERN_ERR "EXIT: Cannot send exit_mm to memory (%d), %s\n", 
				err, tsk->comm);
    }else{
		err = 0;
	}

    //TODO clear req buf if cnt == 0?
    // clear cache
    // disagg_clear_req_buffer(tsk);
    return err;
}

int disagg_exit_for_test(struct task_struct *tsk)
{
    return disagg_exit(tsk);
}
EXPORT_SYMBOL(disagg_exit_for_test); // for unit test in RoceModule
