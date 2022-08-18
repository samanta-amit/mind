#pragma once

#include "ufutex_disagg.hpp"
#include "lock_free_queue.hpp"
#include <atomic>

const int LISTEN_PORT = 8765;
const int MAX_CONN = 10;
const int BACKLOG = 16;
const int RECV_BUF_LEN = 4096;
const int NUM_ASYNC_WAKEUP_WORKER = 1;
const int MAX_WAKEUP_RETRY_CNT = 100000;
//const long MAX_SYNC_RETRY_CNT = 100;
const long MAX_SYNC_RETRY_CNT = 100000000;
const long MAX_RETRY_CNT = 100000000;
const long MAX_INTMAX_SYNC_RETRY_CNT = 1000000;
const long ASYNC_WAKER_SLEEP_US = 200000;


//#define SUPPORT_BITSET

struct event_t {
    std::atomic_ulong n;
    std::atomic_ulong t;
    event_t() {
        n = t = 0;
    }
};

/*
struct futex_server_stat {
    std::atomic_ulong n_wait[MAX_CONN];
    std::atomic_ulong t_wait[MAX_CONN];
    std::atomic_ulong n_wake[MAX_CONN];
    std::atomic_ulong t_wake[MAX_CONN];
};
*/
/*
struct async_wake_data {
    moodycamel::ConcurrentQueue<int> *wq;
    char data[sizeof(struct mem_header) + sizeof(struct futex_msg_struct)];
    int data_len;
};
*/
struct wait_entry {
    int nid;
    int bitset;
};