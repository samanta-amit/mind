#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
//#include <netinet/sctp.h>
#include <iostream>
#include <fstream>
#include <strings.h>
#include <stdlib.h>
#include <string>
#include <pthread.h>
#include <unordered_map>
#include <list>
#include <queue>
#include <chrono>

#include "tcp_server.hpp"
#include "ufutex_disagg.hpp"
#include "lock_free_queue.hpp"
#include "LockFreeQueueCpp11.h"

#define BF_CONTORLLER
#include "../../../include/disagg/cluster_disagg.h"
#undef BF_CONTORLLER

using namespace std;

int listenFd;
int conn_fds[MAX_CONN];
pthread_t threadA[MAX_CONN];
socklen_t len; //store size of the address
struct sockaddr_in svrAdd;

static int n_conn;

//static unordered_map<unsigned long, moodycamel::ConcurrentQueue<int>> wq_ht;
#ifdef SUPPORT_BITSET
//static unordered_map<unsigned long, pair<queue<struct wait_entry>, pthread_spinlock_t>> wq_ht;
#else
static unordered_map<unsigned long, LockFreeQueueCpp11<int> *> wq_ht;
#endif
static pthread_rwlock_t wq_ht_lk;

static unordered_map<int, int> nid2connid;

//static struct futex_server_stat stat;
static unordered_map<string, struct event_t *> stat;

//static moodycamel::ConcurrentQueue<struct async_wake_data> async_wake_q;
//static pthread_t async_waker;

static chrono::time_point<chrono::high_resolution_clock> t_global;
static atomic_ulong log_id;
static atomic_ulong msg_ids[MAX_CONN];
static FILE *log_file;

/*
 * Utility functions
 */
char *_inet_ntoa(struct in_addr in)
{
    char *str_ip = NULL;

    str_ip = (char *)malloc(16 * sizeof(char));
    sprintf(str_ip, "%s", inet_ntoa(in));
    return str_ip;
}

int get_nid_from_ip_str(struct sockaddr_in *addr_in)
{
    unsigned int ip_addr_num[4];
    int nid;
    char *ip_addr = _inet_ntoa(addr_in->sin_addr);

    // == Assign node based on IP ==
    // Controller:      0
    // Computing node:  1 to MAX_NUMBER_COMPUTE_NODE
    // Memory node:     (MAX_NUMBER_COMPUTE_NODE + 1) to (DISAGG_MAX_NODE_CTRL - 1)

    sscanf(ip_addr, "%u.%u.%u.%u", &ip_addr_num[0], &ip_addr_num[1], &ip_addr_num[2], &ip_addr_num[3]);
    nid = ip_addr_num[3] - DISAGG_COMPUTE_NODE_IP_START + 1;
    // clean memory space for the ip string
    free(ip_addr);
    return nid;
}

/*
* TODO:
* 1. more cores for mem server
* 2. async wakeup_worker talk to request_handler with a queue
*/

void init_log(void) {
    log_file = fopen("./futex.log", "w");
    if (!log_file)
        cerr << "can not open log file\n";
    t_global = chrono::high_resolution_clock::now();
}

void add_log(unsigned long msg_id, string &&str) {
    chrono::duration<double, std::micro> t_diff = chrono::high_resolution_clock::now() - t_global;
    fprintf(log_file, "time[%f] msg_id[%lu] %s\n", t_diff.count(), msg_id, str.c_str());
    fflush(log_file);
}

void init_stat(void) {
    stat["handle_wait"] = new event_t();
    stat["handle_wake"] = new event_t();
    stat["wq_ht_lookup"] = new event_t();
    stat["wq_enqueue"] = new event_t();
    stat["wq_dequeue"] = new event_t();
    stat["send_wake_msg"] = new event_t();
    stat["send_wake_msg_async"] = new event_t();
    stat["async_wake_retry"] = new event_t();
}

void cnt_event(string name, unsigned long time) {
    ++(stat[name]->n);
    (stat[name]->t) += time;
}

void init_nid2connid(void) {
    nid2connid[1] = 0;
    nid2connid[3] = 1;
    nid2connid[4] = 2;
    nid2connid[5] = 3;
    nid2connid[6] = 4;
    nid2connid[7] = 5;
    nid2connid[8] = 6;
}

void print_stat(void) {
    printf("stat:\tnr\tavg\n");
    for (auto itr = stat.begin(); itr != stat.end(); ++itr) {
        auto &name = itr->first;
        auto &cnt = itr->second;
        printf("%s\n", name.c_str());
        unsigned long n = cnt->n, t = cnt->t;
        printf("     \t%lu\t%f\n", n, (double)t / (double)n);
    }
}

#ifdef SUPPORT_BITSET
#else
int futex(int nid, int op, int tgid, unsigned long uaddr, int nr, char *data, int len, int conn_id, unsigned long msg_id) {
    int res = 0;
    int wakeup_cnt = 0;
    unsigned long key = (((unsigned long)tgid) << 48) + uaddr;
    chrono::duration<double, std::micro> t_diff;

    //printf("\tfutex nid[%d] op[%d] tgid[%d] uaddr[%lx]\n", nid, op, tgid, uaddr);
    auto t_begin = std::chrono::high_resolution_clock::now();

    pthread_rwlock_rdlock(&wq_ht_lk);
    auto itr = wq_ht.find(key);
    pthread_rwlock_unlock(&wq_ht_lk);

    if (itr == wq_ht.end()) {
        pthread_rwlock_wrlock(&wq_ht_lk);
        if (wq_ht.find(key) == wq_ht.end())
            wq_ht[key] = new LockFreeQueueCpp11<int>{100};
            //wq_ht[key] = moodycamel::ConcurrentQueue<int>{};
        itr = wq_ht.find(key);
        pthread_rwlock_unlock(&wq_ht_lk);
    }

    auto &wq = itr->second;

    t_diff = chrono::high_resolution_clock::now() - t_begin;
    cnt_event("wq_ht_lookup", t_diff.count());

    if (op == COND_WAIT || op == COND_WAIT_BITSET) {
        //wq.push(nid);
        //pthread_spin_unlock(&wq_lk);
        add_log(msg_id, string("before enqueue:") + to_string(nid));
        auto t_before_enqueue = chrono::high_resolution_clock::now();
        //wq.enqueue(nid);
        wq->push(nid);
        t_diff = chrono::high_resolution_clock::now() - t_before_enqueue;
        cnt_event("wq_enqueue", t_diff.count());
        add_log(msg_id, string("after enqueue:") + to_string(nid));

        t_diff = chrono::high_resolution_clock::now() - t_begin;
        cnt_event("handle_wait", t_diff.count());

    } else if (op == COND_WAKE || op == COND_WAKE_BITSET) {
        /*
        if (wq.empty()) {
            //cerr << "can not dequeue waiter, retry...\n";
            pthread_spin_unlock(&wq_lk);
            //usleep(1000);
            usleep(1);
            ++wakeup_cnt;
            goto retry;
        }
        int wakeup_nid = wq.front();
        wq.pop();
        pthread_spin_unlock(&wq_lk);
        */
        add_log(msg_id, string("before dequeue:"));

        long retry_cnt = 0;
        int wakeup_nid;
        vector<int> wakeup_nids;
        bool succ;
        auto t_before_dequeue = chrono::high_resolution_clock::now();
        //while (!(succ = wq.try_dequeue(wakeup_nid)) && ((++retry_cnt) < MAX_SYNC_RETRY_CNT));
        if (nr == 1) {
            while (!(succ = wq->pop(wakeup_nid)) && ((++retry_cnt) < MAX_SYNC_RETRY_CNT));
            if (succ)
                wakeup_nids.push_back(wakeup_nid);
            else
                print_stat();
        } else {
            //INT_MAX
            while ((++retry_cnt) < MAX_INTMAX_SYNC_RETRY_CNT) {
                succ = wq->pop(wakeup_nid);
                if (succ)
                    wakeup_nids.push_back(wakeup_nid);
            }
        }

        t_diff = chrono::high_resolution_clock::now() - t_before_dequeue;
        cnt_event("wq_dequeue", t_diff.count());

        add_log(msg_id, string("after dequeue:") + to_string(wakeup_nid));

        for (auto itr = wakeup_nids.begin(); itr != wakeup_nids.end(); ++itr) {
            auto t_before_send_msg = chrono::high_resolution_clock::now();
            write(conn_fds[nid2connid[*itr]], data, len);
            t_diff = chrono::high_resolution_clock::now() - t_before_send_msg;
            cnt_event("send_wake_msg", t_diff.count());
        }

        t_diff = chrono::high_resolution_clock::now() - t_begin;
        cnt_event("handle_wake", t_diff.count());
    }
ret:
    return res;
};
#endif
/*
void *async_wake(void *arg) {
    pthread_detach(pthread_self());

    queue<LockFreeQueueCpp11<int> *> wq_list;    

    while (1) {
        usleep(ASYNC_WAKER_SLEEP_US);
        
        pthread_rwlock_rdlock(&wq_ht_lk);
        for (auto itr = wq_ht.begin(); itr != wq_ht.end(); ++itr)
            wq_list.push(itr->second);
        pthread_rwlock_unlock(&wq_ht_lk);

        for (auto itr = wq_list.begin(); itr != wq_list.end(); ++itr) {
            int retry_cnt = 0;
            int wakeup_nid;
            bool succ;
            while ((++retry_cnt) < MAX_INTMAX_SYNC_RETRY_CNT) {
                succ = wq->pop(wakeup_nid);
                if (succ) {

                }
            }
        }

        wq_list.clear();
    }
}
*/
void *handle_request(void *arg) {
    int res = 0;
    struct mem_header *hdr;
    struct futex_msg_struct *msg;
    struct futex_reply_struct reply;
    int read_size = sizeof(*hdr) + sizeof(*msg);
    int conn_id = (long)arg;
    int conn_fd = conn_fds[conn_id];

    pthread_detach(pthread_self());

    char *recv_buf = new char[RECV_BUF_LEN];
    if (!recv_buf) {
        cerr << "can not allocate recv_buf\n" << endl;
        res = -1;
        return 0;
        //goto ret;
    }

    //auto t_begin = std::chrono::high_resolution_clock::now();
    while (1) {
        bzero(recv_buf, RECV_BUF_LEN);
        res = read(conn_fds[conn_id], recv_buf, read_size);
        if (res != read_size) {
            if (res != 0)
                cerr << "read size[" << res << "] but expect[" << read_size << "]\n";
            //goto ret;
        } else {
            //auto t_end = std::chrono::high_resolution_clock::now();
            //std::chrono::duration<double, std::micro> t_diff = t_end - t_begin;
            //printf("TCP Msg arrive from conn[%d] at %f\n", conn_id, t_diff);
        }

        hdr = (struct mem_header *)recv_buf;
        msg = (struct futex_msg_struct *)(recv_buf + sizeof(*hdr));
/*
        struct async_futex_data data;
        data.nid = hdr->sender_id;
        data.op = msg->op;
        data.tgid = msg->tgid;
        data.uaddr = msg->uaddr;
        data.data_len = read_size;
        memcpy(data.data, recv_buf, read_size);

        pthread_spin_lock(&async_futex_q_lk[conn_id]);
        async_futex_q[conn_id].push(data);
        pthread_spin_unlock(&async_futex_q_lk[conn_id]);
*/      
        unsigned long msg_id = (((unsigned long)conn_id) * 10000000) + (msg_ids[conn_id]++);
        add_log(msg_id, string("op:") + to_string(msg->op));
#ifdef SUPPORT_BITSET
        //futex(hdr->sender_id, msg->op, msg->tgid, msg->uaddr, msg->nr, msg->bitset, recv_buf, read_size, conn_id, msg_id);
#else
        futex(hdr->sender_id, msg->op, msg->tgid, msg->uaddr, msg->nr, recv_buf, read_size, conn_id, msg_id);
#endif
    }
ret:
    if (recv_buf)
        delete [] recv_buf;
    return (void *)(long)res;
}

void init_futex_man() {
    pthread_rwlock_init(&wq_ht_lk, NULL);
    //for (int i = 0; i < MAX_CONN; ++i)
    //    pthread_spin_init(&async_futex_q_lk[i], PTHREAD_PROCESS_PRIVATE);
    //for (int i = 0; i < NUM_ASYNC_WORKER; ++i)
    //    pthread_create(&async_futex_workers[i], NULL, async_futex, NULL);
    //pthread_create(&async_waker, NULL, async_wake, NULL);
}

int main(int argc, char* argv[]) {
    int res = 0;
    struct sockaddr_in clntAdd;
    
    if((LISTEN_PORT > 65535) || (LISTEN_PORT < 2000)) {
        cerr << "Please enter a port number between 2000 - 65535" << endl;
        return 0;
    }

    init_stat();
    init_futex_man();
    // init_nid2connid();
    init_log();

    //create socket
    listenFd = socket(AF_INET, /*SOCK_SEQPACKET*/SOCK_STREAM, /*IPPROTO_SCTP*/0);
    if(listenFd < 0) {
        cerr << "Cannot open socket err[" << listenFd << "]" << endl;
        res = listenFd;
        goto ret;
    }
    
    //bzero((char*) &svrAdd, sizeof(svrAdd));
    svrAdd.sin_family = AF_INET;
    svrAdd.sin_addr.s_addr = INADDR_ANY;
    svrAdd.sin_port = htons(LISTEN_PORT);
    
    //bind socket
    if((res = bind(listenFd, (struct sockaddr *)&svrAdd, sizeof(svrAdd))) < 0) {
        cerr << "Cannot bind" << endl;
        goto ret;
    }
    
    listen(listenFd, BACKLOG);
    
    len = sizeof(clntAdd);
    while (n_conn < MAX_CONN) {
        cout << "futex server listening" << endl;

        //this is where client connects. svr will hang in this mode until client conn
        conn_fds[n_conn] = accept(listenFd, (struct sockaddr *)&clntAdd, &len);
        if (conn_fds[n_conn] < 0) {
            cerr << "Cannot accept connection" << endl;
            return 0;
        } else {
            int nid = 0;
            cout << "Conn built with " << clntAdd.sin_addr.s_addr << endl;
            // dynamic conn id selection
            nid = get_nid_from_ip_str(&clntAdd);
            cout << "ID from IP: " << nid << endl;
            nid2connid[nid] = n_conn;
        }
        
        //pthread_create(&async_futex_workers[n_conn], NULL, async_futex, (void *)n_conn);
        pthread_create(&threadA[n_conn], NULL, handle_request, (void *)(long)n_conn); 
        
        ++n_conn;
    }

ret:
    return res;
}
