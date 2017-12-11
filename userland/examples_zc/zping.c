/*
 * (C) 2003-17 - ntop
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#define _GNU_SOURCE
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <sys/time.h>
#include <time.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>
#include <net/ethernet.h>     /* the L2 protocols */

#include "pfring.h"
#include "pfring_zc.h"

#include "zutils.c"

#define MAX_CARD_SLOTS      32768
#define MIN_BUFFER_LEN       1536
#define ETH_LEN									6
#define ETHER_ADDR_FMT_SIZE		 18	

//#define USE_BURST_API
#define BURST_LEN   32
#define NBUFF      256 /* pow 2 */
#define NBUFFMASK 	0xFF /* 256-1 */
//#define DEBUG

#define ICMP_ID 0x9988

typedef u_int64_t ticks;

pfring_zc_cluster *zc_rx;
pfring_zc_queue *zq_rx;
pfring_zc_pkt_buff *buffers_rx[BURST_LEN];

pfring_zc_cluster *zc_tx;
pfring_zc_queue *zq_tx;
pfring_zc_pkt_buff *buffers_tx[BURST_LEN];

int bind_core_rx = -1;
int bind_core_tx = -1;
u_int8_t wait_for_packet = 1, do_shutdown = 0, flush_packet=1;
u_int32_t dst_ip = 0;
u_int32_t nic_ip = 0;
u_int8_t nic_mac[ETH_LEN];
u_int8_t dst_mac[ETH_LEN];

u_int8_t null_mac[ETH_LEN] = {0x00,0x00, 0x00, 0x00,0x00,0x00};
u_int32_t icmp_reached =0;
ticks icmp_reached_tick;
u_int16_t curr_seq = 0;

static __inline__ ticks getticks(void) {
    u_int32_t a, d;
    asm volatile("rdtsc" : "=a" (a), "=d" (d));
    return (((ticks)a) | (((ticks)d) << 32));
}

static double ticks_to_us(ticks dtick,const ticks hz){
    return ((double) 1000000 /* us */) / ( hz / dtick );
}

/* ******************************** */

void sigproc(int sig) {
    static int called = 0;
    fprintf(stderr, "Leaving...\n");
    if(called) return; else called = 1;
    
    do_shutdown = 1;
    
    if(zq_rx)
        pfring_zc_queue_breakloop(zq_rx);
    
    if(zq_tx)
        pfring_zc_queue_breakloop(zq_tx);
}

/* *************************************** */

void printHelp(void) {
    printf("zping - (C) 2014 ntop.org\n");
    printf("Using PFRING_ZC v.%s\n", pfring_zc_version());
    printf("A simple pinger and pingd application.\n\n");
    printf("Usage:   zping -i <device> -c <cluster id> [-d <ip address>] \n"
           "                [-h] [-R <Rx core id>] [-T <Tx core id>] [-v] [-a]\n\n");
    printf("-h              Print this help\n");
    printf("-i <device>     Device name\n");
    printf("-d <ip address> Dest ip address\n");
    printf("-c <rx cluster id> Rx cluster id\n");
    printf("-l <tx cluster id> Tx cluster id\n");
    printf("-R <core id>    Bind this app rx to a core\n");
    printf("-T <core id>    Bind this app tx to a core\n");
    printf("-n <ping times> Max ping times\n");
    printf("-a              Active packet wait\n");
}

void packet_xmit(u_int8_t *buff, u_int16_t len)
{
    int sent_bytes;
    
    u_char *buffer = pfring_zc_pkt_buff_data(buffers_tx[0], zq_tx);
    buffers_tx[0]->len = len;
    memcpy(buffer, buff, len);
    
    while (unlikely((sent_bytes = pfring_zc_send_pkt(zq_tx, &buffers_tx[0], flush_packet)) < 0)) ;
}

#include "zicmp.c"

/* *************************************** */

void *packet_consumer_rx_thread(void *user) {
#ifdef USE_BURST_API
    int i, n;
#endif
    
    if (bind_core_rx >= 0)
        bind2core(bind_core_rx);
    
    while(!do_shutdown) {
        
#ifndef USE_BURST_API
        if(pfring_zc_recv_pkt(zq_rx, &buffers_rx[0], wait_for_packet) > 0) {
            arp_icmp_process(buffers_rx[0]);
        }
#else
        if((n = pfring_zc_recv_pkt_burst(zq_rx, buffers_rx, BURST_LEN, wait_for_packet)) > 0) {
            
            for (i = 0; i < n; i++) {
                arp_icmp_process(buffers_rx);
            }
        }
#endif
    }
    
    if(zq_rx)
        pfring_zc_sync_queue(zq_rx, rx_only);
    
    return NULL;
}

/* *************************************** */
int zc_rx_init(int cluster_id, int bind_core_rx, char *device) {
    int i;
    
    int buffer_len = max_packet_len(device);
    
    zc_rx = pfring_zc_create_cluster(
                cluster_id,
                buffer_len,
                0,
                MAX_CARD_SLOTS + BURST_LEN,
                pfring_zc_numa_get_cpu_node(bind_core_rx),
                NULL /* auto hugetlb mountpoint */
                );
    
    if(zc_rx == NULL) {
        fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check that pf_ring.ko is loaded and hugetlb fs is mounted\n",
                strerror(errno));
        return -1;
    }
    
    zq_rx = pfring_zc_open_device(zc_rx, device, rx_only, 0);
    
    if(zq_rx == NULL) {
        fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
                strerror(errno), device);
        return -1;
    }
    
    for (i = 0; i < BURST_LEN; i++) {
        
        buffers_rx[i] = pfring_zc_get_packet_handle(zc_rx);
        
        if (buffers_rx[i] == NULL) {
            fprintf(stderr, "pfring_zc_get_packet_handle error\n");
            return -1;
        }
    }
    
    return 0;
}

int zc_tx_init(int cluster_id, int bind_core_tx, char *device) {
    int i;
    
    int buffer_len = max_packet_len(device);
    
    zc_tx = pfring_zc_create_cluster(
                cluster_id,
                buffer_len,
                0,
                MAX_CARD_SLOTS + NBUFF,
                pfring_zc_numa_get_cpu_node(bind_core_tx),
                NULL /* auto hugetlb mountpoint */
                );
    
    if(zc_tx == NULL) {
        fprintf(stderr, "pfring_zc_create_cluster error [%s] Please check that pf_ring.ko is loaded and hugetlb fs is mounted\n",
                strerror(errno));
        return -1;
    }
    
    
    zq_tx = pfring_zc_open_device(zc_tx, device, tx_only, 0);
    
    if(zq_tx == NULL) {
        fprintf(stderr, "pfring_zc_open_device error [%s] Please check that %s is up and not already used\n",
                strerror(errno), device);
        return -1;
    }
    
    for (i = 0; i < BURST_LEN; i++) {
        
        buffers_tx[i] = pfring_zc_get_packet_handle(zc_tx);
        
        if (buffers_tx[i] == NULL) {
            fprintf(stderr, "pfring_zc_get_packet_handle error\n");
            return -1;
        }
    }
    
    return 0;
}

/* *************************************** */

int main(int argc, char* argv[]) {
    char *device = NULL, c, real_device[IFNAMSIZ]={'\0'}, *pname, buf1[64];
    int rx_cluster_id = DEFAULT_CLUSTER_ID;
    int tx_cluster_id = DEFAULT_CLUSTER_ID-2;
    int max_ping_times = 3;
    pthread_t rx_thread;
    ticks tick_start = 0, tick_delta = 0;
    ticks hz = 0;

    while((c = getopt(argc,argv,"hac:l:d:i:R:T:n:")) != '?') {
        if((c == 255) || (c == -1)) break;
        
        switch(c) {
        case 'h':
            printHelp();
            exit(0);
            break;
        case 'a':
            wait_for_packet = 0;
            break;
        case 'c':
            rx_cluster_id = atoi(optarg);
            break;
        case 'l':
            tx_cluster_id = atoi(optarg);
            break;
        case 'd':
            dst_ip = inet_addr(optarg);
            break;
        case 'i':
            device = strdup(optarg);
            break;
        case 'R':
            bind_core_rx = atoi(optarg);
            break;
        case 'T':
            bind_core_tx = atoi(optarg);
            break;
        case 'n':
            max_ping_times = atoi(optarg);
            break;

        }
    }
    
    if (device == NULL || rx_cluster_id < 0) {
        printHelp();
        exit(-1);
    }
    
    pname = strstr(device, ":");
    if(pname)
        snprintf(real_device, sizeof(real_device), "%s", pname+1);
    
    if(get_mac(real_device, nic_mac, ETH_LEN) < 0) {
        printf("cannot get mac from nic %s\n", real_device);
        exit(0);
    }
    
    nic_ip = get_ipaddrs(real_device);
    if(!nic_ip) {
        printf("cannot get primary address from nic %s\n", real_device);
        exit(0);
    }
    
    if(zc_rx_init(rx_cluster_id, bind_core_rx, device) < 0)
        goto cleanup;
    
    if(zc_tx_init(tx_cluster_id, bind_core_tx, device) < 0)
        goto cleanup;
    
    signal(SIGINT,  sigproc);
    signal(SIGTERM, sigproc);
    signal(SIGINT,  sigproc);
    
    pthread_create(&rx_thread, NULL, packet_consumer_rx_thread, (void*) NULL);

    if(dst_ip == 0)
        goto pthread_join;

    /* cumputing usleep delay */
    tick_start = getticks();
    usleep(1);
    tick_delta = getticks() - tick_start;

    /* cumputing CPU freq */
    tick_start = getticks();
    usleep(1001);
    hz = (getticks() - tick_start - tick_delta) * 1000 /*kHz -> Hz*/;

    printf("Estimated CPU freq: %.3f Hz\n", (double)hz/(1000*1000));

    int retry = 0;
    ticks icmp_sended_tick;

    while(1) {
        if(do_shutdown)
            break;

re_start:
        if(retry >= max_ping_times) {
            do_shutdown =1;
            break;
        }

        if(!memcmp(dst_mac, null_mac, ETH_LEN)) {
            build_arp_echo_xmit(dst_ip);

            int arp_retry = 0;
            while(arp_retry < 30) {
                if(do_shutdown)
                    break;

                if(memcmp(dst_mac, null_mac, ETH_LEN))
                    break;

                usleep(100);
                arp_retry++;
            }

            if(arp_retry == 30)
            {
                printf("ping timeout no arp get\n");
                retry++;
                goto	re_start;
            }
        }

        build_icmp_echo_xmit(dst_ip, ICMP_ID, curr_seq);
        icmp_sended_tick = getticks();
        icmp_reached = 0;
        int icmp_retry = 0;
        while(icmp_retry < 30) {
            if(do_shutdown)
                break;

            if(icmp_reached)
                break;

            usleep(100);
            icmp_retry++;
        }

        if(icmp_retry == 30)
        {
            printf("ping timeout no icmp reply\n");
        }
        else
        {
            const ticks curr_tick1 = getticks();
            printf("\nPackets received time diff: %s usec\n", pfring_format_numbers(ticks_to_us(curr_tick1 - icmp_reached_tick,hz), buf1, sizeof(buf1), 1));
        }

        curr_seq++;
        retry++;
    }

pthread_join:

    pthread_join(rx_thread, NULL);
    
    sleep(1);
    
cleanup:
    
    if(zc_rx)
        pfring_zc_destroy_cluster(zc_rx);
    
    if(zc_tx)
        pfring_zc_destroy_cluster(zc_tx);
    
    return 0;
}

