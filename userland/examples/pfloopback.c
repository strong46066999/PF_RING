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
#include <poll.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/ethernet.h>
#include <sys/time.h>
#include <time.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "pfring.h"
#include "pfutils.c"

pfring  *pdo,*pdi;
char *out_dev = NULL,*in_dev = NULL;
u_int8_t do_shutdown = 0;

#define DEFAULT_DEVICE     "eth0"

/* ******************************** */

void sigproc(int sig) {
  static int called = 0;

  fprintf(stdout, "Leaving...\n");
  if(called) return; else called = 1;
  do_shutdown = 1;
}

/* *************************************** */

void printHelp(void) {
  printf("pfloopback - Recv a packet and send it back\n");
  printf("(C) 2012 ntop\n\n");
  printf("-i <device>     Producer device name\n");
  printf("-o <device>     Receiver device name (same as -i by default)\n");
  printf("-g <core_id>    Bind this app to a core\n");
  printf("-h              Print this help\n");
  exit(0);
}

/* *************************************** */

static void close_pd() {
  pfring_close(pdo);
  if(pdo != pdi)
    pfring_close(pdi);
}

int main(int argc, char* argv[]) {
  char c;
  int bind_core = -1;
  //u_int num_tx_slots = 0;
  int rc;
  u_char *pkt_buffer = NULL;
  struct pfring_pkthdr hdr;
  memset(&hdr, 0, sizeof(hdr));

  while((c = getopt(argc,argv,"hi:o:g:")) != -1) {
    switch(c) {
    case 'h':
      printHelp();
      break;
    case 'o':
      out_dev = strdup(optarg);
      break;
    case 'i':
      in_dev = strdup(optarg);
      break;
    case 'g':
      bind_core = atoi(optarg);
      break;
    };
  }

  if(out_dev == NULL)  printHelp();

  if(in_dev == NULL) out_dev = in_dev;

  printf("Receiving on %s and Sending packets on %s\n", in_dev, out_dev);

  pdo = pfring_open(out_dev, 1500, PF_RING_PROMISC);
  pdi = (in_dev && strcmp(out_dev, in_dev) != 0) ? pfring_open(in_dev, 1500, PF_RING_PROMISC) : pdo;
  if(pdo == NULL) {
    printf("pfring_open %s error [%s]\n", out_dev, strerror(errno));
    return(-1);
  } else if(pdi == NULL){
    printf("pfring_open %s error [%s]\n", in_dev, strerror(errno));
    return(-1);
  } else {
    u_int32_t version;

    pfring_set_application_name(pdo, "pfloopback");
    pfring_set_application_name(pdi, "pfloopback");
    pfring_version(pdo, &version);
    pfring_version(pdi, &version);

    printf("Using PF_RING v.%d.%d.%d\n", (version & 0xFFFF0000) >> 16,
	   (version & 0x0000FF00) >> 8, version & 0x000000FF);
  }

  signal(SIGINT, sigproc);
  signal(SIGTERM, sigproc);
  signal(SIGINT, sigproc);

  if(bind_core >= 0) bind2core(bind_core);

  pfring_set_socket_mode(pdo, send_and_recv_mode);
  pfring_set_socket_mode(pdi, send_and_recv_mode);
  
  pfring_set_direction(pdo, rx_and_tx_direction);
  pfring_set_direction(pdi, rx_and_tx_direction);

  pfring_set_poll_watermark(pdo, 0);
  pfring_set_poll_watermark(pdi, 0);

  if(pfring_enable_ring(pdo) != 0 || pfring_enable_ring(pdi) != 0) {
    printf("Unable to enable ring :-(\n");
    close_pd();
    return(-1);
  }

  while(1) {
    if(unlikely(do_shutdown))
      break;

    const int recv_rc = pfring_recv(pdi, &pkt_buffer, 0, &hdr, 1);
    printf("Recv len %d\n", hdr.len);
  redo:
    rc = pfring_send(pdo, (char*)pkt_buffer, hdr.len, 1);
  
    if(rc == PF_RING_ERROR_INVALID_ARGUMENT) {
      printf("Attempting to send invalid packet [len: %u][MTU: %u]\n",
	     hdr.len, pdo->mtu);
    } else if (rc < 0) {
      goto redo;
    }

  }

  close_pd();

  return(0);
}
