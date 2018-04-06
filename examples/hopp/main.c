/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */
#include <stdio.h>

#include "tlsf-malloc.h"
#include "msg.h"
#include "shell.h"
#include "net/gnrc/netif.h"

#include "thread.h"
#include "xtimer.h"
#include "random.h"

#include "ccn-lite-riot.h"

#include "net/hopp/hopp.h"

#include "pktcnt.h"

#define MAIN_QSZ (4)
static msg_t _main_q[MAIN_QSZ];

uint8_t hwaddr[GNRC_NETIF_L2ADDR_MAXLEN];
char hwaddr_str[GNRC_NETIF_L2ADDR_MAXLEN * 3];

#define TLSF_BUFFER     ((40 * 1024) / sizeof(uint32_t))
static uint32_t _tlsf_heap[TLSF_BUFFER];

static int _root(int argc, char **argv)
{
    if (argc == 2) {
        hopp_root_start((const char *)argv[1], strlen(argv[1]));
    }
    else {
        puts("error");
        return -1;
    }
    return 0;
}

/*
static void cb_published(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt,
                         struct ccnl_face_s *from)
{
    static char scratch[32];
    struct ccnl_prefix_s *prefix;


    snprintf(scratch, sizeof(scratch)/sizeof(scratch[0]),
             "/%.*s/%.*s", pkt->pfx->complen[0], pkt->pfx->comp[0],
                           pkt->pfx->complen[1], pkt->pfx->comp[1]);
    //printf("PUBLISHED: %s\n", scratch);
    prefix = ccnl_URItoPrefix(scratch, CCNL_SUITE_NDNTLV, NULL, NULL);

    from->flags |= CCNL_FACE_FLAGS_STATIC;
    ccnl_fib_add_entry(relay, ccnl_prefix_dup(prefix), from);
    ccnl_prefix_free(prefix);
}
*/

static int _publish(int argc, char **argv)
{
    if (argc == 2) {
        hopp_publish_content((const char *)argv[1], strlen(argv[1]), NULL, 0);
    }
    else {
        puts("error");
        return -1;
    }
    return 0;
}

static const shell_command_t shell_commands[] = {
    { "hr", "start HoPP root", _root },
    { "hp", "publish data", _publish },
    { NULL, NULL, NULL }
};

int main(void)
{
    tlsf_create_with_pool(_tlsf_heap, sizeof(_tlsf_heap));
    msg_init_queue(_main_q, MAIN_QSZ);

    ccnl_core_init();

    ccnl_start();

    if (((hopp_netif = gnrc_netif_iter(NULL)) == NULL) ||
        (ccnl_open_netif(hopp_netif->pid, GNRC_NETTYPE_CCN) < 0)) {
        return -1;
    }

    uint16_t chan = 11;
    gnrc_netapi_set(hopp_netif->pid, NETOPT_CHANNEL, 0, &chan, sizeof(chan));

    uint16_t src_len = 8U;
    gnrc_netapi_set(hopp_netif->pid, NETOPT_SRC_LEN, 0, &src_len, sizeof(src_len));
#ifdef BOARD_NATIVE
    gnrc_netapi_get(hopp_netif->pid, NETOPT_ADDRESS, 0, hwaddr, sizeof(hwaddr));
#else
    gnrc_netapi_get(hopp_netif->pid, NETOPT_ADDRESS_LONG, 0, hwaddr, sizeof(hwaddr));
#endif
    gnrc_netif_addr_to_str(hwaddr, sizeof(hwaddr), hwaddr_str);

    /* init pktcnt */
    if (pktcnt_init() != PKTCNT_OK) {
        puts("error: unable to initialize pktcnt");
        return 1;
    }

    hopp_pid = thread_create(hopp_stack, sizeof(hopp_stack), THREAD_PRIORITY_MAIN - 1,
                             THREAD_CREATE_STACKTEST, hopp, &ccnl_relay,
                             "hopp");

    if (hopp_pid <= KERNEL_PID_UNDEF) {
        return 1;
    }

    //hopp_set_cb_published(cb_published);

    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
