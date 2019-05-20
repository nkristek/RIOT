/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef HOPP_H
#define HOPP_H

#include "compas/routing/dodag.h"
#include "thread.h"

#ifndef HOPP_STACKSZ
#define HOPP_STACKSZ (THREAD_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF + 1024)
#endif

#ifndef HOPP_QSZ
#define HOPP_QSZ  (32)
#endif

#ifndef HOPP_TRICKLE_IMIN
#define HOPP_TRICKLE_IMIN           (64)
#endif
#ifndef HOPP_TRICKLE_IMAX
#define HOPP_TRICKLE_IMAX           (16)
#endif
#ifndef HOPP_TRICKLE_REDCONST
#define HOPP_TRICKLE_REDCONST       (5)
#endif

#ifndef HOPP_SOL_PERIOD_BASE
#define HOPP_SOL_PERIOD_BASE        (4 * MS_PER_SEC)
#endif
#ifndef HOPP_SOL_PERIOD_JITTER
#define HOPP_SOL_PERIOD_JITTER      (1 * MS_PER_SEC)
#endif
#define HOPP_SOL_PERIOD             (HOPP_SOL_PERIOD_BASE + (random_uint32() % HOPP_SOL_PERIOD_JITTER))

#ifndef HOPP_NAM_PERIOD_BASE
#define HOPP_NAM_PERIOD_BASE        (1 * MS_PER_SEC)
#endif
#ifndef HOPP_NAM_PERIOD_JITTER
#define HOPP_NAM_PERIOD_JITTER      (500)
#endif
#define HOPP_NAM_PERIOD             (HOPP_NAM_PERIOD_BASE + (random_uint32() % HOPP_NAM_PERIOD_JITTER))

#ifndef HOPP_PARENT_TIMEOUT_PERIOD_BASE
#define HOPP_PARENT_TIMEOUT_PERIOD_BASE     (30 * MS_PER_SEC)
#endif
#ifndef HOPP_PARENT_TIMEOUT_PERIOD_JITTER
#define HOPP_PARENT_TIMEOUT_PERIOD_JITTER   (5 * MS_PER_SEC)
#endif
#ifndef HOPP_PARENT_TIMEOUT_PERIOD
#define HOPP_PARENT_TIMEOUT_PERIOD          (HOPP_PARENT_TIMEOUT_PERIOD_BASE + (random_uint32() % HOPP_PARENT_TIMEOUT_PERIOD_JITTER))
#endif

#ifndef HOPP_SOL_MSG
#define HOPP_SOL_MSG                (0xBEF0)
#endif
#ifndef HOPP_PAM_MSG
#define HOPP_PAM_MSG                (0xBEF1)
#endif
#ifndef HOPP_NAM_MSG
#define HOPP_NAM_MSG                (0xBEF2)
#endif
#ifndef HOPP_NAM_TRIGGER_MSG
#define HOPP_NAM_TRIGGER_MSG        (0xBEF3)
#endif
#ifndef HOPP_NAM_DEL_MSG
#define HOPP_NAM_DEL_MSG            (0xBEF4)
#endif
#ifndef HOPP_PARENT_TIMEOUT_MSG
#define HOPP_PARENT_TIMEOUT_MSG     (0xBFF5)
#endif
#ifndef HOPP_STOP_MSG
#define HOPP_STOP_MSG               (0xBFF6)
#endif

#ifndef HOPP_NAM_STALE_TIME
#define HOPP_NAM_STALE_TIME         (10 * US_PER_SEC)
#endif

#ifndef HOPP_INTEREST_BUFSIZE
#define HOPP_INTEREST_BUFSIZE       (64)
#endif

#ifndef RD_STACKSZ
#define RD_STACKSZ                  (THREAD_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF + 1024)
#endif
#ifndef RD_QSZ
#define RD_QSZ                      (32)
#endif
#ifndef RD_MSG_POOL_SIZE
#define RD_MSG_POOL_SIZE            (32)
#endif
#ifndef RD_LOOKUP_REQUEST_TX
#define RD_LOOKUP_REQUEST_TX        (0xC000)
#endif
#ifndef RD_LOOKUP_REQUEST_RX
#define RD_LOOKUP_REQUEST_RX        (0xC001)
#endif
#ifndef RD_REGISTER_REQUEST_TX
#define RD_REGISTER_REQUEST_TX      (0xC002)
#endif
#ifndef RD_PREFIX
#define RD_PREFIX                   "/rd"
#endif
#ifndef RD_PREFIX_LEN
#define RD_PREFIX_LEN               (3)
#endif
#ifndef RD_REGISTER_PREFIX_SUFFIX
#define RD_REGISTER_PREFIX_SUFFIX   "/r"
#endif
#ifndef RD_REGISTER_PREFIX
#define RD_REGISTER_PREFIX          (RD_PREFIX RD_REGISTER_PREFIX_SUFFIX)
#endif
#ifndef RD_REGISTER_PREFIX_LEN
#define RD_REGISTER_PREFIX_LEN      (RD_PREFIX_LEN + 2)
#endif
#ifndef RD_LOOKUP_PREFIX_SUFFIX
#define RD_LOOKUP_PREFIX_SUFFIX     "/l"
#endif
#ifndef RD_LOOKUP_PREFIX
#define RD_LOOKUP_PREFIX            (RD_PREFIX RD_LOOKUP_PREFIX_SUFFIX)
#endif
#ifndef RD_LOOKUP_PREFIX_LEN
#define RD_LOOKUP_PREFIX_LEN        (RD_PREFIX_LEN + 2)
#endif
#ifndef REGISTERED_CONTENT_COUNT
#define REGISTERED_CONTENT_COUNT    (100)
#endif

extern char hopp_stack[HOPP_STACKSZ];
extern gnrc_netif_t *hopp_netif;
extern kernel_pid_t hopp_pid;
extern compas_dodag_t dodag;

extern char rd_stack[RD_STACKSZ];
extern kernel_pid_t rd_pid;

typedef struct __attribute__((packed)) {
    char name[COMPAS_NAME_LEN];     /**< Name */
    size_t name_len;                /**< Length of a name */
    char type[COMPAS_NAME_LEN];     /**< Content-Type */
    size_t type_len;                /**< Length of the content type */
    uint64_t lifetime;              /**< Lifetime */
} rd_entry_t;

typedef struct __attribute__((packed)) {
    char contenttype[COMPAS_NAME_LEN];
    size_t contenttype_len;
} rd_lookup_msg_t;

typedef int (*hopp_data_received_func)(struct ccnl_relay_s *relay,
                                       struct ccnl_pkt_s *pkt,
                                       struct ccnl_face_s *from);
void hopp_callback_set_data_received(hopp_data_received_func func);
int hopp_callback_data_received(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt,
                                struct ccnl_face_s *from);

typedef void (*hopp_cb_published)(struct ccnl_relay_s *relay,
                                  struct ccnl_pkt_s *pkt,
                                  struct ccnl_face_s *from);

void *hopp(void *arg);
void hopp_root_start(const char *prefix, size_t prefix_len);
bool hopp_publish_content(const char *name, size_t name_len,
                          unsigned char *content, size_t content_len);
void hopp_set_cb_published(hopp_cb_published cb);

void *rd(void* arg);
bool rd_register(const char *name, size_t name_len,
                 const char *contenttype, size_t contenttype_len,
                 uint64_t lifetime);
bool rd_lookup(const char *contenttype, size_t contenttype_len);

#endif /* HOPP_H */
