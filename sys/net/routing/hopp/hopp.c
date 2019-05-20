/*
 * Copyright (C) 2018 HAW Hamburg
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>

#include "xtimer.h"
#include "evtimer.h"
#include "evtimer_msg.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/netreg.h"

#include "ccnl-pkt-builder.h"
#include "ccn-lite-riot.h"
#include "ccnl-producer.h"

#include "compas/routing/dodag.h"
#include "compas/routing/nam.h"
#include "compas/routing/pam.h"
#include "compas/routing/sol.h"
#include "compas/trickle.h"

#include "net/hopp/hopp.h"

#include "hashes/sha256.h"
#include "libbase58.h"
#include "cbor.h"
#include "thread.h"
#include "random.h"
#include "mutex.h"
#define ENABLE_DEBUG    (1)

#ifdef MODULE_PKTCNT_FAST
#include "pktcnt.h"
#endif

#define CCNL_ENC_HOPP (0x08)

char hopp_stack[HOPP_STACKSZ];
gnrc_netif_t *hopp_netif;
kernel_pid_t hopp_pid;

static unsigned char _out[CCNL_MAX_PACKET_SIZE];

extern kernel_pid_t _ccnl_event_loop_pid;

static struct ccnl_face_s *loopback_face;
static msg_t hopp_q[HOPP_QSZ];
static evtimer_msg_t evtimer;
compas_dodag_t dodag;
static evtimer_msg_event_t sol_msg_evt = { .msg = { .type = HOPP_SOL_MSG } };
static evtimer_msg_event_t pam_msg_evt = { .msg = { .type = HOPP_PAM_MSG } };
//static evtimer_msg_event_t nam_msg_evt = { .msg.type = HOPP_NAM_MSG };
static evtimer_msg_event_t pto_msg_evt = { .msg = { .type = HOPP_PARENT_TIMEOUT_MSG } };
static uint32_t nce_times[COMPAS_NAM_CACHE_LEN];
static evtimer_msg_event_t nam_msg_evts[COMPAS_NAM_CACHE_LEN];

static hopp_cb_published cb_published = NULL;

char rd_stack[RD_STACKSZ];
kernel_pid_t rd_pid;
static msg_t rd_q[RD_QSZ];
static unsigned char _lookup_int_buf[HOPP_INTEREST_BUFSIZE];
static rd_entry_t _registered_content[REGISTERED_CONTENT_COUNT];
static mutex_t _registered_content_mutex = MUTEX_INIT;
static rd_lookup_msg_t _rd_lookup_msg_pool[RD_MSG_POOL_SIZE];
static mutex_t _rd_lookup_msg_pool_mutex = MUTEX_INIT;

static rd_lookup_msg_t *rd_lookup_msg_get_free_entry(void) 
{
    mutex_lock(&_rd_lookup_msg_pool_mutex);
    for (unsigned i = 0; i < RD_MSG_POOL_SIZE; i++) {
        if (_rd_lookup_msg_pool[i].contenttype_len == 0)
            return &_rd_lookup_msg_pool[i];
    }
    mutex_unlock(&_rd_lookup_msg_pool_mutex);
    return NULL;
}

static hopp_data_received_func _data_received_func = NULL;

void
hopp_callback_set_data_received(hopp_data_received_func func)
{
    _data_received_func = func;
}

int
hopp_callback_data_received(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt,
                            struct ccnl_face_s *from)
{
    if (_data_received_func) {
        return _data_received_func(relay, pkt, from);
    }

    return 1;
}

void hopp_set_cb_published(hopp_cb_published cb)
{
    cb_published = cb;
}

static void hopp_parent_timeout(compas_dodag_t *dodag)
{
    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pto_msg_evt);
    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&sol_msg_evt);
    dodag->parent.alive = false;
    msg_t m = { .type = HOPP_SOL_MSG, .content.value = 0 };
    msg_try_send(&m, hopp_pid);
}

static bool hopp_send(gnrc_pktsnip_t *pkt, uint8_t *addr, uint8_t addr_len)
{
    gnrc_pktsnip_t *hdr = gnrc_netif_hdr_build(NULL, 0, addr, addr_len);

    if (hdr == NULL) {
        puts("error: packet buffer full");
        gnrc_pktbuf_release(pkt);
        return false;
    }

    LL_PREPEND(pkt, hdr);

    if (!addr) {
        gnrc_netif_hdr_t *nethdr = (gnrc_netif_hdr_t *)hdr->data;
        nethdr->flags = GNRC_NETIF_HDR_FLAGS_BROADCAST;
    }

    if (gnrc_netapi_send(hopp_netif->pid, pkt) < 1) {
        puts("error: unable to send");
        gnrc_pktbuf_release(pkt);
        return false;
    }
    return true;
}

static void hopp_send_pam(compas_dodag_t *dodag, uint8_t *dst_addr, uint8_t dst_addr_len, bool redun)
{
    if (redun && (dodag->trickle.c >= dodag->trickle.k)) {
        return;
    }

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, compas_pam_len(dodag) + 2, GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("send_pam: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_HOPP;
    compas_pam_create(dodag, (compas_pam_t *) (((uint8_t *) pkt->data) + 2));
#ifdef MODULE_PKTCNT_FAST
    tx_pam++;
#endif
    hopp_send(pkt, dst_addr, dst_addr_len);
}

static void hopp_send_sol(compas_dodag_t *dodag, bool force_bcast)
{
    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, compas_sol_len() + 2, GNRC_NETTYPE_CCN);
    if (pkt == NULL) {
        puts("send_sol: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_HOPP;

    uint8_t *addr = NULL;
    size_t addr_len = 0;
    uint8_t flags = 0;

    if (!force_bcast) {
        if ((dodag->rank != COMPAS_DODAG_UNDEF) && (dodag->sol_num < 4)) {
            addr = dodag->parent.face.face_addr;
            addr_len = dodag->parent.face.face_addr_len;
        }
        else {
            dodag->flags |= COMPAS_DODAG_FLAGS_FLOATING;
            /*
            if (dodag->rank != COMPAS_DODAG_UNDEF) {
                flags = COMPAS_SOL_FLAGS_TRICKLE;
            }
            */
            if (dodag->parent.alive) {
                hopp_parent_timeout(dodag);
            }
        }
        dodag->sol_num++;
    }

    compas_sol_create((compas_sol_t *) (((uint8_t *) pkt->data) + 2), flags);
#ifdef MODULE_PKTCNT_FAST
    tx_sol++;
#endif
    hopp_send(pkt, addr, addr_len);

}

static void hopp_send_nam(compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    if (dodag->rank == COMPAS_DODAG_UNDEF) {
        puts("send_nam: not part of a DODAG");
        return;
    }

    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, 2 + sizeof(compas_nam_t) +
                                          nce->name.name_len +
                                          sizeof(compas_tlv_t), GNRC_NETTYPE_CCN);

    if (pkt == NULL) {
        puts("send_nam: packet buffer full");
        return;
    }

    ((uint8_t *) pkt->data)[0] = 0x80;
    ((uint8_t *) pkt->data)[1] = CCNL_ENC_HOPP;
    compas_nam_t *nam = (compas_nam_t *)(((uint8_t *) pkt->data) + 2);
    compas_nam_create(nam);
    compas_nam_tlv_add_name(nam, &nce->name);

#ifdef MODULE_PKTCNT_FAST
    tx_nam++;
#endif
    hopp_send(pkt, dodag->parent.face.face_addr, dodag->parent.face.face_addr_len);
}

static void hopp_handle_pam(struct ccnl_relay_s *relay,
                            compas_dodag_t *dodag, compas_pam_t *pam,
                            uint8_t *src_addr, uint8_t src_addr_len)
{
    uint16_t old_rank = dodag->rank;

    int state = compas_pam_parse(dodag, pam, src_addr, src_addr_len);
    //compas_dodag_print(dodag);

    if ((state == COMPAS_PAM_RET_CODE_CURRPARENT) ||
        (state == COMPAS_PAM_RET_CODE_NEWPARENT)  ||
        (state == COMPAS_PAM_RET_CODE_PARENT_WORSERANK)  ||
        (state == COMPAS_PAM_RET_CODE_NONFLOATINGDODAG_WORSERANK)) {

        if (old_rank != dodag->rank) {
            /*
            trickle_init(&dodag->trickle, HOPP_TRICKLE_IMIN, HOPP_TRICKLE_IMAX, HOPP_TRICKLE_REDCONST);
            uint64_t trickle_int = trickle_next(&dodag->trickle);
            evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pam_msg_evt);
            ((evtimer_event_t *)&pam_msg_evt)->offset = trickle_int;
            evtimer_add_msg(&evtimer, &pam_msg_evt, hopp_pid);
            */
            hopp_send_sol(dodag, true);
            hopp_send_pam(dodag, NULL, 0, false);
        }

        char dodag_prfx[COMPAS_PREFIX_LEN + 1];
        memcpy(dodag_prfx, dodag->prefix.prefix, dodag->prefix.prefix_len);
        dodag_prfx[dodag->prefix.prefix_len] = '\0';
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(dodag_prfx, CCNL_SUITE_NDNTLV, NULL, NULL);

        if (state == COMPAS_PAM_RET_CODE_NEWPARENT) {
            sockunion su;
            memset(&su, 0, sizeof(su));
            su.sa.sa_family = AF_PACKET;
            su.linklayer.sll_halen = src_addr_len;
            memcpy(su.linklayer.sll_addr, src_addr, src_addr_len);
            struct ccnl_face_s* from = ccnl_get_face_or_create(relay, 0, &(su.sa), sizeof(su.sa));

            from->flags |= CCNL_FACE_FLAGS_STATIC;
            ccnl_fib_rem_entry(relay, prefix, from);
            ccnl_fib_add_entry(relay, ccnl_prefix_dup(prefix), from);
        }

        if (!dodag->parent.alive) {
            dodag->parent.alive = true;
            for (size_t i = 0; i < COMPAS_NAM_CACHE_LEN; i++) {
                compas_nam_cache_entry_t *nce = &dodag->nam_cache[i];
                if (nce->in_use && compas_nam_cache_requested(nce->flags)) {
                    unsigned pos = nce - dodag->nam_cache;
                    nce->retries = COMPAS_NAM_CACHE_RETRIES;
                    nam_msg_evts->msg.type = HOPP_NAM_MSG;
                    nam_msg_evts->msg.content.ptr = nce;
                    evtimer_del(&evtimer, (evtimer_event_t *)&nam_msg_evts[pos]);
                    ((evtimer_event_t *)&nam_msg_evts[pos])->offset = HOPP_NAM_PERIOD;
                    evtimer_add_msg(&evtimer, &nam_msg_evts[pos], hopp_pid);
                }
            }
        }

        ccnl_prefix_free(prefix);

        dodag->sol_num = 0;

        if ((state == COMPAS_PAM_RET_CODE_PARENT_WORSERANK) && dodag->parent.alive) {
            /*
            dodag->sol_num = 0xFF;
            hopp_send_sol(dodag);
            dodag->sol_num = 0x0;
            */
            hopp_parent_timeout(dodag);
            return;
        }

        evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&sol_msg_evt);

        evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pto_msg_evt);
        ((evtimer_event_t *)&pto_msg_evt)->offset = HOPP_PARENT_TIMEOUT_PERIOD;
        evtimer_add_msg(&evtimer, &pto_msg_evt, hopp_pid);

        return;
    }

    if (dodag->rank >= pam->rank) {
        trickle_increment_counter(&dodag->trickle);
    }

    return;
}

void hopp_request(struct ccnl_relay_s *relay, compas_nam_cache_entry_t *nce)
{
    static unsigned char int_buf[HOPP_INTEREST_BUFSIZE];
    char name[COMPAS_NAME_LEN + 1];
    uint16_t name_len = nce->name.name_len > COMPAS_NAME_LEN ? COMPAS_NAME_LEN : nce->name.name_len;
    memcpy(name, nce->name.name, name_len);
    name[name_len] = '\0';
    
    struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL, NULL);
    sockunion su;
    memset(&su, 0, sizeof(su));
    su.sa.sa_family = AF_PACKET;
    su.linklayer.sll_halen = nce->face.face_addr_len;
    memcpy(su.linklayer.sll_addr, nce->face.face_addr, nce->face.face_addr_len);
    struct ccnl_face_s* to = ccnl_get_face_or_create(relay, 0, &(su.sa), sizeof(su.sa));
    memset(int_buf, 0, HOPP_INTEREST_BUFSIZE);

    /*
    msg_t mr, ms = { .type = CCNL_MSG_DEL_CS, .content.ptr = nce->name.name };
    msg_send_receive(&ms, &mr, _ccnl_event_loop_pid);
    */

    if (ccnl_send_interest(prefix, int_buf, HOPP_INTEREST_BUFSIZE, NULL, to) != 0) {
        puts("hopp: failed to send Interest");
    }
    ccnl_prefix_free(prefix);
}

static void hopp_handle_nam(struct ccnl_relay_s *relay, compas_dodag_t *dodag,
                            compas_nam_t *nam, uint8_t *src_addr, uint8_t src_addr_len)
{
    uint16_t offset = 0;
    compas_tlv_t *tlv = NULL;

    compas_face_t face;
    compas_face_init(&face, src_addr, src_addr_len);

    while(compas_nam_tlv_iter(nam, &offset, &tlv)) {
        if (tlv->type == COMPAS_TLV_NAME) {
            compas_name_t cname;
            compas_name_init(&cname, (const char *) (tlv + 1), tlv->length);

            char name[COMPAS_NAME_LEN + 1];
            memcpy(name, cname.name, cname.name_len);
            name[cname.name_len] = '\0';
            compas_nam_cache_entry_t *n = compas_nam_cache_find(dodag, &cname);
            if (!n) {
                n = compas_nam_cache_add(dodag, &cname, &face);
                if (!n) {
                    uint32_t now = xtimer_now_usec();
                    for (size_t i = 0; i < COMPAS_NAM_CACHE_LEN; i++) {
                        compas_nam_cache_entry_t *nce = &dodag->nam_cache[i];
                        unsigned pos = nce - dodag->nam_cache;
                        unsigned time = now - nce_times[pos];
                        if (nce->in_use && !compas_nam_cache_requested(nce->flags) && (time > HOPP_NAM_STALE_TIME)) {
                            evtimer_del(&evtimer, (evtimer_event_t *)&nam_msg_evts[pos]);
                            memset(nce, 0, sizeof(*nce));
                            n = compas_nam_cache_add(dodag, &cname, &face);
                            break;
                        }
                    }
                    if (!n) {
                        for (size_t i = 0; i < COMPAS_NAM_CACHE_LEN; i++) {
                            compas_nam_cache_entry_t *nce = &dodag->nam_cache[i];
                            unsigned pos = nce - dodag->nam_cache;
                            unsigned time = now - nce_times[pos];
                            if (nce->in_use && (time > HOPP_NAM_STALE_TIME)) {
                                evtimer_del(&evtimer, (evtimer_event_t *)&nam_msg_evts[pos]);
                                memset(nce, 0, sizeof(*nce));
                                n = compas_nam_cache_add(dodag, &cname, &face);
                                break;
                            }
                        }
                    }
                    if (!n) {
                        puts("NAM: NO SPACE LEFT");
                        continue;
                    }
                }
            }
            if (n) {
                nce_times[n - dodag->nam_cache] = xtimer_now_usec();
                hopp_request(relay, n);
#if 0
                msg_t msg = { .type = HOPP_NAM_MSG, .content.ptr = n };
                msg_try_send(&msg, hopp_pid);
#endif
            }
        }
    }

    return;
}

static void hopp_handle_sol(compas_dodag_t *dodag, compas_sol_t *sol,
                            uint8_t *dst_addr, uint8_t dst_addr_len)
{
    if ((dodag->rank == COMPAS_DODAG_UNDEF) || (compas_dodag_floating(dodag->flags))) {
        return;
    }

    bool empty = false;
    for (size_t i = 0; i < COMPAS_NAM_CACHE_LEN; i++) {
        compas_nam_cache_entry_t *nce = &dodag->nam_cache[i];
        if (!nce->in_use) {
            empty = true;
            break;
        }
    }

    if (!empty) {
        return;
    }

    if (compas_sol_reset_trickle(sol->flags)) {
        trickle_init(&dodag->trickle, HOPP_TRICKLE_IMIN, HOPP_TRICKLE_IMAX, HOPP_TRICKLE_REDCONST);
        uint64_t trickle_int = trickle_next(&dodag->trickle);
        evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pam_msg_evt);
        ((evtimer_event_t *)&pam_msg_evt)->offset = trickle_int;
        evtimer_add_msg(&evtimer, &pam_msg_evt, hopp_pid);
    }
    else {
        hopp_send_pam(dodag, dst_addr, dst_addr_len, false);
    }

    return;
}

static void hopp_dispatcher(struct ccnl_relay_s *relay, compas_dodag_t *dodag,
                            uint8_t *data, size_t data_len, uint8_t *src_addr,
                            uint8_t src_addr_len, uint8_t *dst_addr,
                            uint8_t dst_addr_len)
{
    (void) relay;
    (void) dst_addr;
    (void) dst_addr_len;
    (void) data_len;
    if (!((data[0] == 0x80) && (data[1] == CCNL_ENC_HOPP))) {
        return;
    }
    switch (data[2]) {
        case COMPAS_MSG_TYPE_SOL:
#ifdef MODULE_PKTCNT_FAST
            rx_sol++;
#endif
            hopp_handle_sol(dodag, (compas_sol_t *) (data + 2),
                            src_addr, src_addr_len);
            break;
        case COMPAS_MSG_TYPE_PAM:
#ifdef MODULE_PKTCNT_FAST
            rx_pam++;
#endif
            hopp_handle_pam(relay, dodag, (compas_pam_t *) (data + 2),
                            src_addr, src_addr_len);
            break;
        case COMPAS_MSG_TYPE_NAM:
#ifdef MODULE_PKTCNT_FAST
            rx_nam++;
#endif
            hopp_handle_nam(relay, dodag, (compas_nam_t *) (data + 2),
                              src_addr, src_addr_len);
            break;
        default:
            break;
    }
}

static void hopp_nce_del(compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    unsigned pos = nce - dodag->nam_cache;
    evtimer_del(&evtimer, (evtimer_event_t *)&nam_msg_evts[pos]);
    memset(nce, 0, sizeof(*nce));
}

static bool check_nce(compas_dodag_t *dodag, compas_nam_cache_entry_t *nce)
{
    if (nce->in_use && compas_nam_cache_requested(nce->flags)) {
        if (nce->retries > 0) {
            nce->retries--;
            hopp_send_nam(dodag, nce);
            return true;
        }
        else {
            msg_t mr, ms = { .type = CCNL_MSG_IN_CS, .content.ptr = nce->name.name };
            msg_send_receive(&ms, &mr, _ccnl_event_loop_pid);
            if (!mr.content.value) {
                hopp_nce_del(dodag, nce);
            }
            dodag->sol_num = 0xFF;
            hopp_parent_timeout(dodag);
        }
    }

    return false;
}

static int content_send(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt) 
{
    (void) relay;
    compas_name_t cname;
    char *s = ccnl_prefix_to_path(pkt->pfx);
    compas_name_init(&cname, s, strlen(s));
    ccnl_free(s);
    compas_nam_cache_entry_t *n = compas_nam_cache_find(&dodag, &cname);

    if (n) {
        msg_t msg = { .type = HOPP_NAM_DEL_MSG, .content.ptr = n };
        msg_try_send(&msg, hopp_pid);
    }

    return 1;
}

static inline void rd_entry_init(rd_entry_t *entry,
                                 const char *name, size_t name_len,
                                 const char *type, size_t type_len, 
                                 uint64_t lifetime)
{
    memcpy(entry->name, name, (name_len > COMPAS_NAME_LEN) ? COMPAS_NAME_LEN : name_len);
    entry->name_len = name_len;
    memcpy(entry->type, type, (type_len > COMPAS_NAME_LEN) ? COMPAS_NAME_LEN : type_len);
    entry->type_len = type_len;
    entry->lifetime = lifetime;
}

static int print_entry(const rd_entry_t *entry) 
{
    printf("-------------\n");
    printf("\tName: %.*s\n", entry->name_len, entry->name);
    printf("\tType: %.*s\n", entry->type_len, entry->type);
    printf("\tLifetime: %llu\n", entry->lifetime);
    printf("-------------\n");
    return 0;
}

static CborError encode_entry(CborEncoder *encoder, const rd_entry_t *entry) 
{
    CborEncoder mapEncoder;
    CborError error;
    error = cbor_encoder_create_map(encoder, &mapEncoder, 3);
    if (error != CborNoError) {
        DEBUG("encode_entry: error creating map\n");
        return error;
    }

    // Name
    error = cbor_encode_text_stringz(&mapEncoder, "n");
    if (error != CborNoError) {
        DEBUG("encode_entry: error encoding name key\n");
        return error;
    }
    error = cbor_encode_text_string(&mapEncoder, entry->name, entry->name_len);
    if (error != CborNoError) {
        DEBUG("encode_entry: error encoding name value\n");
        return error;
    }

    // Type
    error = cbor_encode_text_stringz(&mapEncoder, "t");
    if (error != CborNoError) {
        DEBUG("encode_entry: error encoding type key\n");
        return error;
    }
    error = cbor_encode_text_string(&mapEncoder, entry->type, entry->type_len);
    if (error != CborNoError) {
        DEBUG("encode_entry: error encoding type value\n");
        return error;
    }

    // Lifetime
    error = cbor_encode_text_stringz(&mapEncoder, "lt");
    if (error != CborNoError) {
        DEBUG("encode_entry: error encoding lifetime key\n");
        return error;
    }
    error = cbor_encode_uint(&mapEncoder, entry->lifetime);
    if (error != CborNoError) {
        DEBUG("encode_entry: error encoding lifetime value\n");
        return error;
    }

    error = cbor_encoder_close_container(encoder, &mapEncoder);
    if (error != CborNoError) {
        DEBUG("encode_entry: error closing map\n");
        return error;
    }
    return CborNoError;
}

static CborError parse_entry(const CborValue *map, rd_entry_t *entry) 
{
    if (!cbor_value_is_map(map)) {
        DEBUG("parse_entry: error value is not map\n");
        return -1;
    }

    CborError error;
    char name[COMPAS_NAME_LEN];
    size_t name_len;
    char type[COMPAS_NAME_LEN];
    size_t type_len; 
    uint64_t lifetime;

    // Name
    CborValue nameValue;
    error = cbor_value_map_find_value(map, "n", &nameValue);
    if (error != CborNoError) {
        DEBUG("parse_entry: error finding field n\n");
        return error;
    }
    if (!cbor_value_is_text_string(&nameValue)) {
        DEBUG("parse_entry: error field n is not text string\n");
        return CborErrorImproperValue;
    }
    error = cbor_value_get_string_length(&nameValue, &name_len); 
    if (error != CborNoError) {
        DEBUG("parse_entry: error getting length of value of field n\n");
        return error;
    }
    if (name_len > COMPAS_NAME_LEN) {
        DEBUG("parse_entry: error getting length of value of field n\n");
        return CborErrorDataTooLarge;
    }
    error = cbor_value_copy_text_string(&nameValue, name, &name_len, NULL); 
    if (error != CborNoError) {
        DEBUG("parse_entry: error getting value of field n\n");
        return error;
    }

    // Type
    CborValue typeValue;
    error = cbor_value_map_find_value(map, "t", &typeValue); 
    if (error != CborNoError) {
        DEBUG("parse_entry: error finding field t\n");
        return error;
    }
    if (!cbor_value_is_text_string(&typeValue)) {
        DEBUG("parse_entry: error field t is not text string\n");
        return CborErrorImproperValue;
    }
    error = cbor_value_get_string_length(&typeValue, &type_len); 
    if (error != CborNoError) {
        DEBUG("parse_entry: error getting length of value of field t\n");
        return error;
    }
    if (type_len > COMPAS_NAME_LEN) {
        DEBUG("parse_entry: error getting length of value of field t\n");
        return CborErrorDataTooLarge;
    }
    error = cbor_value_copy_text_string(&typeValue, type, &type_len, NULL); 
    if (error != CborNoError) {
        DEBUG("parse_entry: error getting value of field t\n");
        return error;
    }

    // Lifetime
    CborValue lifetimeValue;
    error = cbor_value_map_find_value(map, "lt", &lifetimeValue); 
    if (error != CborNoError) {
        DEBUG("parse_entry: error finding field lt \n");
        return error;
    }
    if (!cbor_value_is_unsigned_integer(&lifetimeValue)) {
        DEBUG("parse_entry: error field lt is not unsigned integer\n");
        return CborErrorImproperValue;
    }
    error = cbor_value_get_uint64(&lifetimeValue, &lifetime); 
    if (error != CborNoError) {
        DEBUG("parse_entry: error gettings value of field lt\n");
        return error;
    }

    rd_entry_init(entry, name, name_len, type, type_len, lifetime);
    return CborNoError;
}

static int parse_entries(const uint8_t *content, size_t content_len,
                         int(*entry_callback)(const rd_entry_t *)) 
{
    CborParser parser;
    CborValue array, map;
    if (cbor_parser_init(content, content_len, 0, &parser, &array) != CborNoError) {
        DEBUG("parse_registration: error creating parser\n");
        return -1;
    }
    if (!cbor_value_is_array(&array)) {
        DEBUG("parse_registration: error value is not array\n");
        return -1;
    }
    if (cbor_value_enter_container(&array, &map) != CborNoError) {
        DEBUG("parse_registration: error entering array\n");
        return -1;
    }

    while (!cbor_value_at_end(&map)) {
        rd_entry_t entry;
        if (parse_entry(&map, &entry) != CborNoError) {
            DEBUG("parse_registration: parsing entry failed\n");
            return -1;
        }

        int callback_result = entry_callback(&entry);
        if (callback_result != 0) {
            return callback_result;
        }

        if (cbor_value_advance(&map) != CborNoError) {
            DEBUG("parse_registration: error advancing the array\n");
            return -1;
        }
    }
    
    if (cbor_value_leave_container(&array, &map) != CborNoError) {
        DEBUG("parse_registration: error leaving array\n");
        return -1;
    }

    return 0;
}

static int content_requested(struct ccnl_relay_s *relay, struct ccnl_pkt_s *p,
                             struct ccnl_face_s *from)
{
    (void) relay;
    (void) from;

    int cb_res = hopp_callback_data_received(relay, p, from);
    if (cb_res)
        return cb_res; // handled

    char *content_name = ccnl_prefix_to_path(p->pfx);
    if (content_name == NULL)
    {
        DEBUG("content_requested: content name is null\n");
        return 0; // not handled
    }
    size_t content_name_len = strlen(content_name);

    compas_name_t cname;
    compas_name_init(&cname, content_name, content_name_len);
    DEBUG("content_requested: got content with name: %.*s\n", cname.name_len, cname.name);
    compas_nam_cache_entry_t *n = compas_nam_cache_find(&dodag, &cname);

    if (n) {
        if (cb_published) {
            cb_published(relay, p, from);
        }

        msg_t msg = { .content.ptr = n };
        if ((dodag.rank == COMPAS_DODAG_ROOT_RANK)) {
            msg.type = HOPP_NAM_DEL_MSG;
        }
        else {
            n->flags |= COMPAS_NAM_CACHE_FLAGS_REQUESTED;
            n->retries = COMPAS_NAM_CACHE_RETRIES;
            msg.type = HOPP_NAM_MSG;
        }
        msg_try_send(&msg, hopp_pid);
    }

    ccnl_free(content_name);
    return 1;
}

static int interest_received(struct ccnl_relay_s *relay,
                             struct ccnl_face_s *from,
                             struct ccnl_pkt_s *pkt)
{
    // only respond to interest if this node is root
    if (dodag.rank != COMPAS_DODAG_ROOT_RANK) {
        return 0; // interest not handled
    }

    // get name from interest and check if it starts with /rd/lookup/
    if (pkt->pfx == NULL) {
        DEBUG("interest_received: prefix is null\n");
        return 0; // interest not handled
    }
    char *interest_name = ccnl_prefix_to_path(pkt->pfx);
    if (interest_name == NULL) {
        DEBUG("interest_received: name is null\n");
        return 0; // interest not handled
    }
    size_t interest_name_len = strlen(interest_name);

    // check if lookup request
    if (interest_name_len > RD_LOOKUP_PREFIX_LEN 
    &&  strncmp(interest_name, RD_LOOKUP_PREFIX, RD_LOOKUP_PREFIX_LEN) == 0) {
        // is lookup request
        
        rd_msg_t rdmsg = { .relay = relay, .from = from, .pkt = pkt };
        msg_t msg = { .content.ptr = &rdmsg, .type = RD_LOOKUP_REQUEST_RX };
        if (msg_send(&msg, rd_pid) != 1) {
            DEBUG("content_requested: sending msg to rd thread failed\n");
        }
        ccnl_free(interest_name);
        return 1; // interest handled
    }

    return 0; // interest not handled
}

void *hopp(void *arg)
{
    struct ccnl_relay_s *relay = (struct ccnl_relay_s *) arg;
    (void) relay;

    msg_init_queue(hopp_q, HOPP_QSZ);
    evtimer_init_msg(&evtimer);

    memset(&dodag, 0, sizeof(dodag));

    ((evtimer_event_t *)&sol_msg_evt)->offset = HOPP_SOL_PERIOD;
    evtimer_add_msg(&evtimer, &sol_msg_evt, sched_active_pid);

    gnrc_netreg_entry_t _ne = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL, sched_active_pid);
    gnrc_netreg_register(GNRC_NETTYPE_CCN_HOPP, &_ne);
    loopback_face = ccnl_get_face_or_create(&ccnl_relay, -1, NULL, 0);

    ccnl_callback_set_data_send(content_send);
    ccnl_callback_set_data_received(content_requested);

    while (1) {
        msg_t msg;
        msg_receive(&msg);
        gnrc_pktsnip_t *pkt, *netif_snip;
        gnrc_netif_hdr_t *netif_hdr;
        compas_nam_cache_entry_t *nce;
        unsigned pos = 0;

        switch (msg.type) {
            case HOPP_SOL_MSG:
                if ((dodag.rank != COMPAS_DODAG_ROOT_RANK) &&
                    (dodag.rank == COMPAS_DODAG_UNDEF || !dodag.parent.alive)) {
                    hopp_send_sol(&dodag, false);
                    ((evtimer_event_t *)&sol_msg_evt)->offset = HOPP_SOL_PERIOD;
                    evtimer_add_msg(&evtimer, &sol_msg_evt, sched_active_pid);
                    if (dodag.sol_num == 3) {
                        dodag.flags |= COMPAS_DODAG_FLAGS_FLOATING;
                        trickle_init(&dodag.trickle, HOPP_TRICKLE_IMIN, HOPP_TRICKLE_IMAX, HOPP_TRICKLE_REDCONST);
                        uint64_t trickle_int = trickle_next(&dodag.trickle);
                        evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pam_msg_evt);
                        ((evtimer_event_t *)&pam_msg_evt)->offset = trickle_int;
                        evtimer_add_msg(&evtimer, &pam_msg_evt, sched_active_pid);
                    }
                }
                break;
            case HOPP_PAM_MSG:
                if (dodag.rank != COMPAS_DODAG_UNDEF) {
                    hopp_send_pam(&dodag, NULL, 0, true);
                    uint64_t trickle_int = trickle_next(&dodag.trickle);
                    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pam_msg_evt);
                    ((evtimer_event_t *)&pam_msg_evt)->offset = trickle_int;
                    evtimer_add_msg(&evtimer, &pam_msg_evt, sched_active_pid);
                }
                break;
            case HOPP_NAM_MSG:
                nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                pos = nce - dodag.nam_cache;
                evtimer_del(&evtimer, (evtimer_event_t *)&nam_msg_evts[pos]);
                if (dodag.rank != COMPAS_DODAG_UNDEF) {
                    if ((dodag.parent.alive || dodag.rank == COMPAS_DODAG_ROOT_RANK) &&
                         check_nce(&dodag, nce)) {
                        nam_msg_evts[pos].msg.type = HOPP_NAM_MSG;
                        nam_msg_evts[pos].msg.content.ptr = nce;
                        ((evtimer_event_t *)&nam_msg_evts[pos])->offset = HOPP_NAM_PERIOD;
                        evtimer_add_msg(&evtimer, &nam_msg_evts[pos], sched_active_pid);
                    }
                }

                break;
            case HOPP_NAM_DEL_MSG:
                nce = (compas_nam_cache_entry_t *) msg.content.ptr;
                hopp_nce_del(&dodag, nce);
                break;
            case HOPP_PARENT_TIMEOUT_MSG:
                hopp_parent_timeout(&dodag);
                break;
            case HOPP_STOP_MSG:
                ccnl_callback_set_data_send(NULL);
                ccnl_callback_set_data_received(NULL);
                return NULL;
            case GNRC_NETAPI_MSG_TYPE_RCV:
                pkt = (gnrc_pktsnip_t *) msg.content.ptr;
                netif_snip = gnrc_pktsnip_search_type(pkt, GNRC_NETTYPE_NETIF);
                if (netif_snip) {
                    netif_hdr = (gnrc_netif_hdr_t *) netif_snip->data;
                    hopp_dispatcher(relay, &dodag, pkt->data, pkt->size,
                                    gnrc_netif_hdr_get_src_addr(netif_hdr),
                                    netif_hdr->src_l2addr_len,
                                    gnrc_netif_hdr_get_dst_addr(netif_hdr),
                                    netif_hdr->dst_l2addr_len);
                }
                gnrc_pktbuf_release(pkt);
                break;
            default:
                break;
        }
    }

    return NULL;
}

void hopp_root_start(const char *prefix, size_t prefix_len)
{
    compas_dodag_init_root(&dodag, prefix, prefix_len);
    compas_dodag_print(&dodag);
    trickle_init(&dodag.trickle, HOPP_TRICKLE_IMIN, HOPP_TRICKLE_IMAX, HOPP_TRICKLE_REDCONST);
    uint64_t trickle_int = trickle_next(&dodag.trickle);
    evtimer_del((evtimer_t *)(&evtimer), (evtimer_event_t *)&pam_msg_evt);
    ((evtimer_event_t *)&pam_msg_evt)->offset = trickle_int;
    evtimer_add_msg(&evtimer, &pam_msg_evt, hopp_pid);
}

bool hopp_publish_content(const char *name, size_t name_len,
                          unsigned char *content, size_t content_len)
{
    static compas_name_t cname;
    compas_name_init(&cname, name, name_len);

    compas_nam_cache_entry_t *nce = compas_nam_cache_add(&dodag, &cname, NULL);
    if (nce) {
        nce->flags |= COMPAS_NAM_CACHE_FLAGS_REQUESTED;
        static char prefix_n[COMPAS_NAME_LEN + 1];
        memcpy(prefix_n, cname.name, cname.name_len);
        prefix_n[cname.name_len] = '\0';
        struct ccnl_prefix_s *prefix = ccnl_URItoPrefix(prefix_n, CCNL_SUITE_NDNTLV, NULL, NULL);
        int offs = CCNL_MAX_PACKET_SIZE;
        content_len = ccnl_ndntlv_prependContent(prefix, (unsigned char*) content, content_len, NULL, NULL, &offs, _out);
        ccnl_prefix_free(prefix);
        if ((int)content_len < 0) {
            DEBUG("hopp_publish_content: Error, content length: %u\n", content_len);
            return false;
        }
        unsigned char *olddata;
        unsigned char *data = olddata = _out + offs;
        int len;
        unsigned typ;
        if (ccnl_ndntlv_dehead(&data, (int *)&content_len, (int*) &typ, &len) ||
            typ != NDN_TLV_Data) {
            DEBUG("hopp_publish_content: ccnl_ndntlv_dehead\n");
            return false;
        }
        struct ccnl_pkt_s *pk = ccnl_ndntlv_bytes2pkt(typ, olddata, &data, (int *)&content_len);
        struct ccnl_content_s *c = ccnl_content_new(&pk);

        msg_t ms = { .type = CCNL_MSG_ADD_CS, .content.ptr = c };
        msg_send(&ms, _ccnl_event_loop_pid);

        msg_t msg = { .type = HOPP_NAM_MSG, .content.ptr = nce };
        msg_try_send(&msg, hopp_pid);

        return true;
    }

    return false;
}

bool rd_register(const char *name, size_t name_len,
                 const char *contenttype, size_t contenttype_len,
                 uint64_t lifetime)
{
    if (name_len <= 0 || contenttype_len <= 0 || lifetime <= 0) {
        return false;
    }

    rd_entry_t entry;
    rd_entry_init(&entry, name, name_len, contenttype, contenttype_len, lifetime);

    msg_t msg = { .content.ptr = &entry, .type = RD_REGISTER_REQUEST_TX };
    if (msg_send(&msg, rd_pid) != 1) {
        DEBUG("content_requested: sending msg to rd thread failed\n");
        return false;
    }

    return true;
}

static int rd_register_entry(const rd_entry_t *entry) 
{
    DEBUG("rd_register_entry: Trying to register entry:\n");
    print_entry(entry);

    mutex_lock(&_registered_content_mutex);
    for (int j = 0; j < REGISTERED_CONTENT_COUNT; j++) {
        if (_registered_content[j].lifetime > 0) {
            continue;
        }
        _registered_content[j] = *entry;
        DEBUG("rd_register_content: content was registered at index %u\n", j);
        mutex_unlock(&_registered_content_mutex);
        return 0;
    }
    DEBUG("rd_register_content: Content could not be registered, no available space left.\n");
    mutex_unlock(&_registered_content_mutex);
    return -1;
}

static int rd_lookup_registered_content(const char *contenttype, size_t contenttype_len,
                                        uint8_t *response, size_t *response_len)
{
    DEBUG("rd_lookup_registered_content: searching registered content with type: %.*s\n", contenttype_len, contenttype);

    CborEncoder encoder, arrayEncoder;
    cbor_encoder_init(&encoder, response, *response_len, 0);
    if (cbor_encoder_create_array(&encoder, &arrayEncoder, 1) != CborNoError) {
        DEBUG("rd_lookup_registered_content: creating array failed\n");
        return -1;
    }

    mutex_lock(&_registered_content_mutex);
    for (int i = 0; i < REGISTERED_CONTENT_COUNT; i++) {
        rd_entry_t entry = _registered_content[i];
        if (entry.lifetime <= 0) {
            continue;
        }
        if (entry.type_len != contenttype_len) {
            continue;
        }
        if (strncmp(entry.type, contenttype, contenttype_len != 0)) {
            continue;
        }

        DEBUG("rd_lookup_registered_content: found matching content with name: %.*s\n", entry.name_len, entry.name);
        if (encode_entry(&arrayEncoder, &entry) != CborNoError) {
            DEBUG("rd_lookup_registered_content: Encoding entry failed\n");
            mutex_unlock(&_registered_content_mutex);
            return -1;
        } 
    }
    mutex_unlock(&_registered_content_mutex);

    if (cbor_encoder_close_container(&encoder, &arrayEncoder) != CborNoError) {
        DEBUG("rd_lookup_registered_content: Closing array failed\n");
        return -1;
    }

    DEBUG("rd_lookup_registered_content: done searching.\n");

    *response_len = cbor_encoder_get_buffer_size(&encoder, response);
    DEBUG("rd_lookup_registered_content: length of encoded message: %u\n", *response_len);
    return 0;
}

static char *rand_string(char *str, size_t size)
{
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ12345667890";
    if (size) {
        --size;
        for (size_t n = 0; n < size; n++) {
            int key = random_uint32_range(0, (sizeof charset - 1));
            str[n] = charset[key];
        }
        str[size] = '\0';
    }
    return str;

    /* 

    if (!b58enc(&register_message_name[RD_REGISTER_PREFIX_LEN], &register_message_name_len, hash, 32))
                {
                    DEBUG("RD_REGISTER_REQUEST_TX: ERROR, b58enc failed.\n");
                    break;
                }

                */
}

static int data_received_process_rd(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt, struct ccnl_face_s *from) 
{
    (void)relay;
    (void)from;

    char *content_name = ccnl_prefix_to_path(pkt->pfx);
    if (content_name == NULL)
    {
        DEBUG("process_rd: content name is null\n");
        return 0; // not handled
    }
    size_t content_name_len = strlen(content_name);

    // check if lookup response
    if (content_name_len > RD_LOOKUP_PREFIX_LEN 
    &&  strncmp(content_name, RD_LOOKUP_PREFIX, RD_LOOKUP_PREFIX_LEN) == 0) {
        // is lookup response
        
        ccnl_free(content_name);

        if (parse_entries((const uint8_t *)pkt->content, (const size_t)pkt->contlen, print_entry) != 0)
            DEBUG("RD_LOOKUP_RESPONSE_RX: parsing lookup response failed\n");
        return 1;
    }

    // check if register request
    if (content_name_len > RD_REGISTER_PREFIX_LEN 
    &&  strncmp(content_name, RD_REGISTER_PREFIX, RD_REGISTER_PREFIX_LEN) == 0
    &&  dodag.rank == COMPAS_DODAG_ROOT_RANK) {
        // is register request

        ccnl_free(content_name);

        if (parse_entries((const uint8_t *)pkt->content, pkt->contlen, rd_register_entry) != 0)
            DEBUG("RD_REGISTER_REQUEST_RX: parsing failed\n");
        return 1;
    }
    return 0;
}

void *rd(void* arg)
{
    (void) arg;

    msg_init_queue(rd_q, RD_QSZ);
    ccnl_set_local_producer(interest_received);
    hopp_callback_set_data_received(data_received_process_rd);

    msg_t msg;
    while (1) {
        msg_receive(&msg);
        DEBUG("rd: received msg\n");

        char name[COMPAS_NAME_LEN];
        size_t payload_len;
        uint8_t name_current_char, name_chars_available, payload[128];
        struct ccnl_prefix_s *prefix_ccnl;
        struct rd_entry_t *entry;
        rd_lookup_msg_t *lookupmsg;

        switch (msg.type) {
            case RD_LOOKUP_REQUEST_TX:
                // client sends lookup request
                DEBUG("rd: RD_LOOKUP_REQUEST_TX\n");

                lookupmsg = (rd_lookup_msg_t *)msg.content.ptr;

                memset(name, 0, sizeof(name));
                name_current_char = 0;
                name_chars_available = sizeof(name) - 1;
                
                // add rd lookup prefix
                if (name_chars_available < RD_LOOKUP_PREFIX_LEN)
                {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                strncpy(&name[name_current_char], RD_LOOKUP_PREFIX, RD_LOOKUP_PREFIX_LEN);
                name_current_char += RD_LOOKUP_PREFIX_LEN;
                name_chars_available -= RD_LOOKUP_PREFIX_LEN;

                // add slash
                if (name_chars_available < 1) 
                {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                name[name_current_char] = '/';
                name_current_char++;
                name_chars_available--;

                // add contenttype
                if (name_chars_available < lookupmsg->contenttype_len)
                {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                strncpy(&name[name_current_char], lookupmsg->contenttype, lookupmsg->contenttype_len);
                name_current_char += lookupmsg->contenttype_len;
                name_chars_available -= lookupmsg->contenttype_len;

                // add slash
                if (name_chars_available < 1) 
                {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                name[name_current_char] = '/';
                name_current_char++;
                name_chars_available--;

                // add session id
                if (name_chars_available < 1) 
                {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                rand_string(&name[name_current_char], name_chars_available > 31 ? 31 : name_chars_available);

                // temporary workaround for bug in CCNL
                name[32] = 0;

                DEBUG("RD_LOOKUP_REQUEST_TX: sending interest with name: %s\n", name);

                prefix_ccnl = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL, 0);

                memset(_lookup_int_buf, 0, HOPP_INTEREST_BUFSIZE);
                if (ccnl_send_interest(prefix_ccnl, _lookup_int_buf, HOPP_INTEREST_BUFSIZE, NULL, NULL) != 0) {
                    DEBUG("RD_LOOKUP_REQUEST_TX: sending interest failed\n");
                }
                ccnl_prefix_free(prefix_ccnl);
            case RD_REGISTER_REQUEST_TX:
                // client sends register request
                DEBUG("rd: RD_REGISTER_REQUEST_TX\n");

                // TODO: store rd_entry in static array
                entry = (struct rd_entry_t *)msg.content.ptr;

                payload_len = sizeof(payload);

                CborEncoder encoder, arrayEncoder;
                cbor_encoder_init(&encoder, payload, payload_len, 0);
                if (cbor_encoder_create_array(&encoder, &arrayEncoder, 1) != CborNoError) {
                    DEBUG("RD_REGISTER_REQUEST_TX: creating array failed\n");
                    break;
                }

                if (encode_entry(&arrayEncoder, (const rd_entry_t *)entry) != CborNoError) {
                    DEBUG("RD_REGISTER_REQUEST_TX: Encoding entry failed\n");
                    break;
                } 
                
                if (cbor_encoder_close_container(&encoder, &arrayEncoder) != CborNoError) {
                    DEBUG("RD_REGISTER_REQUEST_TX: Closing array failed\n");
                    break;
                }

                payload_len = cbor_encoder_get_buffer_size(&encoder, payload);
                DEBUG("RD_REGISTER_REQUEST_TX: length of encoded message: %u\n", payload_len);

                // build message name

                memset(name, 0, sizeof(name));
                name_current_char = 0;
                name_chars_available = sizeof(name) - 1;

                unsigned char hash[SHA256_DIGEST_LENGTH];
                sha256(payload, (size_t)payload_len, hash);

                // add rd register prefix
                if (name_chars_available < RD_REGISTER_PREFIX_LEN)
                {
                    DEBUG("RD_REGISTER_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                strncpy(&name[name_current_char], RD_REGISTER_PREFIX, RD_REGISTER_PREFIX_LEN);
                name_current_char += RD_REGISTER_PREFIX_LEN;
                name_chars_available -= RD_REGISTER_PREFIX_LEN;

                // add slash
                if (name_chars_available < 1) 
                {
                    DEBUG("RD_REGISTER_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                name[name_current_char] = '/';
                name_current_char++;
                name_chars_available--;

                if (!b58enc(&name[name_current_char], (size_t *) &name_chars_available, hash, 32))
                {
                    DEBUG("RD_REGISTER_REQUEST_TX: ERROR, b58enc failed.\n");
                    break;
                }
                name[32] = 0;
                DEBUG("RD_REGISTER_REQUEST_TX: name of registration message: %s\n", name);

                if (!hopp_publish_content(name, strlen(name), (unsigned char*) payload, payload_len))
                    DEBUG("RD_REGISTER_REQUEST_TX: publishing content failed.\n");
                DEBUG("RD_REGISTER_REQUEST_TX: registration send\n");
                break;
            default: 
                DEBUG("Default case, should not happen\n");
                break;
        }
    }

    return NULL;
}

bool rd_lookup(const char *contenttype, size_t contenttype_len)
{   
    if (contenttype_len > COMPAS_NAME_LEN) {
        DEBUG("contenttype is too long\n");
        return false;
    }

    rd_lookup_msg_t *lookup_msg = rd_lookup_msg_get_free_entry();
    strncpy(lookup_msg->contenttype, contenttype, contenttype_len);
    lookup_msg->contenttype_len = contenttype_len;
    msg_t msg = { .content.ptr = lookup_msg, .type = RD_LOOKUP_REQUEST_TX };
    if (msg_send(&msg, rd_pid) != 1) {
        DEBUG("content_requested: sending msg to rd thread failed\n");
        return false;
    }

    return true;
}