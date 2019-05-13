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
#define ENABLE_DEBUG    (1)
//#include "debug.h"

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


char lookup_stack[THREAD_STACKSIZE_DEFAULT];
kernel_pid_t lookup_pid;
static msg_t lookup_q[LOOKUP_QSZ];

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

typedef struct __attribute__((packed)) {
    char name[COMPAS_NAME_LEN];     /**< Name */
    size_t name_len;                /**< Length of a name */
    char type[COMPAS_NAME_LEN];     /**< Content-Type */
    size_t type_len;                /**< Length of the content type */
    uint64_t lifetime;              /**< Lifetime */
} rd_entry_t;

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
    DEBUG("-------------\n");
    DEBUG("\tName: %.*s\n", entry->name_len, entry->name);
    DEBUG("\tType: %.*s\n", entry->type_len, entry->type);
    DEBUG("\tLifetime: %llu\n", entry->lifetime);
    DEBUG("-------------\n");
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

#define REGISTERED_CONTENT_COUNT (100)

static rd_entry_t registered_content[REGISTERED_CONTENT_COUNT];

static int rd_register_entry(const rd_entry_t *entry) 
{
    DEBUG("rd_register_entry: Trying to register entry:\n");
    print_entry(entry);

    for (int j = 0; j < REGISTERED_CONTENT_COUNT; j++) {
        if (registered_content[j].lifetime > 0) {
            continue;
        }
        registered_content[j] = *entry;
        DEBUG("rd_register_content: content was registered at index %u\n", j);
        return 0;
    }
    DEBUG("rd_register_content: Content could not be registered, no available space left.\n");
    return -1;
}

static int rd_register_content(const uint8_t *registercontent, size_t registercontent_len) 
{
    if (parse_entries(registercontent, registercontent_len, rd_register_entry) != 0) {
        DEBUG("rd_register_content: parsing failed\n");
        return -1;
    }
    return 0;
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

    for (int i = 0; i < REGISTERED_CONTENT_COUNT; i++) {
        rd_entry_t entry = registered_content[i];
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
            return -1;
        } 
    }

    if (cbor_encoder_close_container(&encoder, &arrayEncoder) != CborNoError) {
        DEBUG("rd_lookup_registered_content: Closing array failed\n");
        return -1;
    }

    DEBUG("rd_lookup_registered_content: done searching.\n");

    *response_len = cbor_encoder_get_buffer_size(&encoder, response);
    DEBUG("rd_lookup_registered_content: length of encoded message: %u\n", *response_len);
    return 0;
}

#define RD_REGISTER_PREFIX "/rd/register/"
#define RD_REGISTER_PREFIX_LEN 13

#define RD_LOOKUP_PREFIX "/rd/lookup/"
#define RD_LOOKUP_PREFIX_LEN 11

static int content_requested(struct ccnl_relay_s *relay, struct ccnl_pkt_s *p,
                             struct ccnl_face_s *from)
{
    (void) relay;
    (void) from;
    char *content_name = ccnl_prefix_to_path(p->pfx);
    size_t content_name_len = strlen(content_name);

    if (content_name_len > RD_LOOKUP_PREFIX_LEN 
    &&  strncmp(content_name, RD_LOOKUP_PREFIX, RD_LOOKUP_PREFIX_LEN) == 0) {
        // is lookup response
        DEBUG("content_requested: got lookup response\n");
        
        msg_t msg = { .content.ptr = p, .type = LOOKUP_RESPONSE };
        if (msg_send(&msg, lookup_pid) != 1) {
            DEBUG("content_requested: sending msg to lookup thread failed\n");
        }
        ccnl_free(content_name);
        return 1;
    }

    if (content_name_len > RD_REGISTER_PREFIX_LEN 
    &&  strncmp(content_name, RD_REGISTER_PREFIX, RD_REGISTER_PREFIX_LEN) == 0
    &&  dodag.rank == COMPAS_DODAG_ROOT_RANK) {
        // is register request
        DEBUG("content_requested: got register request:\n");
        
        rd_register_content((const uint8_t *)p->content, p->contlen);
        ccnl_free(content_name);
        return 1;
    }

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
    // get name from interest and check if it starts with /rd/lookup/
    char *interest_name = ccnl_prefix_to_path(pkt->pfx);
    size_t interest_name_len = strlen(interest_name);
    if (interest_name_len <= RD_LOOKUP_PREFIX_LEN 
    || strncmp(interest_name, RD_LOOKUP_PREFIX, RD_LOOKUP_PREFIX_LEN))
        return 0; // interest not handled
    
    if (dodag.rank != COMPAS_DODAG_ROOT_RANK) {
        DEBUG("interest_received: is lookup request but this node is not root\n");
        return 0; // interest not handled
    }
    DEBUG("interest_received: is lookup request and node is root, will respond as RD\n");

    // build response 

    char *query = interest_name + RD_LOOKUP_PREFIX_LEN;
    DEBUG("interest_received: query: %s\n", query);

    uint8_t payload[256];
    size_t payload_len = sizeof(payload);
    int lookup_result = rd_lookup_registered_content(query, strlen(query), payload, &payload_len);
    if (lookup_result) {
        DEBUG("interest_received: failed to build response message\n");
        return 0; // interest not handled
    }

    ccnl_free(interest_name);

    // send response

    int offs = CCNL_MAX_PACKET_SIZE;
    int content_len = ccnl_ndntlv_prependContent(pkt->pfx, (unsigned char*) payload, payload_len, NULL, NULL, &offs, _out);
    if (content_len < 0) {
        DEBUG("interest_received: Error, content length: %u\n", content_len);
        return 0; // interest not handled
    }
    unsigned char *olddata;
    unsigned char *data = olddata = _out + offs;
    int len;
    unsigned type;
    if (ccnl_ndntlv_dehead(&data, &content_len, (int*) &type, &len) ||
        type != NDN_TLV_Data) {
        DEBUG("interest_received: ccnl_ndntlv_dehead\n");
        return 0; // interest not handled
    }
    struct ccnl_pkt_s *response_pkt = ccnl_ndntlv_bytes2pkt(type, olddata, &data, &content_len);
    int send_response_result = ccnl_send_pkt(relay, from, response_pkt);
    if (send_response_result)
        DEBUG("interest_received: send response failed with code: %i\n", send_response_result);

    return 1; // interest handled
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
                ccnl_set_local_producer(NULL);
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

    // build message content

    rd_entry_t entry;
    rd_entry_init(&entry, name, name_len, contenttype, contenttype_len, lifetime);

    uint8_t encoded[128];
    size_t encoded_len = sizeof(encoded);

    CborEncoder encoder, arrayEncoder;
    cbor_encoder_init(&encoder, encoded, encoded_len, 0);
    if (cbor_encoder_create_array(&encoder, &arrayEncoder, 1) != CborNoError) {
        DEBUG("rd_register: creating array failed\n");
        return false;
    }

    if (encode_entry(&arrayEncoder, &entry) != CborNoError) {
        DEBUG("rd_register: Encoding entry failed\n");
        return false;
    } 
    
    if (cbor_encoder_close_container(&encoder, &arrayEncoder) != CborNoError) {
        DEBUG("rd_register: Closing array failed\n");
        return false;
    }

    encoded_len = cbor_encoder_get_buffer_size(&encoder, encoded);
    DEBUG("rd_register: length of encoded message: %u\n", encoded_len);

    // build message name

    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256(encoded, (size_t)encoded_len, hash);

    char register_message_name[64];
    size_t register_message_name_len = sizeof(register_message_name)-RD_REGISTER_PREFIX_LEN;
    strcpy(register_message_name, RD_REGISTER_PREFIX);
    if (!b58enc(&register_message_name[RD_REGISTER_PREFIX_LEN], &register_message_name_len, hash, 32))
    {
        DEBUG("rd_register: ERROR, b58enc failed.\n");
        return false;
    }
    register_message_name[32] = 0;
    DEBUG("rd_register: name of registration message: %s\n", register_message_name);
    DEBUG("rd_register: length: %i\n", strlen(register_message_name));

    return hopp_publish_content(register_message_name, strlen(register_message_name), (unsigned char*) encoded, encoded_len);
}

#define BUF_SIZE (100)
static unsigned char _int_buf[BUF_SIZE];

void *lookup(void *arg)
{
    (void)arg;
    msg_init_queue(lookup_q, LOOKUP_QSZ);
    ccnl_set_local_producer(interest_received);

    msg_t msg;
    while (1) {
        msg_receive(&msg);
        DEBUG("lookup: received msg\n");

        char *prefix;
        struct ccnl_prefix_s *prefix_ccnl;

        struct ccnl_pkt_s *pkt;
        uint8_t *response;
        size_t response_len;

        switch (msg.type) {
            case LOOKUP_REQUEST:
                prefix = (char *) msg.content.ptr;
                DEBUG("lookup: sending interest with name: %s\n", prefix);

                prefix_ccnl = ccnl_URItoPrefix(prefix, CCNL_SUITE_NDNTLV, NULL, 0);
                memset(_int_buf, '\0', BUF_SIZE);
                
                if (ccnl_send_interest(prefix_ccnl, _int_buf, BUF_SIZE, NULL, NULL) != 0) {
                    DEBUG("lookup: sending interest failed\n");
                }
                ccnl_prefix_free(prefix_ccnl);
                
                break;
            case LOOKUP_RESPONSE:
                pkt = (struct ccnl_pkt_s *)msg.content.ptr;
                response = (uint8_t *)pkt->content;
                response_len = (size_t)pkt->contlen;

                if (parse_entries(response, response_len, print_entry) != 0) {
                    DEBUG("lookup: parsing lookup response failed\n");
                    break;
                }
                break;
            default: break;
        }
    }

    return NULL;
}

bool rd_lookup(const char *contenttype, size_t contenttype_len)
{   
    // send interest

    char prefix[65];
    memset(prefix, 0, sizeof(prefix));

    strcpy(prefix, RD_LOOKUP_PREFIX);
    strncpy(&prefix[RD_LOOKUP_PREFIX_LEN], contenttype, contenttype_len);
    prefix[32] = 0;
    
    msg_t msg = { .content.ptr = &prefix, .type = LOOKUP_REQUEST };
    if (msg_send(&msg, lookup_pid) != 1) {
        DEBUG("content_requested: sending msg to lookup thread failed\n");
    }

    return true;
}