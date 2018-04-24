

#include <stdio.h>

#include "div.h"
#include "fmt.h"
#include "pktcnt.h"
#include "net/gnrc.h"
#include "net/ipv6/hdr.h"
#include "net/icmpv6.h"
#include "net/udp.h"
#include "net/protnum.h"
#include "net/sixlowpan.h"
#include "thread.h"
#include "xtimer.h"

#ifdef MODULE_SIXLOWPAN
#define NETREG_TYPE     (GNRC_NETTYPE_SIXLOWPAN)
#elif MODULE_CCN_LITE
#define NETREG_TYPE     (GNRC_NETTYPE_CCN)
#else
#define NETREG_TYPE     (GNRC_NETTYPE_IPV6)
#endif

#define PKTCNT_MSG_QUEUE_SIZE   (4)
#ifndef PKTCNT_PRIO
#define PKTCNT_PRIO             (THREAD_PRIORITY_MAIN - 1)
#endif
#ifndef PKTCNT_STACKSIZE
#define PKTCNT_STACKSIZE        (THREAD_STACKSIZE_DEFAULT)
#endif
/* net/emcute.h and net/gcoap.h require sock_udp so we can't include them with
 * e.g. gnrc_networking, so just define ports here */
#define COAP_PORT           (5683U)
#define MQTT_PORT           (1883U)

#define NDN_INTEREST_TYPE   (0x05U)
#define NDN_DATA_TYPE       (0x06U)

#ifdef MODULE_PKTCNT_FAST
#include "net/netstats.h"

/* following counters are only for fast mode*/
uint32_t retransmissions;
uint32_t tx_interest;
uint32_t tx_data;
uint32_t rx_interest;
uint32_t rx_data;
uint32_t netdev_evt_tx_noack;
uint32_t tx_pam;
uint32_t tx_nam;
uint32_t tx_sol;
uint32_t rx_nam;
uint32_t rx_pam;
uint32_t rx_sol;

#ifdef MODULE_GNRC_IPV6
char pktcnt_addr_str[17];
#endif

void pktcnt_fast_print(void)
{
    netstats_t *stats;
    gnrc_netif_t *netif;
#if GNRC_NETIF_NUMOF > 1
    netif = NULL;
    while ((netif = gnrc_netif_iter(netif))) {
        if (gnrc_netapi_get(netif->pid, NETOPT_IS_WIRED, 0, NULL, 0) != 1) {
            break;
        }
    }
#else
    netif = gnrc_netif_iter(NULL);
#endif
    gnrc_netapi_get(netif->pid, NETOPT_STATS, 0, &stats,
                    sizeof(&stats));
    printf("STATS;%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";"
      "%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";"
      "%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32";%" PRIu32"\n",
        retransmissions,
        tx_interest,
        tx_data,
        rx_interest,
        rx_data,
        stats->rx_count,
        stats->rx_bytes,
        stats->tx_unicast_count,
        stats->tx_mcast_count,
        stats->tx_bytes,
        stats->tx_success,
        stats->tx_failed,
        netdev_evt_tx_noack,
        tx_pam,
        tx_nam,
        tx_sol,
        rx_nam,
        rx_pam,
        rx_sol);
}

void pktcnt_timer_init(void)
{
    puts("");   /* clear buffer from reboot */
    puts("PKT 00 TIMER 0.00000");   /* fake timer here, I need this to sync my bootstrapping */
}

#else

enum {
    TYPE_TIMER,
    TYPE_STARTUP,
    TYPE_PKT_TX,
    TYPE_PKT_RX,
};

typedef struct {
    char id[24];
} pktcnt_ctx_t;


static char pktcnt_stack[PKTCNT_STACKSIZE];
static kernel_pid_t pktcnt_pid = KERNEL_PID_UNDEF;
static msg_t pktcnt_msg_queue[PKTCNT_MSG_QUEUE_SIZE];
static pktcnt_ctx_t ctx;
#ifdef MODULE_GNRC_IPV6
static char src[IPV6_ADDR_MAX_STR_LEN], dst[IPV6_ADDR_MAX_STR_LEN];
#endif

const char *keyword = "PKT";
const char *typestr[] = { "TIMER", "STARTUP", "PKT_TX", "PKT_RX", };




static void log_event(int type)
{
    uint64_t now = xtimer_now_usec64();
    /* now overflows for after ~71.5 min! */
    printf("%s %s %s %lu.%06lu ", keyword,
           ctx.id, typestr[type],
           (unsigned long)div_u64_by_1000000(now),
           (unsigned long)now % US_PER_SEC
       );
}

static void _log_tx(gnrc_pktsnip_t *pkt);

static void *pktcnt_thread(void *args)
{
    (void)args;
    gnrc_netreg_entry_t entry = GNRC_NETREG_ENTRY_INIT_PID(
                                        GNRC_NETREG_DEMUX_CTX_ALL,
                                        thread_getpid()
                                    );
    msg_init_queue(pktcnt_msg_queue, PKTCNT_MSG_QUEUE_SIZE);
    gnrc_netreg_register(NETREG_TYPE, &entry);
/*#ifdef MODULE_CCN_LITE
      we need HOPP for pub/sub as well as initial FIB setup
    gnrc_netreg_register(GNRC_NETTYPE_CCN_HOPP, &entry);
#endif*/

    while (1) {
        msg_t msg;
        msg_receive(&msg);
        if (msg.type == GNRC_NETAPI_MSG_TYPE_RCV) {
            pktcnt_log_rx(msg.content.ptr);
            gnrc_pktbuf_release(msg.content.ptr);
        }
        else if (msg.type == GNRC_NETAPI_MSG_TYPE_SND) {
            _log_tx(msg.content.ptr);
            gnrc_pktbuf_release(msg.content.ptr);
        }
    }
    return NULL;
}

int pktcnt_init(void)
{
    /* find link layer address of lowpan device: use first device for now */
    if (pktcnt_pid <= KERNEL_PID_UNDEF) {
        gnrc_netif_t *dev = gnrc_netif_iter(NULL);
        if ((dev == NULL) || (dev->l2addr_len == 0)) {
            return PKTCNT_ERR_INIT;
        }
        gnrc_netif_addr_to_str(dev->l2addr, dev->l2addr_len, ctx.id);

        log_event(TYPE_STARTUP);
        puts("");

        if ((pktcnt_pid = thread_create(pktcnt_stack, sizeof(pktcnt_stack),
                                        PKTCNT_PRIO, THREAD_CREATE_STACKTEST,
                                        pktcnt_thread, NULL, "pktcnt")) < 0) {
            return PKTCNT_ERR_INIT;
        }
        return PKTCNT_OK;
    }
    return PKTCNT_ERR_INIT;
}

void pktcnt_timer_init(void)
{
    puts("");   /* clear buffer from reboot */
    strcpy(ctx.id, "00");
    log_event(TYPE_TIMER);
    memset(ctx.id, 0, sizeof(ctx.id));
    puts("");
}

static void log_l2_rx(gnrc_pktsnip_t *pkt)
{
    char addr_str[24];
    gnrc_netif_hdr_t *netif_hdr = pkt->next->data;

    log_event(TYPE_PKT_RX);
    printf("%s ", gnrc_netif_addr_to_str(gnrc_netif_hdr_get_src_addr(netif_hdr),
                                         netif_hdr->src_l2addr_len, addr_str));
    printf("%s ", gnrc_netif_addr_to_str(gnrc_netif_hdr_get_dst_addr(netif_hdr),
                                         netif_hdr->dst_l2addr_len, addr_str));
    printf("seq=%u ", (unsigned)netif_hdr->seq);
    printf("%u ", (unsigned)pkt->size);
}

static void log_l2_tx(gnrc_pktsnip_t *pkt)
{
    char addr_str[24];
    gnrc_netif_hdr_t *netif_hdr = pkt->data;

    log_event(TYPE_PKT_TX);
    printf("%s ", ctx.id);
    if (netif_hdr->flags &
        (GNRC_NETIF_HDR_FLAGS_BROADCAST | GNRC_NETIF_HDR_FLAGS_MULTICAST)) {
        printf("BROADCAST ");
    }
    else {
        printf("%s ", gnrc_netif_addr_to_str(gnrc_netif_hdr_get_dst_addr(netif_hdr),
                                             netif_hdr->dst_l2addr_len, addr_str));
    }
    printf("%u ", (unsigned)gnrc_pkt_len(pkt->next));
}

#ifdef MODULE_CCN_LITE

static void log_name(uint8_t *payload, unsigned len)
{
    unsigned i = 0;
    while (i < len) {
        if (payload[i] == 0x08) {
            unsigned complen = payload[i+1];
            printf("/%.*s", complen, (char *)&payload[i+2]);
            i += complen + 2;
        }
        else {
            /* this should not happen, actually */
            break;
        }
    }
    return;
}

static void log_ndn(uint8_t *payload)
{
    /* print type */
    printf("NDN %02x ", payload[0]);

    unsigned pkttype = payload[0];
    (void) pkttype;
    unsigned pktlen = payload[1];
    unsigned i = 2;

    while (i < pktlen) {
        unsigned tlvtype = payload[i];
        unsigned tlvlen = payload[i+1];

        /* Name TLV */
        if (tlvtype == 0x7) {
            log_name(payload + i + 2, tlvlen);
            i += tlvlen + 2;
            break;
        }
        /* Nonce TLV */
        /*
        else if ((pkttype == 0x5) && (payload[i] == 0x0a)) {
            printf("-0x%02x%02x%02x%02x", payload[i+2],
                                          payload[i+3],
                                          payload[i+4],
                                          payload[i+5]);
            i += 4 + 2;
        }
        */
        else{
            i++;
        }
    }

    printf("\n");
}

static void log_hopp(uint8_t *payload)
{
    /* print type
     * 0xC0: PAM
     * 0xC1: NAM
     * 0xC2: SOL
     */
    printf("HOPP %02x ", payload[2]);

    /* print rank for PAM */
    if (payload[2] == 0xC0) {
        printf("RANK-%" PRIu16, (uint16_t)(payload[6] << 8) | (payload[5] & 0xFF));
    }
    /* print name from NAM if it's has name type*/
    else if ((payload[2] == 0xC1) && (payload[4] == 0X00)) {
        uint16_t nam_len = (uint16_t)(payload[6] << 8) | (payload[5] & 0xFF);
        printf("%.*s", nam_len, &payload[7]);
    }
    printf("\n");
}
#endif

#ifdef MODULE_GNRC_IPV6
static unsigned _code_class(uint8_t code)
{
    return code >> 5;
}

static unsigned _code_detail(uint8_t code)
{
    return code & 0x1f;
}

static void log_coap(uint8_t *payload)
{
    uint8_t code = payload[1];
    printf("CoAP %u.%02u %u\n", _code_class(code), _code_detail(code),
           (((uint16_t)payload[2]) << 8) | (payload[3]));
}

static void log_mqtt(uint8_t *payload)
{
    uint8_t type_offset = (payload[0] != 0x01) ? 1 : 3;
    uint8_t type = payload[type_offset];
    uint16_t msgid;

    switch (type) {
        case 0x0a:  /* REGISTER */
            msgid = (((uint16_t)payload[type_offset + 3]) << 8) | payload[type_offset + 4];
            break;
        case 0x0b:  /* REGACK */
            msgid = (((uint16_t)payload[type_offset + 3]) << 8) | payload[type_offset + 4];
            break;
        case 0x0c:  /* PUBLISH */
            msgid = (((uint16_t)payload[type_offset + 4]) << 8) | payload[type_offset + 5];
            break;
        case 0x0d:  /* PUBACK */
            msgid = (((uint16_t)payload[type_offset + 3]) << 8) | payload[type_offset + 4];
            break;
        case 0x12:  /* SUBSCRIBE */
            msgid = (((uint16_t)payload[type_offset + 2]) << 8) | payload[type_offset + 3];
            break;
        case 0x13:  /* SUBACK */
            msgid = (((uint16_t)payload[type_offset + 4]) << 8) | payload[type_offset + 5];
            break;
        default:
            printf("MQTT %02x\n", type);
            return;
    }
    printf("MQTT %02x %u\n", type, msgid);
}

static bool demux_udp_port(uint8_t *payload, uint16_t port)
{

    switch (port) {
        case COAP_PORT:
            log_coap(payload);
            break;
        case MQTT_PORT:
            log_mqtt(payload);
            break;
        default:
            return false;
    }
    return true;
}

static void log_udp(uint8_t *payload, uint16_t src_port, uint16_t dst_port)
{
    if (!demux_udp_port(payload, dst_port) &&
        !demux_udp_port(payload, src_port)) {
        printf("UDP %u:%u\n", src_port, dst_port);
    }
}

static void log_icmpv6(icmpv6_hdr_t *hdr)
{
    printf("ICMPv6 %u(%u)\n", hdr->type, hdr->code);
}

static void log_flow(char *src, char *dst)
{
    if (src[0] != '\0') {
        printf("src=%s ", src);
        src[0] = '\0';
    }
    if (dst[0] != '\0') {
        printf("dst=%s ", dst);
        dst[0] = '\0';
    }
}
#endif

#ifdef MODULE_GNRC_SIXLOWPAN
#include "od.h"

static unsigned get_sixlo_src_len(uint8_t *data, char *src, int offset)
{
    int res = 0;
    if (!(data[1] & SIXLOWPAN_IPHC2_SAC) && !(data[1] & SIXLOWPAN_IPHC2_SAM)) {
        /* source address is fully attached */
        ipv6_addr_to_str(src, (ipv6_addr_t *)&data[offset], IPV6_ADDR_MAX_STR_LEN);
        res += sizeof(ipv6_addr_t);
    }
    else {
        switch (data[1] & SIXLOWPAN_IPHC2_SAM) {
            case 0x1:
                /* last 64 bits of source address are carried inline */
                fmt_bytes_hex(src, &data[offset], sizeof(uint64_t));
                src[sizeof(uint64_t)] = '\0';
                res += sizeof(uint64_t);
                break;
            case 0x2:
                /* last 16 bits of source address are carried inline */
                fmt_bytes_hex(src, &data[offset], sizeof(uint16_t));
                src[sizeof(uint16_t)] = '\0';
                res += sizeof(uint16_t);
                break;
            default:
                /* rest causes elision of source address */
                memcpy(src, "l2_src", sizeof("l2_src"));
                break;
        }
    }
    return res;
}

static int get_sixlo_multicast_dst_len(uint8_t *data)
{
    int res = 0;

    if ((data[1] & SIXLOWPAN_IPHC2_DAC) && !(data[1] & SIXLOWPAN_IPHC2_DAM)) {
        /* 48 bits of a multicast destination address are carried inline */
        res += 6;
    }
    else if (!(data[1] & SIXLOWPAN_IPHC2_DAC)) {
        switch (data[1] & SIXLOWPAN_IPHC2_DAM) {
            case 0x1:
                /* 48 bits of a multicast destination address are carried inline */
                res += 6;
                break;
            case 0x2:
                /* 32 bits of a multicast destination address are carried inline */
                res += sizeof(uint32_t);
                break;
            case 0x3:
                /* 8 bits of a multicast destination address are carried inline */
                res += sizeof(uint8_t);
                break;
        }
    }
    else {
        return -1;
    }
    return res;
}

static int get_sixlo_dst_len(uint8_t *data, char *dst, int offset)
{
    int res = 0;

    if (!(data[1] & SIXLOWPAN_IPHC2_DAC) && !(data[1] & SIXLOWPAN_IPHC2_DAM)) {
        /* destination address is fully attached */
        ipv6_addr_to_str(dst, (ipv6_addr_t *)&data[offset], IPV6_ADDR_MAX_STR_LEN);
        res += sizeof(ipv6_addr_t);
    }
    else if (data[1] & SIXLOWPAN_IPHC2_M) {
        /* XXX intentionally used = here */
        res = get_sixlo_multicast_dst_len(data);
        memcpy(dst, "mcast", sizeof("mcast"));
    } else {
        switch (data[1] & SIXLOWPAN_IPHC2_DAM) {
            case 0x0:
                if (data[1] & SIXLOWPAN_IPHC2_DAC) {
                    /* reserved flag combination */
                    return -1;
                }
                ipv6_addr_to_str(dst, (ipv6_addr_t *)&data[offset], sizeof(dst));
                break;
            case 0x1:
                /* last 64 bits of destination address are carried inline */
                fmt_bytes_hex(dst, &data[offset], sizeof(uint64_t));
                dst[sizeof(uint64_t)] = '\0';
                res += sizeof(uint64_t);
                break;
            case 0x2:
                /* last 16 bits of destination address are carried inline */
                fmt_bytes_hex(dst, &data[offset], sizeof(uint16_t));
                dst[sizeof(uint16_t)] = '\0';
                res += sizeof(uint16_t);
                break;
            default:
                /* rest causes elision of destination address */
                memcpy(dst, "l2_dst", sizeof("l2_dst"));
                break;
        }
    }
    return res;
}

static unsigned get_sixlo_nhc_udp_len(uint8_t *data, uint16_t *src_port,
                                      uint16_t *dst_port)
{
    int res = sizeof(uint8_t);  /* NHC_UDP dispatch */

    switch (data[0] & 0x3) {
        case 0x0:
            /* source port is carried inline at current offset */
            *src_port = byteorder_ntohs(*((network_uint16_t *)&data[res]));
            res += sizeof(uint16_t);
            /* destination port is carried inline at current offset */
            *dst_port = byteorder_ntohs(*((network_uint16_t *)&data[res]));
            res += sizeof(uint16_t);
            break;
        case 0x1:
            /* source port is carried inline at current offset */
            *src_port = byteorder_ntohs(*((network_uint16_t *)&data[res]));
            res += sizeof(uint16_t);
            /* 8 bits of destination port is carried inline at current offset
             * and its first 8 bits are 0xf0 */
            *dst_port = (0xf000 | data[res]);
            res += sizeof(uint8_t);
            break;
        case 0x2:
            /* 8 bits of source port is carried inline at current offset
             * and its first 8 bits are 0xf0 */
            *src_port = (0xf000 | data[res]);
            res += sizeof(uint8_t);
            /* destination port is carried inline at current offset */
            *dst_port = byteorder_ntohs(*((network_uint16_t *)&data[res]));
            res += sizeof(uint16_t);
            break;
        case 0x3:
            /* 4 bits of source and destination address are carried inline. They
             * are the respective nibbles at the current offset*/
            *src_port = (0xf0b0 | (data[res] & 0xf0));
            *dst_port = (0xf0b0 | (data[res] & 0x0f));
            res += sizeof(uint8_t);
            break;
    }
    if (!(data[0] & 0x4)) {
        /* checksum carried inline */
        res += sizeof(uint16_t);
    }
    return res;
}

static int get_from_sixlo_dispatch(uint8_t *data, uint8_t *protnum,
                                   char *src, char *dst,
                                   uint16_t *src_port, uint16_t *dst_port)
{
    int res = SIXLOWPAN_IPHC_HDR_LEN;
    bool nhc = false;
    if (sixlowpan_iphc_is(data)) {
        int tmp;
        switch (data[0] & SIXLOWPAN_IPHC1_TF) {
            case 0x00:
                res += 4;
                break;
            case 0x08:
                res += 3;
                break;
            case 0x10:
                res += 1;
                break;
            default:
                break;
        }
        if (data[0] & SIXLOWPAN_IPHC1_NH) {
            nhc = true;
        }
        else {
            /* protnum carried inline at current offset */
            *protnum = data[res++];
        }
        if (!(data[0] & SIXLOWPAN_IPHC1_HL)) {
            /* hop limit is uncompressed */
            res++;
        }
        if (data[1] & SIXLOWPAN_IPHC2_CID_EXT) {
            /* CID extension is attached */
            res++;
        }
        res += get_sixlo_src_len(data, src, res);
        if ((tmp = get_sixlo_dst_len(data, dst, res)) < 0) {
            printf("WARNING: reseved 6Lo dst comp flags 0x%02x\n",
                   data[1] & (SIXLOWPAN_IPHC2_M | SIXLOWPAN_IPHC2_DAC |
                              SIXLOWPAN_IPHC2_DAM));
            return -1;
        }
        res += tmp;
        if (nhc) {
            if ((data[res] & (0xf8)) == 0xf0) {
                *protnum = PROTNUM_UDP;
                res += get_sixlo_nhc_udp_len(&data[res], src_port, dst_port);
            }
            else {
                printf("WARNING: unexpected NHC dispatch 0x%02x (offset = %i)\n",
                       data[res], res);
                return -1;
            }
        }
    }
    else if ((data[0] & SIXLOWPAN_FRAG_DISP_MASK) == SIXLOWPAN_FRAG_1_DISP) {
        /* we don't care about fragmentation, right? Right??!? ;-) */
        return get_from_sixlo_dispatch(&data[sizeof(sixlowpan_frag_t)], protnum,
                                       src, dst, src_port, dst_port) +
               sizeof(sixlowpan_frag_t);
    }
    else {
        printf("WARNING: unexpected 6Lo dispatch 0x%02x\n", data[0]);
        return -1;
    }
    return res;
}
#endif

void pktcnt_log_rx(gnrc_pktsnip_t *pkt)
{
#if defined(MODULE_GNRC_SIXLOWPAN)
    if (pkt->type == GNRC_NETTYPE_SIXLOWPAN) {
        uint8_t *payload = pkt->data;
        int offset;
        uint16_t src_port = 0, dst_port = 0;
        uint8_t protnum = 0;

        if ((payload[0] & SIXLOWPAN_FRAG_DISP_MASK) == SIXLOWPAN_FRAG_N_DISP) {
            log_l2_rx(pkt);
            puts("6Lo n-frag");
            return;
        }
        offset = get_from_sixlo_dispatch(payload, &protnum, src, dst,
                                         &src_port, &dst_port);
        if (offset < 0) {
            return;
        }
        else if (((unsigned)offset) > pkt->size) {
            puts("WARNING: 6Lo offset larger than expected");
            return;
        }
        switch (protnum) {
            case PROTNUM_UDP:
                log_l2_rx(pkt);
                log_flow(src, dst);
                /* no next header compression */
                if (src_port == 0) {
                    udp_hdr_t *udp_hdr = (udp_hdr_t *)&payload[offset];
                    dst_port = byteorder_ntohs(udp_hdr->dst_port);
                    src_port = byteorder_ntohs(udp_hdr->dst_port);
                    offset += sizeof(udp_hdr_t);
                }
                log_udp(&payload[offset], src_port, dst_port);
                break;
            case PROTNUM_ICMPV6:
                log_l2_rx(pkt);
                log_icmpv6((icmpv6_hdr_t *)&payload[offset]);
                break;
            default:
                log_l2_rx(pkt);
                log_flow(src, dst);
                puts("UNKNOWN");
                break;
        }
    }
#elif defined(MODULE_GNRC_IPV6)
    if (pkt->type == GNRC_NETTYPE_IPV6) {
        uint8_t *payload = pkt->data;
        ipv6_hdr_t *ipv6_hdr = pkt->data;

        ipv6_addr_to_str(src, (ipv6_addr_t *)&ipv6_hdr->src, sizeof(src));
        ipv6_addr_to_str(dst, (ipv6_addr_t *)&ipv6_hdr->dst, sizeof(dst));
        /* ipv6_hdr_print(ipv6_hdr); */
        switch (ipv6_hdr->nh) {
            case PROTNUM_UDP: {
                udp_hdr_t *udp_hdr = (udp_hdr_t *)&payload[offset];
                uint16_t dst_port = byteorder_ntohs(udp_hdr->dst_port);
                uint16_t src_port = byteorder_ntohs(udp_hdr->dst_port);

                log_l2_rx(pkt);
                log_flow(src, dst);
                log_udp(&payload[sizeof(ipv6_hdr_t) + sizeof(udp_hdr_t)],
                        src_port, dst_port);
                break;
            }
            case PROTNUM_ICMPV6:
                log_l2_rx(pkt);
                log_icmpv6((icmpv6_hdr_t *)&payload[sizeof(ipv6_hdr_t)]);
                break;
            default:
                log_l2_rx(pkt);
                log_flow(src, dst);
                puts("UNKNOWN");
                break;

        }
    }
#elif defined(MODULE_CCN_LITE)
    if ((pkt->type == GNRC_NETTYPE_CCN) ||
        (pkt->type == GNRC_NETTYPE_CCN_CHUNK) ||
        (pkt->type == GNRC_NETTYPE_CCN_HOPP)) {
        uint8_t *payload = pkt->data;
        /* 0x5: Interest, 0x6: data*/
        if ((payload[0] == 0x5) || payload[0] == 0x6) {
            log_l2_rx(pkt);
            log_ndn(payload);
        }
        /* HOPP identifier*/
        else if ((payload[0] == 0x80) && (payload[1] == 0x08)) {
            log_l2_rx(pkt);
            log_hopp(payload);
        }
        else {
            log_l2_rx(pkt);
            puts("UNKNOWN");
        }
    }
#endif
    (void)pkt;
}

void pktcnt_log_tx(gnrc_pktsnip_t *pkt)
{
    if (pktcnt_pid > KERNEL_PID_UNDEF) {
        msg_t msg = { .type = GNRC_NETAPI_MSG_TYPE_SND,
                      .content = { .ptr = pkt } };

        /* we divert the packet, so hold */
        gnrc_pktbuf_hold(pkt, 1);
        msg_try_send(&msg, pktcnt_pid);
    }
}

static void _log_tx(gnrc_pktsnip_t *pkt)
{
#if defined(MODULE_GNRC_IPV6)
#if defined(MODULE_GNRC_SIXLOWPAN)
    gnrc_nettype_t exp_type = GNRC_NETTYPE_SIXLOWPAN;
#else
    gnrc_nettype_t exp_type = GNRC_NETTYPE_IPV6;
#endif

    if (pkt->next->type == exp_type) {
        if (pkt->next->next != NULL) {
            /* don't look at follow-up fragments */
            switch (pkt->next->next->type) {
                case GNRC_NETTYPE_UDP: {
                    udp_hdr_t *udp_hdr = pkt->next->next->data;
                    /* XXX: assume no next header compression is in effect */
                    ipv6_hdr_t *ipv6_hdr = pkt->next->data;
                    uint16_t src_port = byteorder_ntohs(udp_hdr->src_port);
                    uint16_t dst_port = byteorder_ntohs(udp_hdr->dst_port);

                    ipv6_addr_to_str(src, (ipv6_addr_t *)&ipv6_hdr->src, sizeof(src));
                    ipv6_addr_to_str(dst, (ipv6_addr_t *)&ipv6_hdr->dst, sizeof(dst));
                    log_l2_tx(pkt);
                    log_flow(src, dst);
                    log_udp(pkt->next->next->next->data, src_port, dst_port);
                    break;
                }
                case GNRC_NETTYPE_ICMPV6:
                    log_l2_tx(pkt);
                    log_icmpv6(pkt->next->next->data);
                    break;
                default: {
#ifdef MODULE_GNRC_SIXLOWPAN
                    /* check for NHC */
                    int offset;
                    uint16_t src_port = 0, dst_port = 0;
                    uint8_t protnum = 0;

                    offset = get_from_sixlo_dispatch(pkt->next->data, &protnum,
                                                     src, dst,
                                                     &src_port, &dst_port);
                    if (offset < 0) {
                        return;
                    }
                    else if (((unsigned)offset) > pkt->next->size) {
                        printf("WARNING: 6Lo offset (%i) larger "
                               "than expected (%u)\n", offset,
                               (unsigned)pkt->next->size);
                        return;
                    }
                    /* next header compression for UDP *is* activated  */
                    if ((protnum == PROTNUM_UDP) && (src_port != 0)) {
                        log_l2_tx(pkt);
                        log_flow(src, dst);
                        log_udp(pkt->next->next->data, src_port, dst_port);
                        /* return early */
                        return;
                    }
                    /* IP header compressed, but no next header compression?*/
                    switch (protnum) {
                        case PROTNUM_UDP: {
                            udp_hdr_t *udp_hdr = pkt->next->next->data;
                            uint16_t src_port = byteorder_ntohs(udp_hdr->src_port);
                            uint16_t dst_port = byteorder_ntohs(udp_hdr->dst_port);
                            log_l2_tx(pkt);
                            log_flow(src, dst);
                            log_udp(pkt->next->next->data, src_port, dst_port);
                            /* return early */
                            return;
                        }
                        case PROTNUM_ICMPV6:
                            log_l2_tx(pkt);
                            log_icmpv6(pkt->next->next->data);
                            /* return early */
                            return;
                        default:
                            break;

                    }
#endif
                    log_l2_tx(pkt);
                    puts("UNKNOWN");
                    break;
                }
            }
        }
#ifdef MODULE_GNRC_SIXLOWPAN
        else {
            log_l2_tx(pkt);
            puts("6Lo n-frag");
        }
#endif
    }
#if (GNRC_NETIF_NUMOF > 1) && defined(MODULE_GNRC_SIXLOWPAN)
    /* border router case */
    else if (pkt->next->type == GNRC_NETTYPE_IPV6) {
        puts("INFO: IPv6 packet to upstream interface sent");
    }
#endif
#elif defined(MODULE_CCN_LITE)
    if ((pkt->next->type == GNRC_NETTYPE_CCN) ||
        (pkt->next->type == GNRC_NETTYPE_CCN_CHUNK) ||
        (pkt->next->type == GNRC_NETTYPE_CCN_HOPP)) {
        uint8_t *payload = pkt->next->data;
        /* 0x5: Interest, 0x6: data*/
        if ((payload[0] == 0x5) || payload[0] == 0x6) {
            log_l2_tx(pkt);
            log_ndn(payload);
        }
        /* HOPP identifier*/
        else if ((payload[0] == 0x80) && (payload[1] == 0x08)) {
            log_l2_tx(pkt);
            log_hopp(payload);
        }
        else {
            log_l2_tx(pkt);
            puts("UNKNOWN");
        }
    }
#endif
    (void)pkt;
}
#endif