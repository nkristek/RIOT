#include "kernel_types.h"

#ifndef RD_STACKSZ
#define RD_STACKSZ                  (THREAD_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF)
#endif
#ifndef RD_QSZ
#define RD_QSZ                      (4)
#endif
#ifndef RD_MSG_POOL_SIZE
#define RD_MSG_POOL_SIZE            (4)
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

extern char rd_stack[RD_STACKSZ];
extern kernel_pid_t rd_pid;

typedef struct __attribute__((packed)) {
    char name[CCNL_MAX_PREFIX_SIZE];     /**< Name */
    size_t name_len;                /**< Length of a name */
    char type[CCNL_MAX_PREFIX_SIZE];     /**< Content-Type */
    size_t type_len;                /**< Length of the content type */
    uint64_t lifetime;              /**< Lifetime */
} rd_entry_t;

static inline void rd_entry_init(rd_entry_t *entry,
                                 const char *name, size_t name_len,
                                 const char *type, size_t type_len, 
                                 uint64_t lifetime)
{
    memcpy(entry->name, name, (name_len > CCNL_MAX_PREFIX_SIZE) ? CCNL_MAX_PREFIX_SIZE : name_len);
    entry->name_len = name_len;
    memcpy(entry->type, type, (type_len > CCNL_MAX_PREFIX_SIZE) ? CCNL_MAX_PREFIX_SIZE : type_len);
    entry->type_len = type_len;
    entry->lifetime = lifetime;
}

typedef struct __attribute__((packed)) {
    char contenttype[COMPAS_NAME_LEN];
    size_t contenttype_len;
    uint64_t chunk;
} rd_lookup_msg_t;

static inline void rd_lookup_msg_init(rd_lookup_msg_t *lookup_msg,
                                      const char *contenttype, size_t contenttype_len,
                                      uint64_t chunk)
{
    memcpy(lookup_msg->contenttype, contenttype, (contenttype_len > COMPAS_NAME_LEN) ? COMPAS_NAME_LEN : contenttype_len);
    lookup_msg->contenttype_len = contenttype_len;
    lookup_msg->chunk = chunk;
}

typedef int (*rd_lookup_response_received_func)(struct ccnl_relay_s *relay,
                                                struct ccnl_pkt_s *pkt,
                                                struct ccnl_face_s *from);
void rd_callback_set_lookup_response_received(rd_lookup_response_received_func func);
int rd_callback_lookup_response_received(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt,
                                         struct ccnl_face_s *from);

void *rd(void* arg);

int rd_register_entry(const rd_entry_t *entry);
bool rd_register(const char *name, size_t name_len,
                 const char *contenttype, size_t contenttype_len,
                 uint64_t lifetime);
bool rd_lookup(const char *contenttype, size_t contenttype_len);
