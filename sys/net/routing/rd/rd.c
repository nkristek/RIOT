#include "net/hopp/hopp.h"
#include "net/rd/rd.h"
#include "hashes/sha256.h"
#include "libbase58.h"
#include "cbor.h"
#include "thread.h"
#include "random.h"
#include "mutex.h"
#include "xtimer.h"
#include "fmt.h"
#define ENABLE_DEBUG    (1)

static uint8_t _out[CCNL_MAX_PACKET_SIZE];
char rd_stack[RD_STACKSZ];
kernel_pid_t rd_pid;
static msg_t rd_q[RD_QSZ];

static uint8_t _lookup_int_buf[CCNL_MAX_PACKET_SIZE];

typedef struct __attribute__((packed)) {
    rd_entry_t entry;  
    uint64_t valid_until_usec;             
} rd_registered_entry_t;
static rd_registered_entry_t _registered_content[REGISTERED_CONTENT_COUNT];
static mutex_t _registered_content_mutex = MUTEX_INIT;

static rd_lookup_msg_t _rd_lookup_msg_pool[RD_MSG_POOL_SIZE];
static mutex_t _rd_lookup_msg_pool_mutex = MUTEX_INIT;

static rd_entry_t _rd_entry_pool[RD_MSG_POOL_SIZE];
static mutex_t _rd_entry_pool_mutex = MUTEX_INIT;

static rd_lookup_msg_t *rd_lookup_msg_get_free_entry(void) 
{
    mutex_lock(&_rd_lookup_msg_pool_mutex);
    for (unsigned i = 0; i < RD_MSG_POOL_SIZE; i++) {
        if (_rd_lookup_msg_pool[i].contenttype_len == 0) {
            mutex_unlock(&_rd_lookup_msg_pool_mutex);
            return &_rd_lookup_msg_pool[i];
        }

    }
    mutex_unlock(&_rd_lookup_msg_pool_mutex);
    return NULL;
}

static void rd_lookup_msg_free(rd_lookup_msg_t *lookup_msg) 
{
    if (lookup_msg == NULL)
        return;

    mutex_lock(&_rd_lookup_msg_pool_mutex);
    lookup_msg->contenttype_len = 0;
    mutex_unlock(&_rd_lookup_msg_pool_mutex);
}

static rd_entry_t *rd_entry_get_free_entry(void) 
{
    mutex_lock(&_rd_entry_pool_mutex);
    for (unsigned i = 0; i < RD_MSG_POOL_SIZE; i++) {
        if (_rd_entry_pool[i].lifetime == 0) {
            mutex_unlock(&_rd_entry_pool_mutex);
            return &_rd_entry_pool[i];
        }
    }
    mutex_unlock(&_rd_entry_pool_mutex);
    return NULL;
}

static void rd_entry_free(rd_entry_t *entry) 
{
    if (entry == NULL)
        return;

    mutex_lock(&_rd_entry_pool_mutex);
    entry->lifetime = 0;
    mutex_unlock(&_rd_entry_pool_mutex);
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

static rd_lookup_response_received_func _lookup_response_received_func = NULL;

void
rd_callback_set_lookup_response_received(rd_lookup_response_received_func func)
{
    _lookup_response_received_func = func;
}

int
rd_callback_lookup_response_received(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt,
                                     struct ccnl_face_s *from)
{
    if (_lookup_response_received_func) {
        return _lookup_response_received_func(relay, pkt, from);
    }

    return 1;
}

static CborError encode_entry(CborEncoder *encoder, const rd_entry_t *entry, uint64_t *next_index) 
{
    CborEncoder mapEncoder;
    CborError error;
    error = cbor_encoder_create_map(encoder, &mapEncoder, next_index ? 4 : 3);
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
    // TODO: calculate time left
    error = cbor_encode_uint(&mapEncoder, entry->lifetime);
    if (error != CborNoError) {
        DEBUG("encode_entry: error encoding lifetime value\n");
        return error;
    }

    // Next Index
    if (next_index) {
        error = cbor_encode_text_stringz(&mapEncoder, "ni");
        if (error != CborNoError) {
            DEBUG("encode_entry: error encoding next index key: %i\n", error);
            return error;
        }
        error = cbor_encode_uint(&mapEncoder, *next_index);
        if (error != CborNoError) {
            DEBUG("encode_entry: error encoding next index\n");
            return error;
        }
        DEBUG("encode_entry: encoded next index\n");
    }

    error = cbor_encoder_close_container(encoder, &mapEncoder);
    if (error != CborNoError) {
        DEBUG("encode_entry: error closing map\n");
        return error;
    }
    return CborNoError;
}

static CborError parse_entry(const CborValue *map, rd_entry_t *entry, uint64_t *next_index) 
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
    if (error != CborNoError && cbor_value_get_type(&nameValue) != CborInvalidType) {
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
    if (name_len > CCNL_MAX_PREFIX_SIZE) {
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
    if (error != CborNoError && cbor_value_get_type(&typeValue) != CborInvalidType) {
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
    if (type_len > CCNL_MAX_PREFIX_SIZE) {
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
    if (error != CborNoError && cbor_value_get_type(&lifetimeValue) != CborInvalidType) {
        DEBUG("parse_entry: error finding field lt \n");
        return error;
    }
    if (!cbor_value_is_unsigned_integer(&lifetimeValue)) {
        DEBUG("parse_entry: error field lt is not unsigned integer\n");
        return CborErrorImproperValue;
    }
    error = cbor_value_get_uint64(&lifetimeValue, &lifetime); 
    if (error != CborNoError) {
        DEBUG("parse_entry: error getting value of field lt\n");
        return error;
    }

    // Next Index
    CborValue nextindexValue;
    error = cbor_value_map_find_value(map, "ni", &nextindexValue);
    if (error == CborNoError && cbor_value_get_type(&nextindexValue) != CborInvalidType) {
        if (!cbor_value_is_unsigned_integer(&nextindexValue)) {
            DEBUG("parse_entry: error field ni is not unsigned integer\n");
            return CborErrorImproperValue;
        }
        error = cbor_value_get_uint64(&nextindexValue, next_index); 
        if (error != CborNoError) {
            DEBUG("parse_entry: error getting value of field ni\n");
            return error;
        }
        DEBUG("parse_entry: has next index: %llu\n", *next_index);
    }

    rd_entry_init(entry, name, name_len, type, type_len, lifetime);
    return CborNoError;
}

static int parse_content(const uint8_t *content, size_t content_len,
                         int(*entry_callback)(const rd_entry_t *),
                         uint64_t *next_index) 
{
    if (content_len == 0)
        return 0;

    CborParser parser;
    CborValue map;
    if (cbor_parser_init(content, content_len, 0, &parser, &map) != CborNoError) {
        DEBUG("parse_registration: error creating parser\n");
        return -1;
    }

    rd_entry_t entry;
    if (parse_entry(&map, &entry, next_index) != CborNoError) {
        DEBUG("parse_registration: parsing entry failed\n");
        return -1;
    }

    if (entry_callback != NULL) {
        int callback_result = entry_callback(&entry);
        if (callback_result) {
            return callback_result;
        }
    }

    return 0;
}

static int parse_contenttype_of_prefix(const char *prefix, size_t prefix_len, char *contenttype, size_t contenttype_len)
{
    size_t output_len = 0;
    const unsigned lookup_prefix_offset = RD_LOOKUP_PREFIX_LEN + 1; // length of rd-lookup prefix and following /
    for (unsigned i = 0; ; i++) {
        // check if out of bounds
        if (i >= contenttype_len || i >= (prefix_len - lookup_prefix_offset))
            return -1;

        // check if char is terminator or /
        if (prefix[lookup_prefix_offset + i] == 0 || prefix[lookup_prefix_offset + i] == '/')
            break;

        contenttype[i] = prefix[lookup_prefix_offset + i];
        output_len++;
    }
    return output_len;
}

static int parse_chunk_of_prefix(const char *prefix, size_t prefix_len, uint64_t *chunk)
{
    char buf[4];
    memset(buf, 0, sizeof(buf));

    const unsigned lookup_prefix_offset = RD_LOOKUP_PREFIX_LEN + 1; // length of rd-lookup prefix and following /
    unsigned contenttype_len = 0;
    for (unsigned i = 0; ; i++) { 
        // check if out of bounds
        if (i >= (prefix_len - lookup_prefix_offset))
            return -1;

        // check if char is terminator or /
        if (prefix[lookup_prefix_offset + i] == 0)
            return -1;

        contenttype_len++;
        if (prefix[lookup_prefix_offset + i] == '/')
            break;
    }


    unsigned prefix_offset = lookup_prefix_offset + contenttype_len;
    for (unsigned i = 0; ; i++) { 
        // check if out of bounds
        if (i >= sizeof(buf)-1 || i >= (prefix_len - prefix_offset))
            return -1;

        // check if char is terminator or /
        if (prefix[prefix_offset + i] == 0 || prefix[prefix_offset + i] == '/')
            break;

        buf[i] = prefix[prefix_offset + i];
    }
    
    *chunk = atoi(buf);
    return 0;
}

static int rd_lookup_registered_content(const char *contenttype, size_t contenttype_len,
                                        uint64_t start_index,
                                        uint8_t *response, size_t response_len)
{
    DEBUG("rd_lookup_registered_content: searching registered content with type: %.*s\n", contenttype_len, contenttype);

    if (start_index > REGISTERED_CONTENT_COUNT) {
        DEBUG("rd_lookup_registered_content: invalid start index %llu\n", start_index);
        return -1;
    }

    CborEncoder encoder;
    cbor_encoder_init(&encoder, response, response_len, 0);

    mutex_lock(&_registered_content_mutex);
    uint64_t time_now = xtimer_now_usec64();
    rd_registered_entry_t *matching_entry = NULL;
    uint64_t next_matching_index;
    bool has_next_matching_index = false;
    for (uint64_t i = start_index; i < REGISTERED_CONTENT_COUNT; i++) {
        if (_registered_content[i].valid_until_usec < time_now) {
            continue;
        }
        if (contenttype_len > 0) {
            if (_registered_content[i].entry.type_len != contenttype_len) {
                continue;
            }
            if (strncmp(_registered_content[i].entry.type, contenttype, contenttype_len != 0)) {
                continue;
            }
        }

        DEBUG("rd_lookup_registered_content: found matching content with name: %.*s\n", _registered_content[i].entry.name_len, _registered_content[i].entry.name);

        if (matching_entry == NULL) {
            matching_entry = &_registered_content[i];
            continue;
        }
        next_matching_index = i;
        has_next_matching_index = true;
        break;
    }
    if (matching_entry != NULL) {
        if (has_next_matching_index)
            DEBUG("Has next matching index %llu\n", next_matching_index);

        if (encode_entry(&encoder, &matching_entry->entry, has_next_matching_index ? &next_matching_index : NULL) != CborNoError) {
            DEBUG("rd_lookup_registered_content: Encoding entry failed\n");
            mutex_unlock(&_registered_content_mutex);
            return -1;
        } 
    }
    mutex_unlock(&_registered_content_mutex);

    size_t return_response_len = cbor_encoder_get_buffer_size(&encoder, response);
    DEBUG("rd_lookup_registered_content: length of encoded message: %u\n", return_response_len);
    return return_response_len;
}

static int interest_received(struct ccnl_relay_s *relay,
                             struct ccnl_face_s *from,
                             struct ccnl_pkt_s *pkt)
{
    if (dodag.rank != COMPAS_DODAG_ROOT_RANK)
        return 0; // interest not handled

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

        printf("RD_LOOKUP_REQUEST_RX;%.*s\n", interest_name_len, interest_name);

        char contenttype[CCNL_MAX_PREFIX_SIZE];
        memset(contenttype, 0, sizeof(contenttype));
        int contenttype_len = parse_contenttype_of_prefix(interest_name, interest_name_len, contenttype, sizeof(contenttype));
        if (contenttype_len < 0) {
            DEBUG("process_lookup_response: parsing the contenttype failed, input was: %.*s\n", interest_name_len, interest_name);
            return 1; // handled
        }
        DEBUG("requested contenttype: %.*s\n", contenttype_len, contenttype);

        uint64_t chunk;
        if (parse_chunk_of_prefix(interest_name, interest_name_len, &chunk)) {
            DEBUG("process_lookup_response: parsing the chunk failed, input was: %.*s\n", interest_name_len, interest_name);
            return 1; // handled
        }
        DEBUG("requested chunk: %llu\n", chunk);

        uint8_t payload[CCNL_MAX_PACKET_SIZE];
        memset(payload, 0, sizeof(payload));
        int payload_len = rd_lookup_registered_content(contenttype, contenttype_len, chunk, payload, sizeof(payload));
        if (payload_len <= 0) {
            DEBUG("RD_LOOKUP_REQUEST_RX: failed to build response message\n");
            return 0; // interest not handled
        }

        // send response

        int offs = CCNL_MAX_PACKET_SIZE;
        int content_len = ccnl_ndntlv_prependContent(pkt->pfx, (unsigned char *) payload, payload_len, NULL, NULL, &offs, _out);
        if (content_len < 0) {
            DEBUG("RD_LOOKUP_RESPONSE_TX: Error, content length: %i\n", content_len);
            return 0; // interest not handled
        }

        unsigned char *olddata;
        unsigned char *data = olddata = _out + offs;
        int len;
        unsigned type;
        if (ccnl_ndntlv_dehead(&data, &content_len, (int*) &type, &len) ||
            type != NDN_TLV_Data) {
            DEBUG("RD_LOOKUP_RESPONSE_TX: ccnl_ndntlv_dehead\n");
            return 0; // interest not handled
        }

        printf("RD_LOOKUP_RESPONSE_TX;%.*s\n", interest_name_len, interest_name);
        ccnl_free(interest_name);

        struct ccnl_pkt_s *resp_pkt = ccnl_ndntlv_bytes2pkt(type, olddata, &data, &content_len);
        if (ccnl_send_pkt(relay, from, resp_pkt))
            DEBUG("RD_LOOKUP_RESPONSE_TX: send response failed\n");
        
        return 1; // interest handled
    }

    return 0; // interest not handled
}

static int rd_register_entry(const rd_entry_t *entry) 
{
#ifdef DEBUG
    printf("Registering entry:\n");
    print_entry(entry);
#endif

    mutex_lock(&_registered_content_mutex);
    uint64_t time_now = xtimer_now_usec64();
    for (unsigned j = 0; j < REGISTERED_CONTENT_COUNT; j++) {
        if (_registered_content[j].valid_until_usec > time_now) {
            continue;
        }
        rd_entry_init(&_registered_content[j].entry, entry->name, entry->name_len, entry->type, entry->type_len, entry->lifetime);
        _registered_content[j].valid_until_usec = time_now + xtimer_usec_from_ticks64(xtimer_ticks_from_usec64(entry->lifetime * 1000000));
        DEBUG("rd_register_content: content was registered at index %u\n", j);
        mutex_unlock(&_registered_content_mutex);
        return 0;
    }
    DEBUG("rd_register_content: content could not be registered, no available space left.\n");
    mutex_unlock(&_registered_content_mutex);
    return -1;
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
}

static int data_received_process_rd(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt, struct ccnl_face_s *from) 
{
    char *content_name = ccnl_prefix_to_path(pkt->pfx);
    if (content_name == NULL)
    {
        DEBUG("data_received_process_rd: content name is null\n");
        return 0; // not handled
    }
    size_t content_name_len = strlen(content_name);

    // check if lookup response
    if (content_name_len > RD_LOOKUP_PREFIX_LEN 
    &&  strncmp(content_name, RD_LOOKUP_PREFIX, RD_LOOKUP_PREFIX_LEN) == 0) {
        // is lookup response
        printf("RD_LOOKUP_RESPONSE_RX;%.*s\n", content_name_len, content_name);
        ccnl_free(content_name);

        if (rd_callback_lookup_response_received(relay, pkt, from))
            return 1; // handled

        return 0; // not handled
    }

    // check if register request
    if (content_name_len > RD_REGISTER_PREFIX_LEN 
    &&  strncmp(content_name, RD_REGISTER_PREFIX, RD_REGISTER_PREFIX_LEN) == 0
    &&  dodag.rank == COMPAS_DODAG_ROOT_RANK) {
        // is register request
        printf("RD_REGISTER_REQUEST_RX;%.*s\n", content_name_len, content_name);

        uint64_t next_index = 0;
        if (parse_content((const uint8_t *)pkt->content, pkt->contlen, rd_register_entry, &next_index))
            DEBUG("RD_REGISTER_REQUEST_RX: parsing failed\n");

        ccnl_free(content_name);
        return 1; // handled
    }
    return 0; // not handled
}

static int process_lookup_response(struct ccnl_relay_s *relay, struct ccnl_pkt_s *pkt, struct ccnl_face_s *from) 
{
    (void)relay;
    (void)from;

    uint64_t next_index = 0;
    if (parse_content((const uint8_t *)pkt->content, pkt->contlen, print_entry, &next_index)) {
        DEBUG("RD_LOOKUP_RESPONSE_RX: parsing lookup response failed\n");
        return 0; // not handled
    }

    if (next_index == 0)
        return 1; // handled

    DEBUG("Asking for next chunk: %llu\n", next_index);
    
    if (pkt->pfx == NULL) {
        DEBUG("process_lookup_response: prefix is null\n");
        return 1; // handled
    }
    char *interest_name = ccnl_prefix_to_path(pkt->pfx);
    if (interest_name == NULL) {
        DEBUG("process_lookup_response: name is null\n");
        return 1; // handled
    }
    size_t interest_name_len = strlen(interest_name);

    char contenttype[CCNL_MAX_PREFIX_SIZE];
    memset(contenttype, 0, sizeof(contenttype));
    int contenttype_len = parse_contenttype_of_prefix(interest_name, interest_name_len, contenttype, sizeof(contenttype));
    if (contenttype_len < 0) {
        DEBUG("process_lookup_response: parsing the contenttype failed, input was: %.*s\n", interest_name_len, interest_name);
        return 1; // handled
    }

    rd_lookup_msg_t *lookup_msg = rd_lookup_msg_get_free_entry();
    rd_lookup_msg_init(lookup_msg, contenttype, contenttype_len, next_index);
    msg_t msg = { .content.ptr = lookup_msg, .type = RD_LOOKUP_REQUEST_TX };
    if (msg_send(&msg, rd_pid) != 1) {
        DEBUG("process_lookup_response: sending msg to rd thread failed\n");
    }
    return 1; // handled
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

        char name[CCNL_MAX_PREFIX_SIZE + 1];
        uint8_t name_current_char, name_chars_available;
        struct ccnl_prefix_s *prefix_ccnl;
        rd_entry_t *entry;
        rd_lookup_msg_t *lookup_msg;

        switch (msg.type) {
            case RD_LOOKUP_REQUEST_TX:
                // client sends lookup request

                lookup_msg = (rd_lookup_msg_t *)msg.content.ptr;

                memset(name, 0, sizeof(name));
                name_current_char = 0;
                name_chars_available = sizeof(name) - 1;
                
                // add rd lookup prefix
                if (name_chars_available < RD_LOOKUP_PREFIX_LEN) {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                strncpy(&name[name_current_char], RD_LOOKUP_PREFIX, RD_LOOKUP_PREFIX_LEN);
                name_current_char += RD_LOOKUP_PREFIX_LEN;
                name_chars_available -= RD_LOOKUP_PREFIX_LEN;

                // add slash
                if (name_chars_available < 1) {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                name[name_current_char] = '/';
                name_current_char++;
                name_chars_available--;

                // add contenttype
                if (lookup_msg->contenttype != NULL) {
                    if (name_chars_available < lookup_msg->contenttype_len)
                    {
                        DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                        break;
                    }
                    strncpy(&name[name_current_char], lookup_msg->contenttype, lookup_msg->contenttype_len);
                    name_current_char += lookup_msg->contenttype_len;
                    name_chars_available -= lookup_msg->contenttype_len;
                }

                // add slash
                if (name_chars_available < 1) {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                name[name_current_char] = '/';
                name_current_char++;
                name_chars_available--;

                // add chunk_number
                if (name_chars_available < 8) {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                size_t result = fmt_u64_dec(&name[name_current_char], lookup_msg->chunk);
                name_current_char += result;
                name_chars_available -= result;

                rd_lookup_msg_free(lookup_msg);
                
                // add slash
                if (name_chars_available < 1) {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                name[name_current_char] = '/';
                name_current_char++;
                name_chars_available--;

                // add session id
                if (name_chars_available < 1) {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                rand_string(&name[name_current_char], name_chars_available);

                name[32] = 0;

                printf("RD_LOOKUP_REQUEST_TX;%s\n", name);

                prefix_ccnl = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL, 0);

                memset(_lookup_int_buf, 0, HOPP_INTEREST_BUFSIZE);
                if (ccnl_send_interest(prefix_ccnl, _lookup_int_buf, sizeof(_lookup_int_buf), NULL, NULL) != 0)
                    DEBUG("RD_LOOKUP_REQUEST_TX: sending interest failed\n");
                
                ccnl_prefix_free(prefix_ccnl);
                break;
            case RD_REGISTER_REQUEST_TX:
                // client sends register request

                entry = (rd_entry_t *)msg.content.ptr;
                
                uint8_t payload[CCNL_MAX_PACKET_SIZE];
                size_t payload_len = sizeof(payload);
                memset(payload, 0, sizeof(payload));

                CborEncoder encoder;
                cbor_encoder_init(&encoder, payload, payload_len, 0);

                if (encode_entry(&encoder, (const rd_entry_t *)entry, NULL) != CborNoError) {
                    DEBUG("RD_REGISTER_REQUEST_TX: Encoding entry failed\n");
                    break;
                } 
                rd_entry_free(entry);

                payload_len = cbor_encoder_get_buffer_size(&encoder, payload);

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

                // add session id
                if (!b58enc(&name[name_current_char], (size_t *) &name_chars_available, hash, 32))
                {
                    DEBUG("RD_REGISTER_REQUEST_TX: ERROR, b58enc failed.\n");
                    break;
                }

                name[32] = 0;

                printf("RD_REGISTER_REQUEST_TX;%s\n", name);

                if (!hopp_publish_content(name, strlen(name), (unsigned char *) payload, payload_len))
                    DEBUG("RD_REGISTER_REQUEST_TX: publishing content failed.\n");

                break;
            default: 
                DEBUG("unknown msg type\n");
                break;
        }
    }

    return NULL;
}

bool rd_register(const char *name, size_t name_len,
                 const char *contenttype, size_t contenttype_len,
                 uint64_t lifetime)
{
    if (name_len <= 0 || contenttype_len <= 0 || lifetime <= 0) {
        DEBUG("length of name, length of contenttype or lifetime should be bigger than 0\n");
        return false;
    }

    rd_entry_t *entry = rd_entry_get_free_entry();
    rd_entry_init(entry, name, name_len, contenttype, contenttype_len, lifetime);

    msg_t msg = { .content.ptr = entry, .type = RD_REGISTER_REQUEST_TX };
    if (msg_send(&msg, rd_pid) != 1) {
        DEBUG("content_requested: sending msg to rd thread failed\n");
        rd_entry_free(entry);
        return false;
    }

    return true;
}

bool rd_lookup(const char *contenttype, size_t contenttype_len)
{   
    if (contenttype_len > CCNL_MAX_PREFIX_SIZE-RD_LOOKUP_PREFIX_LEN) {
        DEBUG("contenttype is too long\n");
        return false;
    }

    rd_callback_set_lookup_response_received(process_lookup_response);

    rd_lookup_msg_t *lookup_msg = rd_lookup_msg_get_free_entry();
    rd_lookup_msg_init(lookup_msg, contenttype, contenttype_len, 0);

    msg_t msg = { .content.ptr = lookup_msg, .type = RD_LOOKUP_REQUEST_TX };
    if (msg_send(&msg, rd_pid) != 1) {
        DEBUG("content_requested: sending msg to rd thread failed\n");
        return false;
    }

    return true;
}