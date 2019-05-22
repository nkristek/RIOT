#include "net/hopp/hopp.h"
#include "net/rd/rd.h"
#include "hashes/sha256.h"
#include "libbase58.h"
#include "cbor.h"
#include "thread.h"
#include "random.h"
#include "mutex.h"
#define ENABLE_DEBUG    (1)

static unsigned char _out[CCNL_MAX_PACKET_SIZE];
char rd_stack[RD_STACKSZ];
kernel_pid_t rd_pid;
static msg_t rd_q[RD_QSZ];

static unsigned char _lookup_int_buf[HOPP_INTEREST_BUFSIZE];

static rd_entry_t _registered_content[REGISTERED_CONTENT_COUNT];
static mutex_t _registered_content_mutex = MUTEX_INIT;

static rd_lookup_msg_t _rd_lookup_msg_pool[RD_MSG_POOL_SIZE];
static mutex_t _rd_lookup_msg_pool_mutex = MUTEX_INIT;

static rd_entry_t _rd_entry_pool[RD_MSG_POOL_SIZE];
static mutex_t _rd_entry_pool_mutex = MUTEX_INIT;

static uint8_t payload[CCNL_MAX_PACKET_SIZE];
static size_t payload_len = sizeof(payload);

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

static int rd_lookup_registered_content(const char *contenttype, size_t contenttype_len,
                                        uint8_t *response, size_t *response_len)
{
    DEBUG("rd_lookup_registered_content: searching registered content with type: %.*s\n", contenttype_len, contenttype);

    CborEncoder encoder, arrayEncoder;
    cbor_encoder_init(&encoder, response, *response_len, 0);
    if (cbor_encoder_create_array(&encoder, &arrayEncoder, CborIndefiniteLength) != CborNoError) {
        DEBUG("rd_lookup_registered_content: creating array failed\n");
        return -1;
    }

    mutex_lock(&_registered_content_mutex);
    for (int i = 0; i < REGISTERED_CONTENT_COUNT; i++) {
        rd_entry_t entry = _registered_content[i];
        if (entry.lifetime <= 0) {
            continue;
        }
        if (contenttype_len > 0) {
            if (entry.type_len != contenttype_len) {
                continue;
            }
            if (strncmp(entry.type, contenttype, contenttype_len != 0)) {
                continue;
            }
            DEBUG("rd_lookup_registered_content: found matching content with name: %.*s\n", entry.name_len, entry.name);
        }

        if (encode_entry(&arrayEncoder, &entry) != CborNoError) {
            DEBUG("rd_lookup_registered_content: Encoding entry failed\n");
            cbor_encoder_close_container(&encoder, &arrayEncoder);
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

        DEBUG("RD_LOOKUP_REQUEST_RX: got interest: %s\n", interest_name);

        char query[COMPAS_NAME_LEN];
        memset(query, 0, sizeof(query));

        const unsigned prefix_offset = RD_LOOKUP_PREFIX_LEN + 1; // length of rd-lookup prefix and following /
        for (unsigned i = 0; ; i++) { 
            // check if out of bounds
            if (i >= sizeof(query) || i >= (interest_name_len - prefix_offset))
                break;

            // check if char is terminator or /
            if (interest_name[prefix_offset + i] == 0 || interest_name[prefix_offset + i] == '/')
                break;

            query[i] = interest_name[prefix_offset + i];
        }
        DEBUG("RD_LOOKUP_REQUEST_RX: contenttype to query: %s\n", query);
        ccnl_free(interest_name);

        uint8_t payload[CCNL_MAX_PACKET_SIZE];
        size_t payload_len = sizeof(payload);
        int lookup_result = rd_lookup_registered_content(query, strlen(query), payload, &payload_len);
        if (lookup_result) {
            DEBUG("RD_LOOKUP_REQUEST_RX: failed to build response message\n");
            return 0; // interest not handled
        }

        // send response

        int offs = CCNL_MAX_PACKET_SIZE;
        int content_len = ccnl_ndntlv_prependContent(pkt->pfx, (unsigned char*) payload, payload_len, NULL, NULL, &offs, _out);
        if (content_len < 0) {
            DEBUG("RD_LOOKUP_REQUEST_RX: Error, content length: %u\n", content_len);
            return 0; // interest not handled
        }
        unsigned char *olddata;
        unsigned char *data = olddata = _out + offs;
        int len;
        unsigned type;
        if (ccnl_ndntlv_dehead(&data, &content_len, (int*) &type, &len) ||
            type != NDN_TLV_Data) {
            DEBUG("RD_LOOKUP_REQUEST_RX: ccnl_ndntlv_dehead\n");
            return 0; // interest not handled
        }
        struct ccnl_pkt_s *resp_pkt = ccnl_ndntlv_bytes2pkt(type, olddata, &data, &content_len);
        if (ccnl_send_pkt(relay, from, resp_pkt))
            DEBUG("RD_LOOKUP_REQUEST_RX: send response failed\n");
        
        DEBUG("RD_LOOKUP_REQUEST_RX: response send\n");
        return 1; // interest handled
    }

    return 0; // interest not handled
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
        DEBUG("data_received_process_rd: is lookup response\n");
        
        if (parse_entries((const uint8_t *)pkt->content, pkt->contlen, print_entry) != 0)
            DEBUG("RD_LOOKUP_RESPONSE_RX: parsing lookup response failed\n");

        ccnl_free(content_name);
        return 1;
    }

    // check if register request
    if (content_name_len > RD_REGISTER_PREFIX_LEN 
    &&  strncmp(content_name, RD_REGISTER_PREFIX, RD_REGISTER_PREFIX_LEN) == 0
    &&  dodag.rank == COMPAS_DODAG_ROOT_RANK) {
        // is register request
        DEBUG("data_received_process_rd: is register request\n");

        if (parse_entries((const uint8_t *)pkt->content, pkt->contlen, rd_register_entry) != 0)
            DEBUG("RD_REGISTER_REQUEST_RX: parsing failed\n");

        ccnl_free(content_name);
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

        char name[COMPAS_NAME_LEN];
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
                if (name_chars_available < lookup_msg->contenttype_len)
                {
                    DEBUG("RD_LOOKUP_REQUEST_TX: prefix will be too long\n");
                    break;
                }
                strncpy(&name[name_current_char], lookup_msg->contenttype, lookup_msg->contenttype_len);
                name_current_char += lookup_msg->contenttype_len;
                name_chars_available -= lookup_msg->contenttype_len;
                rd_lookup_msg_free(lookup_msg);

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
                rand_string(&name[name_current_char], name_chars_available > 32 ? 32 : name_chars_available);

                // temporary workaround for bug in CCNL
                name[32] = 0;

                DEBUG("RD_LOOKUP_REQUEST_TX: sending interest with name: %s\n", name);

                prefix_ccnl = ccnl_URItoPrefix(name, CCNL_SUITE_NDNTLV, NULL, 0);

                memset(_lookup_int_buf, 0, HOPP_INTEREST_BUFSIZE);
                if (ccnl_send_interest(prefix_ccnl, _lookup_int_buf, HOPP_INTEREST_BUFSIZE, NULL, NULL) != 0) {
                    DEBUG("RD_LOOKUP_REQUEST_TX: sending interest failed\n");
                }
                ccnl_prefix_free(prefix_ccnl);
                break;
            case RD_REGISTER_REQUEST_TX:
                // client sends register request

                entry = (rd_entry_t *)msg.content.ptr;

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
                rd_entry_free(entry);
                
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
        return false;
    }

    return true;
}

bool rd_lookup(const char *contenttype, size_t contenttype_len)
{   
    if (contenttype_len > COMPAS_NAME_LEN) {
        DEBUG("contenttype is too long\n");
        return false;
    }

    rd_lookup_msg_t *lookup_msg = rd_lookup_msg_get_free_entry();
    rd_lookup_msg_init(lookup_msg, contenttype, contenttype_len);

    msg_t msg = { .content.ptr = lookup_msg, .type = RD_LOOKUP_REQUEST_TX };
    if (msg_send(&msg, rd_pid) != 1) {
        DEBUG("content_requested: sending msg to rd thread failed\n");
        return false;
    }

    return true;
}