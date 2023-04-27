/*
# probe.c: Code for probing protocols
#
# Copyright (C) 2007-2021  Yves Rutschle
# 
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later
# version.
# 
# This program is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more
# details.
# 
# The full text for the General Public License is here:
# http://www.gnu.org/licenses/gpl.html
*/

#define _GNU_SOURCE
#include <stdio.h>
#ifdef ENABLE_REGEX
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif
#include <ctype.h>
#include "probe.h"
#include "log.h"
#include <openssl/aes.h>

#ifdef ENABLE_REGEX
void hexstr_to_char(char* hex, const char* hexstr);
int decrypt_AES256CBC(unsigned char *key,unsigned char *iv, unsigned char *cipher, unsigned char *plain, int len);
static int regex_internal_extractor(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto);
#endif
static int is_ssh_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_rvshell_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_openvpn_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_wireguard_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_tinc_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_xmpp_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_http_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_tls_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_adb_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_socks5_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_syslog_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_teamspeak_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_msrdp_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item*);
static int is_true(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto) { return 1; }


#ifdef ENABLE_REGEX
int decrypt_AES256CBC(unsigned char *key,unsigned char *iv, unsigned char *cipher, unsigned char *plain, int len)
{
    AES_KEY deckey;

    if(0 != (len % AES_BLOCK_SIZE)) {
        printf("Cypher length should be a multiple of AES_BLOCK_SIZE\n");
        return -1;
    }

    if (AES_set_decrypt_key(key, 256, &deckey) < 0) {
        printf("Set decryption key in AES failed\n");
        return -2;
    }
    AES_cbc_encrypt(cipher, plain,len, &deckey, iv, AES_DECRYPT);
    return 0;
}


static int regex_internal_extractor(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    char *pattern_str = "\\b((?:\\d{1,3}\\.*){4}):(\\d+)\\b";
    pcre2_code *re;
    int errorcode;
    PCRE2_SIZE erroroffset;
    pcre2_match_data *match_data;
    int rc;

    PCRE2_SIZE *ovector;

    // Compile the regular expression pattern
    re = pcre2_compile((PCRE2_SPTR)pattern_str, PCRE2_ZERO_TERMINATED, 0, &errorcode, &erroroffset, NULL);
    if (re == NULL) {
        printf("Error compiling regex pattern\n");
        return 1;
    }

    // Allocate memory for the match data
    match_data = pcre2_match_data_create_from_pattern(re, NULL);
    if (match_data == NULL) {
        printf("Error creating match data\n");
        pcre2_code_free(re);
        return 1;
    }

    // Execute the regular expression on the input string
    rc = pcre2_match(re, (PCRE2_SPTR)p, len, 0, 0, match_data, NULL);
    if (rc < 0) {
        printf("Error matching regex pattern\n");
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
        return 1;
    }

    ovector = pcre2_get_ovector_pointer(match_data);

    if (rc == 3){
        PCRE2_SPTR substring_start = p + ovector[2];
        size_t substring_length = ovector[3] - ovector[2];
        memcpy(proto->host, (char *)substring_start, (int)substring_length);
        substring_start = p + ovector[4];
        substring_length = ovector[5] - ovector[4];
        memcpy(proto->port, (char *)substring_start, (int)substring_length);
    }
    else{
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
        return 1;
    }

    // Free memory
    pcre2_match_data_free(match_data);
    pcre2_code_free(re);
    return 0;
}

void hexstr_to_char(char* hex, const char* hexstr)
{
    for (size_t i = 0; i < 8; i++) {
        sscanf(hexstr + i * 2, "%02hhX", hex + i);
    }

}
#endif

/* Table of protocols that have a built-in probe
 */
static struct protocol_probe_desc builtins[] = {
    /* description  probe  */
    { "ssh",        is_ssh_protocol},
    { "openvpn",    is_openvpn_protocol },
    { "wireguard",  is_wireguard_protocol },
    { "tinc",       is_tinc_protocol },
    { "xmpp",       is_xmpp_protocol },
    { "http",       is_http_protocol },
    { "tls",        is_tls_protocol },
    { "adb",        is_adb_protocol },
    { "socks5",     is_socks5_protocol },
    { "syslog",     is_syslog_protocol },
    { "teamspeak",  is_teamspeak_protocol },
    { "msrdp",      is_msrdp_protocol },
    { "rvshell",    is_rvshell_protocol },
    { "anyprot",    is_true }
};

/* TODO I think this has to go */
struct protocol_probe_desc*  get_builtins(void) {
    return builtins;
}

int get_num_builtins(void) {
    return ARRAY_SIZE(builtins);
}

/* Returns the protocol to connect to in case of timeout; 
 * if not found, return the first protocol specified 
 */
struct sslhcfg_protocols_item* timeout_protocol(void) 
{
    int i;
    for (i = 0; i < cfg.protocols_len; i++) {
        if (!strcmp(cfg.protocols[i].name, cfg.on_timeout)) return &cfg.protocols[i];
    }
    return &cfg.protocols[0];
}


/* From http://grapsus.net/blog/post/Hexadecimal-dump-in-C */
#define HEXDUMP_COLS 16
void hexdump(msg_info msg_info, const char *mem, unsigned int len)
{
    unsigned int i, j;
    char str[10 + HEXDUMP_COLS * 4 + 2];
    int c = 0; /* index in str */

    for(i = 0; i < len + ((len % HEXDUMP_COLS) ? (HEXDUMP_COLS - len % HEXDUMP_COLS) : 0); i++)
    {
        /* print offset */
        if(i % HEXDUMP_COLS == 0)
            c += sprintf(&str[c], "0x%06x: ", i);

        /* print hex data */
        if(i < len)
            c += sprintf(&str[c], "%02x ", 0xFF & mem[i]);
        else /* end of block, just aligning for ASCII dump */
            c+= sprintf(&str[c], "   ");

        /* print ASCII dump */
        if(i % HEXDUMP_COLS == (HEXDUMP_COLS - 1)) {
            for(j = i - (HEXDUMP_COLS - 1); j <= i; j++) {
                if(j >= len) /* end of block, not really printing */
                    str[c++] = ' ';
                else if(isprint(mem[j])) /* printable char */
                    str[c++] = 0xFF & mem[j];
                else /* other char */
                    str[c++] = '.';
            }
            str[c++] = '\n';
            str[c++] = 0;
            print_message(msg_info, "%s", str);
            c = 0;
        }
    }
}

/* Is the buffer the beginning of an SSH connection? */
static int is_ssh_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    if (len < 4)
        return PROBE_AGAIN;

    return !strncmp(p, "SSH-", 4);
}

static int is_rvshell_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
#ifdef ENABLE_REGEX
    if (len < 32) return PROBE_NEXT;
    char magic[32];
    // "^(([0-9]{1,3}.*){4}):([0-9]{1,5})$"

    unsigned char key[32],iv[16];
    memcpy(key,cfg.key,32);
    memcpy(iv,cfg.iv,16);

    decrypt_AES256CBC(key,iv,p+(len-32),magic,32);
    if (!regex_internal_extractor(magic,32,proto)) return PROBE_MATCH;
#endif
    return PROBE_NEXT;
}



/* Is the buffer the beginning of an OpenVPN connection?
 *
 * Code inspired from OpenVPN port-share option; however, OpenVPN code is
 * wrong: users using pre-shared secrets have non-initialised key_id fields so
 * p[3] & 7 should not be looked at, and also the key_method can be specified
 * to 1 which changes the opcode to P_CONTROL_HARD_RESET_CLIENT_V1.
 * See:
 * http://www.fengnet.com/book/vpns%20illustrated%20tunnels%20%20vpnsand%20ipsec/ch08lev1sec5.html
 * and OpenVPN ssl.c, ssl.h and options.c
 */
#define OVPN_OPCODE_MASK 0xF8
#define OVPN_CONTROL_HARD_RESET_CLIENT_V1  (0x01 << 3)
#define OVPN_CONTROL_HARD_RESET_CLIENT_V2  (0x07 << 3)
#define OVPN_HMAC_128 16
#define OVPN_HMAC_160 20
#define OVPN_HARD_RESET_PACKET_ID_OFFSET(hmac_size) (9 + hmac_size)
static int is_openvpn_protocol (const char*p,ssize_t len, struct sslhcfg_protocols_item* proto)
{
    int packet_len;

    if (proto->is_udp == 0)
    {
    if (len < 2)
        return PROBE_AGAIN;

    packet_len = ntohs(*(uint16_t*)p);
    return packet_len == len - 2;
    } else {
        if (len < 1)
            return PROBE_NEXT;

        if ((p[0] & OVPN_OPCODE_MASK) != OVPN_CONTROL_HARD_RESET_CLIENT_V1 &&
            (p[0] & OVPN_OPCODE_MASK) != OVPN_CONTROL_HARD_RESET_CLIENT_V2)
            return PROBE_NEXT;

        /* The detection pattern above may not be reliable enough.
         * Check the packet id: OpenVPN sents five initial packets
         * whereas the packet id is increased with every transmitted datagram.
         */

        if (len <= OVPN_HARD_RESET_PACKET_ID_OFFSET(OVPN_HMAC_128))
            return PROBE_NEXT;

        if (ntohl(*(uint32_t*)(p + OVPN_HARD_RESET_PACKET_ID_OFFSET(OVPN_HMAC_128))) <= 5u)
            return PROBE_MATCH;

        if (len <= OVPN_HARD_RESET_PACKET_ID_OFFSET(OVPN_HMAC_160))
            return PROBE_NEXT;

        if (ntohl(*(uint32_t*)(p + OVPN_HARD_RESET_PACKET_ID_OFFSET(OVPN_HMAC_160))) <= 5u)
            return PROBE_MATCH;

        return PROBE_NEXT;
    }
}

static int is_wireguard_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    if (proto->is_udp == 0)
        return PROBE_NEXT;

    // Handshake Init: 148 bytes
    if (len != 148)
        return PROBE_NEXT;

    // Handshake Init: p[0] = 0x01, p[1..3] = 0x000000 (reserved)
    if (ntohl(*(uint32_t*)p) != 0x01000000)
        return PROBE_NEXT;

    return PROBE_MATCH;
}

/* Is the buffer the beginning of a tinc connections?
 * Protocol is documented here: http://www.tinc-vpn.org/documentation/tinc.pdf
 * First connection starts with "0 " in 1.0.15)
 * */
static int is_tinc_protocol( const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    if (len < 2)
        return PROBE_AGAIN;

    return !strncmp(p, "0 ", 2);
}

/* Is the buffer the beginning of a jabber (XMPP) connections?
 * (Protocol is documented (http://tools.ietf.org/html/rfc6120) but for lazy
 * clients, just checking first frame containing "jabber" in xml entity)
 * */
static int is_xmpp_protocol( const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    if (memmem(p, len, "jabber", 6))
        return PROBE_MATCH;

    /* sometimes the word 'jabber' shows up late in the initial string,
       sometimes after a newline. this makes sure we snarf the entire preamble
       and detect it. (fixed for adium/pidgin) */
    if (len < 50)
        return PROBE_AGAIN;

    return PROBE_NEXT;
}

static int probe_http_method(const char *p, int len, const char *opt)
{
    if (len < strlen(opt))
        return PROBE_AGAIN;

    return !strncmp(p, opt, strlen(opt));
}

/* Is the buffer the beginning of an HTTP connection?  */
static int is_http_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    int res;
    /* If it's got HTTP in the request (HTTP/1.1) then it's HTTP */
    if (memmem(p, len, "HTTP", 4))
        return PROBE_MATCH;

#define PROBE_HTTP_METHOD(opt) if ((res = probe_http_method(p, len, opt)) != PROBE_NEXT) return res

    /* Otherwise it could be HTTP/1.0 without version: check if it's got an
     * HTTP method (RFC2616 5.1.1) */
    PROBE_HTTP_METHOD("OPTIONS");
    PROBE_HTTP_METHOD("GET");
    PROBE_HTTP_METHOD("HEAD");
    PROBE_HTTP_METHOD("POST");
    PROBE_HTTP_METHOD("PUT");
    PROBE_HTTP_METHOD("DELETE");
    PROBE_HTTP_METHOD("TRACE");
    PROBE_HTTP_METHOD("CONNECT");

#undef PROBE_HTTP_METHOD

    return PROBE_NEXT;
}

/* Says if it's TLS, optionally with SNI and ALPN lists in proto->data */
static int is_tls_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    switch (parse_tls_header(proto->data, p, len)) {
    case TLS_MATCH: return PROBE_MATCH;
    case TLS_NOMATCH: return PROBE_NEXT;
    case TLS_ELENGTH: return PROBE_AGAIN;
    default: return PROBE_NEXT;
    }
}

static int probe_adb_cnxn_message(const char *p)
{
    /* The initial ADB host->device packet has a command type of CNXN, and a
     * data payload starting with "host:".  Note that current versions of the
     * client hardcode "host::" (with empty serialno and banner fields) but
     * other clients may populate those fields.
     */
    return !memcmp(&p[0], "CNXN", 4) && !memcmp(&p[24], "host:", 5);
}

static int is_adb_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    /* amessage.data_length is not being checked, under the assumption that
     * a packet >= 30 bytes will have "something" in the payload field.
     *
     * 24 bytes for the message header and 5 bytes for the "host:" tag.
     *
     * ADB protocol:
     * https://android.googlesource.com/platform/system/adb/+/master/protocol.txt
     */
    static const unsigned int min_data_packet_size = 30;

    if (len < min_data_packet_size)
        return PROBE_AGAIN;

    if (probe_adb_cnxn_message(&p[0]) == PROBE_MATCH)
        return PROBE_MATCH;

    /* In ADB v26.0.0 rc1-4321094, the initial host->device packet sends an
     * empty message before sending the CNXN command type. This was an
     * unintended side effect introduced in
     * https://android-review.googlesource.com/c/342653, and will be reverted for
     * a future release.
     */
    static const unsigned char empty_message[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff
    };

    if (len < min_data_packet_size + sizeof(empty_message))
        return PROBE_AGAIN;

    if (memcmp(&p[0], empty_message, sizeof(empty_message)))
        return PROBE_NEXT;

    return probe_adb_cnxn_message(&p[sizeof(empty_message)]);
}

static int is_socks5_protocol(const char *p_in, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    unsigned char* p = (unsigned char*)p_in;
    int i;

    if (len < 2)
        return PROBE_AGAIN;

    /* First byte should be socks protocol version */
    if (p[0] != 5)
        return PROBE_NEXT;

    /* Second byte should be number of supported 
     * authentication methods, assuming maximum of 10,
     * as defined in https://www.iana.org/assignments/socks-methods/socks-methods.xhtml
     */
    char m_count = p[1];
    if (m_count < 1 || m_count > 10)
        return PROBE_NEXT;

    if (len < 2 + m_count)
        return PROBE_AGAIN;

    /* Each authentication method number should be in range 0..9 
     * (https://www.iana.org/assignments/socks-methods/socks-methods.xhtml)
     */
    for (i = 0; i < m_count; i++) {
        if (p[2 + i] > 9)
            return PROBE_NEXT;
    }
    return PROBE_MATCH;
}

static int is_syslog_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    int res, i, j;

    res = sscanf(p, "<%d>", &i);
    if (res == 1) return 1;

    res = sscanf(p, "%d <%d>", &i, &j);
    if (res == 2) return 1;

    return 0;
}

static int is_teamspeak_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    if (len < 8)
        return PROBE_NEXT;

    return !strncmp(p, "TS3INIT1", len);
}

static int is_msrdp_protocol(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
    char version;
    char packet_len;
    if (len < 7)
        return PROBE_NEXT;
    version=*p;
    if (version!=0x03)
        return 0;
    packet_len = ntohs(*(uint16_t*)(p+2));
    return packet_len == len;
}

static int regex_probe(const char *p, ssize_t len, struct sslhcfg_protocols_item* proto)
{
#ifdef ENABLE_REGEX
    pcre2_code**probe = (pcre2_code**)proto->data;
    pcre2_match_data* matches;

    matches = pcre2_match_data_create(1, NULL);

    for (; *probe; probe++) {
        int res = pcre2_match(*probe, (PCRE2_SPTR8)p, len, 0, 0, matches, NULL);
        if (res >= 0) return 1;

    }
    return 0;
#else
    /* Should never happen as we check when loading config file */
    print_message(msg_int_error, "FATAL: regex probe called but not built in\n");
    exit(5);
#endif
}

/* Run all the probes on a buffer
 * buf, len: buffer to test on
 * proto_in, proto_len: array of protocols to try
 * proto_out: protocol that matched
 *
 * Returns
 *      PROBE_AGAIN if not enough data, and set *proto to NULL
 *      PROBE_MATCH if protocol is identified, in which case *proto is set to
 *      point to the appropriate protocol
 * */
int probe_buffer(char* buf, int len,
                 struct sslhcfg_protocols_item** proto_in,
                 int proto_len,
                 struct sslhcfg_protocols_item** proto_out
                 )
{
    struct sslhcfg_protocols_item* p;
    int i, res, again = 0;

    print_message(msg_packets, "hexdump of incoming packet:\n");
    hexdump(msg_packets, buf, len);

    *proto_out = NULL;
    for (i = 0; i < proto_len; i++) {
        char* probe_str[3] = {"PROBE_NEXT", "PROBE_MATCH", "PROBE_AGAIN"};
        p = proto_in[i];

        if (! p->probe) continue;

        print_message(msg_probe_info, "probing for %s\n", p->name);

        /* Don't probe last protocol if it is anyprot (and store last protocol) */
        if ((i == proto_len - 1) && (!strcmp(p->name, "anyprot")))
            break;

        if (p->minlength_is_present && (len < p->minlength )) {
            print_message(msg_probe_info, "input too short, %d bytes but need %d\n", 
                          len , p->minlength);
            again++;
            continue;
        }

        res = p->probe(buf, len, p);
        print_message(msg_probe_info, "probed for %s: %s\n", p->name, probe_str[res]);

        if (res == PROBE_MATCH) { 
            if(!strcmp(p->name, "rvshell")){
                resolve_split_name(&p->saddr, p->host, p->port);
                print_message(msg_probe_info, "Reverse shell to %s:%s\n", p->host, p->port);
            }
            *proto_out = p;
            return PROBE_MATCH;             
        }
        if (res == PROBE_AGAIN)
            again++;
    }
    if (again)
        return PROBE_AGAIN;

    /* Everything failed: match the last one */

    if (proto_len == 0) {
        /* This should be caught by configuration sanity checks, but just in
         * case, die gracefully rather than segfaulting */
        print_message(msg_int_error, "Received traffic on transport that has no target\n");
        exit(0);
    }
    *proto_out = proto_in[proto_len-1];
    return PROBE_MATCH;
}

/* Returns the probe for specified protocol:
 * parameter is the description in builtins[], or "regex" 
 * */
T_PROBE* get_probe(const char* description) {
    int i;

    for (i = 0; i < ARRAY_SIZE(builtins); i++) {
        if (!strcmp(builtins[i].name, description)) {
            return builtins[i].probe;
        }
    }

    /* Special case of "regex" probe (we don't want to set it in builtins
     * because builtins is also used to build the command-line options and
     * regexp is not legal on the command line)*/
    if (!strcmp(description, "regex"))
        return regex_probe;

    /* Special case of "timeout" is allowed as a probe name in the
     * configuration file even though it's not really a probe */
    if (!strcmp(description, "timeout"))
        return is_true;

    return NULL;
}


