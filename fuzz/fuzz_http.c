// Fuzz harness for HTTP parser (chttp.c)
// Compile with:
//   clang -fsanitize=fuzzer,address -g fuzz_http.c -o fuzz_http
// Or for AFL:
//   afl-clang-fast fuzz_http.c -o fuzz_http_afl

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Stub out socket-related and SSL includes
#define CHTTP_DONT_INCLUDE

// Include necessary headers
#include "../src/lib/basic.h"
#include "../src/lib/basic.c"

// Minimal stubs for chttp
typedef struct { char *ptr; int len; } CHTTP_String;
#define CHTTP_STR(X) ((CHTTP_String) {(X), sizeof(X)-1})
#define CHTTP_COUNT(X) (int) (sizeof(X) / sizeof((X)[0]))
#define CHTTP_MAX_HEADERS 32

typedef struct { unsigned int data; } CHTTP_IPv4;
typedef struct { unsigned short data[8]; } CHTTP_IPv6;

typedef enum {
    CHTTP_HOST_MODE_VOID = 0,
    CHTTP_HOST_MODE_NAME,
    CHTTP_HOST_MODE_IPV4,
    CHTTP_HOST_MODE_IPV6,
} CHTTP_HostMode;

typedef struct {
    CHTTP_HostMode mode;
    CHTTP_String   text;
    union {
        CHTTP_String name;
        CHTTP_IPv4   ipv4;
        CHTTP_IPv6   ipv6;
    };
} CHTTP_Host;

typedef struct {
    CHTTP_String userinfo;
    CHTTP_Host   host;
    int         port;
} CHTTP_Authority;

typedef struct {
    CHTTP_String    scheme;
    CHTTP_Authority authority;
    CHTTP_String    path;
    CHTTP_String    query;
    CHTTP_String    fragment;
} CHTTP_URL;

typedef enum {
    CHTTP_METHOD_GET,
    CHTTP_METHOD_HEAD,
    CHTTP_METHOD_POST,
    CHTTP_METHOD_PUT,
    CHTTP_METHOD_DELETE,
    CHTTP_METHOD_CONNECT,
    CHTTP_METHOD_OPTIONS,
    CHTTP_METHOD_TRACE,
    CHTTP_METHOD_PATCH,
} CHTTP_Method;

typedef struct {
    CHTTP_String name;
    CHTTP_String value;
} CHTTP_Header;

typedef struct {
    bool        secure;
    CHTTP_Method method;
    CHTTP_URL    url;
    int         minor;
    int         num_headers;
    CHTTP_Header headers[CHTTP_MAX_HEADERS];
    CHTTP_String body;
} CHTTP_Request;

typedef struct {
    void*       context;
    int         minor;
    int         status;
    CHTTP_String reason;
    int         num_headers;
    CHTTP_Header headers[CHTTP_MAX_HEADERS];
    CHTTP_String body;
} CHTTP_Response;

// Function declarations
int chttp_parse_request(char *src, int len, CHTTP_Request *req);
int chttp_parse_response(char *src, int len, CHTTP_Response *res);
int chttp_parse_url(char *src, int len, CHTTP_URL *url);
int chttp_parse_ipv4(char *src, int len, CHTTP_IPv4 *ipv4);
int chttp_parse_ipv6(char *src, int len, CHTTP_IPv6 *ipv6);
int chttp_find_header(CHTTP_Header *headers, int num_headers, CHTTP_String name);
bool chttp_streq(CHTTP_String s1, CHTTP_String s2);
bool chttp_streqcase(CHTTP_String s1, CHTTP_String s2);
CHTTP_String chttp_trim(CHTTP_String s);

// Include just the parsing portion of chttp.c
// We need to extract the relevant functions

typedef struct {
    char *src;
    int len;
    int cur;
} Scanner;

static int is_digit(char c)
{
    return c >= '0' && c <= '9';
}

static int is_alpha(char c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z');
}

static int is_hex_digit(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

static int is_sub_delim(char c)
{
    return c == '!' || c == '$' || c == '&' || c == '\''
        || c == '(' || c == ')' || c == '*' || c == '+'
        || c == ',' || c == ';' || c == '=';
}

static int is_unreserved(char c)
{
    return is_alpha(c) || is_digit(c)
        || c == '-' || c == '.'
        || c == '_' || c == '~';
}

static int is_pchar(char c)
{
    return is_unreserved(c) || is_sub_delim(c) || c == ':' || c == '@';
}

static int is_tchar(char c)
{
    return is_digit(c) || is_alpha(c)
        || c == '!' || c == '#' || c == '$'
        || c == '%' || c == '&' || c == '\''
        || c == '*' || c == '+' || c == '-'
        || c == '.' || c == '^' || c == '_'
        || c == '~';
}

static int is_vchar(char c)
{
    return c >= ' ' && c <= '~';
}

#define CONSUME_OPTIONAL_SEQUENCE(scanner, func)                                        \
    while ((scanner)->cur < (scanner)->len && (func)((scanner)->src[(scanner)->cur]))   \
        (scanner)->cur++;

static char chttp_to_lower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    return c;
}

bool chttp_streq(CHTTP_String s1, CHTTP_String s2)
{
    if (s1.len != s2.len)
        return false;
    for (int i = 0; i < s1.len; i++)
        if (s1.ptr[i] != s2.ptr[i])
            return false;
    return true;
}

bool chttp_streqcase(CHTTP_String s1, CHTTP_String s2)
{
    if (s1.len != s2.len)
        return false;
    for (int i = 0; i < s1.len; i++)
        if (chttp_to_lower(s1.ptr[i]) != chttp_to_lower(s2.ptr[i]))
            return false;
    return true;
}

CHTTP_String chttp_trim(CHTTP_String s)
{
    int i = 0;
    while (i < s.len && (s.ptr[i] == ' ' || s.ptr[i] == '\t'))
        i++;

    if (i == s.len) {
        s.ptr = NULL;
        s.len = 0;
    } else {
        s.ptr += i;
        s.len -= i;
        while (s.ptr[s.len-1] == ' ' || s.ptr[s.len-1] == '\t')
            s.len--;
    }
    return s;
}

int chttp_find_header(CHTTP_Header *headers, int num_headers, CHTTP_String name)
{
    for (int i = 0; i < num_headers; i++)
        if (chttp_streqcase(name, headers[i].name))
            return i;
    return -1;
}

static int little_endian(void)
{
    uint16_t x = 1;
    return *((uint8_t*) &x);
}

static void invert_bytes(void *p, int len)
{
    char *c = p;
    for (int i = 0; i < len/2; i++) {
        char tmp = c[i];
        c[i] = c[len-i-1];
        c[len-i-1] = tmp;
    }
}

static int parse_ipv4(Scanner *s, CHTTP_IPv4 *ipv4)
{
    unsigned int out = 0;
    int i = 0;
    for (;;) {
        if (s->cur == s->len || !is_digit(s->src[s->cur]))
            return -1;
        int b = 0;
        do {
            int x = s->src[s->cur++] - '0';
            if (b > (255 - x) / 10)
                return -1;
            b = b * 10 + x;
        } while (s->cur < s->len && is_digit(s->src[s->cur]));
        out <<= 8;
        out |= (unsigned char) b;
        i++;
        if (i == 4) break;
        if (s->cur == s->len || s->src[s->cur] != '.')
            return -1;
        s->cur++;
    }
    if (little_endian()) invert_bytes(&out, 4);
    ipv4->data = out;
    return 0;
}

static int hex_digit_to_int(char c)
{
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= '0' && c <= '9') return c - '0';
    return -1;
}

static int parse_ipv6_comp(Scanner *s)
{
    unsigned short buf;
    if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
        return -1;
    buf = hex_digit_to_int(s->src[s->cur]);
    s->cur++;
    if (s->cur == s->len || !is_hex_digit(s->src[s->cur])) return buf;
    buf <<= 4; buf |= hex_digit_to_int(s->src[s->cur]); s->cur++;
    if (s->cur == s->len || !is_hex_digit(s->src[s->cur])) return buf;
    buf <<= 4; buf |= hex_digit_to_int(s->src[s->cur]); s->cur++;
    if (s->cur == s->len || !is_hex_digit(s->src[s->cur])) return buf;
    buf <<= 4; buf |= hex_digit_to_int(s->src[s->cur]); s->cur++;
    return (int) buf;
}

static int parse_ipv6(Scanner *s, CHTTP_IPv6 *ipv6)
{
    unsigned short head[8];
    unsigned short tail[8];
    int head_len = 0;
    int tail_len = 0;

    if (s->len - s->cur > 1 && s->src[s->cur+0] == ':' && s->src[s->cur+1] == ':')
        s->cur += 2;
    else {
        for (;;) {
            int ret = parse_ipv6_comp(s);
            if (ret < 0) return ret;
            head[head_len++] = (unsigned short) ret;
            if (head_len == 8) break;
            if (s->cur == s->len || s->src[s->cur] != ':') return -1;
            s->cur++;
            if (s->cur < s->len && s->src[s->cur] == ':') { s->cur++; break; }
        }
    }

    if (head_len < 8) {
        while (s->cur < s->len && is_hex_digit(s->src[s->cur])) {
            int ret = parse_ipv6_comp(s);
            if (ret < 0) return ret;
            tail[tail_len++] = (unsigned short) ret;
            if (head_len + tail_len == 8) break;
            if (s->cur == s->len || s->src[s->cur] != ':') break;
            s->cur++;
        }
    }

    for (int i = 0; i < head_len; i++) ipv6->data[i] = head[i];
    for (int i = 0; i < 8 - head_len - tail_len; i++) ipv6->data[head_len + i] = 0;
    for (int i = 0; i < tail_len; i++) ipv6->data[8 - tail_len + i] = tail[i];
    if (little_endian())
        for (int i = 0; i < 8; i++) invert_bytes(&ipv6->data[i], 2);
    return 0;
}

static int is_regname(char c)
{
    return is_unreserved(c) || is_sub_delim(c);
}

static int parse_regname(Scanner *s, CHTTP_String *regname)
{
    if (s->cur == s->len || !is_regname(s->src[s->cur]))
        return -1;
    int start = s->cur;
    do s->cur++; while (s->cur < s->len && is_regname(s->src[s->cur]));
    regname->ptr = s->src + start;
    regname->len = s->cur - start;
    return 0;
}

static int parse_host(Scanner *s, CHTTP_Host *host)
{
    int ret;
    if (s->cur < s->len && s->src[s->cur] == '[') {
        s->cur++;
        int start = s->cur;
        CHTTP_IPv6 ipv6;
        ret = parse_ipv6(s, &ipv6);
        if (ret < 0) return ret;
        host->mode = CHTTP_HOST_MODE_IPV6;
        host->ipv6 = ipv6;
        host->text = (CHTTP_String) { s->src + start, s->cur - start };
        if (s->cur == s->len || s->src[s->cur] != ']') return -1;
        s->cur++;
    } else {
        int start = s->cur;
        CHTTP_IPv4 ipv4;
        ret = parse_ipv4(s, &ipv4);
        if (ret >= 0) {
            host->mode = CHTTP_HOST_MODE_IPV4;
            host->ipv4 = ipv4;
        } else {
            s->cur = start;
            CHTTP_String regname;
            ret = parse_regname(s, &regname);
            if (ret < 0) return ret;
            host->mode = CHTTP_HOST_MODE_NAME;
            host->name = regname;
        }
        host->text = (CHTTP_String) { s->src + start, s->cur - start };
    }
    return 0;
}

static int is_scheme_head(char c) { return is_alpha(c); }
static int is_scheme_body(char c) { return is_alpha(c) || is_digit(c) || c == '+' || c == '-' || c == '.'; }
static int is_userinfo(char c) { return is_unreserved(c) || is_sub_delim(c) || c == ':'; }

static int parse_authority(Scanner *s, CHTTP_Authority *authority)
{
    CHTTP_String userinfo;
    {
        int start = s->cur;
        CONSUME_OPTIONAL_SEQUENCE(s, is_userinfo);
        if (s->cur < s->len && s->src[s->cur] == '@') {
            userinfo = (CHTTP_String) { s->src + start, s->cur - start };
            s->cur++;
        } else {
            s->cur = start;
            userinfo = (CHTTP_String) {NULL, 0};
        }
    }
    CHTTP_Host host;
    int ret = parse_host(s, &host);
    if (ret < 0) return ret;

    int port = 0;
    if (s->cur < s->len && s->src[s->cur] == ':') {
        s->cur++;
        if (s->cur < s->len && is_digit(s->src[s->cur])) {
            port = s->src[s->cur++] - '0';
            while (s->cur < s->len && is_digit(s->src[s->cur])) {
                int x = s->src[s->cur++] - '0';
                if (port > (65535 - x) / 10) return -1;
                port = port * 10 + x;
            }
        }
    }
    authority->userinfo = userinfo;
    authority->host = host;
    authority->port = port;
    return 0;
}

static int is_query(char c) { return is_pchar(c) || c == '/' || c == '?'; }
static int is_fragment(char c) { return is_pchar(c) || c == '/' || c == '?'; }

static int parse_path(Scanner *s, CHTTP_String *path, int abempty)
{
    int start = s->cur;
    if (abempty) {
        while (s->cur < s->len && s->src[s->cur] == '/') {
            do s->cur++; while (s->cur < s->len && is_pchar(s->src[s->cur]));
        }
    } else if (s->cur < s->len && (s->src[s->cur] == '/')) {
        s->cur++;
        if (s->cur < s->len && is_pchar(s->src[s->cur])) {
            s->cur++;
            for (;;) {
                CONSUME_OPTIONAL_SEQUENCE(s, is_pchar);
                if (s->cur == s->len || s->src[s->cur] != '/') break;
                s->cur++;
            }
        }
    } else if (s->cur < s->len && is_pchar(s->src[s->cur])) {
        s->cur++;
        for (;;) {
            CONSUME_OPTIONAL_SEQUENCE(s, is_pchar);
            if (s->cur == s->len || s->src[s->cur] != '/') break;
            s->cur++;
        }
    }
    *path = (CHTTP_String) { s->src + start, s->cur - start };
    if (path->len == 0) path->ptr = NULL;
    return 0;
}

static int parse_uri(Scanner *s, CHTTP_URL *url, int allow_fragment)
{
    CHTTP_String scheme = {0};
    int start = s->cur;
    if (s->cur == s->len || !is_scheme_head(s->src[s->cur])) return -1;
    do s->cur++; while (s->cur < s->len && is_scheme_body(s->src[s->cur]));
    scheme = (CHTTP_String) { s->src + start, s->cur - start };
    if (s->cur == s->len || s->src[s->cur] != ':') return -1;
    s->cur++;

    int abempty = 0;
    CHTTP_Authority authority = {0};
    if (s->len - s->cur > 1 && s->src[s->cur+0] == '/' && s->src[s->cur+1] == '/') {
        s->cur += 2;
        int ret = parse_authority(s, &authority);
        if (ret < 0) return ret;
        abempty = 1;
    }

    CHTTP_String path;
    int ret = parse_path(s, &path, abempty);
    if (ret < 0) return ret;

    CHTTP_String query = {0};
    if (s->cur < s->len && s->src[s->cur] == '?') {
        start = s->cur;
        do s->cur++; while (s->cur < s->len && is_query(s->src[s->cur]));
        query = (CHTTP_String) { s->src + start, s->cur - start };
    }

    CHTTP_String fragment = {0};
    if (allow_fragment && s->cur < s->len && s->src[s->cur] == '#') {
        start = s->cur;
        do s->cur++; while (s->cur < s->len && is_fragment(s->src[s->cur]));
        fragment = (CHTTP_String) { s->src + start, s->cur - start };
    }

    url->scheme = scheme;
    url->authority = authority;
    url->path = path;
    url->query = query;
    url->fragment = fragment;
    return 1;
}

static int consume_absolute_path(Scanner *s)
{
    if (s->cur == s->len || s->src[s->cur] != '/') return -1;
    s->cur++;
    for (;;) {
        CONSUME_OPTIONAL_SEQUENCE(s, is_pchar);
        if (s->cur == s->len || s->src[s->cur] != '/') break;
        s->cur++;
    }
    return 0;
}

static int parse_origin_form(Scanner *s, CHTTP_String *path, CHTTP_String *query)
{
    int start = s->cur;
    int ret = consume_absolute_path(s);
    if (ret < 0) return ret;
    *path = (CHTTP_String) { s->src + start, s->cur - start };
    if (s->cur < s->len && s->src[s->cur] == '?') {
        start = s->cur;
        do s->cur++; while (s->cur < s->len && is_query(s->src[s->cur]));
        *query = (CHTTP_String) { s->src + start, s->cur - start };
    } else {
        *query = (CHTTP_String) { NULL, 0 };
    }
    return 0;
}

static int parse_authority_form(Scanner *s, CHTTP_Host *host, int *port)
{
    int ret = parse_host(s, host);
    if (ret < 0) return ret;
    *port = 0;
    if (s->cur == s->len || s->src[s->cur] != ':') return 0;
    s->cur++;
    if (s->cur == s->len || !is_digit(s->src[s->cur])) return 0;
    int buf = 0;
    do {
        int x = s->src[s->cur++] - '0';
        if (buf > (65535 - x) / 10) return -1;
        buf = buf * 10 + x;
    } while (s->cur < s->len && is_digit(s->src[s->cur]));
    *port = buf;
    return 0;
}

static int parse_asterisk_form(Scanner *s)
{
    if (s->len - s->cur < 2 || s->src[s->cur+0] != '*' || s->src[s->cur+1] != ' ')
        return -1;
    s->cur++;
    return 0;
}

static int parse_request_target(Scanner *s, CHTTP_URL *url)
{
    memset(url, 0, sizeof(CHTTP_URL));
    int ret = parse_asterisk_form(s);
    if (ret >= 0) return ret;
    ret = parse_uri(s, url, 0);
    if (ret >= 0) return ret;
    ret = parse_authority_form(s, &url->authority.host, &url->authority.port);
    if (ret >= 0) return ret;
    ret = parse_origin_form(s, &url->path, &url->query);
    if (ret >= 0) return ret;
    return -1;
}

static bool consume_str(Scanner *scan, CHTTP_String token)
{
    if (token.len > scan->len - scan->cur) return false;
    for (int i = 0; i < token.len; i++)
        if (scan->src[scan->cur + i] != token.ptr[i])
            return false;
    scan->cur += token.len;
    return true;
}

static int is_header_body(char c) { return is_vchar(c) || c == ' ' || c == '\t'; }

static int parse_headers(Scanner *s, CHTTP_Header *headers, int max_headers)
{
    int num_headers = 0;
    while (!consume_str(s, CHTTP_STR("\r\n"))) {
        int start;
        if (s->cur == s->len || !is_tchar(s->src[s->cur])) return -1;
        start = s->cur;
        do s->cur++; while (s->cur < s->len && is_tchar(s->src[s->cur]));
        CHTTP_String name = { s->src + start, s->cur - start };
        if (s->cur == s->len || s->src[s->cur] != ':') return -1;
        s->cur++;
        start = s->cur;
        CONSUME_OPTIONAL_SEQUENCE(s, is_header_body);
        CHTTP_String body = { s->src + start, s->cur - start };
        body = chttp_trim(body);
        if (num_headers < max_headers)
            headers[num_headers++] = (CHTTP_Header) { name, body };
        if (!consume_str(s, CHTTP_STR("\r\n"))) return -1;
    }
    return num_headers;
}

static int contains_head(char *src, int len)
{
    int cur = 0;
    while (len - cur > 3) {
        if (src[cur+0] == '\r' && src[cur+1] == '\n' &&
            src[cur+2] == '\r' && src[cur+3] == '\n')
            return 1;
        cur++;
    }
    return 0;
}

static int parse_request(Scanner *s, CHTTP_Request *req)
{
    if (!contains_head(s->src + s->cur, s->len - s->cur)) return 0;
    req->secure = false;
    if (0) {}
    else if (consume_str(s, CHTTP_STR("GET ")))     req->method = CHTTP_METHOD_GET;
    else if (consume_str(s, CHTTP_STR("POST ")))    req->method = CHTTP_METHOD_POST;
    else if (consume_str(s, CHTTP_STR("PUT ")))     req->method = CHTTP_METHOD_PUT;
    else if (consume_str(s, CHTTP_STR("HEAD ")))    req->method = CHTTP_METHOD_HEAD;
    else if (consume_str(s, CHTTP_STR("DELETE ")))  req->method = CHTTP_METHOD_DELETE;
    else if (consume_str(s, CHTTP_STR("CONNECT "))) req->method = CHTTP_METHOD_CONNECT;
    else if (consume_str(s, CHTTP_STR("OPTIONS "))) req->method = CHTTP_METHOD_OPTIONS;
    else if (consume_str(s, CHTTP_STR("TRACE ")))   req->method = CHTTP_METHOD_TRACE;
    else if (consume_str(s, CHTTP_STR("PATCH ")))   req->method = CHTTP_METHOD_PATCH;
    else return -1;

    {
        Scanner s2 = *s;
        int peek = s->cur;
        while (peek < s->len && s->src[peek] != ' ') peek++;
        if (peek == s->len) return -1;
        s2.len = peek;
        int ret = parse_request_target(&s2, &req->url);
        if (ret < 0) return ret;
        s->cur = s2.cur;
    }

    if (consume_str(s, CHTTP_STR(" HTTP/1.1\r\n"))) req->minor = 1;
    else if (consume_str(s, CHTTP_STR(" HTTP/1.0\r\n")) || consume_str(s, CHTTP_STR(" HTTP/1\r\n"))) req->minor = 0;
    else return -1;

    int num_headers = parse_headers(s, req->headers, CHTTP_MAX_HEADERS);
    if (num_headers < 0) return num_headers;
    req->num_headers = num_headers;
    req->body = (CHTTP_String){NULL, 0};
    return 1;
}

static int parse_response(Scanner *s, CHTTP_Response *res)
{
    if (!contains_head(s->src + s->cur, s->len - s->cur)) return 0;
    if (consume_str(s, CHTTP_STR("HTTP/1.1 "))) res->minor = 1;
    else if (consume_str(s, CHTTP_STR("HTTP/1.0 ")) || consume_str(s, CHTTP_STR("HTTP/1 "))) res->minor = 0;
    else return -1;

    if (s->len - s->cur < 4 || !is_digit(s->src[s->cur+0]) ||
        !is_digit(s->src[s->cur+1]) || !is_digit(s->src[s->cur+2]) ||
        s->src[s->cur+3] != ' ')
        return -1;

    res->status = (s->src[s->cur+0] - '0') * 100 +
                  (s->src[s->cur+1] - '0') * 10 +
                  (s->src[s->cur+2] - '0') * 1;
    s->cur += 4;

    while (s->cur < s->len && (s->src[s->cur] == '\t' || s->src[s->cur] == ' ' || is_vchar(s->src[s->cur])))
        s->cur++;

    if (s->len - s->cur < 2 || s->src[s->cur+0] != '\r' || s->src[s->cur+1] != '\n')
        return -1;
    s->cur += 2;

    int num_headers = parse_headers(s, res->headers, CHTTP_MAX_HEADERS);
    if (num_headers < 0) return num_headers;
    res->num_headers = num_headers;
    res->body = (CHTTP_String){NULL, 0};
    return 1;
}

int chttp_parse_request(char *src, int len, CHTTP_Request *req)
{
    Scanner s = {src, len, 0};
    int ret = parse_request(&s, req);
    if (ret == 1) return s.cur;
    return ret;
}

int chttp_parse_response(char *src, int len, CHTTP_Response *res)
{
    Scanner s = {src, len, 0};
    int ret = parse_response(&s, res);
    if (ret == 1) return s.cur;
    return ret;
}

int chttp_parse_url(char *src, int len, CHTTP_URL *url)
{
    Scanner s = {src, len, 0};
    int ret = parse_uri(&s, url, 1);
    if (ret == 1) return s.cur;
    return ret;
}

int chttp_parse_ipv4(char *src, int len, CHTTP_IPv4 *ipv4)
{
    Scanner s = {src, len, 0};
    int ret = parse_ipv4(&s, ipv4);
    if (ret < 0) return ret;
    return s.cur;
}

int chttp_parse_ipv6(char *src, int len, CHTTP_IPv6 *ipv6)
{
    Scanner s = {src, len, 0};
    int ret = parse_ipv6(&s, ipv6);
    if (ret < 0) return ret;
    return s.cur;
}

// Fuzzer entry points

#ifdef __AFL_FUZZ_TESTCASE_LEN
__AFL_FUZZ_INIT();

int main(void)
{
    __AFL_INIT();
    unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

    while (__AFL_LOOP(100000)) {
        int len = __AFL_FUZZ_TESTCASE_LEN;

        char *input = malloc(len + 1);
        if (!input) continue;
        memcpy(input, buf, len);
        input[len] = '\0';

        // Fuzz HTTP request parsing
        CHTTP_Request req = {0};
        (void)chttp_parse_request(input, len, &req);

        // Fuzz HTTP response parsing
        CHTTP_Response res = {0};
        (void)chttp_parse_response(input, len, &res);

        // Fuzz URL parsing
        CHTTP_URL url = {0};
        (void)chttp_parse_url(input, len, &url);

        // Fuzz IPv4 parsing
        CHTTP_IPv4 ipv4 = {0};
        (void)chttp_parse_ipv4(input, len, &ipv4);

        // Fuzz IPv6 parsing
        CHTTP_IPv6 ipv6 = {0};
        (void)chttp_parse_ipv6(input, len, &ipv6);

        free(input);
    }
    return 0;
}

#else
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size == 0 || size > 1024 * 1024) return 0;

    char *input = malloc(size + 1);
    if (!input) return 0;
    memcpy(input, data, size);
    input[size] = '\0';

    // Fuzz HTTP request parsing
    CHTTP_Request req = {0};
    int ret = chttp_parse_request(input, (int)size, &req);
    if (ret > 0) {
        // Exercise parsed data
        (void)req.method;
        (void)req.minor;
        (void)req.num_headers;
        for (int i = 0; i < req.num_headers; i++) {
            (void)chttp_find_header(req.headers, req.num_headers, req.headers[i].name);
        }
    }

    // Fuzz HTTP response parsing
    CHTTP_Response res = {0};
    ret = chttp_parse_response(input, (int)size, &res);
    if (ret > 0) {
        (void)res.status;
        (void)res.minor;
        (void)res.num_headers;
    }

    // Fuzz URL parsing
    CHTTP_URL url = {0};
    ret = chttp_parse_url(input, (int)size, &url);
    if (ret > 0) {
        (void)url.scheme.len;
        (void)url.path.len;
        (void)url.query.len;
        (void)url.authority.port;
    }

    // Fuzz IPv4 parsing
    CHTTP_IPv4 ipv4 = {0};
    (void)chttp_parse_ipv4(input, (int)size, &ipv4);

    // Fuzz IPv6 parsing
    CHTTP_IPv6 ipv6 = {0};
    (void)chttp_parse_ipv6(input, (int)size, &ipv6);

    free(input);
    return 0;
}
#endif

#ifdef STANDALONE
int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) { perror("fopen"); return 1; }
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *data = malloc(size);
    if (!data) { fclose(f); return 1; }
    fread(data, 1, size, f);
    fclose(f);
    int result = LLVMFuzzerTestOneInput(data, size);
    free(data);
    printf("Test completed\n");
    return result;
}
#endif
