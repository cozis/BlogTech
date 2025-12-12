// cHTTP, an HTTP client and server library!
//
// This file was generated automatically. Do not modify directly.
//
// Refer to the end of this file for the license
#ifndef CHTTP_DONT_INCLUDE
#include "chttp.h"
#endif

////////////////////////////////////////////////////////////////////////////////////////
// src/basic.c
////////////////////////////////////////////////////////////////////////////////////////

bool chttp_streq(CHTTP_String s1, CHTTP_String s2)
{
	if (s1.len != s2.len)
		return false;

    for (int i = 0; i < s1.len; i++)
		if (s1.ptr[i] != s2.ptr[i])
			return false;

	return true;
}

static char to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}

bool chttp_streqcase(CHTTP_String s1, CHTTP_String s2)
{
	if (s1.len != s2.len)
		return false;

	for (int i = 0; i < s1.len; i++)
		if (to_lower(s1.ptr[i]) != to_lower(s2.ptr[i]))
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

static bool is_printable(char c)
{
    return c >= ' ' && c <= '~';
}

void print_bytes(CHTTP_String prefix, CHTTP_String src)
{
    if (src.len == 0)
        return;

    FILE *stream = stdout;

    bool new_line = true;
    int cur = 0;
    for (;;) {
        int start = cur;

        while (cur < src.len && is_printable(src.ptr[cur]))
            cur++;

        if (new_line) {
            fwrite(prefix.ptr, 1, prefix.len, stream);
            new_line = false;
        }

        fwrite(src.ptr + start, 1, cur - start, stream);

        if (cur == src.len)
            break;

        if (src.ptr[cur] == '\n') {
            putc('\\', stream);
            putc('n',  stream);
            putc('\n', stream);
            new_line = true;
        } else if (src.ptr[cur] == '\r') {
            putc('\\', stream);
            putc('r',  stream);
        } else {
            putc('.', stream);
        }
        cur++;
    }
    putc('\n', stream);
}

char *chttp_strerror(int code)
{
    switch (code) {
        case CHTTP_OK: return "No error";
        case CHTTP_ERROR_UNSPECIFIED: return "Unspecified error";
        case CHTTP_ERROR_OOM: return "Out of memory";
        case CHTTP_ERROR_BADURL: return "Invalid URL";
        case CHTTP_ERROR_REQLIMIT: return "Parallel request limit reached";
        case CHTTP_ERROR_BADHANDLE: return "Invalid handle";
        case CHTTP_ERROR_NOTLS: return "TLS support not built-in";
    }
    return "???";
}

////////////////////////////////////////////////////////////////////////////////////////
// src/parse.c
////////////////////////////////////////////////////////////////////////////////////////
// From RFC 9112
//   request-target = origin-form
//                  / absolute-form
//                  / authority-form
//                  / asterisk-form
//   origin-form    = absolute-path [ "?" query ]
//   absolute-form  = absolute-URI
//   authority-form = uri-host ":" port
//   asterisk-form  = "*"
//
// From RFC 9110
//   URI-reference = <URI-reference, see [URI], Section 4.1>
//   absolute-URI  = <absolute-URI, see [URI], Section 4.3>
//   relative-part = <relative-part, see [URI], Section 4.2>
//   authority     = <authority, see [URI], Section 3.2>
//   uri-host      = <host, see [URI], Section 3.2.2>
//   port          = <port, see [URI], Section 3.2.3>
//   path-abempty  = <path-abempty, see [URI], Section 3.3>
//   segment       = <segment, see [URI], Section 3.3>
//   query         = <query, see [URI], Section 3.4>
//
//   absolute-path = 1*( "/" segment )
//   partial-URI   = relative-part [ "?" query ]
//
// From RFC 3986:
//   segment       = *pchar
//   pchar         = unreserved / pct-encoded / sub-delims / ":" / "@"
//   pct-encoded   = "%" HEXDIG HEXDIG
//   sub-delims    = "!" / "$" / "&" / "'" / "(" / ")"
//                 / "*" / "+" / "," / ";" / "="
//   unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
//   query         = *( pchar / "/" / "?" )
//   absolute-URI  = scheme ":" hier-part [ "?" query ]
//   hier-part     = "//" authority path-abempty
//                 / path-absolute
//                 / path-rootless
//                 / path-empty
//   scheme      = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )

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

// From RFC 3986:
//   sub-delims = "!" / "$" / "&" / "'" / "(" / ")"
//              / "*" / "+" / "," / ";" / "="
static int is_sub_delim(char c)
{
	return c == '!' || c == '$' || c == '&' || c == '\''
		|| c == '(' || c == ')' || c == '*' || c == '+'
		|| c == ',' || c == ';' || c == '=';
}

// From RFC 3986:
//   unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
static int is_unreserved(char c)
{
	return is_alpha(c) || is_digit(c)
		|| c == '-' || c == '.'
		|| c == '_' || c == '~';
}

// From RFC 3986:
//   pchar = unreserved / pct-encoded / sub-delims / ":" / "@"
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

static int
consume_absolute_path(Scanner *s)
{
	if (s->cur == s->len || s->src[s->cur] != '/')
		return -1; // ERROR
	s->cur++;

	for (;;) {

        CONSUME_OPTIONAL_SEQUENCE(s, is_pchar);

		if (s->cur == s->len || s->src[s->cur] != '/')
			break;
		s->cur++;
	}

	return 0;
}

// If abempty=1:
//   path-abempty  = *( "/" segment )
// else:
//   path-absolute = "/" [ segment-nz *( "/" segment ) ]
//   path-rootless = segment-nz *( "/" segment )
//   path-empty    = 0<pchar>
static int parse_path(Scanner *s, CHTTP_String *path, int abempty)
{
	int start = s->cur;

	if (abempty) {

		// path-abempty
		while (s->cur < s->len && s->src[s->cur] == '/') {
			do
				s->cur++;
			while (s->cur < s->len && is_pchar(s->src[s->cur]));
		}

	} else if (s->cur < s->len && (s->src[s->cur] == '/')) {

		// path-absolute
		s->cur++;
		if (s->cur < s->len && is_pchar(s->src[s->cur])) {
			s->cur++;
			for (;;) {

                CONSUME_OPTIONAL_SEQUENCE(s, is_pchar);

				if (s->cur == s->len || s->src[s->cur] != '/')
					break;
				s->cur++;
			}
		}

	} else if (s->cur < s->len && is_pchar(s->src[s->cur])) {

		// path-rootless
		s->cur++;
		for (;;) {

            CONSUME_OPTIONAL_SEQUENCE(s, is_pchar)

			if (s->cur == s->len || s->src[s->cur] != '/')
				break;
			s->cur++;
		}

	} else {
		// path->empty
		// (do nothing)
	}

	*path = (CHTTP_String) {
		s->src + start,
		s->cur - start,
	};
	if (path->len == 0)
		path->ptr = NULL;

	return 0;
}

// RFC 3986:
//   query = *( pchar / "/" / "?" )
static int is_query(char c)
{
	return is_pchar(c) || c == '/' || c == '?';
}

// RFC 3986:
//   fragment = *( pchar / "/" / "?" )
static int is_fragment(char c)
{
	return is_pchar(c) || c == '/' || c == '?';
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
			if (b > (UINT8_MAX - x) / 10)
				return -1;
			b = b * 10 + x;
		} while (s->cur < s->len && is_digit(s->src[s->cur]));

		out <<= 8;
		out |= (unsigned char) b;

		i++;
		if (i == 4)
			break;

		if (s->cur == s->len || s->src[s->cur] != '.')
			return -1;
		s->cur++;
	}

	if (little_endian())
		invert_bytes(&out, 4);

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

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return buf;
	buf <<= 4;
	buf |= hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return buf;
	buf <<= 4;
	buf |= hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	if (s->cur == s->len || !is_hex_digit(s->src[s->cur]))
		return buf;
	buf <<= 4;
	buf |= hex_digit_to_int(s->src[s->cur]);
	s->cur++;

	return (int) buf;
}

static int parse_ipv6(Scanner *s, CHTTP_IPv6 *ipv6)
{
	unsigned short head[8];
	unsigned short tail[8];
	int head_len = 0;
	int tail_len = 0;

	if (s->len - s->cur > 1
		&& s->src[s->cur+0] == ':'
		&& s->src[s->cur+1] == ':')
		s->cur += 2;
	else {

		for (;;) {

			int ret = parse_ipv6_comp(s);
			if (ret < 0) return ret;

			head[head_len++] = (unsigned short) ret;
			if (head_len == 8) break;

			if (s->cur == s->len || s->src[s->cur] != ':')
				return -1;
			s->cur++;

			if (s->cur < s->len && s->src[s->cur] == ':') {
				s->cur++;
				break;
			}
		}
	}

	if (head_len < 8) {
		while (s->cur < s->len && is_hex_digit(s->src[s->cur])) {

			int ret = parse_ipv6_comp(s);
			if (ret < 0) return ret;

			tail[tail_len++] = (unsigned short) ret;
			if (head_len + tail_len == 8) break;

			if (s->cur == s->len || s->src[s->cur] != ':')
				break;
			s->cur++;
		}
	}

	for (int i = 0; i < head_len; i++)
		ipv6->data[i] = head[i];

	for (int i = 0; i < 8 - head_len - tail_len; i++)
		ipv6->data[head_len + i] = 0;

	for (int i = 0; i < tail_len; i++)
		ipv6->data[8 - tail_len + i] = tail[i];

	if (little_endian())
		for (int i = 0; i < 8; i++)
			invert_bytes(&ipv6->data[i], 2);

	return 0;
}

// From RFC 3986:
//   reg-name = *( unreserved / pct-encoded / sub-delims )
static int is_regname(char c)
{
	return is_unreserved(c) || is_sub_delim(c);
}

static int parse_regname(Scanner *s, CHTTP_String *regname)
{
	if (s->cur == s->len || !is_regname(s->src[s->cur]))
		return -1;
	int start = s->cur;
	do
		s->cur++;
	while (s->cur < s->len && is_regname(s->src[s->cur]));
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

		if (s->cur == s->len || s->src[s->cur] != ']')
			return -1;
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

// scheme = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
static int is_scheme_head(char c)
{
	return is_alpha(c);
}

static int is_scheme_body(char c)
{
	return is_alpha(c)
		|| is_digit(c)
		|| c == '+'
		|| c == '-'
		|| c == '.';
}

// userinfo = *( unreserved / pct-encoded / sub-delims / ":" )
// Note: percent-encoded characters (%XX) are not currently validated
static int is_userinfo(char c)
{
	return is_unreserved(c) || is_sub_delim(c) || c == ':';
}

// authority = [ userinfo "@" ] host [ ":" port ]
static int parse_authority(Scanner *s, CHTTP_Authority *authority)
{
	CHTTP_String userinfo;
	{
		int start = s->cur;

        CONSUME_OPTIONAL_SEQUENCE(s, is_userinfo);

		if (s->cur < s->len && s->src[s->cur] == '@') {
			userinfo = (CHTTP_String) {
				s->src + start,
				s->cur - start
			};
			s->cur++;
		} else {
			// Rollback
			s->cur = start;
			userinfo = (CHTTP_String) {NULL, 0};
		}
	}

	CHTTP_Host host;
	{
		int ret = parse_host(s, &host);
		if (ret < 0)
			return ret;
	}

	int port = 0;
	if (s->cur < s->len && s->src[s->cur] == ':') {
		s->cur++;
		if (s->cur < s->len && is_digit(s->src[s->cur])) {
			port = s->src[s->cur++] - '0';
			while (s->cur < s->len && is_digit(s->src[s->cur])) {
				int x = s->src[s->cur++] - '0';
				if (port > (UINT16_MAX - x) / 10)
					return -1; // ERROR: Port too big
				port = port * 10 + x;
			}
		}
	}

	authority->userinfo = userinfo;
	authority->host = host;
	authority->port = port;
	return 0;
}

static int parse_uri(Scanner *s, CHTTP_URL *url, int allow_fragment)
{
	CHTTP_String scheme = {0};
	{
		int start = s->cur;
		if (s->cur == s->len || !is_scheme_head(s->src[s->cur]))
			return -1; // ERROR: Missing scheme
		do
			s->cur++;
		while (s->cur < s->len && is_scheme_body(s->src[s->cur]));
		scheme = (CHTTP_String) {
			s->src + start,
			s->cur - start,
		};

		if (s->cur == s->len || s->src[s->cur] != ':')
			return -1; // ERROR: Missing ':' after scheme
		s->cur++;
	}

	int abempty = 0;
	CHTTP_Authority authority = {0};
	if (s->len - s->cur > 1
		&& s->src[s->cur+0] == '/'
		&& s->src[s->cur+1] == '/') {

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
		int start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_query(s->src[s->cur]));
		query = (CHTTP_String) {
			s->src + start,
			s->cur - start,
		};
	}

	CHTTP_String fragment = {0};
	if (allow_fragment && s->cur < s->len && s->src[s->cur] == '#') {
		int start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_fragment(s->src[s->cur]));
		fragment = (CHTTP_String) {
			s->src + start,
			s->cur - start,
		};
	}

	url->scheme    = scheme;
	url->authority = authority;
	url->path      = path;
	url->query     = query;
	url->fragment  = fragment;

	return 1;
}

// authority-form = host ":" port
// host           = IP-literal / IPv4address / reg-name
// IP-literal    = "[" ( IPv6address / IPvFuture  ) "]"
// reg-name      = *( unreserved / pct-encoded / sub-delims )
static int parse_authority_form(Scanner *s, CHTTP_Host *host, int *port)
{
	int ret;

	ret = parse_host(s, host);
	if (ret < 0) return ret;

	// Default port value
	*port = 0;

	if (s->cur == s->len || s->src[s->cur] != ':')
		return 0; // No port
	s->cur++;

	if (s->cur == s->len || !is_digit(s->src[s->cur]))
		return 0; // No port

	int buf = 0;
	do {
		int x = s->src[s->cur++] - '0';
		if (buf > (UINT16_MAX - x) / 10)
			return -1; // ERROR
		buf = buf * 10 + x;
	} while (s->cur < s->len && is_digit(s->src[s->cur]));

	*port = buf;
	return 0;
}

static int parse_origin_form(Scanner *s, CHTTP_String *path, CHTTP_String *query)
{
	int ret, start;

	start = s->cur;
	ret = consume_absolute_path(s);
	if (ret < 0) return ret;
	*path = (CHTTP_String) { s->src + start, s->cur - start };

	if (s->cur < s->len && s->src[s->cur] == '?') {
		start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_query(s->src[s->cur]));
		*query = (CHTTP_String) { s->src + start, s->cur - start };
	} else
		*query = (CHTTP_String) { NULL, 0 };

	return 0;
}

static int parse_asterisk_form(Scanner *s)
{
	if (s->len - s->cur < 2
		|| s->src[s->cur+0] != '*'
		|| s->src[s->cur+1] != ' ')
		return -1;
	s->cur++;
	return 0;
}

static int parse_request_target(Scanner *s, CHTTP_URL *url)
{
	int ret;

	memset(url, 0, sizeof(CHTTP_URL));

	// asterisk-form
	ret = parse_asterisk_form(s);
	if (ret >= 0) return ret;

	ret = parse_uri(s, url, 0);
	if (ret >= 0) return ret;

	ret = parse_authority_form(s, &url->authority.host, &url->authority.port);
	if (ret >= 0) return ret;

	ret = parse_origin_form(s, &url->path, &url->query);
	if (ret >= 0) return ret;

	return -1;
}

bool consume_str(Scanner *scan, CHTTP_String token)
{
    assert(token.len > 0);

    if (token.len > scan->len - scan->cur)
        return false;

    for (int i = 0; i < token.len; i++)
        if (scan->src[scan->cur + i] != token.ptr[i])
            return false;

    scan->cur += token.len;
    return true;
}

static int is_header_body(char c)
{
	return is_vchar(c) || c == ' ' || c == '\t';
}

static int parse_headers(Scanner *s, CHTTP_Header *headers, int max_headers)
{
	int num_headers = 0;
    while (!consume_str(s, CHTTP_STR("\r\n"))) {

        // RFC 9112:
		//   field-line = field-name ":" OWS field-value OWS
		//
		// RFC 9110:
		//   field-value    = *field-content
		//   field-content  = field-vchar
		//                    [ 1*( SP / HTAB / field-vchar ) field-vchar ]
		//   field-vchar    = VCHAR / obs-text
		//   obs-text       = %x80-FF

		int start;

		if (s->cur == s->len || !is_tchar(s->src[s->cur]))
			return -1; // ERROR
		start = s->cur;
		do
			s->cur++;
		while (s->cur < s->len && is_tchar(s->src[s->cur]));
		CHTTP_String name = { s->src + start, s->cur - start };

		if (s->cur == s->len || s->src[s->cur] != ':')
			return -1; // ERROR
		s->cur++;

        start = s->cur;
        CONSUME_OPTIONAL_SEQUENCE(s, is_header_body);
		CHTTP_String body = { s->src + start, s->cur - start };
		body = chttp_trim(body);

        if (num_headers < max_headers)
            headers[num_headers++] = (CHTTP_Header) { name, body };

        if (!consume_str(s, CHTTP_STR("\r\n"))) {
            return -1;
        }
    }

    return num_headers;
}

typedef enum {
    TRANSFER_ENCODING_OPTION_CHUNKED,
    TRANSFER_ENCODING_OPTION_COMPRESS,
    TRANSFER_ENCODING_OPTION_DEFLATE,
    TRANSFER_ENCODING_OPTION_GZIP,
} TransferEncodingOption;

static bool is_space(char c)
{
    return c == ' ' || c == '\t';
}

static int
parse_transfer_encoding(CHTTP_String src, TransferEncodingOption *dst, int max)
{
    Scanner s = { src.ptr, src.len, 0 };

    int num = 0;
    for (;;) {

        CONSUME_OPTIONAL_SEQUENCE(&s, is_space);

        TransferEncodingOption opt;
        if (0) {}
        else if (consume_str(&s, CHTTP_STR("chunked")))  opt = TRANSFER_ENCODING_OPTION_CHUNKED;
        else if (consume_str(&s, CHTTP_STR("compress"))) opt = TRANSFER_ENCODING_OPTION_COMPRESS;
        else if (consume_str(&s, CHTTP_STR("deflate")))  opt = TRANSFER_ENCODING_OPTION_DEFLATE;
        else if (consume_str(&s, CHTTP_STR("gzip")))     opt = TRANSFER_ENCODING_OPTION_GZIP;
        else return -1; // Invalid option

        if (num == max)
            return -1; // Too many options
        dst[num++] = opt;

        CONSUME_OPTIONAL_SEQUENCE(&s, is_space);

        if (s.cur == s.len)
            break;

        if (s.src[s.cur] != ',')
            return -1; // Missing comma separator
    }

    return num;
}

static int
parse_content_length(const char *src, int len, uint64_t *out)
{
    int cur = 0;
    while (cur < len && (src[cur] == ' ' || src[cur] == '\t'))
        cur++;

    if (cur == len || !is_digit(src[cur]))
        return -1;

    uint64_t buf = 0;
    do {
        int d = src[cur++] - '0';
        if (buf > (UINT64_MAX - d) / 10)
            return -1;
        buf = buf * 10 + d;
    } while (cur < len && is_digit(src[cur]));

    *out = buf;
    return 0;
}

static int parse_body(Scanner *s,
    CHTTP_Header *headers, int num_headers,
    CHTTP_String *body, bool body_expected)
{

    // RFC 9112 section 6:
    //   The presence of a message body in a request is signaled by a Content-Length or
    //   Transfer-Encoding header field. Request message framing is independent of method
    //   semantics.

    int header_index = chttp_find_header(headers, num_headers, CHTTP_STR("Transfer-Encoding"));
    if (header_index != -1) {

        // RFC 9112 section 6.1:
        //   A server MAY reject a request that contains both Content-Length and Transfer-Encoding
        //   or process such a request in accordance with the Transfer-Encoding alone. Regardless,
        //   the server MUST close the connection after responding to such a request to avoid the
        //   potential attacks.
        if (chttp_find_header(headers, num_headers, CHTTP_STR("Content-Length")) != -1)
            return -1;

        CHTTP_String value = headers[header_index].value;

        // RFC 9112 section 6.1:
        //   If any transfer coding other than chunked is applied to a request's content, the
        //   sender MUST apply chunked as the final transfer coding to ensure that the message
        //   is properly framed. If any transfer coding other than chunked is applied to a
        //   response's content, the sender MUST either apply chunked as the final transfer
        //   coding or terminate the message by closing the connection.

        TransferEncodingOption opts[8];
        int num = parse_transfer_encoding(value, opts, CHTTP_COUNT(opts));
        if (num != 1 || opts[0] != TRANSFER_ENCODING_OPTION_CHUNKED)
            return -1;

        CHTTP_String chunks_maybe[128];
        CHTTP_String *chunks = chunks_maybe;
        int num_chunks = 0;
        int max_chunks = CHTTP_COUNT(chunks_maybe);

        #define FREE_CHUNK_LIST         \
            if (chunks != chunks_maybe) \
                free(chunks);

        char *content_start = s->src + s->cur;

        for (;;) {

            // RFC 9112 section 7.1:
            //   The chunked transfer coding wraps content in order to transfer it as a series of chunks,
            //   each with its own size indicator, followed by an OPTIONAL trailer section containing
            //   trailer fields.

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }

            if (!is_hex_digit(s->src[s->cur])) {
                FREE_CHUNK_LIST
                return -1;
            }

            int chunk_len = 0;

            do {
                char c = s->src[s->cur++];
                int  n = hex_digit_to_int(c);
                if (chunk_len > (INT_MAX - n) / 16) {
                    FREE_CHUNK_LIST
                    return -1; // overflow
                }
                chunk_len = chunk_len * 16 + n;
            } while (s->cur < s->len && is_hex_digit(s->src[s->cur]));

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }
            if (s->src[s->cur] != '\r') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0;
            }
            if (s->src[s->cur] != '\n') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            char *chunk_ptr = s->src + s->cur;

            if (chunk_len > s->len - s->cur) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }
            s->cur += chunk_len;

            if (s->cur == s->len)
                return 0; // Incomplete request
            if (s->src[s->cur] != '\r') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            if (s->cur == s->len) {
                FREE_CHUNK_LIST
                return 0; // Incomplete request
            }
            if (s->src[s->cur] != '\n') {
                FREE_CHUNK_LIST
                return -1;
            }
            s->cur++;

            if (chunk_len == 0)
                break;

            if (num_chunks == max_chunks) {

                max_chunks *= 2;

                CHTTP_String *new_chunks = malloc(max_chunks * sizeof(CHTTP_String));
                if (new_chunks == NULL) {
                    if (chunks != chunks_maybe)
                        free(chunks);
                    return -1;
                }

                for (int i = 0; i < num_chunks; i++)
                    new_chunks[i] = chunks[i];

                if (chunks != chunks_maybe)
                    free(chunks);

                chunks = new_chunks;
            }
            chunks[num_chunks++] = (CHTTP_String) { chunk_ptr, chunk_len };
        }

        char *content_ptr = content_start;
        for (int i = 0; i < num_chunks; i++) {
            memmove(content_ptr, chunks[i].ptr, chunks[i].len);
            content_ptr += chunks[i].len;
        }

        *body = (CHTTP_String) {
            content_start,
            content_ptr - content_start
        };

        if (chunks != chunks_maybe)
            free(chunks);

        return 1;
    }

    // RFC 9112 section 6.3:
    //   If a valid Content-Length header field is present without Transfer-Encoding,
    //   its decimal value defines the expected message body length in octets.

    header_index = chttp_find_header(headers, num_headers, CHTTP_STR("Content-Length"));
    if (header_index != -1) {

        // Have Content-Length
        CHTTP_String value = headers[header_index].value;

        uint64_t tmp;
        if (parse_content_length(value.ptr, value.len, &tmp) < 0)
            return -1;
        if (tmp > INT_MAX)
            return -1;
        int len = (int) tmp;

        if (len > s->len - s->cur)
            return 0; // Incomplete request

        *body = (CHTTP_String) { s->src + s->cur, len };

        s->cur += len;
        return 1;
    }

    // No Content-Length or Transfer-Encoding
    if (body_expected) return -1;

    *body = (CHTTP_String) { NULL, 0 };
    return 1;
}

static int contains_head(char *src, int len)
{
    int cur = 0;
    while (len - cur > 3) {
        if (src[cur+0] == '\r' &&
            src[cur+1] == '\n' &&
            src[cur+2] == '\r' &&
            src[cur+3] == '\n')
            return 1;
        cur++;
    }
    return 0;
}

static int parse_request(Scanner *s, CHTTP_Request *req)
{
    if (!contains_head(s->src + s->cur, s->len - s->cur))
        return 0;

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
        while (peek < s->len && s->src[peek] != ' ')
            peek++;
        if (peek == s->len)
            return -1;
        s2.len = peek;

        int ret = parse_request_target(&s2, &req->url);
        if (ret < 0) return ret;

        s->cur = s2.cur;
    }

    if (consume_str(s, CHTTP_STR(" HTTP/1.1\r\n"))) {
        req->minor = 1;
    } else if (consume_str(s, CHTTP_STR(" HTTP/1.0\r\n")) || consume_str(s, CHTTP_STR(" HTTP/1\r\n"))) {
        req->minor = 0;
    } else {
        return -1;
    }

    int num_headers = parse_headers(s, req->headers, CHTTP_MAX_HEADERS);
    if (num_headers < 0)
        return num_headers;
    req->num_headers = num_headers;

    // Request methods that typically don't have a body
    bool body_expected = true;
    if (req->method == CHTTP_METHOD_GET ||
        req->method == CHTTP_METHOD_HEAD ||
        req->method == CHTTP_METHOD_DELETE ||
        req->method == CHTTP_METHOD_OPTIONS ||
        req->method == CHTTP_METHOD_TRACE)
        body_expected = false;

    return parse_body(s, req->headers, req->num_headers, &req->body, body_expected);
}

int chttp_find_header(CHTTP_Header *headers, int num_headers, CHTTP_String name)
{
	for (int i = 0; i < num_headers; i++)
		if (chttp_streqcase(name, headers[i].name))
			return i;
	return -1;
}

static int parse_response(Scanner *s, CHTTP_Response *res)
{
	if (!contains_head(s->src + s->cur, s->len - s->cur))
		return 0;

    if (consume_str(s, CHTTP_STR("HTTP/1.1 "))) {
        res->minor = 1;
    } else if (consume_str(s, CHTTP_STR("HTTP/1.0 ")) || consume_str(s, CHTTP_STR("HTTP/1 "))) {
        res->minor = 0;
    } else {
        return -1;
    }

    if (s->len - s->cur < 4
        || !is_digit(s->src[s->cur+0])
        || !is_digit(s->src[s->cur+1])
        || !is_digit(s->src[s->cur+2])
        || s->src[s->cur+3] != ' ')
        return -1;
    res->status =
        (s->src[s->cur+0] - '0') * 100 +
        (s->src[s->cur+1] - '0') * 10 +
        (s->src[s->cur+2] - '0') * 1;
    s->cur += 4;

    // Parse reason phrase: HTAB / SP / VCHAR / obs-text
    // Note: obs-text (obsolete text, octets 0x80-0xFF) is not validated
    while (s->cur < s->len && (
        s->src[s->cur] == '\t' ||
        s->src[s->cur] == ' ' ||
        is_vchar(s->src[s->cur])))
        s->cur++;

    if (s->len - s->cur < 2
        || s->src[s->cur+0] != '\r'
        || s->src[s->cur+1] != '\n')
        return -1;
    s->cur += 2;

    int num_headers = parse_headers(s, res->headers, CHTTP_MAX_HEADERS);
    if (num_headers < 0)
        return num_headers;
    res->num_headers = num_headers;

    // Responses with certain status codes don't have a body:
    // - 1xx (Informational)
    // - 204 (No Content)
    // - 304 (Not Modified)
    // Note: HEAD responses also don't have a body, but we can't determine
    // that here without access to the request method
    bool body_expected = true;
    if ((res->status >= 100 && res->status < 200) ||
        res->status == 204 ||
        res->status == 304)
        body_expected = false;

    return parse_body(s, res->headers, res->num_headers, &res->body, body_expected);
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

int chttp_parse_url(char *src, int len, CHTTP_URL *url)
{
    Scanner s = {src, len, 0};
    int ret = parse_uri(&s, url, 1);
    if (ret == 1)
        return s.cur;
    return ret;
}

int chttp_parse_request(char *src, int len, CHTTP_Request *req)
{
    Scanner s = {src, len, 0};
    int ret = parse_request(&s, req);
    if (ret == 1)
        return s.cur;
    return ret;
}

int chttp_parse_response(char *src, int len, CHTTP_Response *res)
{
    Scanner s = {src, len, 0};
    int ret = parse_response(&s, res);
    if (ret == 1)
        return s.cur;
    return ret;
}

CHTTP_String chttp_get_cookie(CHTTP_Request *req, CHTTP_String name)
{
    // Simple cookie parsing - does not handle quoted values or special characters
    // See RFC 6265 for full cookie specification

    for (int i = 0; i < req->num_headers; i++) {

        if (!chttp_streqcase(req->headers[i].name, CHTTP_STR("Cookie")))
            continue;

        char *src = req->headers[i].value.ptr;
        int   len = req->headers[i].value.len;
        int   cur = 0;

        // Cookie: name1=value1; name2=value2; name3=value3

        for (;;) {

            while (cur < len && src[cur] == ' ')
                cur++;

            int off = cur;
            while (cur < len && src[cur] != '=')
                cur++;

            CHTTP_String cookie_name = { src + off, cur - off };

            if (cur == len)
                break;
            cur++;

            off = cur;
            while (cur < len && src[cur] != ';')
                cur++;

            CHTTP_String cookie_value = { src + off, cur - off };

            if (chttp_streq(name, cookie_name))
                return cookie_value;

            if (cur == len)
                break;
            cur++;
        }
    }

    return CHTTP_STR("");
}

CHTTP_String chttp_get_param(CHTTP_String body, CHTTP_String str, char *mem, int cap)
{
    // This is just a best-effort implementation

    char *src = body.ptr;
    int   len = body.len;
    int   cur = 0;

    if (cur < len && src[cur] == '?')
        cur++;

    while (cur < len) {

        CHTTP_String name;
        {
            int off = cur;
            while (cur < len && src[cur] != '=' && src[cur] != '&')
                cur++;
            name = (CHTTP_String) { src + off, cur - off };
        }

        CHTTP_String body = CHTTP_STR("");
        if (cur < len) {
            cur++;
            if (src[cur-1] == '=') {
                int off = cur;
                while (cur < len && src[cur] != '&')
                    cur++;
                body = (CHTTP_String) { src + off, cur - off };

                if (cur < len)
                    cur++;
            }
        }

        if (chttp_streq(str, name)) {

            bool percent_encoded = false;
            for (int i = 0; i < body.len; i++)
                if (body.ptr[i] == '+' || body.ptr[i] == '%') {
                    percent_encoded = true;
                    break;
                }

            if (!percent_encoded)
                return body;

            if (body.len > cap)
                return (CHTTP_String) { NULL, 0 };

            CHTTP_String decoded = { mem, 0 };
            for (int i = 0; i < body.len; i++) {

                char c = body.ptr[i];
                if (c == '+')
                    c = ' ';
                else {
                    if (body.ptr[i] == '%') {
                        if (body.len - i < 3
                            || !is_hex_digit(body.ptr[i+1])
                            || !is_hex_digit(body.ptr[i+2]))
                            return (CHTTP_String) { NULL, 0 };

                        int h = hex_digit_to_int(body.ptr[i+1]);
                        int l = hex_digit_to_int(body.ptr[i+2]);
                        c = (h << 4) | l;

                        i += 2;
                    }
                }

                decoded.ptr[decoded.len++] = c;
            }

            return decoded;
        }
    }

    return CHTTP_STR("");
}

int chttp_get_param_i(CHTTP_String body, CHTTP_String str)
{
    char buf[128];
    CHTTP_String out = chttp_get_param(body, str, buf, (int) sizeof(buf));
    if (out.len == 0 || !is_digit(out.ptr[0]))
        return -1;

    int cur = 0;
    int res = 0;
    do {
        int d = out.ptr[cur++] - '0';
        if (res > (INT_MAX - d) / 10)
            return -1;
        res = res * 10 + d;
    } while (cur < out.len && is_digit(out.ptr[cur]));

    return res;
}

bool chttp_match_host(CHTTP_Request *req, CHTTP_String domain, int port)
{
    int idx = chttp_find_header(req->headers, req->num_headers, CHTTP_STR("Host"));
    assert(idx != -1); // Requests without the host header are always rejected

    char tmp[1<<8];
    if (port > -1 && port != 80) {
        int ret = snprintf(tmp, sizeof(tmp), "%.*s:%d", domain.len, domain.ptr, port);
        assert(ret > 0);
        domain = (CHTTP_String) { tmp, ret };
    }

    CHTTP_String host = req->headers[idx].value;
    return chttp_streqcase(host, domain);
}


// <day-name>, <day> <month> <year> <hour>:<minute>:<second> GMT
static int parse_date(Scanner *s, CHTTP_Date *out)
{
    struct { CHTTP_String str; CHTTP_WeekDay val; } week_day_table[] = {
        { CHTTP_STR("Mon, "), CHTTP_WEEKDAY_MON },
        { CHTTP_STR("Tue, "), CHTTP_WEEKDAY_TUE },
        { CHTTP_STR("Wed, "), CHTTP_WEEKDAY_WED },
        { CHTTP_STR("Thu, "), CHTTP_WEEKDAY_THU },
        { CHTTP_STR("Fri, "), CHTTP_WEEKDAY_FRI },
        { CHTTP_STR("Sat, "), CHTTP_WEEKDAY_SAT },
        { CHTTP_STR("Sun, "), CHTTP_WEEKDAY_SUN },
    };

    bool found = false;
    for (int i = 0; i < CHTTP_COUNT(week_day_table); i++)
        if (consume_str(s, week_day_table[i].str)) {
            out->week_day = week_day_table[i].val;
            found = true;
            break;
        }
    if (!found)
        return -1;

    if (1 >= s->len - s->cur
        || !is_digit(s->src[s->cur+0])
        || !is_digit(s->src[s->cur+1]))
        return -1;
    out->day
        = (s->src[s->cur+0] - '0') * 10
        + (s->src[s->cur+1] - '0') * 1;
    s->cur += 2;

    struct { CHTTP_String str; CHTTP_Month val; } month_table[] = {
        { CHTTP_STR(" Jan "), CHTTP_MONTH_JAN },
        { CHTTP_STR(" Feb "), CHTTP_MONTH_FEB },
        { CHTTP_STR(" Mar "), CHTTP_MONTH_MAR },
        { CHTTP_STR(" Apr "), CHTTP_MONTH_APR },
        { CHTTP_STR(" May "), CHTTP_MONTH_MAY },
        { CHTTP_STR(" Jun "), CHTTP_MONTH_JUN },
        { CHTTP_STR(" Jul "), CHTTP_MONTH_JUL },
        { CHTTP_STR(" Aug "), CHTTP_MONTH_AUG },
        { CHTTP_STR(" Sep "), CHTTP_MONTH_SEP },
        { CHTTP_STR(" Oct "), CHTTP_MONTH_OCT },
        { CHTTP_STR(" Nov "), CHTTP_MONTH_NOV },
        { CHTTP_STR(" Dec "), CHTTP_MONTH_DEC },
    };

    found = false;
    for (int i = 0; i < CHTTP_COUNT(month_table); i++)
        if (consume_str(s, month_table[i].str)) {
            out->month = month_table[i].val;
            found = true;
            break;
        }
    if (!found)
        return -1;

    if (3 >= s->len - s->cur
        || !is_digit(s->src[s->cur+0])
        || !is_digit(s->src[s->cur+1])
        || !is_digit(s->src[s->cur+2])
        || !is_digit(s->src[s->cur+3]))
        return -1;
    out->year
        = (s->src[s->cur+0] - '0') * 1000
        + (s->src[s->cur+1] - '0') * 100
        + (s->src[s->cur+2] - '0') * 10
        + (s->src[s->cur+3] - '0') * 1;
    s->cur += 4;

    if (s->cur == s->len || s->src[s->cur] != ' ')
        return -1;
    s->cur++;

    if (7 >= s->len - s->cur
        || !is_digit(s->src[s->cur+0])
        || !is_digit(s->src[s->cur+1])
        || s->src[s->cur+2] != ':'
        || !is_digit(s->src[s->cur+3])
        || !is_digit(s->src[s->cur+4])
        || s->src[s->cur+5] != ':'
        || !is_digit(s->src[s->cur+6])
        || !is_digit(s->src[s->cur+7])
        || s->src[s->cur+8] != ' '
        || s->src[s->cur+9] != 'G'
        || s->src[s->cur+10] != 'M'
        || s->src[s->cur+11] != 'T')
        return -1;
    out->hour
        = (s->src[s->cur+0] - '0') * 10
        + (s->src[s->cur+1] - '0') * 1;
    out->minute
        = (s->src[s->cur+3] - '0') * 10
        + (s->src[s->cur+4] - '0') * 1;
    out->second
        = (s->src[s->cur+6] - '0') * 10
        + (s->src[s->cur+7] - '0') * 1;
    s->cur += 12;
    return 0;
}

// cookie-octet = %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E
//              ; US-ASCII characters excluding CTLs,
//              ; whitespace, DQUOTE, comma, semicolon,
//              ; and backslash
static bool is_cookie_octet(char c)
{
    return c == 0x21 ||
           (c >= 0x23 && c <= 0x2B) ||
           (c >= 0x2D && c <= 0x3A) ||
           (c >= 0x3C && c <= 0x5B) ||
           (c >= 0x5D && c <= 0x7E);
}

int chttp_parse_set_cookie(CHTTP_String str, CHTTP_SetCookie *out)
{
    Scanner s = { str.ptr, str.len, 0 };

    // cookie-name = token
    if (s.cur == s.len || !is_tchar(s.src[s.cur]))
        return -1;
    int off = s.cur;
    do
        s.cur++;
    while (s.cur < s.len && is_tchar(s.src[s.cur]));
    out->name = (CHTTP_String) { s.src + off, s.cur - off };

    // cookie-pair = cookie-name "=" cookie-value
    if (s.cur == s.len || s.src[s.cur] != '=')
        return -1;
    s.cur++;

    // cookie-value = *cookie-octet / ( DQUOTE *cookie-octet DQUOTE )
    if (s.cur < s.len && s.src[s.cur] == '"') {
        s.cur++; // Consume opening double quote
        int off = s.cur;
        while (s.cur < s.len && is_cookie_octet(s.src[s.cur]))
            s.cur++;
        if (s.cur == s.len || s.src[s.cur] != '"')
            return -1; // Missing closing double quote
        out->value = (CHTTP_String) { s.src + off, s.cur - off };
        s.cur++; // Consume closing double quote
    } else {
        int off = s.cur;
        while (s.cur < s.len && is_cookie_octet(s.src[s.cur]))
            s.cur++;
        out->value = (CHTTP_String) { s.src + off, s.cur - off };
    }

    // *( ";" SP cookie-av )
    //
    // cookie-av = expires-av / max-age-av / domain-av /
    //             path-av / secure-av / httponly-av /
    //             extension-av
    out->secure = false;
    out->chttp_only = false;
    out->have_date = false;
    out->have_max_age = false;
    out->have_domain = false;
    out->have_path = false;
    while (consume_str(&s, CHTTP_STR("; "))) {
        if (consume_str(&s, CHTTP_STR("Expires="))) {

            // expires-av = "Expires=" sane-cookie-date
            if (parse_date(&s, &out->date) < 0)
                return -1;
            out->have_date = true;

        } else if (consume_str(&s, CHTTP_STR("Max-Age="))) {

            // max-age-av = "Max-Age=" non-zero-digit *DIGIT

            uint32_t value = 0;
            if (s.cur == s.len || !is_digit(s.src[s.cur]))
                return -1;
            do {
                int d = s.src[s.cur++] - '0';
                if (value > (UINT32_MAX - d) / 10)
                    return -1;
                value = value * 10 + d;
            } while (s.cur < s.len && is_digit(s.src[s.cur]));

            out->have_max_age = true;
            out->max_age = value;

        } else if (consume_str(&s, CHTTP_STR("Domain="))) {

            // domain-av = "Domain=" domain-value
            // domain-value = <subdomain>
            //              ; defined in RFC 1034, Section 3.5
            //
            // From RFC 1034:
            //   <subdomain> ::= <label> | <subdomain> "." <label>
            //   <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ]
            //   <ldh-str> ::= <let-dig-hyp> | <let-dig-hyp> <ldh-str>
            //   <let-dig-hyp> ::= <let-dig> | "-"
            //   <let-dig> ::= <letter> | <digit>
            //   <letter> ::= any one of the 52 alphabetic characters A through Z in upper case and a through z in lower case
            //   <digit> ::= any one of the ten digits 0 through 9
            //
            // If my understanding is correct, a domain is a list of labels
            // concatenated by dots. Each label may contain letters, digits,
            // hyphens, but the first character must be a letter and the last
            // one can't be a hyphen.

            int off = s.cur;
            if (s.cur == s.len || !is_alpha(s.src[s.cur]))
                return -1;
            do
                s.cur++;
            while (s.cur < s.len && (
                is_digit(s.src[s.cur]) ||
                is_alpha(s.src[s.cur]) ||
                s.src[s.cur] == '-'));

            if (s.src[s.cur-1] == '-')
                return -1;

            while (s.cur < s.len && s.src[s.cur] == '.') {
                s.cur++; // Consume dot

                if (s.cur == s.len || !is_alpha(s.src[s.cur]))
                    return -1;
                do
                    s.cur++;
                while (s.cur < s.len && (
                    is_digit(s.src[s.cur]) ||
                    is_alpha(s.src[s.cur]) ||
                    s.src[s.cur] == '-'));

                if (s.src[s.cur-1] == '-')
                    return -1;
            }

            out->have_domain = true;
            out->domain = (CHTTP_String) { s.src + off, s.cur - off };

        } else if (consume_str(&s, CHTTP_STR("Path="))) {

            // path-av = "Path=" path-value
            // path-value = <any CHAR except CTLs or ";">

            int off = s.cur;
            while (s.cur < s.len && s.src[s.cur] >= 0x20 && s.src[s.cur] != 0x7F && s.src[s.cur] != ';')
                s.cur++;

            out->have_path = true;
            out->path = (CHTTP_String) { s.src + off, s.cur - off };

        } else if (consume_str(&s, CHTTP_STR("Secure"))) {

            // secure-av = "Secure"
            out->secure = true;

        } else if (consume_str(&s, CHTTP_STR("HttpOnly"))) {

            // httponly-av = "HttpOnly"
            out->chttp_only = true;

        } else {
            return -1; // Invalid attribute
        }
    }

    return 0;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/time.c
////////////////////////////////////////////////////////////////////////////////////////

Time get_current_time(void)
{
#ifdef _WIN32
    {
        int64_t count;
        int64_t freq;
        int ok;

        ok = QueryPerformanceCounter((LARGE_INTEGER*) &count);
        if (!ok) return INVALID_TIME;

        ok = QueryPerformanceFrequency((LARGE_INTEGER*) &freq);
        if (!ok) return INVALID_TIME;

        uint64_t res = 1000 * (double) count / freq;
        return res;
    }
#else
    {
        struct timespec time;

        if (clock_gettime(CLOCK_REALTIME, &time))
            return INVALID_TIME;

        uint64_t res;

        uint64_t sec = time.tv_sec;
        if (sec > UINT64_MAX / 1000)
            return INVALID_TIME;
        res = sec * 1000;

        uint64_t nsec = time.tv_nsec;
        if (res > UINT64_MAX - nsec / 1000000)
            return INVALID_TIME;
        res += nsec / 1000000;

        return res;
    }
#endif
}

////////////////////////////////////////////////////////////////////////////////////////
// src/secure_context.c
////////////////////////////////////////////////////////////////////////////////////////

int global_secure_context_init(void)
{
#ifdef HTTPS_ENABLED
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
#endif
    return 0;
}

int global_secure_context_free(void)
{
#ifdef HTTPS_ENABLED
    EVP_cleanup();
#endif
    return 0;
}

int client_secure_context_init(ClientSecureContext *ctx)
{
#ifdef HTTPS_ENABLED
    SSL_CTX *p = SSL_CTX_new(TLS_client_method());
    if (!p)
        return -1;

    SSL_CTX_set_min_proto_version(p, TLS1_2_VERSION);

    SSL_CTX_set_verify(p, SSL_VERIFY_PEER, NULL);

    if (SSL_CTX_set_default_verify_paths(p) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    ctx->p = p;
    return 0;
#else
    (void) ctx;
    return -1;
#endif
}

void client_secure_context_free(ClientSecureContext *ctx)
{
#ifdef HTTPS_ENABLED
    SSL_CTX_free(ctx->p);
#else
    (void) ctx;
#endif
}

#ifdef HTTPS_ENABLED
static int servername_callback(SSL *ssl, int *ad, void *arg)
{
    ServerSecureContext *ctx = arg;

    // The 'ad' parameter is used to set the alert description when returning
    // SSL_TLSEXT_ERR_ALERT_FATAL. Since we only return OK or NOACK, it's unused.
    (void) ad;

    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername == NULL)
        return SSL_TLSEXT_ERR_NOACK;

    for (int i = 0; i < ctx->num_certs; i++) {
        ServerCertificate *cert = &ctx->certs[i];
        if (!strcmp(cert->domain, servername)) {
            SSL_set_SSL_CTX(ssl, cert->ctx);
            return SSL_TLSEXT_ERR_OK;
        }
    }

    return SSL_TLSEXT_ERR_NOACK;
}
#endif

int server_secure_context_init(ServerSecureContext *ctx,
    CHTTP_String cert_file, CHTTP_String key_file)
{
#ifdef HTTPS_ENABLED
    SSL_CTX *p = SSL_CTX_new(TLS_server_method());
    if (!p)
        return -1;

    SSL_CTX_set_min_proto_version(p, TLS1_2_VERSION);

    char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';

    // Copy private key file path to static buffer
    char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';

    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(p, cert_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(p, key_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    // Verify that the private key matches the certificate
    if (SSL_CTX_check_private_key(p) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    SSL_CTX_set_tlsext_servername_callback(p, servername_callback);
    SSL_CTX_set_tlsext_servername_arg(p, ctx);

    ctx->p = p;
    ctx->num_certs = 0;
    return 0;
#else
    (void) ctx;
    (void) cert_file;
    (void) key_file;
    return -1;
#endif
}

void server_secure_context_free(ServerSecureContext *ctx)
{
#ifdef HTTPS_ENABLED
    SSL_CTX_free(ctx->p);
    for (int i = 0; i < ctx->num_certs; i++)
        SSL_CTX_free(ctx->certs[i].ctx);
#else
    (void) ctx;
#endif
}

int server_secure_context_add_certificate(ServerSecureContext *ctx,
    CHTTP_String domain, CHTTP_String cert_file, CHTTP_String key_file)
{
#ifdef HTTPS_ENABLED
    if (ctx->num_certs == SERVER_CERTIFICATE_LIMIT)
        return -1;

    SSL_CTX *p = SSL_CTX_new(TLS_server_method());
    if (!p)
        return -1;

    SSL_CTX_set_min_proto_version(p, TLS1_2_VERSION);

    char cert_buffer[1024];
    if (cert_file.len >= (int) sizeof(cert_buffer)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(cert_buffer, cert_file.ptr, cert_file.len);
    cert_buffer[cert_file.len] = '\0';

    char key_buffer[1024];
    if (key_file.len >= (int) sizeof(key_buffer)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(key_buffer, key_file.ptr, key_file.len);
    key_buffer[key_file.len] = '\0';

    if (SSL_CTX_use_certificate_file(p, cert_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    if (SSL_CTX_use_PrivateKey_file(p, key_buffer, SSL_FILETYPE_PEM) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    if (SSL_CTX_check_private_key(p) != 1) {
        SSL_CTX_free(p);
        return -1;
    }

    ServerCertificate *cert = &ctx->certs[ctx->num_certs];
    if (domain.len >= (int) sizeof(cert->domain)) {
        SSL_CTX_free(p);
        return -1;
    }
    memcpy(cert->domain, domain.ptr, domain.len);
    cert->domain[domain.len] = '\0';
    cert->ctx = p;
    ctx->num_certs++;
    return 0;
#else
    (void) ctx;
    (void) domain;
    (void) cert_file;
    (void) key_file;
    return -1;
#endif
}

////////////////////////////////////////////////////////////////////////////////////////
// src/socket.c
////////////////////////////////////////////////////////////////////////////////////////

//#define TRACE_STATE_CHANGES

#ifndef TRACE_STATE_CHANGES
#define UPDATE_STATE(a, b) a = b
#else
static char *state_to_str(SocketState state)
{
    switch (state) {
    case SOCKET_STATE_FREE      : return "FREE";
    case SOCKET_STATE_PENDING   : return "PENDING";
    case SOCKET_STATE_CONNECTING: return "CONNECTING";
    case SOCKET_STATE_CONNECTED : return "CONNECTED";
    case SOCKET_STATE_ACCEPTED  : return "ACCEPTED";
    case SOCKET_STATE_ESTABLISHED_WAIT : return "ESTABLISHED_WAIT";
    case SOCKET_STATE_ESTABLISHED_READY: return "ESTABLISHED_READY";
    case SOCKET_STATE_SHUTDOWN  : return "SHUTDOWN";
    case SOCKET_STATE_DIED      : return "DIED";
    }
    return "???";
}
#define UPDATE_STATE(a, b) {    \
    printf("%s -> %s  %s:%d\n", \
        state_to_str(a),        \
        state_to_str(b),        \
        __FILE__, __LINE__);    \
    a = b;                      \
}
#endif

static int create_socket_pair(NATIVE_SOCKET *a, NATIVE_SOCKET *b, bool *global_cleanup)
{
#ifdef _WIN32
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    *global_cleanup = false;
    if (sock == INVALID_SOCKET && WSAGetLastError() == WSANOTINITIALISED) {

        WSADATA wsaData;
        WORD wVersionRequested = MAKEWORD(2, 2);
        if (WSAStartup(wVersionRequested, &wsaData))
            return CHTTP_ERROR_UNSPECIFIED;

        sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (sock == INVALID_SOCKET && *global_cleanup)
            WSACleanup();
    }

    if (sock == INVALID_SOCKET) {
        if (*global_cleanup)
            WSACleanup();
        return CHTTP_ERROR_UNSPECIFIED;
    }

    // Bind to loopback address with port 0 (dynamic port assignment)
    struct sockaddr_in addr;
    int addr_len = sizeof(addr);
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); // 127.0.0.1
    addr.sin_port = 0; // Let system choose port

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        if (*global_cleanup)
            WSACleanup();
        return CHTTP_ERROR_UNSPECIFIED;
    }

    if (getsockname(sock, (struct sockaddr*)&addr, &addr_len) == SOCKET_ERROR) {
        closesocket(sock);
        if (*global_cleanup)
            WSACleanup();
        return CHTTP_ERROR_UNSPECIFIED;
    }

    if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        if (*global_cleanup)
            WSACleanup();
        return CHTTP_ERROR_UNSPECIFIED;
    }

    // Optional: Set socket to non-blocking mode
    // This prevents send() from blocking if the receive buffer is full
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR) {
        closesocket(sock);
        if (*global_cleanup)
            WSACleanup();
        return CHTTP_ERROR_UNSPECIFIED;
    }

    *a = sock;
    *b = sock;
    return CHTTP_OK;
#else
    *global_cleanup = false;
    int fds[2];
    if (pipe(fds) < 0)
        return CHTTP_ERROR_UNSPECIFIED;
    *a = fds[0];
    *b = fds[1];
    return CHTTP_OK;
#endif
}

static int set_socket_blocking(NATIVE_SOCKET sock, bool value)
{
#ifdef _WIN32
    u_long mode = !value;
    if (ioctlsocket(sock, FIONBIO, &mode) == SOCKET_ERROR)
        return CHTTP_ERROR_UNSPECIFIED;
    return CHTTP_OK;
#endif

#ifdef __linux__
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0)
        return CHTTP_ERROR_UNSPECIFIED;
    if (value) flags &= ~O_NONBLOCK;
    else       flags |= O_NONBLOCK;
    if (fcntl(sock, F_SETFL, flags) < 0)
        return CHTTP_ERROR_UNSPECIFIED;
    return CHTTP_OK;
#endif
}

static NATIVE_SOCKET create_listen_socket(CHTTP_String addr,
    Port port, bool reuse_addr, int backlog)
{
    NATIVE_SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock == NATIVE_SOCKET_INVALID)
        return NATIVE_SOCKET_INVALID;

    if (set_socket_blocking(sock, false) < 0) {
        CLOSE_NATIVE_SOCKET(sock);
        return NATIVE_SOCKET_INVALID;
    }

    if (reuse_addr) {
        int one = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (void*) &one, sizeof(one));
    }

    struct in_addr addr_buf;
    if (addr.len == 0)
        addr_buf.s_addr = htonl(INADDR_ANY);
    else {

        char copy[100];
        if (addr.len >= (int) sizeof(copy)) {
            CLOSE_NATIVE_SOCKET(sock);
            return NATIVE_SOCKET_INVALID;
        }
        memcpy(copy, addr.ptr, addr.len);
        copy[addr.len] = '\0';

        if (inet_pton(AF_INET, copy, &addr_buf) < 0) {
            CLOSE_NATIVE_SOCKET(sock);
            return NATIVE_SOCKET_INVALID;
        }
    }

    struct sockaddr_in bind_buf;
    bind_buf.sin_family = AF_INET;
    bind_buf.sin_addr   = addr_buf;
    bind_buf.sin_port   = htons(port);
    if (bind(sock, (struct sockaddr*) &bind_buf, sizeof(bind_buf)) < 0) {
        CLOSE_NATIVE_SOCKET(sock);
        return NATIVE_SOCKET_INVALID;
    }

    if (listen(sock, backlog) < 0) {
        CLOSE_NATIVE_SOCKET(sock);
        return NATIVE_SOCKET_INVALID;
    }

    return sock;
}

static void close_socket_pair(NATIVE_SOCKET a, NATIVE_SOCKET b)
{
#ifdef _WIN32
    closesocket(a);
    (void) b;
#else
    close(a);
    close(b);
#endif
}

int socket_manager_init(SocketManager *sm, Socket *socks,
    int num_socks)
{
    sm->creation_timeout = 60000;
    sm->recv_timeout = 3000;

    sm->plain_sock  = NATIVE_SOCKET_INVALID;
    sm->secure_sock = NATIVE_SOCKET_INVALID;

    int ret = create_socket_pair(
        &sm->wait_sock,
        &sm->signal_sock,
        &sm->global_cleanup);
    if (ret < 0) return ret;

    sm->at_least_one_secure_connect = false;

    sm->num_used = 0;
    sm->max_used = num_socks;
    sm->sockets = socks;

    for (int i = 0; i < num_socks; i++) {
        socks[i].state = SOCKET_STATE_FREE;
        socks[i].gen = 1;
    }
    return CHTTP_OK;
}

void socket_manager_free(SocketManager *sm)
{
    close_socket_pair(sm->wait_sock, sm->signal_sock);

    if (sm->secure_sock != NATIVE_SOCKET_INVALID)
        server_secure_context_free(&sm->server_secure_context);

    if (sm->at_least_one_secure_connect)
        client_secure_context_free(&sm->client_secure_context);

    if (sm->plain_sock  != NATIVE_SOCKET_INVALID)
        CLOSE_NATIVE_SOCKET(sm->plain_sock);

    if (sm->secure_sock != NATIVE_SOCKET_INVALID)
        CLOSE_NATIVE_SOCKET(sm->secure_sock);

#ifdef _WIN32
    if (sm->global_cleanup)
        WSACleanup();
#endif
}

void socket_manager_set_creation_timeout(SocketManager *sm, int timeout)
{
    sm->creation_timeout = (timeout < 0) ? INVALID_TIME : (Time) timeout;
}

void socket_manager_set_recv_timeout(SocketManager *sm, int timeout)
{
    sm->recv_timeout = (timeout < 0) ? INVALID_TIME : (Time) timeout;
}

int socket_manager_listen_tcp(SocketManager *sm,
    CHTTP_String addr, Port port, int backlog,
    bool reuse_addr)
{
    if (sm->plain_sock != NATIVE_SOCKET_INVALID)
        return CHTTP_ERROR_UNSPECIFIED;

    sm->plain_sock = create_listen_socket(addr, port, reuse_addr, backlog);
    if (sm->plain_sock == NATIVE_SOCKET_INVALID)
        return CHTTP_ERROR_UNSPECIFIED;

    return CHTTP_OK;
}

int socket_manager_listen_tls(SocketManager *sm,
    CHTTP_String addr, Port port, int backlog,
    bool reuse_addr, CHTTP_String cert_file,
    CHTTP_String key_file)
{
#ifndef HTTPS_ENABLED
    return CHTTP_ERROR_NOTLS;
#endif

    if (sm->secure_sock != NATIVE_SOCKET_INVALID)
        return CHTTP_ERROR_UNSPECIFIED;

    sm->secure_sock = create_listen_socket(addr, port, reuse_addr, backlog);
    if (sm->secure_sock == NATIVE_SOCKET_INVALID)
        return CHTTP_ERROR_UNSPECIFIED;

    if (server_secure_context_init(&sm->server_secure_context,
        cert_file, key_file) < 0) {
        CLOSE_NATIVE_SOCKET(sm->secure_sock);
        sm->secure_sock = NATIVE_SOCKET_INVALID;
        return CHTTP_ERROR_UNSPECIFIED;
    }

    return CHTTP_OK;
}

int socket_manager_add_certificate(SocketManager *sm,
    CHTTP_String domain, CHTTP_String cert_file, CHTTP_String key_file)
{
    if (sm->secure_sock == NATIVE_SOCKET_INVALID)
        return CHTTP_ERROR_UNSPECIFIED;

    int ret = server_secure_context_add_certificate(
        &sm->server_secure_context, domain, cert_file, key_file);
    if (ret < 0)
        return ret;

    return CHTTP_OK;
}

static bool is_secure(Socket *s)
{
#ifdef HTTPS_ENABLED
    return s->server_secure_context != NULL
        || s->client_secure_context != NULL;
#else
    (void) s;
    return false;
#endif
}

static bool connect_pending(void)
{
#ifdef _WIN32
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

static bool
connect_failed_because_of_peer_2(int err)
{
#ifdef _WIN32
    return err == WSAECONNREFUSED
        || err == WSAETIMEDOUT
        || err == WSAENETUNREACH
        || err == WSAEHOSTUNREACH;
#else
    return err == ECONNREFUSED
        || err == ETIMEDOUT
        || err == ENETUNREACH
        || err == EHOSTUNREACH;
#endif
}

static bool
connect_failed_because_of_peer(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
#else
    int err = errno;
#endif
    return connect_failed_because_of_peer_2(err);
}

static void free_addr_list(AddressAndPort *addrs, int num_addr)
{
#ifdef HTTPS_ENABLED
    for (int i = 0; i < num_addr; i++) {
        RegisteredName *name = addrs[i].name;
        if (name) {
            assert(name->refs > 0);
            name->refs--;
            if (name->refs == 0)
                free(name);
        }
    }
#else
    (void) addrs;
    (void) num_addr;
#endif
}

// This function moves the socket state machine
// to the next state until an I/O event would
// be required to continue.
static void socket_update(Socket *s)
{
    // Each case of this switch encodes a state transition.
    // If the evaluated case requires a given I/O event to
    // continue, the loop will exit so that the caller can
    // wait for that event. If the case can continue to a
    // different case, the again flag is set, which causes
    // a different case to be evaluated.
    bool again;
    do {
        again = false;
        switch (s->state) {
        case SOCKET_STATE_PENDING:
            {
                // This point may be reached because
                //   1. The socket was just created by a connect
                //      operation.
                //   2. Connecting to a host failed and now we
                //      need to try the next one.
                // If (2) is true, we have some resources
                // to clean up.

                if (s->sock != NATIVE_SOCKET_INVALID) {
                    // This is not the first attempt

#ifdef HTTPS_ENABLED
                    if (s->ssl) {
                        SSL_free(s->ssl);
                        s->ssl = NULL;
                    }
#endif

                    CLOSE_NATIVE_SOCKET(s->sock);

                    s->next_addr++;
                    if (s->next_addr == s->num_addr) {
                        // All addresses have been tried and failed
                        UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                        s->events = 0;
                        continue;
                    }
                }

                AddressAndPort addr;
                if (s->num_addr == 1)
                    addr = s->addr;
                else
                    addr = s->addrs[s->next_addr];

                int family = (addr.is_ipv4 ? AF_INET : AF_INET6);
                NATIVE_SOCKET sock = socket(family, SOCK_STREAM, 0);
                if (sock == NATIVE_SOCKET_INVALID) {
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                    continue;
                }

                if (set_socket_blocking(sock, false) < 0) {
                    CLOSE_NATIVE_SOCKET(sock);
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                    continue;
                }

                int ret;
                if (addr.is_ipv4) {
                    struct sockaddr_in buf;
                    buf.sin_family = AF_INET;
                    buf.sin_port = htons(addr.port);
                    memcpy(&buf.sin_addr, &addr.ipv4, sizeof(CHTTP_IPv4));
                    ret = connect(sock, (struct sockaddr*) &buf, sizeof(buf));
                } else {
                    struct sockaddr_in6 buf;
                    buf.sin6_family = AF_INET6;
                    buf.sin6_port = htons(addr.port);
                    memcpy(&buf.sin6_addr, &addr.ipv6, sizeof(CHTTP_IPv6));
                    ret = connect(sock, (struct sockaddr*) &buf, sizeof(buf));
                }

                if (ret == 0) {
                    // Connect resolved immediately
                    s->sock = sock;
                    UPDATE_STATE(s->state, SOCKET_STATE_CONNECTED);
                    s->events = 0;
                    again = true;
                } else if (connect_pending()) {
                    // Connect is pending, which is expected
                    s->sock = sock;
                    UPDATE_STATE(s->state, SOCKET_STATE_CONNECTING);
                    s->events = POLLOUT;
                } else if (connect_failed_because_of_peer()) {
                    // Conenct failed due to the peer host
                    // We should try a different address.
                    s->sock = sock;
                    UPDATE_STATE(s->state, SOCKET_STATE_PENDING);
                    s->events = 0;
                    again = true;
                } else {
                    // An error occurred that we can't recover from
                    s->sock = sock;
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                    again = true;
                }
            }
            break;

        case SOCKET_STATE_CONNECTING:
            {
                // This point is reached when a connect()
                // operation completes.

                int err = 0;
                socklen_t len = sizeof(err);
                if (getsockopt(s->sock, SOL_SOCKET, SO_ERROR, (void*) &err, &len) < 0) {
                    // Failed to get socket error status
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                    continue;
                }

                if (err == 0) {
                    // Connection succeded
                    UPDATE_STATE(s->state, SOCKET_STATE_CONNECTED);
                    s->events = 0;
                    again = true;
                } else if (connect_failed_because_of_peer_2(err)) {
                    // Try the next address
                    UPDATE_STATE(s->state, SOCKET_STATE_PENDING);
                    s->events = 0;
                    again = true;
                } else {
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                }
            }
            break;

        case SOCKET_STATE_CONNECTED:
            {
                if (!is_secure(s)) {

                    // We managed to connect to the peer.
                    // We can free the target array if it
                    // was allocated dynamically.
                    if (s->num_addr > 1)
                        free(s->addrs);

                    s->events = 0;
                    UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
                } else {
#ifdef HTTPS_ENABLED
                    if (s->ssl == NULL) {
                        s->ssl = SSL_new(s->client_secure_context->p);
                        if (s->ssl == NULL) {
                            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                            s->events = 0;
                            break;
                        }

                        if (SSL_set_fd(s->ssl, s->sock) != 1) {
                            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                            s->events = 0;
                            break;
                        }

                        SSL_set_verify(s->ssl, s->dont_verify_cert
                            ? SSL_VERIFY_NONE : SSL_VERIFY_PEER, NULL);

                        AddressAndPort addr;
                        if (s->num_addr > 1)
                            addr = s->addrs[s->next_addr];
                        else
                            addr = s->addr;

                        if (addr.name) {

                            // Set expected hostname for verification
                            if (SSL_set1_host(s->ssl, addr.name->data) != 1) {
                                UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                                s->events = 0;
                                break;
                            }

                            // Optional but recommended: be strict about wildcards
                            SSL_set_hostflags(s->ssl,
                                X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);

                            // Also set for SNI (Server Name Indication)
                            SSL_set_tlsext_host_name(s->ssl, addr.name->data);
                        }
                    }

                    int ret = SSL_connect(s->ssl);
                    if (ret == 1) {
                        // Handshake done

                        // We managed to connect to the peer.
                        // We can free the target array if it
                        // was allocated dynamically.
                        if (s->num_addr == 1)
                            free_addr_list(&s->addr, 1);
                        else {
                            assert(s->num_addr > 1);
                            free_addr_list(s->addrs, s->num_addr);
                            free(s->addrs);
                        }

                        UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
                        s->events = 0;
                        break;
                    }

                    int err = SSL_get_error(s->ssl, ret);
                    if (err == SSL_ERROR_WANT_READ) {
                        s->events = POLLIN;
                        break;
                    }

                    if (err == SSL_ERROR_WANT_WRITE) {
                        s->events = POLLOUT;
                        break;
                    }

                    UPDATE_STATE(s->state, SOCKET_STATE_PENDING);
                    s->events = 0;
                    again = true;
#endif
                }
            }
            break;

        case SOCKET_STATE_ACCEPTED:
            {
                if (!is_secure(s)) {
                    UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
                    s->events = 0;
                } else {
#ifdef HTTPS_ENABLED
                    // Start server-side SSL handshake
                    if (!s->ssl) {

                        s->ssl = SSL_new(s->server_secure_context->p);
                        if (s->ssl == NULL) {
                            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                            s->events = 0;
                            break;
                        }

                        if (SSL_set_fd(s->ssl, s->sock) != 1) {
                            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                            s->events = 0;
                            break;
                        }
                    }

                    int ret = SSL_accept(s->ssl);
                    if (ret == 1) {
                        // Handshake done
                        UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
                        s->events = 0;
                        break;
                    }

                    int err = SSL_get_error(s->ssl, ret);
                    if (err == SSL_ERROR_WANT_READ) {
                        s->events = POLLIN;
                        break;
                    }

                    if (err == SSL_ERROR_WANT_WRITE) {
                        s->events = POLLOUT;
                        break;
                    }

                    // Server socket error - close the connection
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
#endif
                }
            }
            break;

        case SOCKET_STATE_ESTABLISHED_WAIT:
            UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_READY);
            s->events = 0;
            break;

        case SOCKET_STATE_SHUTDOWN:
            {
                if (!is_secure(s)) {
                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
                } else {
#ifdef HTTPS_ENABLED
                    int ret = SSL_shutdown(s->ssl);
                    if (ret == 1) {
                        UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                        s->events = 0;
                        break;
                    }

                    int err = SSL_get_error(s->ssl, ret);
                    if (err == SSL_ERROR_WANT_READ) {
                        s->events = POLLIN;
                        break;
                    }

                    if (err == SSL_ERROR_WANT_WRITE) {
                        s->events = POLLOUT;
                        break;
                    }

                    UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                    s->events = 0;
#endif
                }
            }
            break;

        default:
            // Do nothing
            break;
        }
    } while (again);
}

int socket_manager_wakeup(SocketManager *sm)
{
    // NOTE: It's assumed send/write operate atomically
    //       on The descriptor.
    char byte = 1;
#ifdef _WIN32
    if (send(sm->signal_sock, &byte, 1, 0) < 0)
        return CHTTP_ERROR_UNSPECIFIED;
#else
    if (write(sm->signal_sock, &byte, 1) < 0)
        return CHTTP_ERROR_UNSPECIFIED;
#endif
    return CHTTP_OK;
}

void socket_manager_register_events(
    SocketManager *sm, EventRegister *reg)
{
    reg->num_polled = 0;

    reg->polled[reg->num_polled].fd = sm->wait_sock;
    reg->polled[reg->num_polled].events = POLLIN;
    reg->polled[reg->num_polled].revents = 0;
    reg->ptrs[reg->num_polled] = NULL;
    reg->num_polled++;

    // If the manager isn't at full capacity, monitor
    // the listener sockets for incoming connections.
    if (sm->num_used < sm->max_used) {

        if (sm->plain_sock != NATIVE_SOCKET_INVALID) {
            reg->polled[reg->num_polled].fd = sm->plain_sock;
            reg->polled[reg->num_polled].events = POLLIN;
            reg->polled[reg->num_polled].revents = 0;
            reg->ptrs[reg->num_polled] = NULL;
            reg->num_polled++;
        }

        if (sm->secure_sock != NATIVE_SOCKET_INVALID) {
            reg->polled[reg->num_polled].fd = sm->secure_sock;
            reg->polled[reg->num_polled].events = POLLIN;
            reg->polled[reg->num_polled].revents = 0;
            reg->ptrs[reg->num_polled] = NULL;
            reg->num_polled++;
        }
    }

    // Iterate over each socket and register those that
    // are waiting for I/O. If at least one socket that
    // is ready to be processed exists, return an empty
    // event registration list so that those entries can
    // be processed immediately.
    // TODO: comment about deadline
    Time deadline = INVALID_TIME;
    for (int i = 0, j = 0; j < sm->num_used; i++) {
        Socket *s = &sm->sockets[i];
        if (s->state == SOCKET_STATE_FREE)
            continue;
        j++;

        if (s->silent)
            continue;

        if (s->creation_timeout != INVALID_TIME) {
            Time creation_deadline = s->creation_time + s->creation_timeout;
            if (deadline == INVALID_TIME || creation_deadline < deadline)
                deadline = creation_deadline;
        }

        if (s->recv_timeout != INVALID_TIME) {
            Time recv_deadline = s->last_recv_time + s->recv_timeout;
            if (deadline == INVALID_TIME || recv_deadline < deadline)
                deadline = recv_deadline;
        }

        // If at least one socket can be processed, return an
        // empty list.
        if (s->state == SOCKET_STATE_DIED ||
            s->state == SOCKET_STATE_ESTABLISHED_READY) {
            deadline = 0;
        }

        if (s->events) {
            reg->polled[reg->num_polled].fd = s->sock;
            reg->polled[reg->num_polled].events = s->events;
            reg->polled[reg->num_polled].revents = 0;
            reg->ptrs[reg->num_polled] = s;
            reg->num_polled++;
        }
    }

    if (deadline == INVALID_TIME) {
        reg->timeout = -1;
    } else {

        Time current_time = get_current_time();
        if (current_time == INVALID_TIME) {
            reg->timeout = 1000;
        } else if (deadline < current_time) {
            reg->timeout = 0;
        } else {
            reg->timeout = deadline - current_time;
        }
    }
}

static SocketHandle
socket_to_handle(SocketManager *sm, Socket *s)
{
    return ((uint32_t) (s - sm->sockets) << 16) | s->gen;
}

static Socket *handle_to_socket(SocketManager *sm, SocketHandle handle)
{
    uint16_t gen = handle & 0xFFFF;
    uint16_t idx = handle >> 16;
    if (idx >= sm->max_used)
        return NULL;
    if (sm->sockets[idx].gen != gen)
        return NULL;
    return &sm->sockets[idx];
}

int socket_manager_translate_events(
    SocketManager *sm, SocketEvent *events,
    EventRegister reg)
{
    Time current_time = get_current_time();

    int num_events = 0;
    for (int i = 0; i < reg.num_polled; i++) {

        if (!reg.polled[i].revents)
            continue;

        if (reg.polled[i].fd == sm->plain_sock ||
            reg.polled[i].fd == sm->secure_sock) {

            // We only listen for input events from the listener
            // if the socket pool isn't fool. This ensures that
            // at least one socket struct is available. Note that
            // it's still possible that we were at capacity MAX-1
            // and then got events from both the TCP and TCP/TLS
            // listeners, causing one to be left witout a struct.
            // This means we still need to check for full capacity.
            // Fortunately, poll() is level-triggered, which means
            // we'll handle this at the next iteration.
            if (sm->num_used == sm->max_used)
                continue;

            Socket *s = sm->sockets;
            while (s->state != SOCKET_STATE_FREE) {
                s++;
                assert(s - sm->sockets < + sm->max_used);
            }

            NATIVE_SOCKET sock = accept(reg.polled[i].fd, NULL, NULL);
            if (sock == NATIVE_SOCKET_INVALID)
                continue;

            if (set_socket_blocking(sock, false) < 0) {
                CLOSE_NATIVE_SOCKET(sock);
                continue;
            }

            s->state  = SOCKET_STATE_ACCEPTED;
            s->sock   = sock;
            s->events = 0;
            s->user   = NULL;
            s->silent = false;
            s->creation_time = current_time;
            s->last_recv_time = current_time;
            s->creation_timeout = sm->creation_timeout;
            s->recv_timeout = sm->recv_timeout;
#ifdef HTTPS_ENABLED
            // Determine whether the event came from
            // the encrypted listener or not.
            bool secure = (reg.polled[i].fd == sm->secure_sock);

            s->ssl = NULL;
            s->server_secure_context = NULL;
            s->client_secure_context = NULL;
            if (secure)
                s->server_secure_context = &sm->server_secure_context;
#endif

            socket_update(s);
            if (s->state == SOCKET_STATE_DIED) {
                CLOSE_NATIVE_SOCKET(sock);
                UPDATE_STATE(s->state, SOCKET_STATE_FREE);
                s->gen++;
                if (s->gen == 0)
                    s->gen = 1;
                continue;
            }

            sm->num_used++;

        } else if (reg.polled[i].fd == sm->wait_sock) {

            // Consume one byte from the wakeup signal
            char byte;
#ifdef _WIN32
            recv(sm->wait_sock, &byte, 1, 0);
#else
            read(sm->wait_sock, &byte, 1);
#endif

        } else {

            Socket *s = reg.ptrs[i];
            assert(!s->silent);

            socket_update(s);
        }
    }

    for (int i = 0, j = 0; j < sm->num_used; i++) {
        Socket *s = &sm->sockets[i];
        if (s->state == SOCKET_STATE_FREE)
            continue;
        j++;

        if (s->silent)
            continue;

        if (s->creation_timeout != INVALID_TIME
            && current_time != INVALID_TIME
            && current_time > s->creation_time + s->creation_timeout) {

            s->creation_time = INVALID_TIME;

            events[num_events++] = (SocketEvent) {
                SOCKET_EVENT_CREATION_TIMEOUT,
                socket_to_handle(sm, s),
                s->user
            };

        } else if (s->recv_timeout != INVALID_TIME
            && current_time != INVALID_TIME
            && current_time > s->last_recv_time + s->recv_timeout) {

            s->recv_timeout = INVALID_TIME;

            events[num_events++] = (SocketEvent) {
                SOCKET_EVENT_RECV_TIMEOUT,
                socket_to_handle(sm, s),
                s->user
            };

        } else if (s->state == SOCKET_STATE_DIED) {

            events[num_events++] = (SocketEvent) {
                SOCKET_EVENT_DISCONNECT,
                SOCKET_HANDLE_INVALID,
                s->user
            };

            // Free resources associated to socket
            UPDATE_STATE(s->state, SOCKET_STATE_FREE);
            if (s->sock != NATIVE_SOCKET_INVALID)
                CLOSE_NATIVE_SOCKET(s->sock);
            if (s->sock == SOCKET_STATE_PENDING ||
                s->sock == SOCKET_STATE_CONNECTING) {
                if (s->num_addr > 1)
                    free(s->addrs);
            }
            sm->num_used--;

        } else if (s->state == SOCKET_STATE_ESTABLISHED_READY) {

            events[num_events++] = (SocketEvent) {
                SOCKET_EVENT_READY,
                socket_to_handle(sm, s),
                s->user
            };
        }
    }

    return num_events;
}

static int resolve_connect_targets(ConnectTarget *targets,
    int num_targets, AddressAndPort *resolved, int max_resolved)
{
    int num_resolved = 0;
    for (int i = 0; i < num_targets; i++) {
        switch (targets[i].type) {
        case CONNECT_TARGET_NAME:
            {
                char portstr[16];
                int len = snprintf(portstr, sizeof(portstr), "%u", targets[i].port);
                assert(len > 1 && len < (int) sizeof(portstr));

                struct addrinfo hints = {0};
                hints.ai_family = AF_UNSPEC;
                hints.ai_socktype = SOCK_STREAM;

#ifdef HTTPS_ENABLED
                RegisteredName *name = malloc(sizeof(RegisteredName) + targets[i].name.len + 1);
                if (name == NULL) {
                    free_addr_list(resolved, num_resolved);
                    return CHTTP_ERROR_OOM;
                }
                name->refs = 0;
                memcpy(name->data, targets[i].name.ptr, targets[i].name.len);
                name->data[targets[i].name.len] = '\0';
                char *hostname = name->data;
#else
                // 512 bytes is more than enough for a DNS hostname (max 253 chars)
                char hostname[1<<9];
                if (targets[i].name.len >= (int) sizeof(hostname))
                    return CHTTP_ERROR_OOM;
                memcpy(hostname, targets[i].name.ptr, targets[i].name.len);
                hostname[targets[i].name.len] = '\0';
#endif
                struct addrinfo *res = NULL;
                int ret = getaddrinfo(hostname, portstr, &hints, &res);
                if (ret != 0) {
#ifdef HTTPS_ENABLED
                    // Free the name allocated for this target
                    free(name);
#endif
                    free_addr_list(resolved, num_resolved);
                    return CHTTP_ERROR_UNSPECIFIED;
                }

                for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
                    if (rp->ai_family == AF_INET) {
                        CHTTP_IPv4 ipv4 = *(CHTTP_IPv4*) &((struct sockaddr_in*)rp->ai_addr)->sin_addr;
                        if (num_resolved < max_resolved) {
                            resolved[num_resolved].is_ipv4 = true;
                            resolved[num_resolved].ipv4 = ipv4;
                            resolved[num_resolved].port = targets[i].port;
#ifdef HTTPS_ENABLED
                            resolved[num_resolved].name = name;
                            name->refs++;
#endif
                            num_resolved++;
                        }
                    } else if (rp->ai_family == AF_INET6) {
                        CHTTP_IPv6 ipv6 = *(CHTTP_IPv6*) &((struct sockaddr_in6*)rp->ai_addr)->sin6_addr;
                        if (num_resolved < max_resolved) {
                            resolved[num_resolved].is_ipv4 = false;
                            resolved[num_resolved].ipv6 = ipv6;
                            resolved[num_resolved].port = targets[i].port;
#ifdef HTTPS_ENABLED
                            resolved[num_resolved].name = name;
                            name->refs++;
#endif
                            num_resolved++;
                        }
                    }
                }

#ifdef HTTPS_ENABLED
                if (name->refs == 0)
                    free(name);
#endif

                freeaddrinfo(res);
            }
            break;
        case CONNECT_TARGET_IPV4:
            if (num_resolved < max_resolved) {
                resolved[num_resolved].is_ipv4 = true;
                resolved[num_resolved].ipv4 = targets[i].ipv4;
                resolved[num_resolved].port = targets[i].port;
#ifdef HTTPS_ENABLED
                resolved[num_resolved].name = NULL;
#endif
                num_resolved++;
            }
            break;
        case CONNECT_TARGET_IPV6:
            if (num_resolved < max_resolved) {
                resolved[num_resolved].is_ipv4 = false;
                resolved[num_resolved].ipv6 = targets[i].ipv6;
                resolved[num_resolved].port = targets[i].port;
#ifdef HTTPS_ENABLED
                resolved[num_resolved].name = NULL;
#endif
                num_resolved++;
            }
            break;
        }
    }
    return num_resolved;
}

#define MAX_CONNECT_TARGETS 16

int socket_connect(SocketManager *sm, int num_targets,
    ConnectTarget *targets, bool secure, bool dont_verify_cert,
    void *user)
{
    Time current_time = get_current_time();
    if (current_time == INVALID_TIME)
        return CHTTP_ERROR_UNSPECIFIED;

    if (sm->num_used == sm->max_used)
        return CHTTP_ERROR_UNSPECIFIED;

#ifdef HTTPS_ENABLED
    if (!sm->at_least_one_secure_connect) {
        if (client_secure_context_init(&sm->client_secure_context) < 0)
            return CHTTP_ERROR_UNSPECIFIED;
        sm->at_least_one_secure_connect = true;
    }
#else
    if (secure)
        return CHTTP_ERROR_NOTLS;
#endif

    AddressAndPort resolved[MAX_CONNECT_TARGETS];
    int num_resolved = resolve_connect_targets(
        targets, num_targets, resolved, MAX_CONNECT_TARGETS);

    if (num_resolved <= 0)
        return CHTTP_ERROR_UNSPECIFIED;

    Socket *s = sm->sockets;
    while (s->state != SOCKET_STATE_FREE) {
        s++;
        assert(s - sm->sockets < + sm->max_used);
    }

    if (num_resolved == 1) {
        s->num_addr = 1;
        s->next_addr = 0;
        s->addr = resolved[0];
    } else {
        s->num_addr = num_resolved;
        s->next_addr = 0;
        s->addrs = malloc(num_resolved * sizeof(AddressAndPort));
        if (s->addrs == NULL)
            return CHTTP_ERROR_OOM;
        for (int i = 0; i < num_resolved; i++)
            s->addrs[i] = resolved[i];
    }

    UPDATE_STATE(s->state, SOCKET_STATE_PENDING);
    s->sock = NATIVE_SOCKET_INVALID;
    s->user = user;
    s->silent = false;
    s->creation_time = current_time;
    s->last_recv_time = current_time;
    s->creation_timeout = sm->creation_timeout;
    s->recv_timeout = sm->recv_timeout;
#ifdef HTTPS_ENABLED
    s->server_secure_context = NULL;
    s->client_secure_context = NULL;
    s->ssl = NULL;
    s->dont_verify_cert = false;
    if (secure) {
        s->client_secure_context = &sm->client_secure_context;
        s->dont_verify_cert = dont_verify_cert;
    }
#else
    (void) dont_verify_cert;
#endif
    sm->num_used++;

    socket_update(s);
    return CHTTP_OK;
}

static bool would_block(void)
{
#ifdef _WIN32
    int err = WSAGetLastError();
    return err == WSAEWOULDBLOCK;
#else
    return errno == EAGAIN || errno == EWOULDBLOCK;
#endif
}

static bool interrupted(void)
{
#ifdef _WIN32
    return false;
#else
    return errno == EINTR;
#endif
}

int socket_recv(SocketManager *sm, SocketHandle handle,
    char *dst, int max)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return 0;

    if (s->state != SOCKET_STATE_ESTABLISHED_READY) {
        UPDATE_STATE(s->state, SOCKET_STATE_DIED);
        s->events = 0;
        return 0;
    }

    int ret;
    if (!is_secure(s)) {
        ret = recv(s->sock, dst, max, 0);
        if (ret == 0) {
            UPDATE_STATE(s->state, SOCKET_STATE_DIED);
            s->events = 0;
        } else if (ret < 0) {
            if (would_block()) {
                UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_WAIT);
                s->events = POLLIN;
            } else if (!interrupted()) {
                UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                s->events = 0;
            }
            ret = 0;
        }
    } else {
#ifdef HTTPS_ENABLED
        ret = SSL_read(s->ssl, dst, max);
        if (ret <= 0) {
            int err = SSL_get_error(s->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                s->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_WAIT);
                s->events = POLLOUT;
            } else {
                s->state  = SOCKET_STATE_DIED;
                s->events = 0;
            }
            ret = 0;
        }
#else
        // Unreachable
        ret = 0;
#endif
    }

    if (ret > 0 && s->recv_timeout != INVALID_TIME) {
        Time current_time = get_current_time();
        if (current_time != INVALID_TIME)
            s->last_recv_time = current_time;
    }
    return ret;
}

int socket_send(SocketManager *sm, SocketHandle handle,
    char *src, int len)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return 0;

    if (s->state != SOCKET_STATE_ESTABLISHED_READY) {
        UPDATE_STATE(s->state, SOCKET_STATE_DIED);
        s->events = 0;
        return 0;
    }

    if (!is_secure(s)) {
        int ret = send(s->sock, src, len, 0);
        if (ret < 0) {
            if (would_block()) {
                UPDATE_STATE(s->state, SOCKET_STATE_ESTABLISHED_WAIT);
                s->events = POLLOUT;
            } else if (!interrupted()) {
                UPDATE_STATE(s->state, SOCKET_STATE_DIED);
                s->events = 0;
            }
            ret = 0;
        }
        return ret;
    } else {
#ifdef HTTPS_ENABLED
        int ret = SSL_write(s->ssl, src, len);
        if (ret <= 0) {
            int err = SSL_get_error(s->ssl, ret);
            if (err == SSL_ERROR_WANT_READ) {
                s->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLIN;
            } else if (err == SSL_ERROR_WANT_WRITE) {
                s->state  = SOCKET_STATE_ESTABLISHED_WAIT;
                s->events = POLLOUT;
            } else {
                s->state  = SOCKET_STATE_DIED;
                s->events = 0;
            }
            ret = 0;
        }
        return ret;
#else
        // Unreachable
        return 0;
#endif
    }
}

void socket_close(SocketManager *sm, SocketHandle handle)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return;

    if (s->state != SOCKET_STATE_DIED) {
        UPDATE_STATE(s->state, SOCKET_STATE_SHUTDOWN);
        s->events = 0;
        socket_update(s);
    }
}

bool socket_is_secure(SocketManager *sm, SocketHandle handle)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return false;
    return is_secure(s);
}

void socket_set_user(SocketManager *sm, SocketHandle handle, void *user)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
        return;

    s->user = user;
}

bool socket_ready(SocketManager *sm, SocketHandle handle)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
       return false;

   if (s->events == 0 && s->state != SOCKET_STATE_DIED)
        return true;

    return false;
}

void socket_silent(SocketManager *sm, SocketHandle handle, bool value)
{
    Socket *s = handle_to_socket(sm, handle);
    if (s == NULL)
       return;

    s->silent = value;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/byte_queue.c
////////////////////////////////////////////////////////////////////////////////////////

void byte_queue_init(ByteQueue *queue, uint32_t limit)
{
    queue->flags = 0;
    queue->head = 0;
    queue->size = 0;
    queue->used = 0;
    queue->curs = 0;
    queue->limit = limit;
    queue->data = NULL;
    queue->read_target = NULL;
}

// Deinitialize the queue
void byte_queue_free(ByteQueue *queue)
{
    if (queue->read_target) {
        if (queue->read_target != queue->data)
            free(queue->read_target);
        queue->read_target = NULL;
        queue->read_target_size = 0;
    }

    free(queue->data);
    queue->data = NULL;
}

int byte_queue_error(ByteQueue *queue)
{
    return queue->flags & BYTE_QUEUE_ERROR;
}

int byte_queue_empty(ByteQueue *queue)
{
    return queue->used == 0;
}

int byte_queue_full(ByteQueue *queue)
{
    return queue->used == queue->limit;
}

ByteView byte_queue_read_buf(ByteQueue *queue)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return (ByteView) {NULL, 0};

    assert((queue->flags & BYTE_QUEUE_READ) == 0);
    queue->flags |= BYTE_QUEUE_READ;
    queue->read_target      = queue->data;
    queue->read_target_size = queue->size;

    if (queue->data == NULL)
        return (ByteView) {NULL, 0};

    return (ByteView) { queue->data + queue->head, queue->used };
}

void byte_queue_read_ack(ByteQueue *queue, uint32_t num)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    if ((queue->flags & BYTE_QUEUE_READ) == 0)
        return;

    queue->flags &= ~BYTE_QUEUE_READ;

    assert((uint32_t) num <= queue->used);
    queue->head += (uint32_t) num;
    queue->used -= (uint32_t) num;
    queue->curs += (uint32_t) num;

    if (queue->read_target) {
        if (queue->read_target != queue->data)
            free(queue->read_target);
        queue->read_target = NULL;
        queue->read_target_size = 0;
    }
}

ByteView byte_queue_write_buf(ByteQueue *queue)
{
    if ((queue->flags & BYTE_QUEUE_ERROR) || queue->data == NULL)
        return (ByteView) {NULL, 0};

    assert((queue->flags & BYTE_QUEUE_WRITE) == 0);
    queue->flags |= BYTE_QUEUE_WRITE;

    return (ByteView) {
        queue->data + (queue->head + queue->used),
        queue->size - (queue->head + queue->used),
    };
}

void byte_queue_write_ack(ByteQueue *queue, uint32_t num)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    if ((queue->flags & BYTE_QUEUE_WRITE) == 0)
        return;

    queue->flags &= ~BYTE_QUEUE_WRITE;
    queue->used += num;
}

int byte_queue_write_setmincap(ByteQueue *queue, uint32_t mincap)
{
    // Sticky error
    if (queue->flags & BYTE_QUEUE_ERROR)
        return 0;

    // In general, the queue's contents look like this:
    //
    //                           size
    //                           v
    //   [___xxxxxxxxxxxx________]
    //   ^   ^           ^
    //   0   head        head + used
    //
    // This function needs to make sure that at least [mincap]
    // bytes are available on the right side of the content.
    //
    // We have 3 cases:
    //
    //   1) If there is enough memory already, this function doesn't
    //      need to do anything.
    //
    //   2) If there isn't enough memory on the right but there is
    //      enough free memory if we cound the left unused region,
    //      then the content is moved back to the
    //      start of the buffer.
    //
    //   3) If there isn't enough memory considering both sides, this
    //      function needs to allocate a new buffer.
    //
    // If there are pending read or write operations, the application
    // is holding pointers to the buffer, so we need to make sure
    // to not invalidate them. The only real problem is pending reads
    // since this function can only be called before starting a write
    // opearation.
    //
    // To avoid invalidating the read pointer when we allocate a new
    // buffer, we don't free the old buffer. Instead, we store the
    // pointer in the "old" field so that the read ack function can
    // free it.
    //
    // To avoid invalidating the pointer when we are moving back the
    // content since there is enough memory at the start of the buffer,
    // we just avoid that. Even if there is enough memory considering
    // left and right free regions, we allocate a new buffer.

    assert((queue->flags & BYTE_QUEUE_WRITE) == 0);

    uint32_t total_free_space = queue->size - queue->used;
    uint32_t free_space_after_data = queue->size - queue->used - queue->head;

    int moved = 0;
    if (free_space_after_data < mincap) {

        if (total_free_space < mincap || (queue->read_target == queue->data)) {
            // Resize required

            if (queue->used + mincap > queue->limit) {
                queue->flags |= BYTE_QUEUE_ERROR;
                return 0;
            }

            uint32_t size;
            if (queue->size > UINT32_MAX / 2)
                size = UINT32_MAX;
            else
                size = 2 * queue->size;

            if (size < queue->used + mincap)
                size = queue->used + mincap;

            if (size > queue->limit)
                size = queue->limit;

            char *data = malloc(size);
            if (!data) {
                queue->flags |= BYTE_QUEUE_ERROR;
                return 0;
            }

            if (queue->used > 0)
                memcpy(data, queue->data + queue->head, queue->used);

            if (queue->read_target != queue->data)
                free(queue->data);

            queue->data = data;
            queue->head = 0;
            queue->size = size;

        } else {
            // Move required
            memmove(queue->data, queue->data + queue->head, queue->used);
            queue->head = 0;
        }

        moved = 1;
    }

    return moved;
}

void byte_queue_write(ByteQueue *queue, void *ptr, uint32_t len)
{
    byte_queue_write_setmincap(queue, len);
    ByteView dst = byte_queue_write_buf(queue);
    if (dst.ptr) {
        memcpy(dst.ptr, ptr, len);
        byte_queue_write_ack(queue, len);
    }
}

void byte_queue_write_fmt2(ByteQueue *queue,
    const char *fmt, va_list args)
{
	if (queue->flags & BYTE_QUEUE_ERROR)
		return;

	va_list args2;
	va_copy(args2, args);

	byte_queue_write_setmincap(queue, 128);
	ByteView dst = byte_queue_write_buf(queue);

	int len = vsnprintf(dst.ptr, dst.len, fmt, args);
	if (len < 0) {
		queue->flags |= BYTE_QUEUE_ERROR;
		va_end(args2);
		return;
	}

	if ((size_t) len > dst.len) {
		byte_queue_write_ack(queue, 0);
		byte_queue_write_setmincap(queue, len+1);
		dst = byte_queue_write_buf(queue);
		vsnprintf(dst.ptr, dst.len, fmt, args2);
	}

	byte_queue_write_ack(queue, len);

	va_end(args2);
}

void byte_queue_write_fmt(ByteQueue *queue,
    const char *fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	byte_queue_write_fmt2(queue, fmt, args);
	va_end(args);
}

ByteQueueOffset byte_queue_offset(ByteQueue *queue)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return (ByteQueueOffset) { 0 };
    return (ByteQueueOffset) { queue->curs + queue->used };
}

void byte_queue_patch(ByteQueue *queue, ByteQueueOffset off,
    void *src, uint32_t len)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    // Check that the offset is in range
    assert(off >= queue->curs && off - queue->curs < queue->used);

    // Check that the length is in range
    assert(len <= queue->used - (off - queue->curs));

    // Perform the patch
    char *dst = queue->data + queue->head + (off - queue->curs);
    memcpy(dst, src, len);
}

uint32_t byte_queue_size_from_offset(ByteQueue *queue, ByteQueueOffset off)
{
    return queue->curs + queue->used - off;
}

void byte_queue_remove_from_offset(ByteQueue *queue, ByteQueueOffset offset)
{
    if (queue->flags & BYTE_QUEUE_ERROR)
        return;

    uint64_t num = (queue->curs + queue->used) - offset;
    assert(num <= queue->used);

    queue->used -= num;
}

////////////////////////////////////////////////////////////////////////////////////////
// src/cert.c
////////////////////////////////////////////////////////////////////////////////////////

#ifdef HTTPS_ENABLED

static EVP_PKEY *generate_rsa_key_pair(int key_bits)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, key_bits) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static X509 *create_certificate(EVP_PKEY *pkey, CHTTP_String C, CHTTP_String O, CHTTP_String CN, int days)
{
    X509 *x509 = X509_new();
    if (!x509)
        return NULL;

    // Set version (version 3)
    X509_set_version(x509, 2);

    // Set serial number
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    // Set validity period
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L * days); // days * seconds_per_year

    // Set public key
    X509_set_pubkey(x509, pkey);

    // Set subject name
    X509_NAME *name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*) C.ptr,  C.len,  -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (unsigned char*) O.ptr,  O.len,  -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*) CN.ptr, CN.len, -1, 0);

    // Set issuer name (same as subject for self-signed)
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509);
        return NULL;
    }

    return x509;
}

static int save_private_key(EVP_PKEY *pkey, CHTTP_String file)
{
    char copy[1<<10];
    if (file.len >= (int) sizeof(copy))
        return -1;
    memcpy(copy, file.ptr, file.len);
    copy[file.len] = '\0';

    FILE *fp = fopen(copy, "wb");
    if (!fp)
        return -1;

    // Write private key in PEM format
    if (!PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

static int save_certificate(X509 *x509, CHTTP_String file)
{
    char copy[1<<10];
    if (file.len >= (int) sizeof(copy))
        return -1;
    memcpy(copy, file.ptr, file.len);
    copy[file.len] = '\0';

    FILE *fp = fopen(copy, "wb");
    if (!fp)
        return -1;

    // Write certificate in PEM format
    if (!PEM_write_X509(fp, x509)) {
        fclose(fp);
        return -1;
    }

    fclose(fp);
    return 0;
}

int chttp_create_test_certificate(CHTTP_String C, CHTTP_String O, CHTTP_String CN,
    CHTTP_String cert_file, CHTTP_String key_file)
{
    EVP_PKEY *pkey = generate_rsa_key_pair(2048);
    if (pkey == NULL)
        return -1;

    X509 *x509 = create_certificate(pkey, C, O, CN, 1);
    if (x509 == NULL) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (save_private_key(pkey, key_file) < 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (save_certificate(x509, cert_file) < 0) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return -1;
    }

    X509_free(x509);
    EVP_PKEY_free(pkey);
    return 0;
}

#else

int chttp_create_test_certificate(CHTTP_String C, CHTTP_String O, CHTTP_String CN,
    CHTTP_String cert_file, CHTTP_String key_file)
{
    (void) C;
    (void) O;
    (void) CN;
    (void) cert_file;
    (void) key_file;
    return -1;
}

#endif

////////////////////////////////////////////////////////////////////////////////////////
// src/client.c
////////////////////////////////////////////////////////////////////////////////////////

static void chttp_client_conn_free(CHTTP_ClientConn *conn)
{
    byte_queue_free(&conn->output);
    byte_queue_free(&conn->input);
}

int chttp_client_init(CHTTP_Client *client)
{
    client->input_buffer_limit = 1<<20;
    client->output_buffer_limit = 1<<20;

    client->cookie_jar.count = 0;

    client->num_conns = 0;
    for (int i = 0; i < CHTTP_CLIENT_CAPACITY; i++) {
        client->conns[i].state = CHTTP_CLIENT_CONN_FREE;
        client->conns[i].gen = 0;
    }

    client->num_ready = 0;
    client->ready_head = 0;

    return socket_manager_init(&client->sockets,
        client->socket_pool, CHTTP_CLIENT_CAPACITY);
}

void chttp_client_free(CHTTP_Client *client)
{
    socket_manager_free(&client->sockets);

    for (int i = 0; i < client->cookie_jar.count; i++)
        free(client->cookie_jar.items[i].name.ptr);

    for (int i = 0, j = 0; j < client->num_conns; i++) {
        CHTTP_ClientConn *conn = &client->conns[i];
        if (conn->state == CHTTP_CLIENT_CONN_FREE)
            continue;
        j++;

        chttp_client_conn_free(conn);
    }
}

void chttp_client_set_input_limit(CHTTP_Client *client, uint32_t limit)
{
    client->input_buffer_limit = limit;
}

void chttp_client_set_output_limit(CHTTP_Client *client, uint32_t limit)
{
    client->output_buffer_limit = limit;
}

int chttp_client_wakeup(CHTTP_Client *client)
{
    return socket_manager_wakeup(&client->sockets);
}

// Get a connection pointer from a request builder.
// If the builder is invalid, returns NULL.
static CHTTP_ClientConn*
request_builder_to_conn(CHTTP_RequestBuilder builder)
{
    CHTTP_Client *client = builder.client;
    if (client == NULL)
        return NULL;

    if (builder.index >= CHTTP_CLIENT_CAPACITY)
        return NULL;

    CHTTP_ClientConn *conn = &client->conns[builder.index];
    if (builder.gen != conn->gen)
        return NULL;

    return conn;
}

CHTTP_RequestBuilder chttp_client_get_builder(CHTTP_Client *client)
{
    // Find a free connection slot
    if (client->num_conns == CHTTP_CLIENT_CAPACITY)
        return (CHTTP_RequestBuilder) { NULL, -1, -1 };

    int i = 0;
    while (client->conns[i].state != CHTTP_CLIENT_CONN_FREE) {
        i++;
        assert(i < CHTTP_CLIENT_CAPACITY);
    }
    client->num_conns++;

    client->conns[i].state = CHTTP_CLIENT_CONN_WAIT_METHOD;
    client->conns[i].handle = SOCKET_HANDLE_INVALID;
    client->conns[i].client = client;
    client->conns[i].user = NULL;
    client->conns[i].trace_bytes = false;
    byte_queue_init(&client->conns[i].input,  client->input_buffer_limit);
    byte_queue_init(&client->conns[i].output, client->output_buffer_limit);

    return (CHTTP_RequestBuilder) { client, i, client->conns[i].gen };
}

// TODO: test this function
static bool is_subdomain(CHTTP_String domain, CHTTP_String subdomain)
{
    if (chttp_streq(domain, subdomain))
        return true; // Exact match

    if (domain.len > subdomain.len)
        return false;

    CHTTP_String subdomain_suffix = {
        subdomain.ptr + subdomain.len - domain.len,
        domain.len
    };
    if (subdomain_suffix.ptr[-1] != '.' || !chttp_streq(domain, subdomain_suffix))
        return false;

    return true;
}

// TODO: test this function
static bool is_subpath(CHTTP_String path, CHTTP_String subpath)
{
    if (path.len > subpath.len)
        return false;

    if (subpath.len != path.len && subpath.ptr[path.len] != '/')
        return false;

    subpath.len = path.len;
    return chttp_streq(path, subpath);
}

static bool should_send_cookie(CHTTP_CookieJarEntry entry, CHTTP_URL url)
{
    // TODO: If the cookie is expired, ignore it regardless

    if (entry.exact_domain) {
        // Cookie domain and URL domain must match exactly
        if (!chttp_streq(entry.domain, url.authority.host.text))
            return false;
    } else {
        // The URL's domain must match or be a subdomain of the cookie's domain
        if (!is_subdomain(entry.domain, url.authority.host.text))
            return false;
    }

    if (entry.exact_path) {
        // Cookie path and URL path must match exactly
        if (!chttp_streq(entry.path, url.path))
            return false;
    } else {
        if (!is_subpath(entry.path, url.path))
            return false;
    }

    if (entry.secure) {
        if (!chttp_streq(url.scheme, CHTTP_STR("https")))
            return false; // Cookie was marked as secure but the target URL is not HTTPS
    }

    return true;
}

static CHTTP_String get_method_string(CHTTP_Method method)
{
    switch (method) {
        case CHTTP_METHOD_GET    : return CHTTP_STR("GET");
        case CHTTP_METHOD_HEAD   : return CHTTP_STR("HEAD");
        case CHTTP_METHOD_POST   : return CHTTP_STR("POST");
        case CHTTP_METHOD_PUT    : return CHTTP_STR("PUT");
        case CHTTP_METHOD_DELETE : return CHTTP_STR("DELETE");
        case CHTTP_METHOD_CONNECT: return CHTTP_STR("CONNECT");
        case CHTTP_METHOD_OPTIONS: return CHTTP_STR("OPTIONS");
        case CHTTP_METHOD_TRACE  : return CHTTP_STR("TRACE");
        case CHTTP_METHOD_PATCH  : return CHTTP_STR("PATCH");
    }
    return CHTTP_STR("???");
}

void chttp_request_builder_set_user(CHTTP_RequestBuilder builder, void *user)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    conn->user = user;
}

void chttp_request_builder_trace(CHTTP_RequestBuilder builder, bool trace_bytes)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    conn->trace_bytes = trace_bytes;
}

// TODO: comment
void chttp_request_builder_insecure(CHTTP_RequestBuilder builder,
    bool insecure)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    conn->dont_verify_cert = insecure;
}

void chttp_request_builder_method(CHTTP_RequestBuilder builder,
    CHTTP_Method method)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_METHOD)
        return; // Request line already written

    // Write method
    CHTTP_String method_str = get_method_string(method);
    byte_queue_write(&conn->output, method_str.ptr, method_str.len);
    byte_queue_write(&conn->output, " ", 1);

    conn->state = CHTTP_CLIENT_CONN_WAIT_URL;
}

void chttp_request_builder_target(CHTTP_RequestBuilder builder,
    CHTTP_String url)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return; // Invalid builder

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_URL)
        return; // Request line already written

    if (url.len == 0) {
        conn->state = CHTTP_CLIENT_CONN_COMPLETE;
        conn->result = CHTTP_ERROR_BADURL;
        return;
    }

    // Allocate a copy of the URL string so the parsed
    // URL pointers remain valid
    char *url_copy = malloc(url.len);
    if (url_copy == NULL) {
        conn->state = CHTTP_CLIENT_CONN_COMPLETE;
        conn->result = CHTTP_ERROR_OOM;
        return;
    }
    memcpy(url_copy, url.ptr, url.len);

    conn->url_buffer.ptr = url_copy;
    conn->url_buffer.len = url.len;

    // Parse the copied URL (all url.* pointers will reference url_buffer)
    if (chttp_parse_url(conn->url_buffer.ptr, conn->url_buffer.len, &conn->url) < 0) {
        conn->state = CHTTP_CLIENT_CONN_COMPLETE;
        conn->result = CHTTP_ERROR_BADURL;
        return;
    }

    if (!chttp_streq(conn->url.scheme, CHTTP_STR("http")) &&
        !chttp_streq(conn->url.scheme, CHTTP_STR("https"))) {
        conn->state = CHTTP_CLIENT_CONN_COMPLETE;
        conn->result = CHTTP_ERROR_BADURL;
        return;
    }

    // Write path
    if (conn->url.path.len == 0)
        byte_queue_write(&conn->output, "/", 1);
    else
        byte_queue_write(&conn->output,
            conn->url.path.ptr,
            conn->url.path.len);

    // Write query string
    CHTTP_String query = conn->url.query;
    if (query.len > 0) {
        byte_queue_write(&conn->output, "?", 1);
        byte_queue_write(&conn->output, query.ptr, query.len);
    }

    CHTTP_String version = CHTTP_STR(" HTTP/1.1");
    byte_queue_write(&conn->output, version.ptr, version.len);

    byte_queue_write(&conn->output, "\r\n", 2);

    // Add Host header automatically
    byte_queue_write_fmt(&conn->output, "Host: %.*s",
        conn->url.authority.host.text.len,
        conn->url.authority.host.text.ptr);
    if (conn->url.authority.port > 0)
        byte_queue_write_fmt(&conn->output, ":%d", conn->url.authority.port);

    byte_queue_write(&conn->output, "\r\n", 2);

    // Find all entries from the cookie jar that should
    // be sent to this server and append headers for them
    CHTTP_Client *client = builder.client;
    CHTTP_CookieJar *cookie_jar = &client->cookie_jar;
    for (int i = 0; i < cookie_jar->count; i++) {
        CHTTP_CookieJarEntry entry = cookie_jar->items[i];
        if (should_send_cookie(entry, conn->url)) {
            // TODO: Adding one header per cookie may cause the number of
            //       headers to increase significantly. Should probably group
            //       3-4 cookies in the same headers.
            byte_queue_write(&conn->output, "Cookie: ", 8);
            byte_queue_write(&conn->output, entry.name.ptr, entry.name.len);
            byte_queue_write(&conn->output, "=", 1);
            byte_queue_write(&conn->output, entry.value.ptr, entry.value.len);
            byte_queue_write(&conn->output, "\r\n", 2);
        }
    }

    CHTTP_String s;

    s = CHTTP_STR("Connection: Close\r\n");
    byte_queue_write(&conn->output, s.ptr, s.len);

    s = CHTTP_STR("Content-Length: ");
    byte_queue_write(&conn->output, s.ptr, s.len);

    conn->content_length_value_offset = byte_queue_offset(&conn->output);

    #define TEN_SPACES "          "
    _Static_assert(sizeof(TEN_SPACES) == 10+1, "");

    s = CHTTP_STR(TEN_SPACES "\r\n");
    byte_queue_write(&conn->output, s.ptr, s.len);

    conn->state = CHTTP_CLIENT_CONN_WAIT_HEADER;
}

void chttp_request_builder_header(CHTTP_RequestBuilder builder,
    CHTTP_String str)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_HEADER)
        return;

    // Validate header: must contain a colon and no control characters
    bool has_colon = false;
    for (int i = 0; i < str.len; i++) {
        char c = str.ptr[i];
        if (c == ':')
            has_colon = true;
        // Reject control characters (especially \r and \n)
        if (c < 0x20 && c != '\t')
            return;
    }
    if (!has_colon)
        return;

    byte_queue_write(&conn->output, str.ptr, str.len);
    byte_queue_write(&conn->output, "\r\n", 2);
}

void chttp_request_builder_body(CHTTP_RequestBuilder builder,
    CHTTP_String str)
{
    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return;

    // Transition from WAIT_HEADER to WAIT_BODY if needed
    if (conn->state == CHTTP_CLIENT_CONN_WAIT_HEADER) {
        byte_queue_write(&conn->output, "\r\n", 2);
        conn->content_length_offset = byte_queue_offset(&conn->output);
        conn->state = CHTTP_CLIENT_CONN_WAIT_BODY;
    }

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_BODY)
        return;

    byte_queue_write(&conn->output, str.ptr, str.len);
}

static ConnectTarget url_to_connect_target(CHTTP_URL url)
{
    CHTTP_Authority authority = url.authority;

    ConnectTarget target;
    if (authority.port < 1) {
        if (chttp_streq(url.scheme, CHTTP_STR("https")))
            target.port = 443;
        else
            target.port = 80;
    } else {
        target.port = authority.port;
    }

    if (authority.host.mode == CHTTP_HOST_MODE_NAME) {
        target.type = CONNECT_TARGET_NAME;
        target.name = authority.host.name;
    } else if (authority.host.mode == CHTTP_HOST_MODE_IPV4) {
        target.type = CONNECT_TARGET_IPV4;
        target.ipv4 = authority.host.ipv4;
    } else if (authority.host.mode == CHTTP_HOST_MODE_IPV6) {
        target.type = CONNECT_TARGET_IPV6;
        target.ipv6 = authority.host.ipv6;
    } else {
        CHTTP_UNREACHABLE;
    }

    return target;
}

int chttp_request_builder_send(CHTTP_RequestBuilder builder)
{
    CHTTP_Client *client = builder.client;
    if (client == NULL)
        return CHTTP_ERROR_REQLIMIT;

    CHTTP_ClientConn *conn = request_builder_to_conn(builder);
    if (conn == NULL)
        return CHTTP_ERROR_BADHANDLE;

    if (conn->state == CHTTP_CLIENT_CONN_COMPLETE)
        goto error; // Early completion due to an error

    if (conn->state == CHTTP_CLIENT_CONN_WAIT_HEADER) {
        byte_queue_write(&conn->output, "\r\n", 2);
        conn->content_length_offset = byte_queue_offset(&conn->output);
        conn->state = CHTTP_CLIENT_CONN_WAIT_BODY;
    }

    if (conn->state != CHTTP_CLIENT_CONN_WAIT_BODY)
        goto error;

    if (byte_queue_error(&conn->output))
        goto error;

    int content_length = byte_queue_size_from_offset(&conn->output, conn->content_length_offset);

    char tmp[11];
    int len = snprintf(tmp, sizeof(tmp), "%d", content_length);
    assert(len > 0 && len < 11);

    byte_queue_patch(&conn->output, conn->content_length_value_offset, tmp, len);

    ConnectTarget target = url_to_connect_target(conn->url);
    bool secure = chttp_streq(conn->url.scheme, CHTTP_STR("https"));
    if (socket_connect(&client->sockets, 1, &target, secure, conn->dont_verify_cert, conn) < 0)
        goto error;

    conn->state = CHTTP_CLIENT_CONN_FLUSHING;
    conn->gen++;
    return CHTTP_OK;

error:
    conn->state = CHTTP_CLIENT_CONN_FREE;
    free(conn->url_buffer.ptr);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
    client->num_conns--;
    return conn->result;
}

static void save_one_cookie(CHTTP_CookieJar *cookie_jar,
    CHTTP_Header set_cookie, CHTTP_String domain, CHTTP_String path)
{
    if (cookie_jar->count == CHTTP_COOKIE_JAR_CAPACITY)
        return; // Cookie jar capacity reached

    CHTTP_SetCookie parsed;
    if (chttp_parse_set_cookie(set_cookie.value, &parsed) < 0)
        return; // Ignore invalid Set-Cookie headers

    CHTTP_CookieJarEntry entry;

    entry.name = parsed.name;
    entry.value = parsed.value;

    if (parsed.have_domain) {
        // TODO: Check that the server can set a cookie for this domain
        entry.exact_domain = false;
        entry.domain = parsed.domain;
    } else {
        entry.exact_domain = true;
        entry.domain = domain;
    }

    if (parsed.have_path) {
        entry.exact_path = false;
        entry.path = parsed.path;
    } else {
        // TODO: Set the path to the current endpoint minus one level
        entry.exact_path = true;
        entry.path = path;
    }

    entry.secure = parsed.secure;

    // Now copy all fields
    char *p = malloc(entry.name.len + entry.value.len + entry.domain.len + entry.path.len);
    if (p == NULL)
        return;

    memcpy(p, entry.name.ptr, entry.name.len);
    entry.name.ptr = p;
    p += entry.name.len;

    memcpy(p, entry.value.ptr, entry.value.len);
    entry.value.ptr = p;
    p += entry.value.len;

    memcpy(p, entry.domain.ptr, entry.domain.len);
    entry.domain.ptr = p;
    p += entry.domain.len;

    memcpy(p, entry.path.ptr, entry.path.len);
    entry.path.ptr = p;
    p += entry.path.len;

    cookie_jar->items[cookie_jar->count++] = entry;
}

static void save_cookies(CHTTP_CookieJar *cookie_jar,
    CHTTP_Header *headers, int num_headers,
    CHTTP_String domain, CHTTP_String path)
{
    // TODO: remove expired cookies

    for (int i = 0; i < num_headers; i++)
        if (chttp_streqcase(headers[i].name, CHTTP_STR("Set-Cookie"))) // TODO: headers are case-insensitive, right?
            save_one_cookie(cookie_jar, headers[i], domain, path);
}

void chttp_client_register_events(CHTTP_Client *client,
    EventRegister *reg)
{
    socket_manager_register_events(&client->sockets, reg);
}

void chttp_client_process_events(CHTTP_Client *client,
    EventRegister reg)
{
    SocketEvent events[CHTTP_CLIENT_CAPACITY];
    int num_events = socket_manager_translate_events(&client->sockets, events, reg);

    for (int i = 0; i < num_events; i++) {

        CHTTP_ClientConn *conn = events[i].user;
        if (conn == NULL)
            continue; // If a socket is not couple to a connection,
                      // it means the response was already returned
                      // to the user.

        if (events[i].type == SOCKET_EVENT_DISCONNECT) {

            conn->state = CHTTP_CLIENT_CONN_COMPLETE;
            conn->result = -1;

        } else if (events[i].type == SOCKET_EVENT_CREATION_TIMEOUT) {

            // TODO: This is too abrupt
            socket_close(&client->sockets, events[i].handle);

        } else if (events[i].type == SOCKET_EVENT_RECV_TIMEOUT) {

            // TODO: This is too abrupt
            socket_close(&client->sockets, events[i].handle);

        } else if (events[i].type == SOCKET_EVENT_READY) {

            // Store the handle if this is a new connection
            if (conn->handle == SOCKET_HANDLE_INVALID)
                conn->handle = events[i].handle;

            while (socket_ready(&client->sockets, conn->handle)) {

                if (conn->state == CHTTP_CLIENT_CONN_FLUSHING) {

                    ByteView src = byte_queue_read_buf(&conn->output);

                    int num = 0;
                    if (src.len)
                        num = socket_send(&client->sockets, conn->handle, src.ptr, src.len);

                    if (conn->trace_bytes)
                        print_bytes(CHTTP_STR("<< "), (CHTTP_String){src.ptr, num});

                    byte_queue_read_ack(&conn->output, num);

                    if (byte_queue_error(&conn->output)) {
                        socket_close(&client->sockets, conn->handle);
                        continue;
                    }

                    // Request fully sent, now wait for response
                    if (byte_queue_empty(&conn->output))
                        conn->state = CHTTP_CLIENT_CONN_BUFFERING;
                }

                if (conn->state == CHTTP_CLIENT_CONN_BUFFERING) {

                    // Receive response data
                    int min_recv = 1<<10;
                    byte_queue_write_setmincap(&conn->input, min_recv);

                    ByteView dst = byte_queue_write_buf(&conn->input);

                    int num = 0;
                    if (dst.len)
                        num = socket_recv(&client->sockets, conn->handle, dst.ptr, dst.len);

                    if (conn->trace_bytes)
                        print_bytes(CHTTP_STR(">> "), (CHTTP_String){dst.ptr, num});

                    byte_queue_write_ack(&conn->input, num);

                    if (byte_queue_error(&conn->input)) {
                        socket_close(&client->sockets, conn->handle);
                        continue;
                    }

                    ByteView src = byte_queue_read_buf(&conn->input);
                    int ret = chttp_parse_response(src.ptr, src.len, &conn->response);

                    if (ret == 0) {
                        // Still waiting
                        byte_queue_read_ack(&conn->input, 0);

                        // If the queue reached its limit and we still didn't receive
                        // a complete response, abort the exchange.
                        if (byte_queue_full(&conn->input))
                            socket_close(&client->sockets, conn->handle);
                        continue;
                    }

                    if (ret < 0) {
                        // Invalid response
                        byte_queue_read_ack(&conn->input, 0);
                        socket_close(&client->sockets, conn->handle);
                        continue;
                    }

                    // Ready
                    assert(ret > 0);

                    conn->state = CHTTP_CLIENT_CONN_COMPLETE;
                    conn->result = 0;

                    conn->response.context = client;

                    // Store received cookies in the cookie jar
                    save_cookies(&client->cookie_jar,
                        conn->response.headers,
                        conn->response.num_headers,
                        conn->url.authority.host.text,
                        conn->url.path);

                    // TODO: Handle redirects here
                    break;
                }
            }
        }

        if (conn->state == CHTTP_CLIENT_CONN_COMPLETE) {

            // Decouple from the socket
            socket_set_user(&client->sockets, events[i].handle, NULL);
            socket_close(&client->sockets, events[i].handle);

            // Push to the ready queue
            assert(client->num_ready < CHTTP_CLIENT_CAPACITY);
            int tail = (client->ready_head + client->num_ready) % CHTTP_CLIENT_CAPACITY;
            client->ready[tail] = conn - client->conns;
            client->num_ready++;
        }
    }
}

bool chttp_client_next_response(CHTTP_Client *client,
    int *result, void **user, CHTTP_Response **response)
{
    if (client->num_ready == 0)
        return false;

    CHTTP_ClientConn *conn = &client->conns[client->ready[client->ready_head]];
    client->ready_head = (client->ready_head + 1) % CHTTP_CLIENT_CAPACITY;
    client->num_ready--;

    assert(conn->state == CHTTP_CLIENT_CONN_COMPLETE);

    *result = conn->result;
    *user   = conn->user;
    if (conn->result == CHTTP_OK) {
        *response = &conn->response;
    } else {
        *response = NULL;
    }

    return true;
}

void chttp_free_response(CHTTP_Response *response)
{
    if (response == NULL || response->context == NULL)
        return;
    CHTTP_Client *client = response->context;
    response->context = NULL;

    // TODO: I'm positive there is a better way to do this.
    //       It should just be a bouds check + subtraction.
    CHTTP_ClientConn *conn = NULL;
    for (int i = 0; i < CHTTP_CLIENT_CAPACITY; i++)
        if (&client->conns[i].response == response) {
            conn = &client->conns[i];
            break;
        }
    if (conn == NULL)
        return;

    conn->state = CHTTP_CLIENT_CONN_FREE;
    free(conn->url_buffer.ptr);
    byte_queue_free(&conn->input);
    byte_queue_free(&conn->output);
    client->num_conns--;
}

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

void chttp_client_wait_response(CHTTP_Client *client,
    int *result, void **user, CHTTP_Response **response)
{
    for (;;) {

        void *ptrs[CHTTP_CLIENT_POLL_CAPACITY];
        struct pollfd polled[CHTTP_CLIENT_POLL_CAPACITY];

        EventRegister reg = { ptrs, polled, 0, -1 };
        chttp_client_register_events(client, &reg);

        POLL(reg.polled, reg.num_polled, reg.timeout);

        chttp_client_process_events(client, reg);

        if (chttp_client_next_response(client, result, user, response))
            break;
    }
}

static _Thread_local CHTTP_Client *implicit_client;

static int perform_request(CHTTP_Method method,
    CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_String body,
    CHTTP_Response **response)
{
    if (implicit_client == NULL) {

        implicit_client = malloc(sizeof(CHTTP_Client));
        if (implicit_client == NULL)
            return CHTTP_ERROR_OOM;

        int ret = chttp_client_init(implicit_client);
        if (ret < 0) {
            free(implicit_client);
            implicit_client = NULL;
            return ret;
        }
    }
    CHTTP_Client *client = implicit_client;

    CHTTP_RequestBuilder builder = chttp_client_get_builder(client);
    chttp_request_builder_method(builder, method);
    chttp_request_builder_target(builder, url);
    for (int i = 0; i < num_headers; i++)
        chttp_request_builder_header(builder, headers[i]);
    chttp_request_builder_body(builder, body);
    int ret = chttp_request_builder_send(builder);
    if (ret < 0) return ret;

    int result;
    void *user;
    chttp_client_wait_response(client, &result, &user, response);
    return result;
}

int chttp_get(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_Response **response)
{
    return perform_request(CHTTP_METHOD_GET, url, headers, num_headers, CHTTP_STR(""), response);
}

int chttp_post(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_String body,
    CHTTP_Response **response)
{
    return perform_request(CHTTP_METHOD_POST, url, headers, num_headers, body, response);
}

int chttp_put(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_String body,
    CHTTP_Response **response)
{
    return perform_request(CHTTP_METHOD_PUT, url, headers, num_headers, body, response);
}

int chttp_delete(CHTTP_String url, CHTTP_String *headers,
    int num_headers, CHTTP_Response **response)
{
    return perform_request(CHTTP_METHOD_DELETE, url, headers, num_headers, CHTTP_STR(""), response);
}

////////////////////////////////////////////////////////////////////////////////////////
// src/server.c
////////////////////////////////////////////////////////////////////////////////////////

static void chttp_server_conn_init(CHTTP_ServerConn *conn,
    SocketHandle handle, uint32_t input_buffer_limit,
    uint32_t output_buffer_limit)
{
    conn->state = CHTTP_SERVER_CONN_BUFFERING;
    conn->handle = handle;
    conn->closing = false;
    byte_queue_init(&conn->input, input_buffer_limit);
    byte_queue_init(&conn->output, output_buffer_limit);
}

static void chttp_server_conn_free(CHTTP_ServerConn *conn)
{
    byte_queue_free(&conn->output);
    byte_queue_free(&conn->input);
}

int chttp_server_init(CHTTP_Server *server)
{
    server->input_buffer_limit = 1<<20;
    server->output_buffer_limit = 1<<20;

    server->trace_bytes = false;
    server->reuse_addr = false;
    server->backlog = 32;

    server->num_conns = 0;
    for (int i = 0; i < CHTTP_SERVER_CAPACITY; i++) {
        server->conns[i].state = CHTTP_SERVER_CONN_FREE;
        server->conns[i].gen = 0;
    }

    server->num_ready = 0;
    server->ready_head = 0;

    return socket_manager_init(&server->sockets,
        server->socket_pool, CHTTP_SERVER_CAPACITY);
}

void chttp_server_free(CHTTP_Server *server)
{
    socket_manager_free(&server->sockets);

    for (int i = 0, j = 0; j < server->num_conns; i++) {
        CHTTP_ServerConn *conn = &server->conns[i];
        if (conn->state == CHTTP_SERVER_CONN_FREE)
            continue;
        j++;

        chttp_server_conn_free(conn);
    }
}

void chttp_server_set_input_limit(CHTTP_Server *server, uint32_t limit)
{
    server->input_buffer_limit = limit;
}

void chttp_server_set_output_limit(CHTTP_Server *server, uint32_t limit)
{
    server->output_buffer_limit = limit;
}

void chttp_server_set_trace_bytes(CHTTP_Server *server, bool value)
{
    server->trace_bytes = value;
}

void chttp_server_set_reuse_addr(CHTTP_Server *server, bool reuse)
{
    server->reuse_addr = reuse;
}

void chttp_server_set_backlog(CHTTP_Server *server, int backlog)
{
    server->backlog = backlog;
}

int chttp_server_listen_tcp(CHTTP_Server *server,
    CHTTP_String addr, Port port)
{
    return socket_manager_listen_tcp(&server->sockets,
        addr, port, server->backlog, server->reuse_addr);
}

int chttp_server_listen_tls(CHTTP_Server *server,
    CHTTP_String addr, Port port, CHTTP_String cert_file_name,
    CHTTP_String key_file_name)
{
    return socket_manager_listen_tls(&server->sockets,
        addr, port, server->backlog, server->reuse_addr,
        cert_file_name, key_file_name);
}

int chttp_server_add_certificate(CHTTP_Server *server,
    CHTTP_String domain, CHTTP_String cert_file, CHTTP_String key_file)
{
    return socket_manager_add_certificate(&server->sockets,
        domain, cert_file, key_file);
}

int chttp_server_wakeup(CHTTP_Server *server)
{
    return socket_manager_wakeup(&server->sockets);
}

void chttp_server_register_events(CHTTP_Server *server,
    EventRegister *reg)
{
    socket_manager_register_events(&server->sockets, reg);
}

// Look at the head of the input buffer to see if
// a request was buffered. If it was, change the
// connection's status to WAIT_STATUS and push it
// to the ready queue. If the request is invalid,
// close the socket.
static void
check_request_buffer(CHTTP_Server *server, CHTTP_ServerConn *conn)
{
    assert(conn->state == CHTTP_SERVER_CONN_BUFFERING);

    ByteView src = byte_queue_read_buf(&conn->input);
    int ret = chttp_parse_request(src.ptr, src.len, &conn->request);
    if (ret < 0) {

        // Invalid request
        byte_queue_read_ack(&conn->input, 0);
        socket_close(&server->sockets, conn->handle);

    } else if (ret == 0) {

        // Still waiting
        byte_queue_read_ack(&conn->input, 0);

        // If the queue reached its limit and we still didn't receive
        // a complete request, abort the exchange.
        if (byte_queue_full(&conn->input))
            socket_close(&server->sockets, conn->handle);

    } else {

        // Ready
        assert(ret > 0);

        // Stop receiving I/O events while we are building the response
        socket_silent(&server->sockets, conn->handle, true);

        conn->state = CHTTP_SERVER_CONN_WAIT_STATUS;
        conn->request_len = ret;
        conn->response_offset = byte_queue_offset(&conn->output);

        // Push to the ready queue
        assert(server->num_ready < CHTTP_SERVER_CAPACITY);
        int tail = (server->ready_head + server->num_ready) % CHTTP_SERVER_CAPACITY;
        server->ready[tail] = conn - server->conns;
        server->num_ready++;
    }
}

static void
chttp_server_conn_process_events(CHTTP_Server *server, CHTTP_ServerConn *conn)
{
    if (conn->state == CHTTP_SERVER_CONN_FLUSHING) {

        ByteView src = byte_queue_read_buf(&conn->output);

        int num = 0;
        if (src.len)
            num = socket_send(&server->sockets, conn->handle, src.ptr, src.len);

        if (server->trace_bytes)
            print_bytes(CHTTP_STR("<< "), (CHTTP_String) { src.ptr, num });

        byte_queue_read_ack(&conn->output, num);

        if (byte_queue_error(&conn->output)) {
            socket_close(&server->sockets, conn->handle);
            return;
        }

        if (byte_queue_empty(&conn->output)) {
            // We finished sending the response. Now we can
            // either close the connection or process a new
            // buffered request.
            if (conn->closing) {
                socket_close(&server->sockets, conn->handle);
                return;
            }
            conn->state = CHTTP_SERVER_CONN_BUFFERING;
        }
    }

    if (conn->state == CHTTP_SERVER_CONN_BUFFERING) {

        int min_recv = 1<<10;
        byte_queue_write_setmincap(&conn->input, min_recv);

        // Note that it's extra important that we don't
        // buffer while the user is building the response.
        // If we did that, a resize would invalidate all
        // pointers on the parsed request structure.
        ByteView dst = byte_queue_write_buf(&conn->input);

        int num = 0;
        if (dst.len)
            num = socket_recv(&server->sockets, conn->handle, dst.ptr, dst.len);

        if (server->trace_bytes)
            print_bytes(CHTTP_STR(">> "), (CHTTP_String) { dst.ptr, num });

        byte_queue_write_ack(&conn->input, num);

        if (byte_queue_error(&conn->input)) {
            socket_close(&server->sockets, conn->handle);
        } else {
            check_request_buffer(server, conn);
        }
    }
}

void chttp_server_process_events(CHTTP_Server *server,
    EventRegister reg)
{
    SocketEvent events[CHTTP_SERVER_CAPACITY];
    int num_events = socket_manager_translate_events(&server->sockets, events, reg);

    for (int i = 0; i < num_events; i++) {

        CHTTP_ServerConn *conn = events[i].user;

        if (events[i].type == SOCKET_EVENT_DISCONNECT) {

            chttp_server_conn_free(conn); // TODO: what if this was in the ready queue?
            server->num_conns--;

        } else if (events[i].type == SOCKET_EVENT_CREATION_TIMEOUT) {

            // TODO: This is too abrupt
            socket_close(&server->sockets, events[i].handle);

        } else if (events[i].type == SOCKET_EVENT_RECV_TIMEOUT) {

            // TODO: This is too abrupt
            socket_close(&server->sockets, events[i].handle);

        } else if (events[i].type == SOCKET_EVENT_READY) {

            if (events[i].user == NULL) {

                if (server->num_conns == CHTTP_SERVER_CAPACITY) {
                    socket_close(&server->sockets, events[i].handle);
                    continue;
                }

                int j = 0;
                while (server->conns[j].state != CHTTP_SERVER_CONN_FREE) {
                    j++;
                    assert(i < CHTTP_SERVER_CAPACITY);
                }

                conn = &server->conns[j];
                chttp_server_conn_init(conn,
                    events[i].handle,
                    server->input_buffer_limit,
                    server->output_buffer_limit);
                server->num_conns++;

                socket_set_user(&server->sockets, events[i].handle, conn);
            }

            while (socket_ready(&server->sockets, events[i].handle)
                && conn->state != CHTTP_SERVER_CONN_WAIT_STATUS)
                chttp_server_conn_process_events(server, conn);
        }
    }
}

bool chttp_server_next_request(CHTTP_Server *server,
    CHTTP_Request **request, CHTTP_ResponseBuilder *builder)
{
    if (server->num_ready == 0)
        return false;

    CHTTP_ServerConn *conn = &server->conns[server->ready[server->ready_head]];
    server->ready_head = (server->ready_head + 1) % CHTTP_SERVER_CAPACITY;
    server->num_ready--;

    assert(conn->state == CHTTP_SERVER_CONN_WAIT_STATUS);
    *request = &conn->request;
    *builder = (CHTTP_ResponseBuilder) { server, conn - server->conns, conn->gen };
    return true;
}

void chttp_server_wait_request(CHTTP_Server *server,
    CHTTP_Request **request, CHTTP_ResponseBuilder *builder)
{
    for (;;) {
        void *ptrs[CHTTP_SERVER_POLL_CAPACITY];
        struct pollfd polled[CHTTP_SERVER_POLL_CAPACITY];

        EventRegister reg = { ptrs, polled, 0, -1 };
        chttp_server_register_events(server, &reg);

        POLL(reg.polled, reg.num_polled, reg.timeout);

        chttp_server_process_events(server, reg);

        if (chttp_server_next_request(server, request, builder))
            break;
    }
}

// Get a connection pointer from a response builder.
// If the builder is invalid, returns NULL.
// Note that only connections in the responding states
// can be returned, as any builder is invalidated by
// incrementing the connection's generation counter
// when a response is completed.
static CHTTP_ServerConn*
builder_to_conn(CHTTP_ResponseBuilder builder)
{
    CHTTP_Server *server = builder.server;
    if (server == NULL)
        return NULL;

    if (builder.index > CHTTP_SERVER_CAPACITY)
        return NULL;

    CHTTP_ServerConn *conn = &server->conns[builder.index];
    if (builder.gen != conn->gen)
        return NULL;

    return conn;
}

static const char*
get_status_text(int code)
{
	switch(code) {

		case 100: return "Continue";
		case 101: return "Switching Protocols";
		case 102: return "Processing";

		case 200: return "OK";
		case 201: return "Created";
		case 202: return "Accepted";
		case 203: return "Non-Authoritative Information";
		case 204: return "No Content";
		case 205: return "Reset Content";
		case 206: return "Partial Content";
		case 207: return "Multi-Status";
		case 208: return "Already Reported";

		case 300: return "Multiple Choices";
		case 301: return "Moved Permanently";
		case 302: return "Found";
		case 303: return "See Other";
		case 304: return "Not Modified";
		case 305: return "Use Proxy";
		case 306: return "Switch Proxy";
		case 307: return "Temporary Redirect";
		case 308: return "Permanent Redirect";

		case 400: return "Bad Request";
		case 401: return "Unauthorized";
		case 402: return "Payment Required";
		case 403: return "Forbidden";
		case 404: return "Not Found";
		case 405: return "Method Not Allowed";
		case 406: return "Not Acceptable";
		case 407: return "Proxy Authentication Required";
		case 408: return "Request Timeout";
		case 409: return "Conflict";
		case 410: return "Gone";
		case 411: return "Length Required";
		case 412: return "Precondition Failed";
		case 413: return "Request Entity Too Large";
		case 414: return "Request-URI Too Long";
		case 415: return "Unsupported Media Type";
		case 416: return "Requested Range Not Satisfiable";
		case 417: return "Expectation Failed";
		case 418: return "I'm a teapot";
		case 420: return "Enhance your calm";
		case 422: return "Unprocessable Entity";
		case 426: return "Upgrade Required";
		case 429: return "Too many requests";
		case 431: return "Request Header Fields Too Large";
		case 449: return "Retry With";
		case 451: return "Unavailable For Legal Reasons";

		case 500: return "Internal Server Error";
		case 501: return "Not Implemented";
		case 502: return "Bad Gateway";
		case 503: return "Service Unavailable";
		case 504: return "Gateway Timeout";
		case 505: return "HTTP Version Not Supported";
		case 509: return "Bandwidth Limit Exceeded";
	}
	return "???";
}

static void
write_status(CHTTP_ServerConn *conn, int status)
{
    byte_queue_write_fmt(&conn->output,
		"HTTP/1.1 %d %s\r\n",
		status, get_status_text(status));
}

void chttp_response_builder_status(CHTTP_ResponseBuilder builder, int status)
{
    CHTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != CHTTP_SERVER_CONN_WAIT_STATUS) {
        // Reset all response content and start from scrach.
        byte_queue_remove_from_offset(&conn->output, conn->response_offset);
        conn->state = CHTTP_SERVER_CONN_WAIT_STATUS;
    }

    write_status(conn, status);

    conn->state = CHTTP_SERVER_CONN_WAIT_HEADER;
}

static bool is_header_valid(CHTTP_String str)
{
    bool has_colon = false;
    for (int i = 0; i < str.len; i++) {
        char c = str.ptr[i];
        if (c == ':')
            has_colon = true;
        // Reject control characters (especially \r and \n)
        if (c < 0x20 && c != '\t')
            return false;
    }
    return has_colon;
}

void chttp_response_builder_header(CHTTP_ResponseBuilder builder, CHTTP_String str)
{
    CHTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != CHTTP_SERVER_CONN_WAIT_HEADER)
        return;

    // Header must contain a colon and no control characters
    // to prevent HTTP response splitting attacks
    if (!is_header_valid(str)) return; // Silently drop it

	byte_queue_write(&conn->output, str.ptr, str.len);
	byte_queue_write(&conn->output, "\r\n", 2);
}

static void append_special_headers(CHTTP_ServerConn *conn)
{
    CHTTP_String s;

    if (conn->closing) {
        s = CHTTP_STR("Connection: Close\r\n");
        byte_queue_write(&conn->output, s.ptr, s.len);
    } else {
        s = CHTTP_STR("Connection: Keep-Alive\r\n");
        byte_queue_write(&conn->output, s.ptr, s.len);
    }

    s = CHTTP_STR("Content-Length: ");
    byte_queue_write(&conn->output, s.ptr, s.len);

    conn->content_length_value_offset = byte_queue_offset(&conn->output);

    #define TEN_SPACES "          "
    _Static_assert(sizeof(TEN_SPACES) == 10+1, "");

    s = CHTTP_STR(TEN_SPACES "\r\n");
    byte_queue_write(&conn->output, s.ptr, s.len);

    byte_queue_write(&conn->output, "\r\n", 2);
	conn->content_length_offset = byte_queue_offset(&conn->output);
}

static void patch_special_headers(CHTTP_ServerConn *conn)
{
    int content_length = byte_queue_size_from_offset(&conn->output, conn->content_length_offset);

    char tmp[11];
    int len = snprintf(tmp, sizeof(tmp), "%d", content_length);
    assert(len > 0 && len < 11);

    byte_queue_patch(&conn->output, conn->content_length_value_offset, tmp, len);
}

void chttp_response_builder_body(CHTTP_ResponseBuilder builder, CHTTP_String str)
{
    CHTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state == CHTTP_SERVER_CONN_WAIT_HEADER) {
        append_special_headers(conn);
        conn->state = CHTTP_SERVER_CONN_WAIT_BODY;
    }

    if (conn->state != CHTTP_SERVER_CONN_WAIT_BODY)
        return;

    byte_queue_write(&conn->output, str.ptr, str.len);
}

void chttp_response_builder_body_cap(CHTTP_ResponseBuilder builder, int cap)
{
    CHTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state == CHTTP_SERVER_CONN_WAIT_HEADER) {
        append_special_headers(conn);
        conn->state = CHTTP_SERVER_CONN_WAIT_BODY;
    }

    if (conn->state != CHTTP_SERVER_CONN_WAIT_BODY)
        return;

    byte_queue_write_setmincap(&conn->output, cap);
}

char *chttp_response_builder_body_buf(CHTTP_ResponseBuilder builder, int *cap)
{
    CHTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return NULL;

    if (conn->state == CHTTP_SERVER_CONN_WAIT_HEADER) {
        append_special_headers(conn);
        conn->state = CHTTP_SERVER_CONN_WAIT_BODY;
    }

    if (conn->state != CHTTP_SERVER_CONN_WAIT_BODY)
        return NULL;

    ByteView tmp = byte_queue_write_buf(&conn->output);
    *cap = tmp.len;
    return tmp.ptr;
}

void chttp_response_builder_body_ack(CHTTP_ResponseBuilder builder, int num)
{
    CHTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state != CHTTP_SERVER_CONN_WAIT_BODY)
        return;

    byte_queue_write_ack(&conn->output, num);
}

void chttp_response_builder_send(CHTTP_ResponseBuilder builder)
{
    CHTTP_ServerConn *conn = builder_to_conn(builder);
    if (conn == NULL)
        return;

    if (conn->state == CHTTP_SERVER_CONN_WAIT_STATUS) {
        write_status(conn, 500);
        conn->state = CHTTP_SERVER_CONN_WAIT_HEADER;
    }

    if (conn->state == CHTTP_SERVER_CONN_WAIT_HEADER) {
        append_special_headers(conn);
        conn->state = CHTTP_SERVER_CONN_WAIT_BODY;
    }

    assert(conn->state == CHTTP_SERVER_CONN_WAIT_BODY);
    patch_special_headers(conn);

    // Remove the buffered request
    byte_queue_read_ack(&conn->input, conn->request_len);

    conn->state = CHTTP_SERVER_CONN_FLUSHING;
    conn->gen++;

    // Enable back I/O events
    socket_silent(&builder.server->sockets, conn->handle, false);

    chttp_server_conn_process_events(builder.server, conn);
}

////////////////////////////////////////////////////////////////////////////////////////
// Copyright 2025 Francesco Cozzuto
//
// Permission is hereby granted, free of charge, to any person
// obtaining a copy of this software and associated documentation
// files (the "Software"), to deal in the Software without
// restriction, including without limitation the rights to use,
// copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom
// the Software is furnished to do so, subject to the following
// conditions:
//
// The above copyright notice and this permission notice shall
// be included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
// OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
// WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
////////////////////////////////////////////////////////////////////////////////////////
