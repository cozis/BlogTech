#include "auth.h"
#include "../lib/chttp.h"
#include "../lib/file_system.h"
#include "../common/request_signature.h"

int auth_init(Auth *auth, string password_file)
{
    auth->password.ptr = NULL;
    auth->password.len = 0;

    for (int i = 0; i < MAX_NONCES; i++)
        auth->nonces[i].value = BAD_NONCE;

    if (password_file.len == 0)
        return 0;

    string content;
    if (file_read_all(password_file, &content) < 0)
        return -1;

    // Trim trailing newlines
    while (content.len > 0 &&
           (content.ptr[content.len - 1] == '\n' ||
            content.ptr[content.len - 1] == '\r'))
        content.len--;

    if (content.len >= sizeof(auth->password_buf)) {
        free(content.ptr);
        return -1;
    }

    memcpy_(auth->password_buf, content.ptr, content.len);
    auth->password.ptr = auth->password_buf;
    auth->password.len = content.len;
    free(content.ptr);

    return 0;
}

void auth_free(Auth *auth)
{
    (void) auth;
}

static b8 is_invalidated(Auth *auth, u64 nonce_value)
{
    for (int i = 0; i < MAX_NONCES; i++)
        if (nonce_value == auth->nonces[i].value)
            return true;
    return false;
}

static u64 parse_nonce(string str)
{
    u64 value = 0;
    for (int i = 0; i < str.len; i++) {
        char c = str.ptr[i];
        if (c < '0' || c > '9')
            return BAD_NONCE;
        u64 prev = value;
        value = value * 10 + (c - '0');
        if (value < prev) // overflow
            return BAD_NONCE;
    }
    return value;
}

static u32 parse_expire(string str)
{
    u32 value = 0;
    for (int i = 0; i < str.len; i++) {
        char c = str.ptr[i];
        if (c < '0' || c > '9')
            return 0;
        u32 prev = value;
        value = value * 10 + (c - '0');
        if (value < prev) // overflow
            return 0;
    }
    return value;
}

// Parse a timestamp string into a time_t value.
// The timestamp format is Unix epoch seconds (decimal integer),
// e.g., "1733788800" for 2024-12-10 00:00:00 UTC.
static time_t parse_timestamp(string str)
{
    time_t value = 0;
    for (int i = 0; i < str.len; i++) {
        char c = str.ptr[i];
        if (c < '0' || c > '9')
            return 0;
        time_t prev = value;
        value = value * 10 + (c - '0');
        if (value < prev) // overflow
            return 0;
    }
    return value;
}

static b8 is_expired(string timestamp_str, u32 expire_seconds)
{
    time_t timestamp = parse_timestamp(timestamp_str);
    if (timestamp == 0)
        return true;
    time_t now = time(NULL);
    return now > timestamp + (time_t) expire_seconds;
}

// Remove expired nonces from the table
static void cleanup_expired_nonces(Auth *auth)
{
    time_t now = time(NULL);
    for (int i = 0; i < MAX_NONCES; i++) {
        if (auth->nonces[i].value != BAD_NONCE && auth->nonces[i].expire < now) {
            auth->nonces[i].value = BAD_NONCE;
        }
    }
}

static b8 store_nonce(Auth *auth, u64 nonce_value, time_t expire)
{
    int i = 0;
    while (i < MAX_NONCES && auth->nonces[i].value != BAD_NONCE)
        i++;

    if (i == MAX_NONCES) {
        // Try to clean up expired nonces to make room
        cleanup_expired_nonces(auth);
        i = 0;
        while (i < MAX_NONCES && auth->nonces[i].value != BAD_NONCE)
            i++;
        if (i == MAX_NONCES)
            return false;
    }

    auth->nonces[i].value = nonce_value;
    auth->nonces[i].expire = expire;
    return true;
}

// Returns 0 if the request is verified, 1 if the request is
// not verified, and -1 if an error occurred.
int auth_verify(Auth *auth, CHTTP_Request *request)
{
    // Reject all requests if password is too short
    if (auth->password.len < MIN_PASSWORD_LEN)
        return 1;

    int idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("Host"));
    if (idx < 0)
        return 1;
    string host = request->headers[idx].value;

    idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("X-BlogTech-Nonce"));
    if (idx < 0)
        return 1;
    string nonce_str = request->headers[idx].value;

    idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("X-BlogTech-Timestamp"));
    if (idx < 0)
        return 1;
    string timestamp = request->headers[idx].value;

    idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("X-BlogTech-Expire"));
    if (idx < 0)
        return 1;
    string expire_str = request->headers[idx].value;

    idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("X-BlogTech-Signature"));
    if (idx < 0)
        return 1;
    string signature = request->headers[idx].value;

    // Parse the expire value
    u32 expire = parse_expire(expire_str);
    if (expire == 0)
        return 1;

    // Parse the nonce value
    u64 nonce_value = parse_nonce(nonce_str);
    if (nonce_value == BAD_NONCE)
        return 1;

    // Check if nonce has already been used
    if (is_invalidated(auth, nonce_value))
        return 1;

    // Check if the request has expired
    if (is_expired(timestamp, expire))
        return 1;

    // Verify the signature
    char expected_signature[64];
    int ret = calculate_request_signature(
        request->method,
        request->url.path,
        host,
        timestamp,
        expire,
        nonce_str,
        request->body,
        auth->password,
        expected_signature);
    if (ret < 0)
        return -1;

    if (signature.len != sizeof(expected_signature)
        || memcmp(expected_signature, signature.ptr, sizeof(expected_signature)))
        return 1;

    // Store the nonce to prevent replay attacks
    time_t nonce_expire = parse_timestamp(timestamp) + (time_t) expire;
    if (!store_nonce(auth, nonce_value, nonce_expire))
        return -1;

    return 0;
}
