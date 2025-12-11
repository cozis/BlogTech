#include "lib/http.h"

#include "auth.h"
#include "lib/basic.h"
#include "lib/time.h"
#include "request_signature.h"

#include "lib/encode.h"
#include "lib/file_system.h"

int auth_init(Auth *auth, string password_file, Logger *logger)
{
    auth->logger = logger;

    auth->password = EMPTY_STRING;

    for (int i = 0; i < MAX_NONCES; i++)
        auth->nonces[i].expire = INVALID_UNIX_TIME;

    if (password_file.len == 0)
        return 0;

    string content;
    if (file_read_all(password_file, &content) < 0) {
        log(logger, S("Couldn't read password from '{}'\n"), V(password_file));
        return -1;
    }

    content = trim(content);

    if (content.len >= sizeof(auth->password_buf)) {
        log(logger, S("Password is longer than expected\n"), V());
        free(content.ptr);
        return -1;
    }

    memcpy_(auth->password_buf, content.ptr, content.len);
    auth->password.ptr = auth->password_buf;
    auth->password.len = content.len;
    free(content.ptr);

    log(logger, S("Authentication system initialized\n"), V());
    return 0;
}

void auth_free(Auth *auth)
{
    (void) auth;
}

static b8 is_invalidated(Auth *auth, char *nonce)
{
    for (int i = 0; i < MAX_NONCES; i++)
        if (!memcmp(nonce, auth->nonces[i].value, RAW_NONCE_LEN))
            return true;
    return false;
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
    UnixTime now = get_current_unix_time();
    if (now == INVALID_UNIX_TIME) {
        // TODO
    }
    return now > timestamp + (time_t) expire_seconds;
}

// Remove expired nonces from the table
static void cleanup_expired_nonces(Auth *auth)
{
    UnixTime now = get_current_unix_time();
    if (now == INVALID_UNIX_TIME) {
        // TODO
    }
    for (int i = 0; i < MAX_NONCES; i++)
        if (auth->nonces[i].expire != INVALID_UNIX_TIME &&
            auth->nonces[i].expire < now)
            auth->nonces[i].expire = INVALID_UNIX_TIME;
}

static b8 store_nonce(Auth *auth, char *nonce, UnixTime expire)
{
    int i = 0;
    while (i < MAX_NONCES && auth->nonces[i].expire != INVALID_UNIX_TIME)
        i++;

    if (i == MAX_NONCES) {

        // Try to clean up expired nonces to make room
        cleanup_expired_nonces(auth);

        // Look again
        i = 0;
        while (i < MAX_NONCES && auth->nonces[i].expire != INVALID_UNIX_TIME)
            i++;

        // No luck
        if (i == MAX_NONCES)
            return false;
    }

    memcpy(auth->nonces[i].value, nonce, RAW_NONCE_LEN);
    auth->nonces[i].expire = expire;
    return true;
}

// Returns 0 if the request is verified, 1 if the request is
// not verified, and -1 if an error occurred.
int auth_verify(Auth *auth, CHTTP_Request *request)
{
    log(auth->logger, S("Verifying request authentication\n"), V());

    // Reject all requests if password is too short
    if (auth->password.len < MIN_PASSWORD_LEN) {
        log(auth->logger, S("Request rejected preemptively because the password is too short\n"), V());
        return 1;
    }

    string path = request->url.path;
    if (path.len > 0 && path.ptr[0] == '/') {
        path.ptr++;
        path.len--;
    }

    int idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("Host"));
    if (idx < 0) {
        log(auth->logger, S("Request marked as not authenticated because it's missing the 'Host' header\n"), V());
        return 1;
    }
    string host = request->headers[idx].value;

    // Remove port from the host (this is a very bad way to do it)
    {
        int semicol = -1;
        for (int i = 0; i < host.len; i++)
            if (host.ptr[i] == ':')
                semicol = i;
        if (semicol > -1)
            host.len = semicol;
    }

    idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("X-BlogTech-Nonce"));
    if (idx < 0) {
        log(auth->logger, S("Request marked as not authenticated because it's missing the 'X-BlogTech-Nonce' header\n"), V());
        return 1;
    }
    string nonce_str = request->headers[idx].value;

    idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("X-BlogTech-Timestamp"));
    if (idx < 0) {
        log(auth->logger, S("Request marked as not authenticated because it's missing the 'X-BlogTech-Timestamp' header\n"), V());
        return 1;
    }
    string timestamp = request->headers[idx].value;

    idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("X-BlogTech-Expire"));
    if (idx < 0) {
        log(auth->logger, S("Request marked as not authenticated because it's missing the 'X-BlogTech-Expire' header\n"), V());
        return 1;
    }
    string expire_str = request->headers[idx].value;

    idx = chttp_find_header(
        request->headers,
        request->num_headers,
        CHTTP_STR("X-BlogTech-Signature"));
    if (idx < 0) {
        log(auth->logger, S("Request marked as not authenticated because it's missing the 'X-BlogTech-Signature' header\n"), V());
        return 1;
    }
    string signature = request->headers[idx].value;

    // Parse the expire value
    u32 expire = parse_expire(expire_str);
    if (expire == 0) {
        log(auth->logger, S("Request marked as not authenticated because the expiration '{}' is invalid\n"), V(expire_str));
        return 1;
    }

    // Parse nonce
    char nonce[BASE64_LEN(RAW_NONCE_LEN)];
    if (nonce_str.len > sizeof(nonce)) {
        log(auth->logger, S("Request marked as not authenticated because the nonce is too long\n"), V());
        return 1;
    }
    memcpy(nonce, nonce_str.ptr, nonce_str.len);
    int ret = decode_inplace(nonce, nonce_str.len, sizeof(nonce), ENCODING_B64);
    if (ret != RAW_NONCE_LEN) {
        log(auth->logger, S("Request marked as not authenticated because the nonce couldn't be decode from Base64\n"), V());
        return 1;
    }

    // Check if nonce has already been used
    if (is_invalidated(auth, nonce)) {
        log(auth->logger, S("Request marked as not authenticated because the nonce was invalidated\n"), V());
        return 1;
    }

    // Check if the request has expired
    if (is_expired(timestamp, expire)) {
        log(auth->logger, S("Request marked as not authenticated because it expired\n"), V());
        return 1;
    }

    // Verify the signature
    char expected_signature_buf[128];
    ret = calculate_request_signature(
        request->method,
        path,
        host,
        timestamp,
        expire,
        nonce_str,
        request->body,
        auth->password,
        expected_signature_buf,
        sizeof(expected_signature_buf));
    if (ret < 0) {
        log(auth->logger, S("Request verification failed because it wasn't possible to calculate the signature\n"), V());
        return -1;
    }
    string expected_signature = { expected_signature_buf, ret };

    if (!streq(signature, expected_signature)) {
        log(auth->logger, S("Request marked as not authenticated because its signature is invalid\n"), V());
        return 1;
    }

    // Store the nonce to prevent replay attacks
    time_t nonce_expire = parse_timestamp(timestamp) + (time_t) expire;
    if (!store_nonce(auth, nonce, nonce_expire)) {
        log(auth->logger, S("Request verification failed because the nonce store is full\n"), V());
        return -1;
    }

    log(auth->logger, S("Request marked as authenticated\n"), V());
    return 0;
}
