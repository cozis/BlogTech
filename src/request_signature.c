#include "request_signature.h"

#include "lib/string_builder.h"

//////////////////////////////////////////////////////////////////
// SIGNING FUNCTION
//////////////////////////////////////////////////////////////////

// REQUEST AUTHENTICATION
//
// Requests are signed by clients using a secret shared with
// the server. The server only allows PUT and DELETE operations
// when a request is properly signed.
//
// The signing algorithm is HMAC-SHA256. Of course what is
// being signed is not the entire request string, but a canonical
// representation of it including only relevant information
// for its processing. The signature is then stored in the
// X-BlogTech-Signature header. To verify that a request is
// legitimate, a server recalculates the signature and checks
// whether the result matches the value of X-BlogTech-Signature.
//
// The canonical string must contain:
//   1. method
//   2. path
//   3. host
//   5. Date
//   6. expiration
//   7. nonce
//   8. content length
//   9. content hash

static string method_to_str(CHTTP_Method method)
{
    switch (method) {
    case CHTTP_METHOD_GET    : return S("GET");
    case CHTTP_METHOD_HEAD   : return S("HEAD");
    case CHTTP_METHOD_POST   : return S("POST");
    case CHTTP_METHOD_PUT    : return S("PUT");
    case CHTTP_METHOD_DELETE : return S("DELETE");
    case CHTTP_METHOD_CONNECT: return S("CONNECT");
    case CHTTP_METHOD_OPTIONS: return S("OPTIONS");
    case CHTTP_METHOD_TRACE  : return S("TRACE");
    case CHTTP_METHOD_PATCH  : return S("PATCH");
    default:break;
    }
    return S("???");
}

int calculate_request_signature(
    CHTTP_Method method,
    string path,
    string host,
    string date,
    u32    expire,
    string nonce,
    string body,
    string secret,
    char *dst,
    int   cap)
{
    char body_hash[32];
    if (sha256(body.ptr, body.len, body_hash) < 0)
        return -1;

    // Convert expire and body length to strings
    char expire_str[16];
    int expire_len = snprintf(expire_str, sizeof(expire_str), "%u", expire);
    if (expire_len < 0 || expire_len >= (int) sizeof(expire_str))
        return -1;

    char body_len_str[16];
    int body_len_len = snprintf(body_len_str, sizeof(body_len_str), "%d", body.len);
    if (body_len_len < 0 || body_len_len >= (int) sizeof(body_len_str))
        return -1;

    char pool[1<<12];
    StringBuilder b;
    sb_init(&b, pool, sizeof(pool));
    sb_push_mod(&b, ENCODING_B64);
        sb_push_mod(&b, ENCODING_HMAC);
            sb_write(&b, secret);
            sb_flush(&b);
            sb_write(&b, method_to_str(method));
            sb_write(&b, S("\n"));
            sb_push_mod(&b, ENCODING_PCTL);
                sb_write(&b, path);
            sb_pop_mod(&b);
            sb_write(&b, S("\n"));
            sb_write(&b, host);
            sb_write(&b, S("\n"));
            sb_write(&b, date);
            sb_write(&b, S("\n"));
            sb_write(&b, ((string) { expire_str, expire_len }));
            sb_write(&b, S("\n"));
            sb_write(&b, nonce);
            sb_write(&b, S("\n"));
            sb_write(&b, ((string) { body_len_str, body_len_len }));
            sb_write(&b, S("\n"));
            sb_push_mod(&b, ENCODING_HEXL);
                sb_write(&b, ((string) { body_hash, sizeof(body_hash) }));
            sb_pop_mod(&b);
        sb_pop_mod(&b);
    sb_pop_mod(&b);

    if (b.status < 0)
        return b.status;
    assert(b.status == 0);

    if (b.len <= cap)
        memcpy(dst, b.dst, b.len);
    return b.len;
}
