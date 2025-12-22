#include "request_signature.h"

#include "lib/string_builder.h"

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

int calculate_request_signature(
    CHTTP_Method method,
    string   path,
    string   host,
    UnixTime date,
    u32      expire,
    Nonce    nonce,
    string   body,
    string   secret,
    char*    dst,
    int      cap)
{
    char body_hash[32]; // TODO: this should not be hard-coded
    if (sha256(body.ptr, body.len, body_hash) < 0)
        return -1;

    char pool[1<<12];
    StringBuilder b;
    sb_init(&b, pool, sizeof(pool));
    sb_push_mod(&b, ENCODING_B64);
        sb_push_mod(&b, ENCODING_HMAC);
            sb_write_str(&b, secret);
            sb_flush(&b);
            sb_write_str(&b, method_to_str(method));
            sb_write_str(&b, S("\n"));
            sb_push_mod(&b, ENCODING_PCTL);
                sb_write_str(&b, path);
            sb_pop_mod(&b);
            sb_write_str(&b, S("\n"));
            sb_write_str(&b, host);
            sb_write_str(&b, S("\n"));
            sb_write_u64(&b, date);
            sb_write_str(&b, S("\n"));
            sb_write_u32(&b, expire);
            sb_write_str(&b, S("\n"));
            sb_push_mod(&b, ENCODING_B64);
                sb_write_str(&b, (string) { nonce.data, RAW_NONCE_LEN });
            sb_pop_mod(&b);
            sb_write_str(&b, S("\n"));
            sb_write_u64(&b, body.len);
            sb_write_str(&b, S("\n"));
            sb_push_mod(&b, ENCODING_HEXL);
                sb_write_str(&b, ((string) { body_hash, sizeof(body_hash) }));
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
