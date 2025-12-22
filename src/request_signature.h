#ifndef REQUEST_SIGNATURE_INCLUDED
#define REQUEST_SIGNATURE_INCLUDED

#include "lib/time.h"
#include "lib/http.h"

#define NONCE_RAW_LEN 32

typedef struct {
    char data[RAW_NONCE_LEN];
} Nonce;

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
    int      cap);

#endif // REQUEST_SIGNATURE_INCLUDED
