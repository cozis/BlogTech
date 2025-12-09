#ifndef REQUEST_SIGNATURE_INCLUDED
#define REQUEST_SIGNATURE_INCLUDED

#include "lib/chttp.h"

#define NONCE_RAW_LEN 32

int calculate_request_signature(
    CHTTP_Method method,
    string path,
    string host,
    string date,
    u32    expire,
    string nonce,
    string body,
    string secret,
    char*  dst,
    int    cap);

#endif // REQUEST_SIGNATURE_INCLUDED
