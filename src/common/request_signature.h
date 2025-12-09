#ifndef REQUEST_SIGNATURE_INCLUDED
#define REQUEST_SIGNATURE_INCLUDED

#include "../lib/http.h"

int calculate_request_signature(
    CHTTP_Method method,
    string path,
    string host,
    string date,
    u32    expire,
    string nonce,
    string body,
    string secret,
    char*  dst);

#endif // REQUEST_SIGNATURE_INCLUDED
