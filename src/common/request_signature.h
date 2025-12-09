#ifndef REQUEST_SIGNATURE_INCLUDED
#define REQUEST_SIGNATURE_INCLUDED

#include <stdint.h>
#include "chttp.h"

int calculate_request_signature(
    HTTP_Method method,
    HTTP_String path,
    HTTP_String host,
    HTTP_String date,
    uint32_t    expire,
    HTTP_String nonce,
    HTTP_String body,
    HTTP_String secret,
    char *dst);

#endif // REQUEST_SIGNATURE_INCLUDED
