#include "auth.h"

int auth_init(Auth *auth)
{
    for (int i = 0; i < MAX_NONCES; i++)
        auth->nonces[i].value = BAD_NONCE;
    return 0;
}

void auth_free(Auth *auth)
{
}

// Returns 0 if the request is verified, 1 if the request is
// not verified, and -1 if an error occurred.
int auth_verify(Auth *auth, HTTP_Request *request)
{
    // TODO: Calculate the HMAC of the relevant request information
    //       and check whether its BlogTech-Signature header contains
    //       that HMAC. If they match, the request is authenticated,
    //       else it's not.
    //       If the request expired (it must contain an expiration
    //       time which must be part of the signature) or if the nonce
    //       was already invalidated, consider the request as not
    //       authenticated.
    return 0;
}
