#ifndef AUTH_INCLUDED
#define AUTH_INCLUDED

#include <openssl/evp.h>
#include <chttp.h>

#define BAD_NONCE 0
#define MAX_NONCES 32

typedef struct {
    uint64_t value;
    time_t   expire;
} AppliedNonce;

typedef struct {
    EVP_PKEY *admin_key;
    AppliedNonce nonces[MAX_NONCES];
} Auth;

int  auth_init(Auth *auth);
void auth_free(Auth *auth);
int  auth_verify(Auth *auth, HTTP_Request *request);

#endif // AUTH_INCLUDED
