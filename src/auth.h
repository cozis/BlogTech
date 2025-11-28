#ifndef AUTH_INCLUDED
#define AUTH_INCLUDED

#define BAD_NONCE 0
#define MAX_NONCES 32

typedef struct {
    uint64_t value;
    Time     expire;
} AppliedNonce;

typedef struct {
    PublicKey admin_key;
    AppliedNonce nonces[MAX_NONCES];
} Auth;

void auth_init(Auth *auth);
void auth_free(Auth *auth);
int  auth_verify(Auth *auth, HTTP_Request *request);

#endif // AUTH_INCLUDED
