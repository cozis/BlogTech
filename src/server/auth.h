#ifndef AUTH_INCLUDED
#define AUTH_INCLUDED

#include <time.h>
#include "../common/chttp.h"

#define BAD_NONCE 0
#define MAX_NONCES 32
#define MIN_PASSWORD_LEN 32

typedef struct {
    uint64_t value;
    time_t   expire;
} AppliedNonce;

typedef struct {
    char         password_buf[1<<8];
    HTTP_String  password;
    AppliedNonce nonces[MAX_NONCES];
} Auth;

int  auth_init(Auth *auth, HTTP_String password_file);
void auth_free(Auth *auth);
int  auth_verify(Auth *auth, HTTP_Request *request);

#endif // AUTH_INCLUDED
