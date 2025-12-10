#ifndef AUTH_INCLUDED
#define AUTH_INCLUDED

#include "static_config.h"

#include "lib/time.h"
#include "lib/http.h"
#include "lib/logger.h"

typedef struct {
    char     value[RAW_NONCE_LEN];
    UnixTime expire;
} AppliedNonce;

typedef struct {
    Logger *logger;
    char    password_buf[1<<8];
    string  password;
    AppliedNonce nonces[MAX_NONCES];
} Auth;

int  auth_init(Auth *auth, string password_file, Logger *logger);
void auth_free(Auth *auth);
int  auth_verify(Auth *auth, CHTTP_Request *request);

#endif // AUTH_INCLUDED
