#ifndef AUTH_INCLUDED
#define AUTH_INCLUDED

#include "static_config.h"
#include "request_signature.h"

#include "lib/time.h"
#include "lib/http.h"
#include "lib/logger.h"

#define PASSWORD_LIMIT (1<<8)
#define INVALID_NONCE_LIMIT (1<<8)

// Structure representing the nonce of a request
// that has been processed.
typedef struct {

    // Binary data of the nonce
    Nonce value;

    // Its expiration time in UNIX time. If this
    // structure is unused, this is set to INVALID_UNIX_TIME
    UnixTime expire;

} InvalidNonce;

typedef struct {

    // If set, any request is considered authorized
    b8 skip;

    // Logger used by the authentication system
    Logger *logger;

    // Password string and its backing memory
    string password;
    char   password_buf[PASSWORD_LIMIT];

    // Sparse list of invalid nonces
    InvalidNonce invalid_nonces[INVALID_NONCE_LIMIT];

} Auth;

// Initialize the authentication system
//
// Returns 0 on success or -1 on error. If the provided
// password is empty and skip_auth_check is not set, it
// is considered an error.
//
// The logger may be empty.
int auth_init(Auth *auth, string password_file, b8 skip_auth_check, Logger *logger);

// Deinitialize the authentication system
void auth_free(Auth *auth);

// Verify whether a request is authenticated
//
// Returns 0 if the request is authenticated, 1 if
// it wasn't, and -1 if an internal error occurred.
int auth_verify(Auth *auth, CHTTP_Request *request);

#endif // AUTH_INCLUDED
