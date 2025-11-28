#ifndef ACME_INCLUDED
#define ACME_INCLUDED

#include <chttp.h>

typedef enum {

    // Waiting for the /directory object.
    ACME_STATE_DIRECTORY,

    // The /directory was received and now we
    // are waiting for the first nonce.
    ACME_STATE_FIRST_NONCE,

    // We got the first nonce and we are now
    // waiting for our account to be approved.
    ACME_STATE_CREATE_ACCOUNT,

    // A certificate was created, so we can go
    // idle until it expires.
    ACME_STATE_WAIT_EXPIRATION,

    // We are waiting for our certificate order
    // to be approved.
    ACME_STATE_CREATE_CERT,
} ACME_State;

#define ACME_DOMAIN_LIMIT 32

typedef struct {
    HTTP_String token;
    HTTP_String url;
} ACME_Challenge;

typedef struct {
    HTTP_String new_account;
    HTTP_String new_nonce;
    HTTP_String new_order;
    HTTP_String renewal_info;
    HTTP_String revoke_cert;
} ACME_URLSet;

typedef struct {
    ACME_State state;

    int num_domains;
    HTTP_String domains[ACME_DOMAIN_LIMIT];

    ACME_URLSet urls;

    int num_challenges;
    int current_challenge;
    ACME_Challenge challenges[ACME_DOMAIN_LIMIT];

} ACME;

int  acme_init(ACME *acme, HTTP_Client *client);
void acme_free(ACME *acme);
int  acme_timeout(ACME *acme);
bool acme_process_request(ACME *acme, HTTP_Request *request, HTTP_RequestBuilder builder);
void acme_process_response(ACME *acme, int result, HTTP_Response *response);

#endif // ACME_INCLUDED
