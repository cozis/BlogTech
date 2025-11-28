#ifndef ACME_INCLUDED
#define ACME_INCLUDED

#include <openssl/evp.h>
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

    // We are waiting for our certificate order
    // to be approved.
    ACME_STATE_CREATE_CERT,

    // Waiting for challenge authorization
    ACME_STATE_CHALLENGE_1,

    // Challenge has been requested, waiting for timeout
    ACME_STATE_CHALLENGE_2,

    // Polling challenge status
    ACME_STATE_CHALLENGE_3,

    // Finalizing the order
    ACME_STATE_FINALIZE,

    // Requesting the certificate
    ACME_STATE_CERTIFICATE,

    // A certificate was created, so we can go
    // idle until it expires.
    ACME_STATE_WAIT,

    // Error state
    ACME_STATE_ERROR,
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

    HTTP_Client *client;

    int num_domains;
    HTTP_String domains[ACME_DOMAIN_LIMIT];

    ACME_URLSet urls;
    bool urls_loaded;

    HTTP_String nonce;
    HTTP_String account_url;
    HTTP_String email;
    bool agreed_to_terms_of_service;

    EVP_PKEY *private_key;
    HTTP_String public_key_jwk;

    HTTP_String finalize_url;
    HTTP_String certificate_url;

    int num_challenges;
    int current_challenge;
    ACME_Challenge challenges[ACME_DOMAIN_LIMIT];

} ACME;

int  acme_init(ACME *acme, HTTP_Client *client, HTTP_String *domains, int num_domains);
void acme_free(ACME *acme);
int  acme_timeout(ACME *acme);
void acme_process_timeout(ACME *acme);
bool acme_process_request(ACME *acme, HTTP_Request *request, HTTP_ResponseBuilder builder);
void acme_process_response(ACME *acme, int result, HTTP_Response *response);

#endif // ACME_INCLUDED
