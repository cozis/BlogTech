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

    ACME_STATE_CHALLENGE_2,

    // Challenge has been requested, waiting for timeout
    ACME_STATE_CHALLENGE_3,

    // Polling challenge status
    ACME_STATE_CHALLENGE_4,

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
    HTTP_String new_account;
    HTTP_String new_nonce;
    HTTP_String new_order;
    HTTP_String renewal_info;
    HTTP_String revoke_cert;
} ACME_URLSet;

// Represents a domain name that needs certifying
typedef struct {

    // The actual domain (wildcards are okay)
    //
    //   example.com
    //   *.example.com
    //
    // All "name" fields of the domain array are
    // mallocated in the same region.
    HTTP_String name;

    // When a certificate is being issued and
    // the client is working on the challenges,
    // these fields are set.
    HTTP_String challenge_token;
    HTTP_String challenge_url;
    HTTP_String authorization_url;

} ACME_Domain;

typedef struct {

    // User parameters
    HTTP_String email;
    HTTP_String common_name;
    HTTP_String country;
    HTTP_String org;
    bool agreed_to_terms_of_service;

    // State machine variable
    ACME_State state;

    // List of domains that need verifying
    // The "name" field of each domain is set at
    // startup, while the others are only used
    // during the challenges.
    int num_domains;
    ACME_Domain domains[ACME_DOMAIN_LIMIT];

    // List of endpoints for the ACME server.
    // This is set once at startup by requesting
    // the /directory endpoint.
    ACME_URLSet urls;

    // Every request to the ACME server needs a
    // previously issued nonce. After requesting
    // the /directory endpoint, a first nonce is
    // requested. The nonce is consumed at each
    // request but a new one is issued alongside
    // every response. This if re-malloc'd at each
    // request.
    HTTP_String nonce;

    // This is the account URL. It's set if and
    // only if an account was created.
    HTTP_String account_url;

    // Key pair for the account. This is generated
    // before requesting an account to be created.
    EVP_PKEY *account_key;

    // When an order is created but the challenges
    // are yet to be completed, these fields are
    // set to the finalization URL and certificate
    // URL. They are allocated in batch.
    HTTP_String finalize_url;
    HTTP_String certificate_url;

    // Number of challenges that were resolved.
    // When this value equals the domain count,
    // the order can be finalized.
    int resolved_challenges;

} ACME;

int acme_init(ACME *acme, HTTP_String email,
    HTTP_String *domains, int num_domains,
    HTTP_Client *client);

void acme_free(ACME *acme);

void acme_agree_to_terms_of_service(ACME *acme);

int acme_timeout(ACME *acme);

void acme_process_timeout(ACME *acme, HTTP_Client *client);

bool acme_process_request(ACME *acme, HTTP_Request *request,
    HTTP_ResponseBuilder builder, HTTP_Client *client,
    HTTP_Server *server);

void acme_process_response(ACME *acme, int result,
    HTTP_Response *response, HTTP_Client *client,
    HTTP_Server *server);

#endif // ACME_INCLUDED
