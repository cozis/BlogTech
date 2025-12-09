#ifndef ACME_INCLUDED
#define ACME_INCLUDED

#include <openssl/evp.h>

#include "../lib/time.h"
#include "../lib/chttp.h"

#define ACME_DOMAIN_LIMIT 32

// RFC 8555 doesn't specify a length for a nonce string,
// but the Pebble client implemented by Let's Encrypt is
// 22 characters long. We allocate 100 bytes just to be
// safe.
#define ACME_NONCE_CAPACITY 100

typedef struct {

    /////////////////////////////////////////////
    // General

    string directory_url;

    b8     dont_verify_cert;

    /////////////////////////////////////////////
    // Information

    string email;

    string country;
    string organization;

    string domains[ACME_DOMAIN_LIMIT];
    int    num_domains;

    b8     agree_tos;

    /////////////////////////////////////////////
    // File paths

    string account_key_file;
    string certificate_file;
    string certificate_key_file;

    /////////////////////////////////////////////
    // Misc

    CHTTP_Client *client;

    b8   error;

} ACME_Config;

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

    // Requesting the certificate processing state
    ACME_STATE_CERTIFICATE_POLL,

    // Waiting some time before requesting the certificate
    // state again
    ACME_STATE_CERTIFICATE_POLL_WAIT,

    // Requesting the certificate
    ACME_STATE_CERTIFICATE_DOWNLOAD,

    // A certificate was created, so we can go
    // idle until it expires.
    ACME_STATE_WAIT,

    // Error state
    ACME_STATE_ERROR,
} ACME_State;

typedef struct {

    // This is the account URL. It's set if and
    // only if an account was created.
    string url;

    // Key pair for the account. This is generated
    // before requesting an account to be created.
    EVP_PKEY *key;

} ACME_Account;

typedef struct {
    // If new_account.ptr is NULL, the struct is
    // uninitialized, else all URLs are allocated
    // in a contiguous region starting at new_account.ptr
    string new_account;
    string new_nonce;
    string new_order;
    string renewal_info;
    string revoke_cert;
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
    string name;

    // When a certificate is being issued and
    // the client is working on the challenges,
    // these fields are set.
    string challenge_token;
    string challenge_url;
    string authorization_url;

} ACME_Domain;

typedef struct {

    // User parameters
    string email;
    string country;
    string organization;
    b8     agree_tos;

    CHTTP_Client *client;
    b8            dont_verify_cert;

    string account_key_file;
    string certificate_file;
    string certificate_key_file;

    // State machine variable
    ACME_State state;

    // List of domains that need verifying
    // The "name" field of each domain is set at
    // startup, while the others are only used
    // during the challenges.
    int num_domains;
    ACME_Domain domains[ACME_DOMAIN_LIMIT];

    string directory_url;

    // List of endpoints for the ACME server.
    // This is set once at startup by requesting
    // the /directory endpoint.
    ACME_URLSet urls;

    // Every request to the ACME server needs a
    // previously issued nonce. After requesting
    // the /directory endpoint, a first nonce is
    // requested. The nonce is consumed at each
    // request but a new one is issued alongside
    // every response.
    // The nonce.ptr field is set equal to nonce_buf
    // at startup and is never changed.
    char   nonce_buf[ACME_NONCE_CAPACITY];
    string nonce;

    // This holds account URL and key.
    ACME_Account account;

    string order_url;

    // When an order is created but the challenges
    // are yet to be completed, these fields are
    // set to the finalization URL and certificate
    // URL. They are allocated in batch.
    string finalize_url;
    string certificate_url;

    string certificate;
    string certificate_key;

    // Number of challenges that were resolved.
    // When this value equals the domain count,
    // the order can be finalized.
    int resolved_challenges;

    // When the ACME client moves to a state that
    // requires a timeout, this field is set to the
    // strting time.
    Time state_change_time;

} ACME;

// Initialize a configuration object for an ACME
// client session. The arguments of this function
// are all the required parameters for a configuration,
// and therefore can't be empty. Other fields of
// the configuration struct (except for a couple)
// are set to default values but may be set manually.
void acme_config_init(ACME_Config *config,
    CHTTP_Client *client,
    string directory_url,
    string email,
    string country,
    string organization,
    string domain);

// Add an additional domain to the ACME configuration.
void acme_config_add_domain(ACME_Config *config,
    string domain);

// Initialize the ACME client session. Returns 0 on
// success and -1 on error.
int acme_init(ACME *acme, ACME_Config *config);

// Deinitialize the ACME client session.
void acme_free(ACME *acme);

// Returns the number of milliseconds until the next
// call to acme_process_timeout or -1 if no timeout
// is pending.
int acme_next_timeout(ACME *acme);

// Process a timeout event
void acme_process_timeout(ACME *acme, CHTTP_Client *client);

// Process an HTTP request. If the request wasn't
// directed to the ACME client, false is returned.
// If the request was processed, true is returned.
b8 acme_process_request(ACME *acme, CHTTP_Request *request,
    CHTTP_ResponseBuilder builder);

// Process an HTTP response directed to the ACME
// client. Returns true if a new certificate is
// available.
b8 acme_process_response(ACME *acme, int result,
    CHTTP_Response *response);

#endif // ACME_INCLUDED
