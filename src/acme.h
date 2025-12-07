#ifndef ACME_INCLUDED
#define ACME_INCLUDED

#include <openssl/evp.h>
#include <chttp.h>

#define ACME_DOMAIN_LIMIT 32

// RFC 8555 doesn't specify a length for a nonce string,
// but the Pebble client implemented by Let's Encrypt is
// 22 characters long. We allocate 100 bytes just to be
// safe.
#define ACME_NONCE_CAPACITY 100

typedef struct {

    /////////////////////////////////////////////
    // General

    HTTP_String directory_url;

    bool dont_verify_cert;

    /////////////////////////////////////////////
    // Information

    HTTP_String email;

    HTTP_String country;
    HTTP_String organization;

    HTTP_String domains[ACME_DOMAIN_LIMIT];
    int         num_domains;

    bool        agree_tos;

    /////////////////////////////////////////////
    // File paths

    HTTP_String account_key_file;
    HTTP_String certificate_file;
    HTTP_String certificate_key_file;

    /////////////////////////////////////////////
    // Misc

    HTTP_Client *client;

    bool error;

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
    HTTP_String url;

    // Key pair for the account. This is generated
    // before requesting an account to be created.
    EVP_PKEY *key;

} ACME_Account;

typedef struct {
    // If new_account.ptr is NULL, the struct is
    // uninitialized, else all URLs are allocated
    // in a contiguous region starting at new_account.ptr
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
    HTTP_String country;
    HTTP_String organization;
    bool        agree_tos;

    HTTP_Client *client;
    bool         dont_verify_cert;

    HTTP_String account_key_file;
    HTTP_String certificate_file;
    HTTP_String certificate_key_file;

    // State machine variable
    ACME_State state;

    // List of domains that need verifying
    // The "name" field of each domain is set at
    // startup, while the others are only used
    // during the challenges.
    int num_domains;
    ACME_Domain domains[ACME_DOMAIN_LIMIT];

    HTTP_String directory_url;

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
    char nonce_buf[ACME_NONCE_CAPACITY];
    HTTP_String nonce;

    // This holds account URL and key.
    ACME_Account account;

    HTTP_String order_url;

    // When an order is created but the challenges
    // are yet to be completed, these fields are
    // set to the finalization URL and certificate
    // URL. They are allocated in batch.
    HTTP_String finalize_url;
    HTTP_String certificate_url;

    HTTP_String certificate;
    HTTP_String certificate_key;

    // Number of challenges that were resolved.
    // When this value equals the domain count,
    // the order can be finalized.
    int resolved_challenges;

    // When the ACME client moves to a state that
    // requires a timeout, this field is set to the
    // strting time.
    uint64_t state_change_time;

} ACME;

// Initialize a configuration object for an ACME
// client session. The arguments of this function
// are all the required parameters for a configuration,
// and therefore can't be empty. Other fields of
// the configuration struct (except for a couple)
// are set to default values but may be set manually.
void acme_config_init(ACME_Config *config,
    HTTP_Client *client,
    HTTP_String directory_url,
    HTTP_String email,
    HTTP_String country,
    HTTP_String organization,
    HTTP_String domain);

// Add an additional domain to the ACME configuration.
void acme_config_add_domain(ACME_Config *config,
    HTTP_String domain);

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
void acme_process_timeout(ACME *acme, HTTP_Client *client);

// Process an HTTP request. If the request wasn't
// directed to the ACME client, false is returned.
// If the request was processed, true is returned.
bool acme_process_request(ACME *acme, HTTP_Request *request,
    HTTP_ResponseBuilder builder);

// Process an HTTP response directed to the ACME
// client.
void acme_process_response(ACME *acme, int result,
    HTTP_Response *response);

#endif // ACME_INCLUDED
