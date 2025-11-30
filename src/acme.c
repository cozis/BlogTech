// The ACME protocol (which stands for Automatic Certificate
// Management Environment) is a protocol for renewing certificates
// in an automated fashon.
//
// If a Certification Authority (CA) implements an ACME server,
// HTTP servers can issue certificates automatically by acting
// as ACME clients and requesting new certificates as needed.
// To verify that the HTTP server (acting as ACME client) is
// entitled to the request certificates, it gives the HTTP server
// a special token. The CA then sends a request to the domain
// name being certified looking for that same token. If the
// tokens match, then the HTTP server really is entitled to that
// domain name and the certificate can be issued. This is the
// general gist. There are other things the ACME protocol allows
// one to do, but we are only interested in this interaction.
//
// All ACME servers implement the /directory endpoint, which
// lists all other endpoints. This allows the ACME server to
// switch their endpoints without breaking clients.
//
// The directory endpoint responds with something like this:
//
//     {
//         "newNonce": "https://example.com/acme/new-nonce",
//         "newAccount": "https://example.com/acme/new-account",
//         "newOrder": "https://example.com/acme/new-order",
//         "newAuthz": "https://example.com/acme/new-authz",
//         "revokeCert": "https://example.com/acme/revoke-cert",
//         "keyChange": "https://example.com/acme/key-change",
//         "meta": {
//           "termsOfService": "https://example.com/acme/terms/2017-5-30",
//           "website": "https://www.example.com/",
//           "caaIdentities": ["example.com"],
//           "externalAccountRequired": false
//         }
//       }
//
// TODO: Get the first nonce.
//
// Clients that want new certificates issued need to first create
// an account using the "newAccount" URL. The payload must look like
// this:
//
//     {
//         "contact": [
//             "mailto:some@email.com"
//         ],
//         "termsOfServiceAgreed": true
//     }
//
// This payload is then wrapped into a Json Web Signature (JWT) object
// where the protected field looks like this:
//
//     {
//         "alg": "ES256",
//         "jwk": "the public key to be associated with the account goes here",
//         "nonce": "the current nonce value"
//         "url": "the newAccount URL goes here",
//     }
//
// The actual payload being sent to the newAccount endpoint will look
// like this:
//
//     {"protected":"base64(...)","payload":"base64(...)","signature":"base64(...)"}
//
// If everything goes well, the server will respond with the account URL
// stored in the Location header. All further requests to the ACME server
// that contain a JWS will set the "kid" field of the protected object to
// the account URL. The "jwk" field can be omitted if the "kid" field is
// present.
//
// To request a certificate, clients then send a request to the "newOrder"
// endpoint. The payload looks like this:
//
//     {
//         "identifiers": [
//             { "type": "dns", "value": "example.com" },
//             { "type": "dns", "value": "www.example.com" }
//         ]
//     }
//
// Of course it then needs to be wrapped in a JWS object.
//
// The server then responds with the order object, which looks like this
//
//     {
//         "status": "valid",
//         "expires": "2016-01-20T14:09:07.99Z",
//         "identifiers": [
//             { "type": "dns", "value": "www.example.org" },
//             { "type": "dns", "value": "example.org" }
//         ],
//         "notBefore": "2016-01-01T00:00:00Z",
//         "notAfter": "2016-01-08T00:00:00Z",
//         "authorizations": [
//             "https://example.com/acme/authz/PAniVnsZcis",
//             "https://example.com/acme/authz/r4HqLzrSrpI"
//         ],
//         "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",
//         "certificate": "https://example.com/acme/cert/mAt3xBGaobw"
//     }
//
// The "authorizations" field will hold one entry per identifier.
// Clients need to go through each authorization and verify the
// associated domain by performing a challenge.
//
// Each authorization URL will return an authorization object that
// looks like this:
//
//     {
//         "status": "valid",
//         "expires": "2015-03-01T14:09:07.99Z",
//         "identifier": {
//             "type": "dns",
//             "value": "www.example.org"
//         },
//         "challenges": [
//             {
//                 "url": "https://example.com/acme/chall/prV_B7yEyA4",
//                 "type": "http-01",
//                 "status": "valid",
//                 "token": "DGyRejmCefe7v4NfDGDKfA",
//                 "validated": "2014-12-01T12:05:58.16Z"
//             }
//         ],
//         "wildcard": false
//     }
//
// To perform the challenge, the ACME client picks one entry of
// the "challenges" array and makes an endpoint ".well-known/acme-challenge/<token>"
// available to the public. The endpoint needs to return the challenge
// token concatenated with the thumbprint of the public key associated
// to the account separated by a dot. When the endpoint is available and
// the ACME client is ready to complete the challenge, it sends a POST
// request with an empty JSON object (signed using JWS) to the challenge
// URL. Upon receiving this request, the ACME server will ping the
// endpoint and check that the correct token is being server. If it is,
// the challenge "status" field will change to "valid". If something
// went wrong, the status will be "invalid".
//
// When all identifiers are verified, the ACME client needs to build
// a Certificate Signing Request (CSR) and POST it to the "finalize"
// URL of the order. The certificate will then be available at the
// "certificate" endpoint.

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <json.h>

#include "acme.h"
#include "jws.h"

#ifndef ACME_SERVER_URL
// TODO: comment
#define ACME_SERVER_URL "https://0.0.0.0:14000/dir"
//#define ACME_SERVER_URL "https://acme-v02.api.letsencrypt.org/directory"
#endif

#define ACME_LOG(fmt, ...) fprintf(stderr, "ACME :: " fmt, #__VA_ARGS__);

#define TRACE_STATE_TRANSITIONS

#ifndef TRACE_STATE_TRANSITIONS
#define CHANGE_STATE(var, state) var = state;
#else
static char *state_str(ACME_State state)
{
    switch (state) {
        case ACME_STATE_DIRECTORY     : return "DIRECTORY";
        case ACME_STATE_FIRST_NONCE   : return "FIRST_NONCE";
        case ACME_STATE_CREATE_ACCOUNT: return "CREATE_ACCOUNT";
        case ACME_STATE_CREATE_CERT   : return "CREATE_CERT";
        case ACME_STATE_CHALLENGE_1   : return "CHALLENGE_1";
        case ACME_STATE_CHALLENGE_2   : return "CHALLENGE_2";
        case ACME_STATE_CHALLENGE_3   : return "CHALLENGE_3";
        case ACME_STATE_CHALLENGE_4   : return "CHALLENGE_4";
        case ACME_STATE_FINALIZE      : return "FINALIZE";
        case ACME_STATE_CERTIFICATE_POLL     : return "CERTIFICATE_POLL";
        case ACME_STATE_CERTIFICATE_POLL_WAIT: return "CERTIFICATE_POLL_WAIT";
        case ACME_STATE_CERTIFICATE_DOWNLOAD : return "CERTIFICATE_DOWNLOAD";
        case ACME_STATE_WAIT          : return "WAIT";
        case ACME_STATE_ERROR         : return "ERROR";
    }
    return "???";
}
#define CHANGE_STATE(var, state) {            \
        printf("%s -> %s (at %s:%d)\n",       \
            state_str(var), state_str(state), \
            __FILE__, __LINE__);              \
        var = state;                          \
    }
#endif

// Helper function to compare two JSON_String values
static bool json_streq(JSON_String s1, JSON_String s2)
{
    return s1.len == s2.len && memcmp(s1.ptr, s2.ptr, s1.len) == 0;
}

static HTTP_String allocstr(HTTP_String s)
{
    char *p = malloc(s.len);
    if (p == NULL) {
        assert(0); // TODO
    }
    memcpy(p, s.ptr, s.len);
    s.ptr = p;
    return s;
}

typedef uint64_t Time;
#define INVALID_TIME UINT64_MAX

// Returns the current time in milliseconds since
// an unspecified time in the past (useful to calculate
// elapsed time intervals)
static Time get_current_time(void)
{
#ifdef _WIN32
    {
        int64_t count;
        int64_t freq;
        int ok;

        ok = QueryPerformanceCounter((LARGE_INTEGER*) &count);
        if (!ok) return INVALID_TIME;

        ok = QueryPerformanceFrequency((LARGE_INTEGER*) &freq);
        if (!ok) return INVALID_TIME;

        uint64_t res = 1000 * (double) count / freq;
        return res;
    }
#else
    {
        struct timespec time;

        if (clock_gettime(CLOCK_REALTIME, &time))
            return INVALID_TIME;

        uint64_t res;

        uint64_t sec = time.tv_sec;
        if (sec > UINT64_MAX / 1000)
            return INVALID_TIME;
        res = sec * 1000;

        uint64_t nsec = time.tv_nsec;
        if (res > UINT64_MAX - nsec / 1000000)
            return INVALID_TIME;
        res += nsec / 1000000;

        return res;
    }
#endif
}

typedef struct {

    bool error;
    bool dont_verify_cert;
    HTTP_String url;

    JWS_Builder jws_builder;
    char        jws_buffer[1<<10];

} RequestBuilder;

// NOTE: The url argument must be valid until request_builder_send
//       is called.
static void request_builder_init(RequestBuilder *builder,
    ACME_Account account, HTTP_String nonce, bool dont_verify_cert,
    HTTP_String url)
{
    assert(account.key);

    builder->error = false;
    builder->dont_verify_cert = dont_verify_cert;
    builder->url = url;

    jws_builder_init(&builder->jws_builder,
        account.key, true, builder->jws_buffer,
        (int) sizeof(builder->jws_buffer));

    if (account.url.len == 0) {
        jws_builder_write(&builder->jws_builder, "{\"alg\":\"ES256\",\"jwk\":", -1);
        if (jws_write_jwk(&builder->jws_builder, account.key) < 0) {
            builder->error = true;
            return;
        }
        jws_builder_write(&builder->jws_builder, ",\"nonce\":\"", -1);
        jws_builder_write(&builder->jws_builder, nonce.ptr, nonce.len);
        jws_builder_write(&builder->jws_builder, "\",\"url\":\"", -1);
        jws_builder_write(&builder->jws_builder, url.ptr, url.len);
        jws_builder_write(&builder->jws_builder, "\"}", -1);
        jws_builder_flush(&builder->jws_builder);
    } else {
        jws_builder_write(&builder->jws_builder, "{\"alg\":\"ES256\",\"kid\":\"", -1);
        jws_builder_write(&builder->jws_builder, account.url.ptr, account.url.len);
        jws_builder_write(&builder->jws_builder, "\",\"nonce\":\"", -1);
        jws_builder_write(&builder->jws_builder, nonce.ptr, nonce.len);
        jws_builder_write(&builder->jws_builder, "\",\"url\":\"", -1);
        jws_builder_write(&builder->jws_builder, url.ptr, url.len);
        jws_builder_write(&builder->jws_builder, "\"}", -1);
        jws_builder_flush(&builder->jws_builder);
    }
}

static void request_builder_write(RequestBuilder *builder, char *str, int len)
{
    if (builder->error)
        return;
    jws_builder_write(&builder->jws_builder, str, len);
}

static int request_builder_send(RequestBuilder *builder, HTTP_Client *client)
{
    if (builder->error)
        return -1;

    jws_builder_flush(&builder->jws_builder);
    int ret = jws_builder_result(&builder->jws_builder);
    if (ret < 0)
        return -1;
    HTTP_String jws = { builder->jws_buffer, ret };

    HTTP_RequestBuilder http_builder = http_client_get_builder(client);
    http_request_builder_set_user(http_builder, NULL); // TODO: should set pointer to the acme struct?
    http_request_builder_trace(http_builder, true);
    http_request_builder_insecure(http_builder, builder->dont_verify_cert);
    http_request_builder_method(http_builder, HTTP_METHOD_POST);
    http_request_builder_target(http_builder, builder->url);
    http_request_builder_header(http_builder, HTTP_STR("User-Agent: BlogTech")); // TODO: better user agnet
    http_request_builder_header(http_builder, HTTP_STR("Content-Type: application/jose+json"));
    http_request_builder_body(http_builder, jws);
    if (http_request_builder_send(http_builder) < 0)
        return -1;

    return 0;
}

static int send_directory_request(ACME *acme, HTTP_Client *client);

int acme_init(ACME *acme, HTTP_String email,
    HTTP_String *domains, int num_domains,
    HTTP_Client *client)
{
    acme->email = email; // TODO: copy

    // Initialize certificate fields - use first domain as common name
    acme->common_name = num_domains > 0 ? domains[0] : (HTTP_String){NULL, 0};
    acme->country = (HTTP_String){NULL, 0};  // Empty by default
    acme->org = (HTTP_String){NULL, 0};      // Empty by default

    acme->dont_verify_cert = true; // TODO
    acme->agreed_to_terms_of_service = false;

    acme->state = ACME_STATE_DIRECTORY;

    acme->num_domains = num_domains;
    for (int i = 0; i < num_domains; i++) {

        acme->domains[i].name.ptr = domains[i].ptr; // TODO: this should be a copy
        acme->domains[i].name.len = domains[i].len;

        acme->domains[i].challenge_token.ptr = NULL;
        acme->domains[i].challenge_token.len = 0;

        acme->domains[i].challenge_url.ptr = NULL;
        acme->domains[i].challenge_url.len = 0;

        acme->domains[i].authorization_url.ptr = NULL;
        acme->domains[i].authorization_url.len = 0;
    }

    acme->urls.new_account.ptr = NULL;

    acme->nonce.ptr = NULL;
    acme->nonce.len = 0;

    // TODO: Try loading the account URL from acme/account_url.txt and
    //       the keys from acme/keys.pem. If one of the files is missing,
    //       delete the other one and set the variables to empty. If
    //       reading them failed for some other reason, fail the initialization.
    acme->account.url.ptr = NULL;
    acme->account.url.len = 0;
    acme->account.key = NULL;

    // TODO: If the account wasn't loaded, set the certificate field
    //       to empty and delete acme/certificate.pem. If the account
    //       was loaded but acme/certificate.pem doesn't exist, set
    //       the certificate field to empty. If the file couldn't be
    //       loaded for some other reason, fail the initialization.

    acme->finalize_url.ptr = NULL;
    acme->finalize_url.len = 0;

    acme->certificate_url.ptr = NULL;
    acme->certificate_url.len = 0;

    acme->resolved_challenges = 0;

    // TODO: before requesting a certificate, the ACME client should
    //       send plain HTTP requests to itself through the domains
    //       specified by the user to check whether it's entitled to
    //       the certificates or not.
    if (send_directory_request(acme, client) < 0)
        return -1;

    return 0;
}

void acme_free(ACME *acme)
{
    if (acme->urls.new_account.ptr != NULL) {
        free(acme->urls.new_account.ptr);
    }
    if (acme->nonce.ptr != NULL) {
        free(acme->nonce.ptr);
    }
}

void acme_dont_verify_cert(ACME *acme)
{
    acme->dont_verify_cert = true;
}

void acme_agree_to_terms_of_service(ACME *acme)
{
    acme->agreed_to_terms_of_service = true;
}

static int parse_urls(HTTP_String body, ACME_URLSet *urls)
{
    char pool[1<<13];

    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(body.ptr, body.len, &arena, &error);
    if (json == NULL)
        return -1;

    JSON_String new_account;
    JSON_String new_nonce;
    JSON_String new_order;
    JSON_String renewal_info;
    JSON_String revoke_cert;
    int ret = json_match(json, &error,
        "{'newAccount': ?, 'newNonce': ?, 'newOrder': ?, "
        "'renewalInfo': ?, 'revokeCert': ? }",
        &new_account, &new_nonce, &new_order,
        &renewal_info, &revoke_cert);
    if (ret == 1) return -1;
    if (ret == -1) return -1;
    assert(ret == 0);

    char *p = malloc(new_account.len + new_nonce.len
        + new_order.len + renewal_info.len + revoke_cert.len);
    if (p == NULL)
        return -1;

    memcpy(p, new_account.ptr, new_account.len);
    urls->new_account.ptr = p;
    urls->new_account.len = new_account.len;
    p += new_account.len;

    memcpy(p, new_nonce.ptr, new_nonce.len);
    urls->new_nonce.ptr = p;
    urls->new_nonce.len = new_nonce.len;
    p += new_nonce.len;

    memcpy(p, new_order.ptr, new_order.len);
    urls->new_order.ptr = p;
    urls->new_order.len = new_order.len;
    p += new_order.len;

    memcpy(p, renewal_info.ptr, renewal_info.len);
    urls->renewal_info.ptr = p;
    urls->renewal_info.len = renewal_info.len;
    p += renewal_info.len;

    memcpy(p, revoke_cert.ptr, revoke_cert.len);
    urls->revoke_cert.ptr = p;
    urls->revoke_cert.len = revoke_cert.len;
    p += revoke_cert.len;

    return 0;
}

static int send_directory_request(ACME *acme, HTTP_Client *client)
{
    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_trace(builder, true);
    http_request_builder_insecure(builder, acme->dont_verify_cert);
    http_request_builder_method(builder, HTTP_METHOD_GET);
    http_request_builder_target(builder, HTTP_STR(ACME_SERVER_URL));
    if (http_request_builder_send(builder) < 0)
        return -1;
    return 0;
}

static int complete_directory_request(ACME *acme, HTTP_Response *response)
{
    // TODO: check status

    if (parse_urls(response->body, &acme->urls) < 0)
        return -1;
    return 0;
}

static int send_first_nonce_request(ACME *acme, HTTP_Client *client)
{
    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_trace(builder, true);
    http_request_builder_insecure(builder, acme->dont_verify_cert);
    http_request_builder_method(builder, HTTP_METHOD_GET);
    http_request_builder_target(builder, acme->urls.new_nonce);
    if (http_request_builder_send(builder) < 0)
        return -1;
    return 0;
}

static int extract_nonce(ACME *acme, HTTP_Response *response)
{
    int idx = http_find_header(response->headers, response->num_headers, HTTP_STR("Replay-Nonce"));
    if (idx == -1)
        return -1;

    HTTP_String nonce = response->headers[idx].value;

    // Free old nonce
    free(acme->nonce.ptr);
    acme->nonce.len = 0;

    // Allocate and copy new nonce
    char *p = malloc(nonce.len);
    if (p == NULL)
        return -1;

    memcpy(p, nonce.ptr, nonce.len);
    acme->nonce.ptr = p;
    acme->nonce.len = nonce.len;

    return 0;
}

static int complete_first_nonce_request(ACME *acme, HTTP_Response *response)
{
    if (extract_nonce(acme, response) < 0)
        return -1;
    return 0;
}

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

static int generate_account_key(ACME_Account *account)
{
    // Create context for key generation
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx)
        return -1;

    // Initialize key generation
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // Set the curve to P-256 (prime256v1/secp256r1)
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // Generate the key pair
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    account->key = pkey;

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

static int send_account_creation_request(ACME *acme, HTTP_Client *client)
{
    if (generate_account_key(&acme->account) < 0)
        return -1;

    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce, acme->dont_verify_cert, acme->urls.new_account);
    request_builder_write(&builder, "{\"contact\":[\"mailto:", -1);
    request_builder_write(&builder, acme->email.ptr, acme->email.len);
    request_builder_write(&builder, "\"],\"termsOfServiceAgreed\":", -1);
    if (acme->agreed_to_terms_of_service)
        request_builder_write(&builder, "true", 4);
    else
        request_builder_write(&builder, "false", 5);
    request_builder_write(&builder, "}", 1);
    return request_builder_send(&builder, client);
}

static int complete_account_creation_request(ACME *acme, HTTP_Response *response)
{
    if (response->status != 201 && response->status != 200)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    int idx = http_find_header(response->headers, response->num_headers, HTTP_STR("Location"));
    if (idx == -1)
        return -1; // Location header missing

    acme->account.url = allocstr(response->headers[idx].value);

    // The account was created so we can store the key
    // TODO:
    //   - write the acme->account_key to acme/keys.pem
    //   - write the acme->account_url to acme/account_url.txt

    return 0;
}

static int send_order_creation_request(ACME *acme, HTTP_Client *client)
{
    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce, acme->dont_verify_cert, acme->urls.new_order);
    request_builder_write(&builder, "{\"identifiers\":[", -1);
    for (int i = 0; i < acme->num_domains; i++) {
        if (i > 0)
            request_builder_write(&builder, ",", 1);
        request_builder_write(&builder, "{\"type\":\"dns\",\"value\":\"", -1);
        request_builder_write(&builder, acme->domains[i].name.ptr, acme->domains[i].name.len);
        request_builder_write(&builder, "\"}", -1);
    }
    request_builder_write(&builder, "]}", 2);
    return request_builder_send(&builder, client);
}

static bool account_exists(ACME *acme)
{
    return acme->account.url.len > 0;
}

static bool certificate_exists(ACME *acme)
{
    return acme->certificate_url.len > 0;
}

static bool all_challenges_completed(ACME *acme)
{
    return acme->resolved_challenges == acme->num_domains;
}

static bool acquired_certificate(ACME *acme)
{
    return false; // TODO
}

static int complete_order_creation_request(ACME *acme, HTTP_Response *response)
{
    // TODO: check status

    if (extract_nonce(acme, response) < 0)
        return -1;

    int i = http_find_header(response->headers, response->num_headers, HTTP_STR("Location"));
    if (i < 0)
        return -1;
    acme->order_url = allocstr(response->headers[i].value);

    // Parse the order response to get authorizations and finalize URL
    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL)
        return -1;

    JSON_String finalize_url = json_get_string(json_get_field(json, JSON_STR("finalize")));
    if (finalize_url.len == 0)
        return -1;

    acme->finalize_url = allocstr((HTTP_String) { finalize_url.ptr, finalize_url.len });

    JSON *auths = json_get_field(json, JSON_STR("authorizations"));
    if (auths == NULL || json_get_type(auths) != JSON_TYPE_ARRAY)
        return -1;

    if (auths->len != acme->num_domains)
        return -1;

    int j = 0;
    JSON *item = auths->head;
    while (item) {

        JSON_String tmp = json_get_string(item);
        if (tmp.len == 0)
            return -1;
        HTTP_String auth_url = { tmp.ptr, tmp.len };

        acme->domains[j].authorization_url = allocstr(auth_url);

        j++;
        item = item->next;
    }

    acme->resolved_challenges = 0;
    return 0;
}

static int send_next_challenge_info_request(ACME *acme, HTTP_Client *client)
{
    assert(acme->resolved_challenges < acme->num_domains);
    HTTP_String auth_url = acme->domains[acme->resolved_challenges].authorization_url;

    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce, acme->dont_verify_cert, auth_url);
    request_builder_write(&builder, "", 0);
    return request_builder_send(&builder, client);
}

static int complete_next_challenge_info_request(ACME *acme, HTTP_Response *response)
{
    assert(acme->resolved_challenges < acme->num_domains);

    // TODO: check status

    if (extract_nonce(acme, response) < 0)
        return -1;

    // Parse the authorization response to get the challenge token
    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL)
        return -1;

    JSON *challenges = json_get_field(json, JSON_STR("challenges"));
    if (challenges == NULL || json_get_type(challenges) != JSON_TYPE_ARRAY)
        return -1;

    // Get the first http-01 challenge
    JSON *challenge = challenges->head;
    while (challenge) {
        JSON_String type = json_get_string(json_get_field(challenge, JSON_STR("type")));
        if (type.len == 7 && !memcmp(type.ptr, "http-01", 7))
            break;
        challenge = challenge->next;
    }
    if (challenge == NULL)
        return -1; // No http-01 challenge

    JSON_String tmp = json_get_string(json_get_field(challenge, JSON_STR("token")));
    if (tmp.len == 0)
        return -1;
    HTTP_String token = { tmp.ptr, tmp.len };

    tmp = json_get_string(json_get_field(challenge, JSON_STR("url")));
    if (tmp.len == 0)
        return -1;
    HTTP_String url = { tmp.ptr, tmp.len };

    acme->domains[acme->resolved_challenges].challenge_token = allocstr(token);
    acme->domains[acme->resolved_challenges].challenge_url = allocstr(url);

    return 0;
}

static int send_next_challenge_begin_request(ACME *acme, HTTP_Client *client)
{
    assert(acme->resolved_challenges < acme->num_domains);

    HTTP_String challenge_url = acme->domains[acme->resolved_challenges].challenge_url;

    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce, acme->dont_verify_cert, challenge_url);
    request_builder_write(&builder, "{}", -1);
    return request_builder_send(&builder, client);
}

static int complete_next_challenge_begin_request(ACME *acme, HTTP_Response *response)
{
    assert(acme->resolved_challenges < acme->num_domains);

    // TODO: check status

    if (extract_nonce(acme, response) < 0)
        return -1;

    return 0;
}

static int send_challenge_status_request(ACME *acme,
    HTTP_Client *client)
{
    assert(acme->resolved_challenges < acme->num_domains);

    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce, acme->dont_verify_cert, acme->domains[acme->resolved_challenges].challenge_url);
    request_builder_write(&builder, "", 0);
    return request_builder_send(&builder, client);
}

static int complete_challenge_status_request(ACME *acme,
    HTTP_Response *response, bool *challenge_completed)
{
    *challenge_completed = false;

    // TODO: check status

    if (extract_nonce(acme, response) < 0)
        return -1;

    // Parse response to check if challenge is valid
    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL)
        return -1;

    // Check status field
    JSON_String status;
    if (json_match(json, &error, "{'status': ?}", &status) != 0)
        return -1;

    HTTP_String status_http = { status.ptr, status.len };

    if (http_streq(status_http, HTTP_STR("invalid")))
        return -1;

    if (http_streq(status_http, HTTP_STR("valid"))) {
        acme->resolved_challenges++;
        *challenge_completed = true;
    }

    return 0;
}

static int
create_certificate_signing_request(EVP_PKEY *pkey,
    HTTP_String common_name, HTTP_String country,
    HTTP_String org, char *dst, int cap)
{
    // Create the CSR structure
    X509_REQ *req = X509_REQ_new();
    if (!req)
        return -1;

    // Set version (version 0 for CSR)
    if (!X509_REQ_set_version(req, 0L)) {
        X509_REQ_free(req);
        return -1;
    }

    // Get the subject name
    X509_NAME *name = X509_REQ_get_subject_name(req);
    if (!name) {
        X509_REQ_free(req);
        return -1;
    }

    // Add subject fields
    if (country.len > 0)
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
            (unsigned char *)country.ptr, country.len, -1, 0);

    if (org.len > 0)
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            (unsigned char *)org.ptr, org.len, -1, 0);

    if (common_name.len > 0)
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (unsigned char *)common_name.ptr, common_name.len, -1, 0);

    // Set the public key
    if (!X509_REQ_set_pubkey(req, pkey)) {
        X509_REQ_free(req);
        return -1;
    }

    // Sign the CSR with the private key
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        X509_REQ_free(req);
        return -1;
    }

    // Get required length
    int len = i2d_X509_REQ(req, NULL);
    if (len < 0) {
        // TODO
        return -1;
    }
    if (len > cap) {
        // TODO
        return -1;
    }

    // Actually encode
    unsigned char *p = dst;  // i2d_X509_REQ advances the pointer
    len = i2d_X509_REQ(req, &p);
    if (len < 0) {
        // TODO
        return -1;
    }

    return len;
}

static int send_finalize_order_request(ACME *acme, HTTP_Client *client)
{
    char csr[1<<12];
    int csr_len = create_certificate_signing_request(acme->account.key,
        acme->common_name, acme->country, acme->org, csr, sizeof(csr));
    if (csr_len < 0)
        return -1;

    csr_len = jws_base64url_encode_inplace(csr, csr_len, sizeof(csr), false);
    if (csr_len < 0)
        return -1;

     RequestBuilder builder;
     request_builder_init(&builder, acme->account, acme->nonce, acme->dont_verify_cert, acme->finalize_url);
     request_builder_write(&builder, "{\"csr\":\"", -1);
     request_builder_write(&builder, csr, csr_len);
     request_builder_write(&builder, "\"}", -1);
     return request_builder_send(&builder, client);
}

static int complete_finalize_order_request(ACME *acme, HTTP_Response *response)
{
    // TODO: check status

    if (extract_nonce(acme, response) < 0)
        return -1;

    // The finalization request returns an update order object

    // Parse response to get certificate URL
    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL)
        return -1;

    JSON_String status = json_get_string(json_get_field(json, JSON_STR("status")));

    if (!json_streq(status, JSON_STR("processing")) &&
        !json_streq(status, JSON_STR("valid")))
        return -1;

    return 0;
}

static int send_certificate_poll_request(ACME *acme, HTTP_Client *client)
{
    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce, acme->dont_verify_cert, acme->order_url);
    request_builder_write(&builder, "{}", -1);
    return request_builder_send(&builder, client);
}

static int complete_certificate_poll_request(ACME *acme, HTTP_Response *response)
{
    if (extract_nonce(acme, response) < 0)
        return -1;

    // TODO
    return 0;
}

static int send_certificate_download_request(ACME *acme, HTTP_Client *client)
{
    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce, acme->dont_verify_cert, acme->certificate_url);
    request_builder_write(&builder, "{}", -1);
    return request_builder_send(&builder, client);
}

static int complete_certificate_download_request(ACME *acme, HTTP_Response *response)
{
    if (response->status != 200)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    HTTP_String certificate = response->body;

    // TODO: store the certificate
    return 0;
}

static int current_state_timeout(ACME *acme)
{
    switch (acme->state) {
    case ACME_STATE_CHALLENGE_3:
        return 1000;
    case ACME_STATE_WAIT:
        return 86400000; // 24 hours in milliseconds
    case ACME_STATE_CERTIFICATE_POLL_WAIT:
        return 1000;
    default:
        return -1;
    }
}

static int next_timeout(ACME *acme, Time current_time)
{
    int total = current_state_timeout(acme);
    if (total < 0)
        return total;

    uint64_t elapsed = (current_time - acme->state_change_time);
    if (elapsed > (uint64_t) total)
        return 0;

    return total - (int) elapsed;
}

int acme_next_timeout(ACME *acme)
{
    uint64_t current_time = get_current_time();
    if (current_time == INVALID_TIME) {
        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
        return -1;
    }

    return next_timeout(acme, current_time);
}

void acme_process_timeout(ACME *acme, HTTP_Client *client)
{
    uint64_t current_time = get_current_time();
    if (current_time == INVALID_TIME) {
        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
        return;
    }

    if (next_timeout(acme, current_time) != 0)
        return;

    switch (acme->state) {
    case ACME_STATE_CHALLENGE_3:
        {
            if (send_challenge_status_request(acme, client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CHALLENGE_4);
        }
        break;
    case ACME_STATE_WAIT:
        {
            if (send_order_creation_request(acme, client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CREATE_CERT);
        }
        break;
    case ACME_STATE_CERTIFICATE_POLL_WAIT:
        {
            if (send_certificate_poll_request(acme, client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CERTIFICATE_POLL);
        }
        break;
    }
}

bool acme_process_request(ACME *acme, HTTP_Request *request,
    HTTP_ResponseBuilder builder, HTTP_Client *client,
    HTTP_Server *server)
{
    HTTP_String path = request->url.path;
    HTTP_String prefix = HTTP_STR("/.well-known/acme-challenge/");

    // Check if path starts with prefix
    if (path.len < prefix.len || memcmp(path.ptr, prefix.ptr, prefix.len) != 0)
        return false;

    if (acme->state != ACME_STATE_CHALLENGE_2 &&
        acme->state != ACME_STATE_CHALLENGE_3 &&
        acme->state != ACME_STATE_CHALLENGE_4) {
        http_response_builder_status(builder, 404);
        http_response_builder_send(builder);
    } else {
        if (acme->resolved_challenges == acme->num_domains) {
            http_response_builder_status(builder, 404);
            http_response_builder_send(builder);
            return true;
        }
        HTTP_String expected_token = acme->domains[acme->resolved_challenges].challenge_token;
        HTTP_String token = { path.ptr + prefix.len, path.len - prefix.len };
        if (!http_streq(token, expected_token)) {
            http_response_builder_status(builder, 404);
            http_response_builder_send(builder);
            return true;
        }

        // A raw SHA256 hash is 32 bytes, so the Base64URL encoded
        // version is ceil(32/3)*4=44
        char thumbprint_buf[44];
        int thumbprint_len = jwk_thumbprint(acme->account.key, thumbprint_buf, sizeof(thumbprint_buf));
        if (thumbprint_len < 0) {
            http_response_builder_status(builder, 500);
            http_response_builder_send(builder);
            return true;
        }
        HTTP_String thumbprint = { thumbprint_buf, thumbprint_len };

        http_response_builder_status(builder, 200);
        http_response_builder_body(builder, expected_token);
        http_response_builder_body(builder, HTTP_STR("."));
        http_response_builder_body(builder, thumbprint);
        http_response_builder_send(builder);
    }
    return true;
}

static bool is_invalid_nonce_response(HTTP_Response *response)
{
    if (response->status != 400)
        return false;

    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL)
        return false;

    JSON_String tmp = json_get_string(json_get_field(json, JSON_STR("type")));
    HTTP_String type = { tmp.ptr, tmp.len };
    if (!http_streq(type, HTTP_STR("urn:ietf:params:acme:error:badNonce")))
        return false;

    return true;
}

void acme_process_response(ACME *acme, int result,
    HTTP_Response *response, HTTP_Client *client,
    HTTP_Server *server)
{
    uint64_t current_time = get_current_time();
    if (current_time == INVALID_TIME) {
        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
        return;
    }

    switch (acme->state) {
    case ACME_STATE_DIRECTORY:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            if (complete_directory_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (send_first_nonce_request(acme, client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_FIRST_NONCE);
        }
        break;
    case ACME_STATE_FIRST_NONCE:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            if (complete_first_nonce_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (account_exists(acme)) {
                if (certificate_exists(acme)) {
                    // A certificate exists. Wait for it to expire.
                    CHANGE_STATE(acme->state, ACME_STATE_WAIT);
                    acme->state_change_time = current_time;
                } else {
                    // No certificate associated to this instance. Create one.
                    if (send_order_creation_request(acme, client) < 0) {
                        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                        break;
                    }
                    CHANGE_STATE(acme->state, ACME_STATE_CREATE_CERT);
                }
            } else {
                // No account associated to this instance. Create one.
                if (send_account_creation_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                CHANGE_STATE(acme->state, ACME_STATE_CREATE_ACCOUNT);
            }
        }
        break;
    case ACME_STATE_CREATE_ACCOUNT:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (is_invalid_nonce_response(response)) {
                if (extract_nonce(acme, response) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                if (send_account_creation_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                // Keep the current state
                break;
            }

            if (complete_account_creation_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            // If no account existed, surely a certificate doesn't
            // exist either, so create one.
            if (send_order_creation_request(acme, client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CREATE_CERT);
        }
        break;
    case ACME_STATE_CREATE_CERT:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (is_invalid_nonce_response(response)) {
                if (extract_nonce(acme, response) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                if (send_order_creation_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                // Keep the current state
                break;
            }

            if (complete_order_creation_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            // The order was create. Now we need to perform
            // the challanges.
            if (send_next_challenge_info_request(acme, client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CHALLENGE_1);
        }
        break;
    case ACME_STATE_CHALLENGE_1:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (is_invalid_nonce_response(response)) {
                if (extract_nonce(acme, response) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                if (send_next_challenge_info_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                // Keep the current state
                break;
            }

            if (complete_next_challenge_info_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            if (send_next_challenge_begin_request(acme, client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CHALLENGE_2);
        }
        break;
    case ACME_STATE_CHALLENGE_2:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (is_invalid_nonce_response(response)) {
                if (extract_nonce(acme, response) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                if (send_next_challenge_begin_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                // Keep the current state
                break;
            }

            if (complete_next_challenge_begin_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CHALLENGE_3);
            acme->state_change_time = current_time;
        }
        break;
    case ACME_STATE_CHALLENGE_4:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (is_invalid_nonce_response(response)) {
                if (extract_nonce(acme, response) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                if (send_challenge_status_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                // Keep the current state
                break;
            }

            bool challenge_completed;
            if (complete_challenge_status_request(acme, response, &challenge_completed) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (challenge_completed) {
                if (all_challenges_completed(acme)) {
                    // Finalize the order
                    if (send_finalize_order_request(acme, client) < 0) {
                        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                        break;
                    }
                    CHANGE_STATE(acme->state, ACME_STATE_FINALIZE);
                } else {
                    // Next challenge
                    if (send_next_challenge_info_request(acme, client) < 0) {
                        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                        break;
                    }
                    CHANGE_STATE(acme->state, ACME_STATE_CHALLENGE_1);
                }
            } else {
                // Go back to waiting
                CHANGE_STATE(acme->state, ACME_STATE_CHALLENGE_3);
                acme->state_change_time = current_time;
            }
        }
        break;
    case ACME_STATE_FINALIZE:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (is_invalid_nonce_response(response)) {
                if (extract_nonce(acme, response) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                if (send_finalize_order_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                // Keep the current state
                break;
            }

            if (complete_finalize_order_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            if (send_certificate_poll_request(acme, client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CERTIFICATE_POLL);
        }
        break;
    case ACME_STATE_CERTIFICATE_POLL:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (is_invalid_nonce_response(response)) {
                if (extract_nonce(acme, response) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                if (send_certificate_poll_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                // Keep the current state
                break;
            }

            if (complete_certificate_poll_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            if (acquired_certificate(acme)) {
                if (send_certificate_download_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                CHANGE_STATE(acme->state, ACME_STATE_CERTIFICATE_DOWNLOAD);
            } else {
                CHANGE_STATE(acme->state, ACME_STATE_CERTIFICATE_POLL_WAIT);
                acme->state_change_time = current_time;
            }
        }
        break;
    case ACME_STATE_CERTIFICATE_DOWNLOAD:
        {
            if (result != HTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (is_invalid_nonce_response(response)) {
                if (extract_nonce(acme, response) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                if (send_certificate_download_request(acme, client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                // Keep the current state
                break;
            }

            if (complete_certificate_download_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_WAIT);
            acme->state_change_time = current_time;
        }
        break;
    default:
        // Do nothing
        break;
    }
}
