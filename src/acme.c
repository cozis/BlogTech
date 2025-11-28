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
#include "auth.h"
#include "jws.h"

#ifndef ACME_SERVER_URL
// TODO: comment
#define ACME_SERVER_URL "https://acme-v02.api.letsencrypt.org"
#endif

// ACME state flow:
//   1. Request the endpoint list
//   2. Get a nonce
//   3. Create an account
//   4. Create an order
//   5. Request the first challenge
//   6. Request the second challenge
//
// HTTP request is available:
//   state == STATE_PERFORM_CHALLENGE:
//     Request the status of the current challenge
//     state = STATE_POLL_CHALLENGE_RESULT
//
// HTTP response is available:
//
//   state == STATE_DIRECTORY:
//     The response contains the list of endpoints. Cache them.
//     Request a nonce
//     state = STATE_FIRST_NONCE;
//
//   state == STATE_FIRST_NONCE:
//     Store the nonce
//     Request an account
//     state = STATE_CREATE_ACCOUNT
//
//   state == STATE_CREATE_ACCOUNT:
//     The account was created
//     Request an order
//     state = STATE_CREATE_ORDER
//
//   state == STATE_CREATE_ORDER:
//     The order was created
//     Store the list of challenges
//     Request the first challenge to be performed
//     state = STATE_CHALLENGE_REQUEST
//
//
//

static int send_directory_request(ACME *acme, HTTP_Client *client);

int acme_init(ACME *acme, HTTP_String email,
    HTTP_String *domains, int num_domains,
    HTTP_Client *client)
{
    acme->email = email; // TODO: copy
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

    acme->account_url.ptr = NULL;
    acme->account_url.len = 0;

    acme->account_key = NULL;

    acme->finalize_url.ptr = NULL;
    acme->finalize_url.len = 0;

    acme->certificate_url.ptr = NULL;
    acme->certificate_url.len = 0;

    acme->resolved_challenges = 0;

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
    http_request_builder_method(builder, HTTP_METHOD_GET);
    http_request_builder_target(builder, HTTP_STR(ACME_SERVER_URL "/directory"));
    if (http_request_builder_send(builder) < 0)
        return -1;
    return 0;
}

static int complete_directory_request(ACME *acme, HTTP_Response *response)
{
    if (parse_urls(response->body, &acme->urls) < 0)
        return -1;
    return 0;
}

static int send_first_nonce_request(ACME *acme, HTTP_Client *client)
{
    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_method(builder, HTTP_METHOD_HEAD);
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

static int send_account_creation_request(ACME *acme, HTTP_Client *client)
{
    char jws_buf[1<<9];
    int  jws_len;

    JWS_Builder jws_builder;
    jws_builder_init(&jws_builder, acme->account_key, true, jws_buf, (int) sizeof(jws_buf));
    jws_builder_write(&jws_builder, "{\"alg\":\"ES256\",\"jwk\":", -1);
    // TODO: write acme->account_key as a JWK
    jws_builder_write(&jws_builder, ",\"nonce\":\"", -1);
    jws_builder_write(&jws_builder, acme->nonce.ptr, acme->nonce.len);
    jws_builder_write(&jws_builder, "\",\"url\":\"", -1);
    jws_builder_write(&jws_builder, acme->account_url.ptr, acme->account_url.len);
    jws_builder_write(&jws_builder, "\"}", -1);
    jws_builder_flush(&jws_builder);
    jws_builder_write(&jws_builder, "{\"contact\":[\"mailto:", -1);
    jws_builder_write(&jws_builder, acme->email.ptr, acme->email.len);
    jws_builder_write(&jws_builder, "\"],\"termsOfServiceAgreed\":", -1);
    if (acme->agreed_to_terms_of_service)
        jws_builder_write(&jws_builder, "true", 4);
    else
        jws_builder_write(&jws_builder, "false", 5);
    jws_builder_write(&jws_builder, "}", 1);
    jws_builder_flush(&jws_builder);
    jws_len = jws_builder_result(&jws_builder);
    if (jws_len < 0)
        return -1;

    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_method(builder, HTTP_METHOD_POST);
    http_request_builder_target(builder, acme->urls.new_account);
    http_request_builder_body(builder, (HTTP_String) { jws_buf, jws_len });
    if (http_request_builder_send(builder) < 0)
        return -1;

    return 0;
}

static int complete_account_creation_request(ACME *acme, HTTP_Response *response)
{
    if (response->status != 201 && response->status != 200)
        return -1;

    int idx = http_find_header(response->headers, response->num_headers, HTTP_STR("Location"));
    if (idx == -1)
        return -1; // Location header missing

    acme->account_url = response->headers[idx].value; // TODO: perform a copy

    if (extract_nonce(acme, response) < 0)
        return -1;

    return 0;
}

static int send_order_creation_request(ACME *acme, HTTP_Client *client)
{
    char jws_buf[1<<12];
    int  jws_len;

    JWS_Builder jws_builder;
    jws_builder_init(&jws_builder, acme->account_key, true, jws_buf, (int) sizeof(jws_buf));
    jws_builder_write(&jws_builder, "{\"alg\":\"ES256\",\"kid\":\"", -1);
    jws_builder_write(&jws_builder, acme->account_url.ptr, acme->account_url.len);
    jws_builder_write(&jws_builder, "\",\"nonce\":\"", -1);
    jws_builder_write(&jws_builder, acme->nonce.ptr, acme->nonce.len);
    jws_builder_write(&jws_builder, "\",\"url\":\"", -1);
    jws_builder_write(&jws_builder, acme->urls.new_order.ptr, acme->urls.new_order.len);
    jws_builder_write(&jws_builder, "\"}", -1);
    jws_builder_flush(&jws_builder);
    jws_builder_write(&jws_builder, "{\"identifiers\":[", -1);
    for (int i = 0; i < acme->num_domains; i++) {
        if (i > 0)
            jws_builder_write(&jws_builder, ",", 1);
        jws_builder_write(&jws_builder, "{\"type\":\"dns\",\"value\":\"", -1);
        jws_builder_write(&jws_builder, acme->domains[i].name.ptr, acme->domains[i].name.len);
        jws_builder_write(&jws_builder, "\"}", -1);
    }
    jws_builder_write(&jws_builder, "]}", 2);
    jws_builder_flush(&jws_builder);
    jws_len = jws_builder_result(&jws_builder);
    if (jws_len < 0)
        return -1;

    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_method(builder, HTTP_METHOD_POST);
    http_request_builder_target(builder, acme->urls.new_order);
    http_request_builder_body(builder, (HTTP_String) { jws_buf, jws_len });
    if (http_request_builder_send(builder) < 0)
        return -1;
    return 0;
}

static bool account_exists(ACME *acme)
{
    return acme->account_url.ptr != NULL;
}

static bool certificate_exists(ACME *acme)
{
    return acme->certificate_url.ptr != NULL;
}

static bool all_challenges_completed(ACME *acme)
{
    return acme->resolved_challenges == acme->num_domains;
}

static int complete_order_creation_request(ACME *acme, HTTP_Response *response)
{
    // Update nonce
    if (extract_nonce(acme, response) < 0)
        return -1;

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

    JSON *auths = json_get_field(json, JSON_STR("authorizations"));
    if (auths == NULL || json_get_type(auths) != JSON_TYPE_ARRAY)
        return -1;

    if (auths->len != acme->num_domains)
        return -1;

    int i = 0;
    JSON *item = auths->head;
    while (item) {

        JSON_String auth_url = json_get_string(item);
        if (auth_url.len == 0)
            return -1;

        acme->domains[i].authorization_url.ptr = auth_url.ptr; // TODO: copy
        acme->domains[i].authorization_url.len = auth_url.len;

        i++;
        item = item->next;
    }

    acme->resolved_challenges = 0;
    return 0;
}

static int send_next_challenge_info_request(ACME *acme, HTTP_Client *client)
{
    assert(acme->resolved_challenges < acme->num_domains);
    HTTP_String auth_url = acme->domains[acme->resolved_challenges].authorization_url;

    char jws_buf[1<<9];
    int  jws_len;

    JWS_Builder jws_builder;
    jws_builder_init(&jws_builder, acme->account_key, true, jws_buf, (int) sizeof(jws_buf));
    jws_builder_write(&jws_builder, "{}", -1);
    jws_builder_flush(&jws_builder);
    jws_builder_write(&jws_builder, "{}", -1);
    jws_builder_flush(&jws_builder);
    jws_len = jws_builder_result(&jws_builder);
    if (jws_len < 0)
        return -1;
    HTTP_String jws = { jws_buf, jws_len };

    // Request the authorization object
    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_method(builder, HTTP_METHOD_POST);
    http_request_builder_target(builder, auth_url);
    http_request_builder_body(builder, jws);
    if (http_request_builder_send(builder) < 0)
        return -1;

    return 0;
}

static int complete_next_challenge_info_request(ACME *acme, HTTP_Response *response)
{
    assert(acme->resolved_challenges < acme->num_domains);

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
        if (type.len == 3 && !memcmp(type.ptr, "http-01", 7))
            break;
        challenge = challenge->next;
    }
    if (challenge == NULL)
        return -1; // No http-01 challenge

    JSON_String token = json_get_string(json_get_field(challenge, JSON_STR("token")));
    if (token.len == 0)
        return -1;

    JSON_String url = json_get_string(json_get_field(challenge, JSON_STR("url")));
    if (url.len == 0)
        return -1;

    // TODO: these should be copied
    acme->domains[acme->resolved_challenges].challenge_token.ptr = token.ptr;
    acme->domains[acme->resolved_challenges].challenge_token.len = token.len;
    acme->domains[acme->resolved_challenges].challenge_url.ptr = url.ptr;
    acme->domains[acme->resolved_challenges].challenge_url.len = url.len;

    return 0;
}

static int send_next_challenge_begin_request(ACME *acme, HTTP_Client *client)
{
    assert(acme->resolved_challenges < acme->num_domains);

    HTTP_String challenge_url = acme->domains[acme->resolved_challenges].challenge_url;

    char jws_buf[1<<9];
    int  jws_len;

    JWS_Builder jws_builder;
    jws_builder_init(&jws_builder, acme->account_key, true, jws_buf, (int) sizeof(jws_buf));
    jws_builder_write(&jws_builder, "{}", -1);
    jws_builder_flush(&jws_builder);
    jws_builder_write(&jws_builder, "{}", -1);
    jws_builder_flush(&jws_builder);
    jws_len = jws_builder_result(&jws_builder);
    if (jws_len < 0)
        return -1;
    HTTP_String jws = { jws_buf, jws_len };

    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_method(builder, HTTP_METHOD_POST);
    http_request_builder_target(builder, challenge_url);
    http_request_builder_body(builder, jws);
    if (http_request_builder_send(builder) < 0)
        return -1;

    return 0;
}

static int complete_next_challenge_begin_request(ACME *acme, HTTP_Response *response)
{
    assert(acme->resolved_challenges < acme->num_domains);

    if (extract_nonce(acme, response) < 0)
        return -1;

    return 0;
}

static int send_challenge_status_request(ACME *acme, HTTP_Client *client)
{
    assert(acme->resolved_challenges < acme->num_domains);

    char jws_buf[1<<9];
    int  jws_len;

    JWS_Builder jws_builder;
    jws_builder_init(&jws_builder, acme->account_key, true, jws_buf, (int) sizeof(jws_buf));
    jws_builder_write(&jws_builder, "{\"alg\":\"ES256\",\"kid\":\"", sizeof("{\"alg\":\"ES256\",\"kid\":\"")-1);
    jws_builder_write(&jws_builder, acme->account_url.ptr, acme->account_url.len);
    jws_builder_write(&jws_builder, "\",\"nonce\":\"", sizeof("\",\"nonce\":\"")-1);
    jws_builder_write(&jws_builder, acme->nonce.ptr, acme->nonce.len);
    jws_builder_write(&jws_builder, "\",\"url\":\"", sizeof("\",\"url\":\"")-1);
    jws_builder_write(&jws_builder, acme->account_url.ptr, acme->account_url.len);
    jws_builder_write(&jws_builder, "\"}", sizeof("\"}")-1);
    jws_builder_flush(&jws_builder);
    jws_builder_write(&jws_builder, "{}", 2);
    jws_builder_flush(&jws_builder);
    jws_len = jws_builder_result(&jws_builder);
    if (jws_len < 0)
        return -1;

    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_method(builder, HTTP_METHOD_POST);
    http_request_builder_target(builder, acme->domains[acme->resolved_challenges].challenge_url);
    http_request_builder_body(builder, (HTTP_String) { jws_buf, jws_len });
    if (http_request_builder_send(builder) < 0)
        return -1;

    return 0;
}

static int complete_challenge_status_request(ACME *acme, HTTP_Response *response, bool *challenge_completed)
{
    *challenge_completed = false;

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

    // If status is "valid", move to next challenge
    HTTP_String status_http = { status.ptr, status.len };
    if (http_streq(status_http, HTTP_STR("valid"))) {
        acme->resolved_challenges++;
        *challenge_completed = true;
    }

    return 0;
}

static int send_finalize_order_request(ACME *acme, HTTP_Client *client)
{
    // This should send a CSR to the finalize URL
    // For now, placeholder implementation
    char jws_buf[1<<12];
    int  jws_len;

    JWS_Builder jws_builder;
    jws_builder_init(&jws_builder, acme->account_key, true, jws_buf, (int) sizeof(jws_buf));
    jws_builder_write(&jws_builder, "{\"alg\":\"ES256\",\"kid\":\"", sizeof("{\"alg\":\"ES256\",\"kid\":\"")-1);
    jws_builder_write(&jws_builder, acme->account_url.ptr, acme->account_url.len);
    jws_builder_write(&jws_builder, "\",\"nonce\":\"", sizeof("\",\"nonce\":\"")-1);
    jws_builder_write(&jws_builder, acme->nonce.ptr, acme->nonce.len);
    jws_builder_write(&jws_builder, "\",\"url\":\"", sizeof("\",\"url\":\"")-1);
    jws_builder_write(&jws_builder, acme->finalize_url.ptr, acme->finalize_url.len);
    jws_builder_write(&jws_builder, "\"}", sizeof("\"}")-1);
    jws_builder_flush(&jws_builder);
    jws_builder_write(&jws_builder, "{\"csr\":\"<placeholder_csr>\"}", sizeof("{\"csr\":\"<placeholder_csr>\"}")-1);
    jws_builder_flush(&jws_builder);
    jws_len = jws_builder_result(&jws_builder);
    if (jws_len < 0)
        return -1;

    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_method(builder, HTTP_METHOD_POST);
    http_request_builder_target(builder, acme->finalize_url);
    http_request_builder_body(builder, (HTTP_String) { jws_buf, jws_len });
    if (http_request_builder_send(builder) < 0)
        return -1;

    return 0;
}

static int complete_finalize_request(ACME *acme, HTTP_Response *response)
{
    // Update nonce
    extract_nonce(acme, response);

    // Parse response to get certificate URL
    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL)
        return -1;

    JSON_String cert_url;
    if (json_match(json, &error, "{'certificate': ?}", &cert_url) == 0) {
        acme->certificate_url.ptr = cert_url.ptr;
        acme->certificate_url.len = cert_url.len;
    }

    return 0;
}

static int send_certificate_request(ACME *acme, HTTP_Client *client)
{
    char jws_buf[1<<9];
    int  jws_len;

    JWS_Builder jws_builder;
    jws_builder_init(&jws_builder, acme->account_key, true, jws_buf, (int) sizeof(jws_buf));
    jws_builder_write(&jws_builder, "{\"alg\":\"ES256\",\"kid\":\"", sizeof("{\"alg\":\"ES256\",\"kid\":\"")-1);
    jws_builder_write(&jws_builder, acme->account_url.ptr, acme->account_url.len);
    jws_builder_write(&jws_builder, "\",\"nonce\":\"", sizeof("\",\"nonce\":\"")-1);
    jws_builder_write(&jws_builder, acme->nonce.ptr, acme->nonce.len);
    jws_builder_write(&jws_builder, "\",\"url\":\"", sizeof("\",\"url\":\"")-1);
    jws_builder_write(&jws_builder, acme->certificate_url.ptr, acme->certificate_url.len);
    jws_builder_write(&jws_builder, "\"}", sizeof("\"}")-1);
    jws_builder_flush(&jws_builder);
    jws_builder_write(&jws_builder, "", 0);
    jws_builder_flush(&jws_builder);
    jws_len = jws_builder_result(&jws_builder);
    if (jws_len < 0)
        return -1;

    HTTP_RequestBuilder builder = http_client_get_builder(client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_method(builder, HTTP_METHOD_POST);
    http_request_builder_target(builder, acme->certificate_url);
    http_request_builder_body(builder, (HTTP_String) { jws_buf, jws_len });
    if (http_request_builder_send(builder) < 0)
        return -1;

    return 0;
}

static int complete_certificate_request(ACME *acme, HTTP_Response *response)
{
    // Update nonce
    extract_nonce(acme, response);

    // The response body contains the certificate
    // Store it or process it as needed
    // For now, we just mark success
    return 0;
}

int acme_timeout(ACME *acme)
{
    switch (acme->state) {
    case ACME_STATE_CHALLENGE_3:
        return 1000;
    case ACME_STATE_WAIT:
        return 86400000; // 24 hours in milliseconds
    default:
        return -1;
    }
}

void acme_process_timeout(ACME *acme, HTTP_Client *client)
{
    switch (acme->state) {
    case ACME_STATE_CHALLENGE_3:
        {
            if (send_challenge_status_request(acme, client) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CHALLENGE_4;
        }
        break;
    case ACME_STATE_WAIT:
        {
            if (send_order_creation_request(acme, client) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CREATE_CERT;
        }
        break;
    }
}

bool acme_process_request(ACME *acme, HTTP_Request *request,
    HTTP_ResponseBuilder builder, HTTP_Client *client,
    HTTP_Server *server)
{
    HTTP_String path = request->url.path;
    HTTP_String prefix = HTTP_STR(".well-known/acme-challenge/");

    // Check if path starts with prefix
    if (path.len < prefix.len || memcmp(path.ptr, prefix.ptr, prefix.len) != 0)
        return false;

    if (acme->state != ACME_STATE_CHALLENGE_1 &&
        acme->state != ACME_STATE_CHALLENGE_3) {
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
        HTTP_String thumbprint = HTTP_STR("..."); // TODO: calculate thumbprint
        http_response_builder_status(builder, 200);
        http_response_builder_body(builder, expected_token);
        http_response_builder_body(builder, HTTP_STR("."));
        http_response_builder_body(builder, thumbprint);
        http_response_builder_send(builder);
    }
    return true;
}

void acme_process_response(ACME *acme, int result,
    HTTP_Response *response, HTTP_Client *client,
    HTTP_Server *server)
{
    switch (acme->state) {
    case ACME_STATE_DIRECTORY:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (complete_directory_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }

            if (send_first_nonce_request(acme, client) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_FIRST_NONCE;
        }
        break;
    case ACME_STATE_FIRST_NONCE:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (complete_first_nonce_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }

            if (account_exists(acme)) {
                if (certificate_exists(acme)) {
                    // A certificate exists. Wait for it to expire.
                    acme->state = ACME_STATE_WAIT;
                } else {
                    // No certificate associated to this instance. Create one.
                    if (send_order_creation_request(acme, client) < 0) {
                        acme->state = ACME_STATE_ERROR;
                        break;
                    }
                    acme->state = ACME_STATE_CREATE_CERT;
                }
            } else {
                // No account associated to this instance. Create one.
                if (send_account_creation_request(acme, client) < 0) {
                    acme->state = ACME_STATE_ERROR;
                    break;
                }
                acme->state = ACME_STATE_CREATE_ACCOUNT;
            }
        }
        break;
    case ACME_STATE_CREATE_ACCOUNT:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (complete_account_creation_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }

            // If no account existed, surely a certificate doesn't
            // exist either, so create one.
            if (send_order_creation_request(acme, client) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CREATE_CERT;
        }
        break;
    case ACME_STATE_CREATE_CERT:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (complete_order_creation_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }

            // The order was create. Now we need to perform
            // the challanges.
            if (send_next_challenge_info_request(acme, client) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CHALLENGE_1;
        }
        break;
    case ACME_STATE_CHALLENGE_1:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (complete_next_challenge_info_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (send_next_challenge_begin_request(acme, client) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CHALLENGE_2;
        }
        break;
    case ACME_STATE_CHALLENGE_2:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (complete_next_challenge_begin_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CHALLENGE_3;
        }
        break;
    case ACME_STATE_CHALLENGE_4:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }

            bool challenge_completed;
            if (complete_challenge_status_request(acme, response, &challenge_completed) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }

            if (challenge_completed) {
                if (all_challenges_completed(acme)) {
                    // Finalize the order
                    if (send_finalize_order_request(acme, client) < 0) {
                        acme->state = ACME_STATE_ERROR;
                        break;
                    }
                    acme->state = ACME_STATE_FINALIZE;
                } else {
                    // Next challenge
                    if (send_next_challenge_info_request(acme, client) < 0) {
                        acme->state = ACME_STATE_ERROR;
                        break;
                    }
                    acme->state = ACME_STATE_CHALLENGE_1;
                }
            } else {
                // Go back to waiting
                acme->state = ACME_STATE_CHALLENGE_3;
            }
        }
        break;
    case ACME_STATE_FINALIZE:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (complete_finalize_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (send_certificate_request(acme, client) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CERTIFICATE;
        }
        break;
    case ACME_STATE_CERTIFICATE:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (complete_certificate_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            // Now wait for the certificate to expire
            acme->state = ACME_STATE_WAIT;
        }
        break;
    default:
        // Do nothing
        break;
    }
}

void acme_agree_to_terms_of_service(ACME *acme)
{
    // TODO: Implement terms of service agreement
    (void)acme;
}
