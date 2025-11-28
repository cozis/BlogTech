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

#include <json.h>

#include "acme.h"

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

int acme_init(ACME *acme, HTTP_Client *client,
    HTTP_String *domains, int num_domains)
{
    acme->state = ACME_STATE_DIRECTORY;
    acme->urls_loaded = false;

    acme->num_domains = num_domains;
    for (int i = 0; i < num_domains; i++)
        acme->domains[i] = domains[i]; // TODO: this should be a copy

    if (send_directory_request(acme) < 0)
        return -1;

    return 0;
}

void acme_free(ACME *acme)
{
    if (acme->urls_loaded) {
        free(acme->url_new_account.ptr);
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

    HTTP_String new_account;
    HTTP_String new_nonce;
    HTTP_String new_order;
    HTTP_String renewal_info;
    HTTP_String revoke_cert;
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
    new_account.ptr = p;
    p += new_account.len;

    memcpy(p, new_nonce.ptr, new_nonce.len);
    new_nonce.ptr = p;
    p += new_nonce.len;

    memcpy(p, new_order.ptr, new_order.len);
    new_order.ptr = p;
    p += new_order.len;

    memcpy(p, renewal_info.ptr, renewal_info.len);
    renewal_info.ptr = p;
    p += renewal_info.len;

    memcpy(p, revoke_cert.ptr, revoke_cert.len);
    revoke_cert.ptr = p;
    p += revoke_cert.len;

    urls->new_account  = new_account;
    urls->new_nonce    = new_nonce;
    urls->new_order    = new_order;
    urls->renewal_info = renewal_info;
    urls->revoke_cert  = revoke_cert;

    return 0;
}

static int send_directory_request(ACME *acme)
{
    HTTP_RequestBuilder builder = http_client_get_builder(&client);
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

static int send_first_nonce_request(ACME *acme)
{
    HTTP_RequestBuilder builder = http_client_get_builder(&client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_method(builder, HTTP_METHOD_POST);
    http_request_builder_target(builder, acme->url_new_nonce);
    // TODO: payload?
    if (http_request_builder_send(builder) < 0)
        return -1;
    return 0;
}

static int complete_first_nonce_request(ACME *acme, HTTP_Response *response)
{
    // TODO
}

static int send_account_creation_request(ACME *acme)
{
    char jws_buf[1<<9];
    int  jws_len;

    JWS_Builder jws_builder;
    jws_builder_init(&jws_builder, acme->private_key, true, jws_buf, (int) sizeof(jws_buf));
    jws_builder_write(&jws_builder, HTTP_STR("{\"alg\":\"ES256\",\"jwk\":"));
    jws_builder_write(&jws_builder, acme->public_key);
    jws_builder_write(&jws_builder, HTTP_STR(",\"nonce\":\""));
    jws_builder_write(&jws_builder, acme->nonce);
    jws_builder_write(&jws_builder, HTTP_STR("\",\"url\":\""));
    jws_builder_write(&jws_builder, acme->account_url);
    jws_builder_write(&jws_builder, HTTP_STR("\"}"));
    jws_builder_flush(&jws_builder);
    jws_builder_write(&jws_builder, HTTP_STR("{\"contact\":[\"mailto:"));
    jws_builder_write(&jws_builder, acme->email);
    jws_builder_write(&jws_builder, HTTP_STR("\"],\"termsOfServiceAgreed\":"));
    jws_builder_write(&jws_builder, acme->agreed_to_terms_of_service ? HTTP_STR("true") : HTTP_STR("false"));
    jws_builder_write(&jws_builder, HTTP_STR("}"));
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
    if (response->status != 201)
        return -1;

    int idx = http_find_header(response->headers, response->num_headers, HTTP_STR("Location"));
    if (idx == -1) {
        // TODO: missing the Location header
        return -1;
    }
    HTTP_String account_url = response->headers[idx].value;

    idx = http_find_header(response->headers, response->num_headers, HTTP_STR("Replay-Nonce"));
    if (idx == -1) {
        // TODO: missing nonce header
        return -1;
    }
    HTTP_String nonce = response->headers[idx].value;
}

static int send_order_creation_request(ACME *acme)
{
    HTTP_RequestBuilder builder = http_client_get_builder(&client);
    http_request_builder_set_user(builder, acme);
    http_request_builder_method(builder, HTTP_METHOD_POST);
    http_request_builder_target(builder, acme->url_new_order);
    // TODO: write body
    if (http_request_builder_send(builder) < 0)
        return -1;
    return 0;
}

int acme_timeout(ACME *acme)
{
    switch (acme->state) {
    case ACME_STATE_CHALLENGE_2:
        return 1000;
    case ACME_STATE_WAIT:
        return xxx;
    }
    return -1;
}

void acme_process_timeout(ACME *acme)
{
    switch (acme->state) {
    case ACME_STATE_CHALLENGE_2:
        {
            if (send_challenge_status_request(acme) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CHALLENGE_3;
        }
        break;
    case ACME_STATE_WAIT:
        {
            if (send_order_creation_request(acme) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CREATE_CERT;
        }
        break;
    }
}

bool acme_process_request(ACME *acme, HTTP_Request *request, HTTP_RequestBuilder builder)
{
    HTTP_String path = request->url.path;
    HTTP_String prefix = HTTP_STR(".well-known/acme-challenge/");

    if (!http_startswith(path, prefix))
        return false;

    if (acme->state != ACME_STATE_CHALLENGE_1 &&
        acme->state != ACME_STATE_CHALLENGE_2) {
        http_response_builder_status(builder, 404);
        http_response_builder_send(builder);
    } else {
        HTTP_String token = {
            path.ptr + prefix.len,
            path.len - prefix.len
        };
        // TODO: check that the token is valid
        HTTP_String thumbprint = HTTP_STR("..."); // TODO
        http_response_builder_status(builder, 200);
        http_response_builder_body(builder, token);
        http_response_builder_body(builder, HTTP_STR("."));
        http_response_builder_body(builder, thumbprint);
        http_response_builder_send(builder);
    }
    return true;
}

void acme_process_response(ACME *acme, int result, HTTP_Response *response)
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

            if (send_first_nonce_request(acme) < 0) {
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
                    if (send_order_creation_request(acme) < 0) {
                        acme->state = ACME_STATE_ERROR;
                        break;
                    }
                    acme->state = ACME_STATE_CREATE_CERT;
                }
            } else {
                // No account associated to this instance. Create one.
                if (send_account_creation_request(acme) < 0) {
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
            if (send_order_creation_request(acme) < 0) {
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
            if (send_next_challenge_request(acme) < 0) {
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
            if (complete_next_challenge_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            acme->state = ACME_STATE_CHALLENGE_2;
        }
        break;
    case ACME_STATE_CHALLENGE_3:
        {
            if (result != HTTP_OK) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (complete_challenge_status_request(acme, response) < 0) {
                acme->state = ACME_STATE_ERROR;
                break;
            }
            if (challenge_completed(acme)) {
                if (all_challenges_completed(acme)) {
                    // Finalize the order
                    if (send_finalize_order_request(acme) < 0) {
                        acme->state = ACME_STATE_ERROR;
                        break;
                    }
                    acme->state = ACME_STATE_FINALIZE;
                } else {
                    // Next challenge
                    if (send_next_challenge_request(acme) < 0) {
                        acme->state = ACME_STATE_ERROR;
                        break;
                    }
                    acme->state = ACME_STATE_CHALLENGE_1;
                }
            } else {
                // Go back to waiting
                acme->state = ACME_STATE_CHALLENGE_2;
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
            if (send_certificate_request(acme) < 0) {
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
