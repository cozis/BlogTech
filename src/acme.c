#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "json.h"
#include "acme.h"
#include "jws.h"
#include "file_system.h"

//////////////////////////////////////////////////////////////////////////////////////
// Configurations & Utilities
//////////////////////////////////////////////////////////////////////////////////////

#ifndef ACME_SERVER_URL
// TODO: comment
#define ACME_SERVER_URL "https://0.0.0.0:14000/dir"
//#define ACME_SERVER_URL "https://acme-v02.api.letsencrypt.org/directory"
#endif

//#define TRACE_STATE_TRANSITIONS

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
    if (s.len == 0)
        return (HTTP_String) { NULL, 0 };

    char *p = malloc(s.len);
    if (p == NULL)
        return (HTTP_String) { NULL, 0 };

    memcpy(p, s.ptr, s.len);
    return (HTTP_String) { p, s.len };
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

//////////////////////////////////////////////////////////////////////////////////////
// OpenSSL
//////////////////////////////////////////////////////////////////////////////////////

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

static int
create_certificate_signing_request(EVP_PKEY **out_pkey,
    HTTP_String *domains, int num_domains,
    HTTP_String country, HTTP_String org,
    char *dst, int cap)
{
    if (num_domains < 1)
        return -1;

    // Generate a new key pair
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
    EVP_PKEY_CTX_free(pctx);

    // Create the CSR structure
    X509_REQ *req = X509_REQ_new();
    if (!req) {
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Set version (version 0 for CSR)
    if (!X509_REQ_set_version(req, 0L)) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Get the subject name
    X509_NAME *name = X509_REQ_get_subject_name(req);
    if (!name) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Add subject fields
    if (country.len > 0)
        X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
            (unsigned char *)country.ptr, country.len, -1, 0);

    if (org.len > 0)
        X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            (unsigned char *)org.ptr, org.len, -1, 0);

    // Use first domain as CN
    if (domains[0].len > 0)
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (unsigned char *)domains[0].ptr, domains[0].len, -1, 0);

    // Build SAN string: "DNS:example.com,DNS:www.example.com,..."
    int san_len = 0;
    for (int i = 0; i < num_domains; i++)
        san_len += 4 + domains[i].len + 1;  // "DNS:" + domain + ","

    char *san_str = OPENSSL_malloc(san_len);
    if (!san_str) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    char *p = san_str;
    for (int i = 0; i < num_domains; i++) {
        if (i > 0)
            *p++ = ',';
        memcpy(p, "DNS:", 4);
        p += 4;
        memcpy(p, domains[i].ptr, domains[i].len);
        p += domains[i].len;
    }
    *p = '\0';

    // Create SAN extension
    X509_EXTENSION *san_ext = X509V3_EXT_conf_nid(NULL, NULL,
        NID_subject_alt_name, san_str);
    OPENSSL_free(san_str);

    if (!san_ext) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Add extension to CSR
    X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();
    if (!exts) {
        X509_EXTENSION_free(san_ext);
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }
    sk_X509_EXTENSION_push(exts, san_ext);
    X509_REQ_add_extensions(req, exts);
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);

    // Set the public key
    if (!X509_REQ_set_pubkey(req, pkey)) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Sign the CSR with the private key
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Get required length
    int len = i2d_X509_REQ(req, NULL);
    if (len < 0 || len > cap) {
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Actually encode
    unsigned char *out = (unsigned char *)dst;
    len = i2d_X509_REQ(req, &out);
    X509_REQ_free(req);

    // Return the generated key pair via output parameter
    if (out_pkey)
        *out_pkey = pkey;
    else
        EVP_PKEY_free(pkey);

    return len;
}

static EVP_PKEY *parse_private_key(HTTP_String str)
{
    BIO *bio = BIO_new_mem_buf(str.ptr, str.len);
    if (bio == NULL)
        return NULL;

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);

    BIO_free(bio);
    return pkey;
}

//////////////////////////////////////////////////////////////////////////////////////
// Request Builder
//////////////////////////////////////////////////////////////////////////////////////

typedef struct {

    bool error;
    bool dont_verify_cert;
    HTTP_String url;

    JWS_Builder jws_builder;
    char        jws_buffer[1<<10];

} RequestBuilder;

// NOTE: The url argument must be valid until request_builder_send
//       is called.
static void
request_builder_init(RequestBuilder *builder,
    ACME_Account account, HTTP_String nonce,
    bool dont_verify_cert, HTTP_String url)
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

static void
request_builder_write(RequestBuilder *builder, HTTP_String str)
{
    if (builder->error)
        return;
    jws_builder_write(&builder->jws_builder, str.ptr, str.len);
}

static int
request_builder_send(RequestBuilder *builder, HTTP_Client *client)
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

//////////////////////////////////////////////////////////////////////////////////////
// ACME object management
//////////////////////////////////////////////////////////////////////////////////////

static int send_directory_request(ACME *acme, HTTP_Client *client);

void acme_config_init(ACME_Config *config,
    HTTP_Client *client,
    HTTP_String directory_url,
    HTTP_String email,
    HTTP_String country,
    HTTP_String organization,
    HTTP_String domain)
{
    if (client == NULL
        || 0 == directory_url.len
        || 0 == email.len
        || 0 == country.len
        || 0 == organization.len
        || 0 == domain.len) {
        config->error = true;
        return;
    }

    config->directory_url = directory_url;
    config->dont_verify_cert = false;

    config->email = email;
    config->country = country;
    config->organization = organization;
    config->domains[0] = domain;
    config->num_domains = 1;
    config->agree_tos = false;

    config->account_key_file = HTTP_STR("account_secret_key.pem");
    config->certificate_file = HTTP_STR("certificate.pem");
    config->certificate_key_file = HTTP_STR("certificate_secret_key.pem");

    config->client = client;
    config->error = false;
}

void acme_config_add_domain(ACME_Config *config,
    HTTP_String domain)
{
    if (config->error)
        return;

    if (domain.len == 0 || config->num_domains == ACME_DOMAIN_LIMIT) {
        config->error = true;
        return;
    }

    config->domains[config->num_domains++] = domain;
}

static bool
batch_allocate_strings(HTTP_String **s)
{
    int total_len = 0;
    for (int i = 0; s[i] != NULL; i++)
        total_len += s[i]->len;

    char *p = malloc(total_len);
    if (p == NULL)
        return false;

    for (int i = 0; s[i] != NULL; i++) {
        memcpy(p, s[i]->ptr, s[i]->len);
        s[i]->ptr = p;
        p += s[i]->len;
    }

    return true;
}

int acme_init(ACME *acme, ACME_Config *config)
{
    if (config->error)
        return -1;

    // Initialize all pointer fields to NULL for safe cleanup via acme_free()
    acme->directory_url.ptr = NULL;
    acme->urls.new_account.ptr = NULL;
    acme->account.url.ptr = NULL;
    acme->account.key = NULL;
    acme->order_url.ptr = NULL;
    acme->finalize_url.ptr = NULL;
    acme->certificate_url.ptr = NULL;
    acme->certificate.ptr = NULL;
    acme->certificate_key.ptr = NULL;
    acme->num_domains = 0;
    for (int i = 0; i < ACME_DOMAIN_LIMIT; i++) {
        acme->domains[i].name.ptr = NULL;
        acme->domains[i].authorization_url.ptr = NULL;
        acme->domains[i].challenge_token.ptr = NULL;
        acme->domains[i].challenge_url.ptr = NULL;
    }

    // First, do a shallow copy of all string fields
    acme->directory_url = config->directory_url;
    acme->email = config->email;
    acme->country = config->country;
    acme->organization = config->organization;
    acme->account_key_file = config->account_key_file;
    acme->certificate_file = config->certificate_file;
    acme->certificate_key_file = config->certificate_key_file;

    // Then, batch allocate replacements
    HTTP_String *batch[] = {
        &acme->directory_url,
        &acme->email,
        &acme->country,
        &acme->organization,
        &acme->account_key_file,
        &acme->certificate_file,
        &acme->certificate_key_file,
        NULL,
    };
    if (!batch_allocate_strings(batch))
        return -1;

    // Now, do the same for the domain names

    HTTP_String *batch2[ACME_DOMAIN_LIMIT+1];
    for (int i = 0; i < config->num_domains; i++) {
        acme->domains[i].name = config->domains[i];
        batch2[i] = &acme->domains[i].name;
    }
    acme->num_domains = config->num_domains;
    batch2[config->num_domains] = NULL;
    if (!batch_allocate_strings(batch2)) {
        free(acme->directory_url.ptr);
        return -1;
    }

    // Now set everything else

    acme->client = config->client;
    acme->dont_verify_cert = config->dont_verify_cert;

    acme->agree_tos = config->agree_tos;

    acme->state = ACME_STATE_DIRECTORY;

    acme->nonce = (HTTP_String) { acme->nonce_buf, 0 };

    //////////////////////////////////////////////////////////////
    // Load the account key from the file system.
    //
    // If the file doesn't exist, we start the session without an
    // account. If the file couldn't be read due to an unexpected
    // error, we fail on the spot. If the key does exists but its
    // contents are invalid, we delete the file and continue without
    // an account.
    HTTP_String account_key;
    int ret = file_read_all(config->account_key_file, &account_key);
    if (ret < 0) {
        if (ret != ERROR_FILE_NOT_FOUND) {
            acme_free(acme);
            return -1;
        }
        // File not found - continue without account
    } else {
        EVP_PKEY *key = parse_private_key(account_key);
        if (key == NULL)
            remove_file_or_dir(acme->account_key_file);
        acme->account.key = key;
        free(account_key.ptr);
    }

    // This section loads the certificate and its key from the file system.
    // If only part of the expected data is present on the file system, we
    // delete it and start from scratch. If an error occurs, we just drop
    // what we are doing and fail.
    if (acme->account.key != NULL) {
        HTTP_String certificate;
        ret = file_read_all(acme->certificate_file, &certificate);
        if (ret < 0) {
            if (ret != ERROR_FILE_NOT_FOUND) {
                acme_free(acme);
                return -1;
            }
            // File not found - continue without certificate
        } else {
            HTTP_String certificate_key;
            ret = file_read_all(acme->certificate_key_file, &certificate_key);
            if (ret < 0) {
                free(certificate.ptr);
                if (ret != ERROR_FILE_NOT_FOUND) {
                    acme_free(acme);
                    return -1;
                }
                // File not found - continue without certificate key
            } else {
                acme->certificate = certificate;
                acme->certificate_key = certificate_key;
            }
        }
    }
    if (acme->certificate.len == 0) {
        remove_file_or_dir(acme->certificate_file);
        remove_file_or_dir(acme->certificate_key_file);
    }

    // TODO: before requesting a certificate, the ACME client should
    //       send plain HTTP requests to itself through the domains
    //       specified by the user to check whether it's entitled to
    //       the certificates or not.
    if (send_directory_request(acme, acme->client) < 0) {
        acme_free(acme);
        return -1;
    }

    return 0;
}

void acme_free(ACME *acme)
{
    // Free the account key (OpenSSL)
    if (acme->account.key)
        EVP_PKEY_free(acme->account.key);

    // Free the batch-allocated config strings
    // (directory_url, email, country, organization, account_key_file,
    // certificate_file, certificate_key_file are all in one contiguous block)
    free(acme->directory_url.ptr);

    // Free the batch-allocated domain names
    // (all domain names are in one contiguous block starting at domains[0].name)
    if (acme->num_domains > 0)
        free(acme->domains[0].name.ptr);

    // Free the URL set (all URLs in one contiguous block)
    free(acme->urls.new_account.ptr);

    // Free individually allocated URLs (via allocstr)
    free(acme->account.url.ptr);
    free(acme->order_url.ptr);
    free(acme->finalize_url.ptr);
    free(acme->certificate_url.ptr);

    // Free per-domain challenge data (each allocated via allocstr)
    for (int i = 0; i < acme->num_domains; i++) {
        free(acme->domains[i].authorization_url.ptr);
        free(acme->domains[i].challenge_token.ptr);
        free(acme->domains[i].challenge_url.ptr);
    }

    // Free certificate data
    free(acme->certificate.ptr);
    free(acme->certificate_key.ptr);
}

//////////////////////////////////////////////////////////////////////////////////////
// Request generators & response handlers
//////////////////////////////////////////////////////////////////////////////////////

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
    http_request_builder_target(builder, acme->directory_url);
    if (http_request_builder_send(builder) < 0)
        return -1;
    return 0;
}

static int complete_directory_request(ACME *acme, HTTP_Response *response)
{
    if (response->status != 200)
        return -1;

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
        return -1; // Response doesn't have a nonce

    HTTP_String nonce = response->headers[idx].value;
    if (nonce.len > (int) sizeof(acme->nonce_buf))
        return -1; // Nonce is larger than the buffer

    memset(acme->nonce_buf, 0, sizeof(acme->nonce_buf));
    memcpy(acme->nonce_buf, nonce.ptr, nonce.len);
    acme->nonce.ptr = acme->nonce_buf;
    acme->nonce.len = nonce.len;

    // Nonce updated!
    return 0;
}

static int complete_first_nonce_request(ACME *acme, HTTP_Response *response)
{
    if (response->status != 204)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    // Nothing to be done!
    return 0;
}

static int send_account_creation_request(ACME *acme, HTTP_Client *client)
{
    if (generate_account_key(&acme->account) < 0)
        return -1;

    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce,
        acme->dont_verify_cert, acme->urls.new_account);

    request_builder_write(&builder, HTTP_STR("{\"contact\":[\"mailto:"));
    request_builder_write(&builder, acme->email);
    request_builder_write(&builder, HTTP_STR("\"],\"termsOfServiceAgreed\":"));
    request_builder_write(&builder, acme->agree_tos ? HTTP_STR("true") : HTTP_STR("false"));
    request_builder_write(&builder, HTTP_STR("}"));

    return request_builder_send(&builder, acme->client);
}

static int complete_account_creation_request(ACME *acme, HTTP_Response *response)
{
    // The server returns 201 if it created an account
    // and 200 if it already existed.
    if (response->status != 201 && response->status != 200)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    int idx = http_find_header(response->headers, response->num_headers, HTTP_STR("Location"));
    if (idx == -1)
        return -1; // Location header missing

    acme->account.url = allocstr(response->headers[idx].value);
    if (acme->account.url.ptr == NULL)
        return -1; // Allocation failed

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return -1;

    if (!PEM_write_bio_PrivateKey(bio, acme->account.key, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(bio);
        return -1;
    }

    char *pem_buf;
    long pem_len = BIO_get_mem_data(bio, &pem_buf);

    // The account was created so we can store the key
    if (file_write_all(acme->account_key_file, (HTTP_String) { pem_buf, pem_len }) < 0) {
        BIO_free(bio);
        return -1;
    }

    BIO_free(bio);
    return 0;
}

static int send_order_creation_request(ACME *acme, HTTP_Client *client)
{
    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce,
        acme->dont_verify_cert, acme->urls.new_order);

    request_builder_write(&builder, HTTP_STR("{\"identifiers\":["));
    for (int i = 0; i < acme->num_domains; i++) {
        if (i > 0)
            request_builder_write(&builder, HTTP_STR(","));
        request_builder_write(&builder, HTTP_STR("{\"type\":\"dns\",\"value\":\""));
        request_builder_write(&builder, acme->domains[i].name);
        request_builder_write(&builder, HTTP_STR("\"}"));
    }
    request_builder_write(&builder, HTTP_STR("]}"));

    return request_builder_send(&builder, acme->client);
}

static int complete_order_creation_request(ACME *acme, HTTP_Response *response)
{
    if (response->status != 201)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    int i = http_find_header(response->headers, response->num_headers, HTTP_STR("Location"));
    if (i < 0)
        return -1;
    acme->order_url = allocstr(response->headers[i].value);
    if (acme->order_url.ptr == NULL)
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

    acme->finalize_url = allocstr((HTTP_String) { finalize_url.ptr, finalize_url.len });
    if (acme->finalize_url.ptr == NULL)
        return -1;

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
        if (acme->domains[j].authorization_url.ptr == NULL)
            return -1;

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
    request_builder_init(&builder, acme->account, acme->nonce,
        acme->dont_verify_cert, auth_url);

    request_builder_write(&builder, HTTP_STR(""));

    return request_builder_send(&builder, acme->client);
}

static int complete_next_challenge_info_request(ACME *acme, HTTP_Response *response)
{
    assert(acme->resolved_challenges < acme->num_domains);

    if (response->status != 200)
        return -1;

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
    if (acme->domains[acme->resolved_challenges].challenge_token.ptr == NULL)
        return -1;

    acme->domains[acme->resolved_challenges].challenge_url = allocstr(url);
    if (acme->domains[acme->resolved_challenges].challenge_url.ptr == NULL)
        return -1;

    return 0;
}

static int send_next_challenge_begin_request(ACME *acme, HTTP_Client *client)
{
    assert(acme->resolved_challenges < acme->num_domains);

    HTTP_String challenge_url = acme->domains[acme->resolved_challenges].challenge_url;

    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce,
        acme->dont_verify_cert, challenge_url);

    request_builder_write(&builder, HTTP_STR("{}"));

    return request_builder_send(&builder, acme->client);
}

static int complete_next_challenge_begin_request(ACME *acme, HTTP_Response *response)
{
    assert(acme->resolved_challenges < acme->num_domains);

    if (response->status != 200)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    return 0;
}

static int send_challenge_status_request(ACME *acme,
    HTTP_Client *client)
{
    assert(acme->resolved_challenges < acme->num_domains);

    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce,
        acme->dont_verify_cert, acme->domains[acme->resolved_challenges].challenge_url);

    request_builder_write(&builder, HTTP_STR(""));

    return request_builder_send(&builder, acme->client);
}

static int complete_challenge_status_request(ACME *acme,
    HTTP_Response *response, bool *challenge_completed)
{
    *challenge_completed = false;

    if (response->status != 200)
        return -1;

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

static int send_finalize_order_request(ACME *acme, HTTP_Client *client)
{
    HTTP_String domains[ACME_DOMAIN_LIMIT];
    for (int i = 0; i < acme->num_domains; i++)
        domains[i] = acme->domains[i].name;
    int num_domains = acme->num_domains;

    EVP_PKEY *cert_key;
    char csr_buf[1<<12];
    int csr_len = create_certificate_signing_request(&cert_key, domains,
        num_domains, acme->country, acme->organization, csr_buf, sizeof(csr_buf));
    if (csr_len < 0)
        return -1;

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio)
        return -1;

    if (!PEM_write_bio_PrivateKey(bio, cert_key, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(bio);
        EVP_PKEY_free(cert_key);
        return -1;
    }

    char *pem_buf;
    long pem_len = BIO_get_mem_data(bio, &pem_buf);

    HTTP_String certificate_key = { pem_buf, pem_len };
    if (file_write_all(acme->certificate_key_file, certificate_key) < 0) {
        BIO_free(bio);
        EVP_PKEY_free(cert_key);
        return -1;
    }

    acme->certificate_key.ptr = malloc(certificate_key.len);
    if (acme->certificate_key.ptr == NULL) {
        BIO_free(bio);
        EVP_PKEY_free(cert_key);
        return -1;
    }
    memcpy(acme->certificate_key.ptr, pem_buf, pem_len);
    acme->certificate_key.len = pem_len;

    BIO_free(bio);
    EVP_PKEY_free(cert_key);

    csr_len = jws_base64url_encode_inplace(csr_buf, csr_len, sizeof(csr_buf), false);
    if (csr_len < 0)
        return -1;
    HTTP_String csr = { csr_buf, csr_len };

    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce,
        acme->dont_verify_cert, acme->finalize_url);

    request_builder_write(&builder, HTTP_STR("{\"csr\":\""));
    request_builder_write(&builder, csr);
    request_builder_write(&builder, HTTP_STR("\"}"));

    return request_builder_send(&builder, acme->client);
}

static int complete_finalize_order_request(ACME *acme, HTTP_Response *response)
{
    if (response->status != 200)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    // The finalization request returns an update order object
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
    request_builder_init(&builder, acme->account,
        acme->nonce, acme->dont_verify_cert, acme->order_url);

    request_builder_write(&builder, HTTP_STR(""));

    return request_builder_send(&builder, acme->client);
}

static int complete_certificate_poll_request(ACME *acme, HTTP_Response *response)
{
    if (response->status != 200)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL)
        return -1;

    JSON_String status = json_get_string(json_get_field(json, JSON_STR("status")));
    if (json_streq(status, JSON_STR("valid"))) {

        JSON_String certificate_url = json_get_string(json_get_field(json, JSON_STR("certificate")));
        if (certificate_url.len == 0)
            return -1;
        acme->certificate_url = allocstr((HTTP_String) { certificate_url.ptr, certificate_url.len });
        if (acme->certificate_url.ptr == NULL)
            return -1;

    } else if (!json_streq(status, JSON_STR("processing"))) {
        return -1;
    }

    return 0;
}

static int send_certificate_download_request(ACME *acme, HTTP_Client *client)
{
    RequestBuilder builder;
    request_builder_init(&builder, acme->account, acme->nonce,
        acme->dont_verify_cert, acme->certificate_url);

    request_builder_write(&builder, HTTP_STR(""));

    return request_builder_send(&builder, acme->client);
}

static int complete_certificate_download_request(ACME *acme, HTTP_Response *response)
{
    if (response->status != 200)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    HTTP_String certificate = response->body;
    if (file_write_all(acme->certificate_file, certificate) < 0)
        return -1;

    acme->certificate.ptr = malloc(certificate.len);
    if (acme->certificate.ptr == NULL)
        return -1;
    memcpy(acme->certificate.ptr, certificate.ptr, certificate.len);
    acme->certificate.len = certificate.len;

    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////
// State machine
//////////////////////////////////////////////////////////////////////////////////////

static bool account_exists(ACME *acme)
{
    return acme->account.url.len > 0;
}

static bool certificate_exists(ACME *acme)
{
    return acme->certificate.len > 0;
}

static bool all_challenges_completed(ACME *acme)
{
    return acme->resolved_challenges == acme->num_domains;
}

static bool acquired_certificate(ACME *acme)
{
    return acme->certificate_url.len > 0;
}

// Free order-related memory to prepare for a new certificate order.
// This prevents memory leaks when renewing certificates.
static void reset_order_data(ACME *acme)
{
    // Free URLs from previous order
    free(acme->order_url.ptr);
    acme->order_url = (HTTP_String) { NULL, 0 };

    free(acme->finalize_url.ptr);
    acme->finalize_url = (HTTP_String) { NULL, 0 };

    free(acme->certificate_url.ptr);
    acme->certificate_url = (HTTP_String) { NULL, 0 };

    // Free per-domain challenge data from previous order
    for (int i = 0; i < acme->num_domains; i++) {
        free(acme->domains[i].authorization_url.ptr);
        acme->domains[i].authorization_url = (HTTP_String) { NULL, 0 };

        free(acme->domains[i].challenge_token.ptr);
        acme->domains[i].challenge_token = (HTTP_String) { NULL, 0 };

        free(acme->domains[i].challenge_url.ptr);
        acme->domains[i].challenge_url = (HTTP_String) { NULL, 0 };
    }

    acme->resolved_challenges = 0;
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
            if (send_challenge_status_request(acme, acme->client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CHALLENGE_4);
        }
        break;
    case ACME_STATE_WAIT:
        {
            // Free previous order data before starting a new certificate order
            reset_order_data(acme);
            if (send_order_creation_request(acme, acme->client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CREATE_CERT);
        }
        break;
    case ACME_STATE_CERTIFICATE_POLL_WAIT:
        {
            if (send_certificate_poll_request(acme, acme->client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CERTIFICATE_POLL);
        }
        break;
    }
}

static bool starts_with(HTTP_String str, HTTP_String prefix)
{
    if (str.len < prefix.len || memcmp(str.ptr, prefix.ptr, prefix.len) != 0)
        return false;
    return true;
}

bool acme_process_request(ACME *acme, HTTP_Request *request,
    HTTP_ResponseBuilder builder)
{
    HTTP_String path = request->url.path;
    HTTP_String prefix = HTTP_STR("/.well-known/acme-challenge/");

    if (!starts_with(path, prefix))
        return false;

    if (acme->state != ACME_STATE_CHALLENGE_2 &&
        acme->state != ACME_STATE_CHALLENGE_3 &&
        acme->state != ACME_STATE_CHALLENGE_4) {
        http_response_builder_status(builder, 404);
        http_response_builder_send(builder);
        return true;
    }

    {
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
        char buf[44];
        int len = jwk_thumbprint(acme->account.key, buf, sizeof(buf));
        if (len < 0) {
            http_response_builder_status(builder, 500);
            http_response_builder_send(builder);
            return true;
        }
        HTTP_String thumbprint = { buf, len };

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

bool acme_process_response(ACME *acme, int result, HTTP_Response *response)
{
    uint64_t current_time = get_current_time();
    if (current_time == INVALID_TIME) {
        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
        return false;
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

            if (send_first_nonce_request(acme, acme->client) < 0) {
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
                    if (send_order_creation_request(acme, acme->client) < 0) {
                        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                        break;
                    }
                    CHANGE_STATE(acme->state, ACME_STATE_CREATE_CERT);
                }
            } else {
                // No account associated to this instance. Create one.
                if (send_account_creation_request(acme, acme->client) < 0) {
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
                if (send_account_creation_request(acme, acme->client) < 0) {
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
            if (send_order_creation_request(acme, acme->client) < 0) {
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
                if (send_order_creation_request(acme, acme->client) < 0) {
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
            if (send_next_challenge_info_request(acme, acme->client) < 0) {
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
                if (send_next_challenge_info_request(acme, acme->client) < 0) {
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
            if (send_next_challenge_begin_request(acme, acme->client) < 0) {
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
                if (send_next_challenge_begin_request(acme, acme->client) < 0) {
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
                if (send_challenge_status_request(acme, acme->client) < 0) {
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
                    if (send_finalize_order_request(acme, acme->client) < 0) {
                        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                        break;
                    }
                    CHANGE_STATE(acme->state, ACME_STATE_FINALIZE);
                } else {
                    // Next challenge
                    if (send_next_challenge_info_request(acme, acme->client) < 0) {
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
                if (send_finalize_order_request(acme, acme->client) < 0) {
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
            if (send_certificate_poll_request(acme, acme->client) < 0) {
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
                if (send_certificate_poll_request(acme, acme->client) < 0) {
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
                if (send_certificate_download_request(acme, acme->client) < 0) {
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
                if (send_certificate_download_request(acme, acme->client) < 0) {
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
            return true;
        }
        break;
    default:
        // Do nothing
        break;
    }

    // All branches except the one that obtained a
    // certificate arrive here
    return false;
}

//////////////////////////////////////////////////////////////////////////////////////
// End
//////////////////////////////////////////////////////////////////////////////////////
