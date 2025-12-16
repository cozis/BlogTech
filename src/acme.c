#ifndef _WIN32

#include "acme.h"

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#include "lib/jws.h"
#include "lib/json.h"
#include "lib/encode.h"
#include "lib/file_system.h"

//////////////////////////////////////////////////////////////////////////////////////
// Configurations & Utilities
//////////////////////////////////////////////////////////////////////////////////////

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

//////////////////////////////////////////////////////////////////////////////////////
// OpenSSL
//////////////////////////////////////////////////////////////////////////////////////

static int generate_account_key(ACME_Account *account, Logger *logger)
{
    // Create context for key generation
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        log(logger, S("Failed to create EVP_PKEY_CTX\n"), V());
        return -1;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        log(logger, S("Call to EVP_PKEY_keygen_init failed\n"), V());
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // Set the curve to P-256 (prime256v1/secp256r1)
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        log(logger, S("Call to EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed\n"), V());
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // Generate the key pair
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        log(logger, S("Call to EVP_PKEY_keygen failed\n"), V());
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    account->key = pkey;

    EVP_PKEY_CTX_free(pctx);
    return 0;
}

static int
create_certificate_signing_request(EVP_PKEY **out_pkey,
    string *domains, int num_domains,
    string country, string org,
    char *dst, int cap,
    Logger *logger)
{
    ASSERT(num_domains > 0);

    // Generate a new key pair
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        log(logger, S("Call to EVP_PKEY_CTX_new_id failed\n"), V());
        return -1;
    }

    // Initialize key generation
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        log(logger, S("Call to EVP_PKEY_keygen_init failed\n"), V());
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // Set the curve to P-256 (prime256v1/secp256r1)
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        log(logger, S("Call to EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed\n"), V());
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }

    // Generate the key pair
    EVP_PKEY *pkey = NULL;
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        log(logger, S("Call to EVP_PKEY_keygen failed\n"), V());
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);

    // Create the CSR structure
    X509_REQ *req = X509_REQ_new();
    if (!req) {
        log(logger, S("Call to X509_REQ_new failed\n"), V());
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Set version (version 0 for CSR)
    if (!X509_REQ_set_version(req, 0L)) {
        log(logger, S("Call to X509_REQ_set_version failed\n"), V());
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Get the subject name
    X509_NAME *name = X509_REQ_get_subject_name(req);
    if (!name) {
        log(logger, S("Call to X509_REQ_get_subject_name failed\n"), V());
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
        log(logger, S("Call to OPENSSL_malloc failed\n"), V());
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    char *p = san_str;
    for (int i = 0; i < num_domains; i++) {
        if (i > 0)
            *p++ = ',';
        memcpy_(p, "DNS:", 4);
        p += 4;
        memcpy_(p, domains[i].ptr, domains[i].len);
        p += domains[i].len;
    }
    *p = '\0';

    // Create SAN extension
    X509_EXTENSION *san_ext = X509V3_EXT_conf_nid(NULL, NULL,
        NID_subject_alt_name, san_str);
    OPENSSL_free(san_str);

    if (!san_ext) {
        log(logger, S("Call to X509V3_EXT_conf_nid failed\n"), V());
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Add extension to CSR
    X509_EXTENSIONS *exts = sk_X509_EXTENSION_new_null();
    if (!exts) {
        log(logger, S("Call to sk_X509_EXTENSION_new_null failed\n"), V());
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
        log(logger, S("Call to X509_REQ_set_pubkey failed\n"), V());
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Sign the CSR with the private key
    if (!X509_REQ_sign(req, pkey, EVP_sha256())) {
        log(logger, S("Call to X509_REQ_sign failed\n"), V());
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Get required length
    int len = i2d_X509_REQ(req, NULL);
    if (len < 0 || len > cap) {
        log(logger, S("Call to i2d_X509_REQ failed\n"), V());
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

static EVP_PKEY *parse_private_key(string str, Logger *logger)
{
    BIO *bio = BIO_new_mem_buf(str.ptr, str.len);
    if (bio == NULL) {
        log(logger, S("Call to BIO_new_mem_buf failed\n"), V());
        return NULL;
    }

    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey == NULL)
        log(logger, S("Call to PEM_read_bio_PrivateKey failed\n"), V());

    BIO_free(bio);
    return pkey;
}

static int get_chain_expiry(string pem, Time *out)
{
    BIO *bio = BIO_new_mem_buf(pem.ptr, pem.len);
    if (bio == NULL)
        return -1;

    UnixTime earliest = INVALID_UNIX_TIME;
    for (X509 *cert; (cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL; ) {

        struct tm current_tm;
        const ASN1_TIME *not_after = X509_get_notAfter(cert);
        if (!ASN1_TIME_to_tm(not_after, &current_tm)) {
            X509_free(cert);
            BIO_free(bio);
            return -1;
        }

        time_t tmp = timegm(&current_tm);
        if (tmp == (time_t) -1) {
            X509_free(cert);
            BIO_free(bio);
            return -1;
        }
        UnixTime current = tmp;

        if (earliest == INVALID_UNIX_TIME || current < earliest)
            earliest = current;

        X509_free(cert);
    }

    if (earliest == INVALID_UNIX_TIME) {
        BIO_free(bio);
        return -1;
    }

    UnixTime current_unix_time = get_current_unix_time();
    if (current_unix_time == INVALID_UNIX_TIME) {
        BIO_free(bio);
        return -1;
    }

    Time relative_time = get_current_time();
    if (relative_time == INVALID_TIME) {
        BIO_free(bio);
        return -1;
    }

    if (earliest > current_unix_time) {
        Time diff = (earliest - current_unix_time) * 1000;
        if (relative_time > TIME_MAX - diff) {
            BIO_free(bio);
            return -1;
        }
        relative_time += diff;
    }

    *out = relative_time;
    BIO_free(bio);
    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////
// Request Builder
//////////////////////////////////////////////////////////////////////////////////////

typedef struct {

    Logger *logger;
    b8      error;
    b8      dont_verify_cert;
    b8      trace_bytes;
    string  url;

    JWS_Builder jws_builder;
    char        jws_buffer[1<<10];

} RequestBuilder;

// NOTE: The url argument must be valid until request_builder_send
//       is called.
static void
request_builder_init(
    RequestBuilder* builder,
    ACME_Account    account,
    string          nonce,
    b8              dont_verify_cert,
    b8              trace_bytes,
    string          url,
    Logger*         logger)
{
    ASSERT(account.key);

    builder->logger = logger;
    builder->error = false;
    builder->dont_verify_cert = dont_verify_cert;
    builder->trace_bytes = trace_bytes;
    builder->url = url;

    jws_builder_init(&builder->jws_builder,
        account.key, true, builder->jws_buffer,
        (int) sizeof(builder->jws_buffer));

    if (account.url.ptr == NULL) {
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
request_builder_write(RequestBuilder *builder, string str)
{
    if (builder->error)
        return;
    jws_builder_write(&builder->jws_builder, str.ptr, str.len);
}

static int
request_builder_send(RequestBuilder *builder, CHTTP_Client *client)
{
    if (builder->error)
        return -1;

    jws_builder_flush(&builder->jws_builder);
    int ret = jws_builder_result(&builder->jws_builder);
    if (ret < 0) {
        log(builder->logger, S("JWS builder failure\n"), V());
        return -1;
    }
    string jws = { builder->jws_buffer, ret };

    CHTTP_RequestBuilder http_builder = chttp_client_get_builder(client);
    chttp_request_builder_set_user(http_builder, NULL); // TODO: should set pointer to the acme struct?
    chttp_request_builder_trace(http_builder, builder->trace_bytes);
    chttp_request_builder_insecure(http_builder, builder->dont_verify_cert);
    chttp_request_builder_method(http_builder, CHTTP_METHOD_POST);
    chttp_request_builder_target(http_builder, builder->url);
    chttp_request_builder_header(http_builder, CHTTP_STR("User-Agent: BlogTech")); // TODO: better user agnet
    chttp_request_builder_header(http_builder, CHTTP_STR("Content-Type: application/jose+json"));
    chttp_request_builder_body(http_builder, jws);
    ret = chttp_request_builder_send(http_builder);
    if (ret < 0) {
        string err = ZT2S(chttp_strerror(ret));
        log(builder->logger, S("Coultn't start request due to an HTTP error ({})\n"), V(err));
        return -1;
    }

    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////
// ACME object management
//////////////////////////////////////////////////////////////////////////////////////

static int send_directory_request(ACME *acme, CHTTP_Client *client);

void acme_config_init(ACME_Config *config,
    CHTTP_Client *client,
    string directory_url,
    string email,
    string country,
    string organization,
    string domain)
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
    config->trace_bytes = false;
    config->logger = NULL;

    config->email = email;
    config->country = country;
    config->organization = organization;
    config->domains[0] = domain;
    config->num_domains = 1;
    config->agree_tos = false;

    config->account_key_file = S("account_secret_key.pem");
    config->certificate_file = S("certificate.pem");
    config->certificate_key_file = S("certificate_secret_key.pem");

    config->client = client;
    config->error = false;
}

void acme_config_add_domain(ACME_Config *config,
    string domain)
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
batch_allocate_strings(string **s)
{
    int total_len = 0;
    for (int i = 0; s[i] != NULL; i++)
        total_len += s[i]->len;

    char *p = malloc(total_len);
    if (p == NULL)
        return false;

    for (int i = 0; s[i] != NULL; i++) {
        memcpy_(p, s[i]->ptr, s[i]->len);
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
    string *batch[] = {
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

    string *batch2[ACME_DOMAIN_LIMIT+1];
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
    acme->trace_bytes = config->trace_bytes;
    acme->logger = config->logger;

    acme->agree_tos = config->agree_tos;

    acme->state = ACME_STATE_DIRECTORY;

    acme->nonce = (string) { acme->nonce_buf, 0 };

    //////////////////////////////////////////////////////////////
    // Load the account key from the file system.
    //
    // If the file doesn't exist, we start the session without an
    // account. If the file couldn't be read due to an unexpected
    // error, we fail on the spot. If the key does exists but its
    // contents are invalid, we delete the file and continue without
    // an account.
    string account_key;
    int ret = file_read_all(config->account_key_file, &account_key);
    if (ret < 0) {
        if (ret != FS_ERROR_NOTFOUND) {
            log(acme->logger, S("Coultn't open account key file '{}'. Aborting ACME initialization.\n"), V(config->account_key_file));
            acme_free(acme);
            return -1;
        }
        // File not found - continue without account
        log(acme->logger, S("Account key file '{}' not found. Continuing without an account.\n"), V(config->account_key_file));
    } else {
        EVP_PKEY *key = parse_private_key(account_key, acme->logger);
        if (key == NULL) {
            log(acme->logger, S("Coultn't parse ACME account key in '{}'. Deleting the file and continuing without an account.\n"), V(config->account_key_file));
            file_delete(acme->account_key_file);
        } else {
            log(acme->logger, S("ACME account key parsed.\n"), V());
        }
        acme->account.key = key;
        free(account_key.ptr);
    }

    // This section loads the certificate and its key from the file system.
    // If only part of the expected data is present on the file system, we
    // delete it and start from scratch. If an error occurs, we just drop
    // what we are doing and fail.
    if (acme->account.key != NULL) {
        string certificate;
        ret = file_read_all(acme->certificate_file, &certificate);
        if (ret < 0) {
            if (ret != FS_ERROR_NOTFOUND) {
                log(acme->logger, S("Coultn't open certificate file '{}'. Aborting ACME initialization.\n"), V(config->certificate_file));
                acme_free(acme);
                return -1;
            }
            // File not found - continue without certificate
            log(acme->logger, S("Certificate file '{}' not found. Continuing without a certificate.\n"), V(config->certificate_file));
        } else {

            Time certificate_expiry;
            ret = get_chain_expiry(certificate, &certificate_expiry);
            if (ret < 0) {
                log(acme->logger, S("Couldn't determine expiry of certificate file '{}'.\n"), V(config->certificate_file));
                acme_free(acme);
                return -1;
            }
            log(acme->logger, S("Certificate will expire at {} UNIX time\n"), V(certificate_expiry / 1000));

            string certificate_key;
            ret = file_read_all(acme->certificate_key_file, &certificate_key);
            if (ret < 0) {
                free(certificate.ptr);
                if (ret != FS_ERROR_NOTFOUND) {
                    acme_free(acme);
                    return -1;
                }
                // File not found - continue without certificate key
                log(acme->logger, S("Certificate key file '{}' not found. Continuing without a certificate key.\n"), V(acme->certificate_key_file));
            } else {
                acme->certificate = certificate;
                acme->certificate_key = certificate_key;
                acme->certificate_expiry = certificate_expiry;
                log(acme->logger, S("Certificate and certificate key files found.\n"), V());
            }
        }
    }
    if (acme->certificate.len == 0) {
        log(acme->logger, S("Deleting certificate file '{}' and certificate key file '{}'\n"), V(acme->certificate_file, acme->certificate_key_file));
        file_delete(acme->certificate_file);
        file_delete(acme->certificate_key_file);
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

static int parse_urls(string body, ACME_URLSet *urls)
{
    char pool[1<<13];

    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(body.ptr, body.len, &arena, &error);
    if (json == NULL)
        return -1;

    string new_account;
    string new_nonce;
    string new_order;
    string renewal_info;
    string revoke_cert;
    int ret = json_match(json, &error,
        "{'newAccount': ?, 'newNonce': ?, 'newOrder': ?, "
        "'renewalInfo': ?, 'revokeCert': ? }",
        &new_account, &new_nonce, &new_order,
        &renewal_info, &revoke_cert);
    if (ret == 1) return -1;
    if (ret == -1) return -1;
    ASSERT(ret == 0);

    char *p = malloc(new_account.len + new_nonce.len
        + new_order.len + renewal_info.len + revoke_cert.len);
    if (p == NULL)
        return -1;

    memcpy_(p, new_account.ptr, new_account.len);
    urls->new_account.ptr = p;
    urls->new_account.len = new_account.len;
    p += new_account.len;

    memcpy_(p, new_nonce.ptr, new_nonce.len);
    urls->new_nonce.ptr = p;
    urls->new_nonce.len = new_nonce.len;
    p += new_nonce.len;

    memcpy_(p, new_order.ptr, new_order.len);
    urls->new_order.ptr = p;
    urls->new_order.len = new_order.len;
    p += new_order.len;

    memcpy_(p, renewal_info.ptr, renewal_info.len);
    urls->renewal_info.ptr = p;
    urls->renewal_info.len = renewal_info.len;
    p += renewal_info.len;

    memcpy_(p, revoke_cert.ptr, revoke_cert.len);
    urls->revoke_cert.ptr = p;
    urls->revoke_cert.len = revoke_cert.len;
    p += revoke_cert.len;

    return 0;
}

static int send_directory_request(ACME *acme, CHTTP_Client *client)
{
    CHTTP_RequestBuilder builder = chttp_client_get_builder(client);
    chttp_request_builder_set_user(builder, acme);
    chttp_request_builder_trace(builder, acme->trace_bytes);
    chttp_request_builder_insecure(builder, acme->dont_verify_cert);
    chttp_request_builder_method(builder, CHTTP_METHOD_GET);
    chttp_request_builder_target(builder, acme->directory_url);
    int ret = chttp_request_builder_send(builder);
    if (ret < 0) {
        string err = ZT2S(chttp_strerror(ret));
        log(acme->logger, S("Coultn't start ACME directory request due to an HTTP error ({})\n"), V(err));
        return -1;
    }
    return 0;
}

static int complete_directory_request(ACME *acme, CHTTP_Response *response)
{
    if (response->status != 200)
        return -1;

    if (parse_urls(response->body, &acme->urls) < 0)
        return -1;
    return 0;
}

static int send_first_nonce_request(ACME *acme, CHTTP_Client *client)
{
    CHTTP_RequestBuilder builder = chttp_client_get_builder(client);
    chttp_request_builder_set_user(builder, acme);
    chttp_request_builder_trace(builder, acme->trace_bytes);
    chttp_request_builder_insecure(builder, acme->dont_verify_cert);
    chttp_request_builder_method(builder, CHTTP_METHOD_GET);
    chttp_request_builder_target(builder, acme->urls.new_nonce);
    int ret = chttp_request_builder_send(builder);
    if (ret < 0) {
        string err = ZT2S(chttp_strerror(ret));
        log(acme->logger, S("Coultn't start ACME nonce request due to an HTTP error ({})\n"), V(err));
        return -1;
    }
    return 0;
}

static int extract_nonce(ACME *acme, CHTTP_Response *response)
{
    int idx = chttp_find_header(response->headers, response->num_headers, CHTTP_STR("Replay-Nonce"));
    if (idx == -1) {
        log(acme->logger, S("Response is missing the 'Replay-Nonce' header\n"), V());
        return -1; // Response doesn't have a nonce
    }

    string nonce = response->headers[idx].value;
    if (nonce.len > (int) sizeof(acme->nonce_buf)) {
        log(acme->logger, S("Received nonce is larger than expected\n"), V());
        return -1; // Nonce is larger than the buffer
    }

    memset(acme->nonce_buf, 0, sizeof(acme->nonce_buf));
    memcpy_(acme->nonce_buf, nonce.ptr, nonce.len);
    acme->nonce.ptr = acme->nonce_buf;
    acme->nonce.len = nonce.len;

    // Nonce updated!
    return 0;
}

static int complete_first_nonce_request(ACME *acme, CHTTP_Response *response)
{
    if (response->status != 204) {
        log(acme->logger, S("Response to nonce request returned status {} (was expecting 204)\n"), V(response->status));
        return -1;
    }

    if (extract_nonce(acme, response) < 0)
        return -1;

    // Nothing to be done!
    return 0;
}

static int send_account_creation_request(ACME *acme, CHTTP_Client *client)
{
    if (acme->account.key == NULL) {
        if (generate_account_key(&acme->account, acme->logger) < 0)
            return -1;
    }

    RequestBuilder builder;
    request_builder_init(&builder,
        acme->account,
        acme->nonce,
        acme->dont_verify_cert,
        acme->trace_bytes,
        acme->urls.new_account,
        acme->logger);

    request_builder_write(&builder, S("{\"contact\":[\"mailto:"));
    request_builder_write(&builder, acme->email);
    request_builder_write(&builder, S("\"],\"termsOfServiceAgreed\":"));
    request_builder_write(&builder, acme->agree_tos ? S("true") : S("false"));
    request_builder_write(&builder, S("}"));

    return request_builder_send(&builder, acme->client);
}

static int complete_account_creation_request(ACME *acme, CHTTP_Response *response)
{
    // The server returns 201 if it created an account
    // and 200 if it already existed.
    if (response->status != 201 && response->status != 200) {
        log(acme->logger, S("Account creation response has status {} but 201 or 200 were expected\n"), V(response->status));
        return -1;
    }

    if (extract_nonce(acme, response) < 0)
        return -1;

    int idx = chttp_find_header(response->headers, response->num_headers, CHTTP_STR("Location"));
    if (idx == -1) {
        log(acme->logger, S("Account creation response is missing the 'Location' header\n"), V());
        return -1; // Location header missing
    }

    acme->account.url = allocstr(response->headers[idx].value);
    if (acme->account.url.ptr == NULL) {
        log(acme->logger, S("Allocation failure\n"), V());
        return -1; // Allocation failed
    }

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        log(acme->logger, S("Call to BIO_new failed\n"), V());
        return -1;
    }

    if (!PEM_write_bio_PrivateKey(bio, acme->account.key, NULL, NULL, 0, NULL, NULL)) {
        log(acme->logger, S("Call to PEM_write_bio_PrivateKey failed\n"), V());
        BIO_free(bio);
        return -1;
    }

    char *pem_buf;
    long pem_len = BIO_get_mem_data(bio, &pem_buf);

    // The account was created so we can store the key
    if (file_write_all(acme->account_key_file, (string) { pem_buf, pem_len }) < 0) {
        log(acme->logger, S("Couldn't write to file '{}'\n"), V(acme->account_key_file));
        BIO_free(bio);
        return -1;
    }

    if (response->status == 201) {
        log(acme->logger, S("ACME account was created. The account key was stored in '{}'\n"), V(acme->account_key_file));
    } else {
        ASSERT(response->status == 200);
        log(acme->logger, S("Existing ACME account found"), V());
    }

    BIO_free(bio);
    return 0;
}

static int send_order_creation_request(ACME *acme, CHTTP_Client *client)
{
    RequestBuilder builder;
    request_builder_init(&builder,
        acme->account,
        acme->nonce,
        acme->dont_verify_cert,
        acme->trace_bytes,
        acme->urls.new_order,
        acme->logger);

    request_builder_write(&builder, S("{\"identifiers\":["));
    for (int i = 0; i < acme->num_domains; i++) {
        if (i > 0)
            request_builder_write(&builder, S(","));
        request_builder_write(&builder, S("{\"type\":\"dns\",\"value\":\""));
        request_builder_write(&builder, acme->domains[i].name);
        request_builder_write(&builder, S("\"}"));
    }
    request_builder_write(&builder, S("]}"));

    return request_builder_send(&builder, acme->client);
}

static int complete_order_creation_request(ACME *acme, CHTTP_Response *response)
{
    if (response->status != 201) {
        log(acme->logger, S("Order creation response has status '{}' but 201 was expected\n"), V(response->status));
        return -1;
    }

    if (extract_nonce(acme, response) < 0)
        return -1;

    int i = chttp_find_header(response->headers, response->num_headers, CHTTP_STR("Location"));
    if (i < 0) {
        log(acme->logger, S("Order creation response is missing the 'Location' header\n"), V());
        return -1;
    }
    acme->order_url = allocstr(response->headers[i].value);
    if (acme->order_url.ptr == NULL) {
        log(acme->logger, S("String allocation failure\n"), V());
        return -1;
    }

    // Parse the order response to get authorizations and finalize URL
    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL) {
        string err = ZT2S(error.msg);
        log(acme->logger, S("Order creation response contains invalid JSON ({})\n"), V(err));
        return -1;
    }

    string finalize_url = json_get_string(json_get_field(json, S("finalize")));
    if (finalize_url.len == 0) {
        log(acme->logger, S("Order creation response contains an invalid 'finalize' field\n"), V());
        return -1;
    }

    acme->finalize_url = allocstr((string) { finalize_url.ptr, finalize_url.len });
    if (acme->finalize_url.ptr == NULL) {
        log(acme->logger, S("String allocation failure\n"), V());
        return -1;
    }

    JSON *auths = json_get_field(json, JSON_STR("authorizations"));
    if (auths == NULL || json_get_type(auths) != JSON_TYPE_ARRAY) {
        log(acme->logger, S("Order creation response contains an invalid 'authorizations' field\n"), V());
        return -1;
    }

    if (auths->len != acme->num_domains) {
        log(acme->logger, S("Order creation response contains an invalid 'authorizations' field\n"), V());
        return -1;
    }

    int j = 0;
    JSON *item = auths->head;
    while (item) {

        string tmp = json_get_string(item);
        if (tmp.len == 0) {
            log(acme->logger, S("Order creation response contains an invalid 'authorizations' field\n"), V());
            return -1;
        }
        string auth_url = { tmp.ptr, tmp.len };

        acme->domains[j].authorization_url = allocstr(auth_url);
        if (acme->domains[j].authorization_url.ptr == NULL) {
            log(acme->logger, S("String allocation failure\n"), V());
            return -1;
        }

        j++;
        item = item->next;
    }

    acme->resolved_challenges = 0;
    return 0;
}

static int send_next_challenge_info_request(ACME *acme, CHTTP_Client *client)
{
    ASSERT(acme->resolved_challenges < acme->num_domains);
    string auth_url = acme->domains[acme->resolved_challenges].authorization_url;

    RequestBuilder builder;
    request_builder_init(&builder,
        acme->account,
        acme->nonce,
        acme->dont_verify_cert,
        acme->trace_bytes,
        auth_url,
        acme->logger);

    request_builder_write(&builder, EMPTY_STRING);

    return request_builder_send(&builder, acme->client);
}

static int complete_next_challenge_info_request(ACME *acme, CHTTP_Response *response, b8 *already_resolved)
{
    ASSERT(acme->resolved_challenges < acme->num_domains);

    *already_resolved = false;

    if (response->status != 200) {
        log(acme->logger, S("Challenge info response has status '{}' but 200 was expected\n"), V(response->status));
        return -1;
    }

    if (extract_nonce(acme, response) < 0)
        return -1;

    // Parse the authorization response to get the challenge token
    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL) {
        string err = ZT2S(error.msg);
        log(acme->logger, S("Challenge info response contains invalid JSON ({})\n"), V(err));
        return -1;
    }

    JSON *status = json_get_field(json, JSON_STR("status"));
    if (status == NULL || json_get_type(status) != JSON_TYPE_STRING) {
        log(acme->logger, S("Challenge info response contains an invalid 'status' field\n"), V());
        return -1;
    }

    if (streq(json_get_string(status), S("valid"))) {
        // We already resolved this challenge
        *already_resolved = true;
    }

    JSON *challenges = json_get_field(json, JSON_STR("challenges"));
    if (challenges == NULL || json_get_type(challenges) != JSON_TYPE_ARRAY) {
        log(acme->logger, S("Challenge info response contains an invalid 'challenges' field\n"), V());
        return -1;
    }

    // Get the first http-01 challenge
    JSON *challenge = challenges->head;
    while (challenge) {
        string type = json_get_string(json_get_field(challenge, S("type")));
        if (type.len == 7 && !memcmp(type.ptr, "http-01", 7))
            break;
        challenge = challenge->next;
    }
    if (challenge == NULL) {
        log(acme->logger, S("No 'http-01' challenges found\n"), V());
        return -1; // No http-01 challenge
    }

    string tmp = json_get_string(json_get_field(challenge, S("token")));
    if (tmp.len == 0) {
        log(acme->logger, S("Challenge info response contains an invalid 'token' field\n"), V());
        return -1;
    }
    string token = { tmp.ptr, tmp.len };

    tmp = json_get_string(json_get_field(challenge, JSON_STR("url")));
    if (tmp.len == 0) {
        log(acme->logger, S("Challenge info response contains an invalid 'url' field\n"), V());
        return -1;
    }
    string url = { tmp.ptr, tmp.len };

    acme->domains[acme->resolved_challenges].challenge_token = allocstr(token);
    if (acme->domains[acme->resolved_challenges].challenge_token.ptr == NULL) {
        log(acme->logger, S("String allocation failure\n"), V());
        return -1;
    }

    acme->domains[acme->resolved_challenges].challenge_url = allocstr(url);
    if (acme->domains[acme->resolved_challenges].challenge_url.ptr == NULL) {
        log(acme->logger, S("String allocation failure\n"), V());
        return -1;
    }

    if (*already_resolved) {
        ASSERT(acme->resolved_challenges < acme->num_domains);
        acme->resolved_challenges++;
    }
    return 0;
}

static int send_next_challenge_begin_request(ACME *acme, CHTTP_Client *client)
{
    ASSERT(acme->resolved_challenges < acme->num_domains);

    string challenge_url = acme->domains[acme->resolved_challenges].challenge_url;

    RequestBuilder builder;
    request_builder_init(&builder,
        acme->account,
        acme->nonce,
        acme->dont_verify_cert,
        acme->trace_bytes,
        challenge_url,
        acme->logger);

    request_builder_write(&builder, S("{}"));

    return request_builder_send(&builder, acme->client);
}

static int complete_next_challenge_begin_request(ACME *acme, CHTTP_Response *response)
{
    ASSERT(acme->resolved_challenges < acme->num_domains);

    if (response->status != 200)
        return -1;

    if (extract_nonce(acme, response) < 0)
        return -1;

    return 0;
}

static int send_challenge_status_request(ACME *acme,
    CHTTP_Client *client)
{
    ASSERT(acme->resolved_challenges < acme->num_domains);

    RequestBuilder builder;
    request_builder_init(&builder,
        acme->account,
        acme->nonce,
        acme->dont_verify_cert,
        acme->trace_bytes,
        acme->domains[acme->resolved_challenges].challenge_url,
        acme->logger);

    request_builder_write(&builder, EMPTY_STRING);

    return request_builder_send(&builder, acme->client);
}

static int complete_challenge_status_request(ACME *acme,
    CHTTP_Response *response, b8 *challenge_completed)
{
    *challenge_completed = false;

    if (response->status != 200) {
        log(acme->logger, S("Challenge status response has status '{}' but 200 was expected\n"), V(response->status));
        return -1;
    }

    if (extract_nonce(acme, response) < 0)
        return -1;

    // Parse response to check if challenge is valid
    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL) {
        string err = ZT2S(error.msg);
        log(acme->logger, S("Challenge status response contains invalid JSON ({})\n"), V(err));
        return -1;
    }

    // Check status field
    string status;
    if (json_match(json, &error, "{'status': ?}", &status) != 0) {
        log(acme->logger, S("Challenge status response JSON doesn't have the expected schema\n"), V());
        return -1;
    }

    string status_http = { status.ptr, status.len };

    if (chttp_streq(status_http, CHTTP_STR("invalid"))) {
        log(acme->logger, S("Challenge is in the invalid state\n"), V());
        return -1;
    }

    if (chttp_streq(status_http, CHTTP_STR("valid"))) {
        log(acme->logger, S("Challenge completed\n"), V());
        acme->resolved_challenges++;
        *challenge_completed = true;
    } else {
        log(acme->logger, S("Challenge still hasn't completed (status is '{}')\n"), V(status_http));
    }

    return 0;
}

static int send_finalize_order_request(ACME *acme, CHTTP_Client *client)
{
    string domains[ACME_DOMAIN_LIMIT];
    for (int i = 0; i < acme->num_domains; i++)
        domains[i] = acme->domains[i].name;
    int num_domains = acme->num_domains;

    EVP_PKEY *cert_key;
    char csr_buf[1<<12];
    int csr_len = create_certificate_signing_request(&cert_key, domains, num_domains, acme->country, acme->organization, csr_buf, sizeof(csr_buf), acme->logger);
    if (csr_len < 0)
        return -1;

    log(acme->logger, S("Certificate Signing Request was generated\n"), V());

    BIO *bio = BIO_new(BIO_s_mem());
    if (!bio) {
        log(acme->logger, S("Call to BIO_new failed\n"), V());
        return -1;
    }

    if (!PEM_write_bio_PrivateKey(bio, cert_key, NULL, NULL, 0, NULL, NULL)) {
        log(acme->logger, S("Call to PEM_write_bio_PrivateKey failed\n"), V());
        BIO_free(bio);
        EVP_PKEY_free(cert_key);
        return -1;
    }

    char *pem_buf;
    long pem_len = BIO_get_mem_data(bio, &pem_buf);
    ASSERT(pem_buf != NULL);
    ASSERT(pem_len > 0);

    string certificate_key = { pem_buf, pem_len };
    if (file_write_all(acme->certificate_key_file, certificate_key) < 0) {
        log(acme->logger, S("Couldn't write certificate key to '{}'\n"), V(acme->certificate_key_file));
        BIO_free(bio);
        EVP_PKEY_free(cert_key);
        return -1;
    }

    acme->certificate_key.ptr = malloc(certificate_key.len); // TODO: allocstr?
    if (acme->certificate_key.ptr == NULL) {
        log(acme->logger, S("String allocation failure\n"), V());
        BIO_free(bio);
        EVP_PKEY_free(cert_key);
        return -1;
    }
    memcpy_(acme->certificate_key.ptr, pem_buf, pem_len);
    acme->certificate_key.len = pem_len;

    BIO_free(bio);
    EVP_PKEY_free(cert_key);

    csr_len = encode_inplace(
        csr_buf,
        csr_len,
        0,
        sizeof(csr_buf),
        ENCODING_B64URLNP);
    if (csr_len < 0) {
        log(acme->logger, S("Failed to encode CSR to Base64\n"), V());
        return -1;
    }
    string csr = { csr_buf, csr_len };

    RequestBuilder builder;
    request_builder_init(&builder,
        acme->account,
        acme->nonce,
        acme->dont_verify_cert,
        acme->trace_bytes,
        acme->finalize_url,
        acme->logger);

    request_builder_write(&builder, S("{\"csr\":\""));
    request_builder_write(&builder, csr);
    request_builder_write(&builder, S("\"}"));

    return request_builder_send(&builder, acme->client);
}

static int complete_finalize_order_request(ACME *acme, CHTTP_Response *response)
{
    if (response->status != 200) {
        log(acme->logger, S("Finalize order response has status '{}' but 200 was expected\n"), V(response->status));
        return -1;
    }

    if (extract_nonce(acme, response) < 0)
        return -1;

    // The finalization request returns an update order object
    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL) {
        string err = ZT2S(error.msg);
        log(acme->logger, S("Finalize order response contains invalid JSON ({})\n"), V(err));
        return -1;
    }

    string status = json_get_string(json_get_field(json, JSON_STR("status")));

    if (!streq(status, S("processing")) &&
        !streq(status, S("valid"))) {
        log(acme->logger, S("Finalize order response contains status '{}' ('processing' or 'valid' were expected)\n"), V(status));
        return -1;
    }

    return 0;
}

static int send_certificate_poll_request(ACME *acme, CHTTP_Client *client)
{
    RequestBuilder builder;
    request_builder_init(&builder,
        acme->account,
        acme->nonce,
        acme->dont_verify_cert,
        acme->trace_bytes,
        acme->order_url,
        acme->logger);

    request_builder_write(&builder, EMPTY_STRING);

    return request_builder_send(&builder, acme->client);
}

static int complete_certificate_poll_request(ACME *acme, CHTTP_Response *response)
{
    if (response->status != 200) {
        log(acme->logger, S("Certificate poll response has status '{}' but 200 was expected\n"), V(response->status));
        return -1;
    }

    if (extract_nonce(acme, response) < 0)
        return -1;

    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL) {
        string err = ZT2S(error.msg);
        log(acme->logger, S("Certificate poll response contains invalid JSON ({})\n"), V(err));
        return -1;
    }

    string status = json_get_string(json_get_field(json, JSON_STR("status")));
    if (streq(status, S("valid"))) {

        string certificate_url = json_get_string(json_get_field(json, S("certificate")));
        if (certificate_url.len == 0) {
            log(acme->logger, S("Certificate poll response contains an invalid 'certificate' field\n"), V());
            return -1;
        }

        acme->certificate_url = allocstr(certificate_url);
        if (acme->certificate_url.ptr == NULL) {
            log(acme->logger, S("String allocation failure\n"), V());
            return -1;
        }

    } else if (!streq(status, S("processing"))) {
        log(acme->logger, S("Certificate poll response contains an invalid 'status' field '{}' ('valid' or 'processing' were expected)\n"), V(status));
        return -1;
    }

    return 0;
}

static int send_certificate_download_request(ACME *acme, CHTTP_Client *client)
{
    RequestBuilder builder;
    request_builder_init(&builder,
        acme->account,
        acme->nonce,
        acme->dont_verify_cert,
        acme->trace_bytes,
        acme->certificate_url,
        acme->logger);

    request_builder_write(&builder, EMPTY_STRING);

    return request_builder_send(&builder, acme->client);
}

static int complete_certificate_download_request(ACME *acme, CHTTP_Response *response)
{
    if (response->status != 200) {
        log(acme->logger, S("Certificate download response has status '{}' but 200 was expected\n"), V(response->status));
        return -1;
    }

    if (extract_nonce(acme, response) < 0)
        return -1;

    string certificate = response->body;
    if (file_write_all(acme->certificate_file, certificate) < 0) {
        log(acme->logger, S("Couldn't write certificate to file '{}'\n"), V(acme->certificate_file));
        return -1;
    }

    ASSERT(certificate.ptr != NULL);
    ASSERT(certificate.len > 0);

    Time certificate_expiry;
    int ret = get_chain_expiry(certificate, &certificate_expiry);
    if (ret < 0) {
        log(acme->logger, S("Couldn't determine expiry of the newly issued certificate.\n"), V());
        return -1;
    }
    log(acme->logger, S("Certificate will expire {} UNIX time\n"), V(certificate_expiry / 1000));

    acme->certificate.ptr = malloc(certificate.len); // TODO: allocstr
    if (acme->certificate.ptr == NULL) {
        log(acme->logger, S("String allocation failure\n"), V());
        return -1;
    }
    memcpy_(acme->certificate.ptr, certificate.ptr, certificate.len);
    acme->certificate.len = certificate.len;

    acme->certificate_expiry = certificate_expiry;

    return 0;
}

//////////////////////////////////////////////////////////////////////////////////////
// State machine
//////////////////////////////////////////////////////////////////////////////////////

static b8 account_exists(ACME *acme)
{
    return acme->account.url.ptr != NULL;
}

static b8 certificate_exists(ACME *acme)
{
    return acme->certificate.len > 0;
}

static b8 all_challenges_completed(ACME *acme)
{
    return acme->resolved_challenges == acme->num_domains;
}

static b8 acquired_certificate(ACME *acme)
{
    return acme->certificate_url.len > 0;
}

// Free order-related memory to prepare for a new certificate order.
// This prevents memory leaks when renewing certificates.
static void reset_order_data(ACME *acme)
{
    // Free URLs from previous order
    free(acme->order_url.ptr);
    acme->order_url = EMPTY_STRING;

    free(acme->finalize_url.ptr);
    acme->finalize_url = EMPTY_STRING;

    free(acme->certificate_url.ptr);
    acme->certificate_url = EMPTY_STRING;

    // Free per-domain challenge data from previous order
    for (int i = 0; i < acme->num_domains; i++) {
        free(acme->domains[i].authorization_url.ptr);
        acme->domains[i].authorization_url = EMPTY_STRING;

        free(acme->domains[i].challenge_token.ptr);
        acme->domains[i].challenge_token = EMPTY_STRING;

        free(acme->domains[i].challenge_url.ptr);
        acme->domains[i].challenge_url = EMPTY_STRING;
    }

    acme->resolved_challenges = 0;
}

static int current_state_timeout(ACME *acme)
{
    switch (acme->state) {
    case ACME_STATE_CHALLENGE_3:
        return 1000;
    case ACME_STATE_WAIT:
        {
            int timeout;
            if (acme->certificate_expiry < acme->state_change_time) {
                timeout = 0;
            } else {
                Time diff = acme->certificate_expiry - acme->state_change_time;
                if (diff > INT_MAX)
                    timeout = 86400000; // 24 hours in milliseconds
                else
                    timeout = diff;
            }
            return timeout;
        }
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

void acme_process_timeout(ACME *acme, CHTTP_Client *client)
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

static b8 starts_with(string str, string prefix)
{
    if (str.len < prefix.len || memcmp(str.ptr, prefix.ptr, prefix.len) != 0)
        return false;
    return true;
}

b8 acme_process_request(ACME *acme, CHTTP_Request *request,
    CHTTP_ResponseBuilder builder)
{
    string path = request->url.path;
    string prefix = S("/.well-known/acme-challenge/");

    if (!starts_with(path, prefix))
        return false;

    log(acme->logger, S("Received request for '{}'\n"), V(path));

    if (acme->state != ACME_STATE_CHALLENGE_2 &&
        acme->state != ACME_STATE_CHALLENGE_3 &&
        acme->state != ACME_STATE_CHALLENGE_4) {
        chttp_response_builder_status(builder, 404);
        chttp_response_builder_send(builder);
        return true;
    }

    {
        if (acme->resolved_challenges == acme->num_domains) {
            chttp_response_builder_status(builder, 404);
            chttp_response_builder_send(builder);
            return true;
        }

        string expected_token = acme->domains[acme->resolved_challenges].challenge_token;
        string token = { path.ptr + prefix.len, path.len - prefix.len };
        if (!streq(token, expected_token)) {
            chttp_response_builder_status(builder, 404);
            chttp_response_builder_send(builder);
            return true;
        }

        // A raw SHA256 hash is 32 bytes, so the Base64URL encoded
        // version is ceil(32/3)*4=44
        char buf[44];
        int len = jwk_thumbprint(acme->account.key, buf, sizeof(buf));
        if (len < 0) {
            chttp_response_builder_status(builder, 500);
            chttp_response_builder_send(builder);
            return true;
        }
        string thumbprint = { buf, len };

        chttp_response_builder_status(builder, 200);
        chttp_response_builder_body(builder, expected_token);
        chttp_response_builder_body(builder, CHTTP_STR("."));
        chttp_response_builder_body(builder, thumbprint);
        chttp_response_builder_send(builder);
    }
    return true;
}

static b8 is_invalid_nonce_response(CHTTP_Response *response)
{
    if (response->status != 400)
        return false;

    char pool[1<<13];
    JSON_Error error;
    JSON_Arena arena = json_arena_init(pool, sizeof(pool));
    JSON *json = json_decode(response->body.ptr, response->body.len, &arena, &error);
    if (json == NULL)
        return false;

    string tmp = json_get_string(json_get_field(json, S("type")));
    string type = { tmp.ptr, tmp.len };
    if (!chttp_streq(type, CHTTP_STR("urn:ietf:params:acme:error:badNonce")))
        return false;

    return true;
}

b8 acme_process_response(ACME *acme, int result, CHTTP_Response *response)
{
    uint64_t current_time = get_current_time();
    if (current_time == INVALID_TIME) {
        log(acme->logger, S("Couldn't read the time\n"), V());
        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
        return false;
    }

    switch (acme->state) {
    case ACME_STATE_DIRECTORY:
        {
            if (result != CHTTP_OK) {
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
            if (result != CHTTP_OK) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            if (complete_first_nonce_request(acme, response) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            // We only store the private key associated to the account
            // and not the account URL. To get the account URL we need
            // to follow the same procedure if we already have an account
            // or not.
            if (send_account_creation_request(acme, acme->client) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }
            CHANGE_STATE(acme->state, ACME_STATE_CREATE_ACCOUNT);
        }
        break;
    case ACME_STATE_CREATE_ACCOUNT:
        {
            if (result != CHTTP_OK) {
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

            // Now we need to decide whether we want to issue a
            // certificate or not.
            if (account_exists(acme)) {
                if (certificate_exists(acme)) {

                    log(acme->logger, S("Account and certificate already exists. Waiting for the certificate to expire (in {} seconds).\n"), V((acme->certificate_expiry - current_time) / 1000));

                    // A certificate exists. Wait for it to expire.
                    CHANGE_STATE(acme->state, ACME_STATE_WAIT);
                    acme->state_change_time = current_time;
                } else {

                    log(acme->logger, S("Issuing a new certificate.\n"), V());

                    if (send_order_creation_request(acme, acme->client) < 0) {
                        CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                        break;
                    }
                    CHANGE_STATE(acme->state, ACME_STATE_CREATE_CERT);
                }
            }
        }
        break;
    case ACME_STATE_CREATE_CERT:
        {
            if (result != CHTTP_OK) {
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
            if (result != CHTTP_OK) {
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

            b8 already_resolved;
            if (complete_next_challenge_info_request(acme, response, &already_resolved) < 0) {
                CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                break;
            }

            if (already_resolved) {
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
                if (send_next_challenge_begin_request(acme, acme->client) < 0) {
                    CHANGE_STATE(acme->state, ACME_STATE_ERROR);
                    break;
                }
                CHANGE_STATE(acme->state, ACME_STATE_CHALLENGE_2);
            }
        }
        break;
    case ACME_STATE_CHALLENGE_2:
        {
            if (result != CHTTP_OK) {
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
            if (result != CHTTP_OK) {
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

            b8 challenge_completed;
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
            if (result != CHTTP_OK) {
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
            if (result != CHTTP_OK) {
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
            if (result != CHTTP_OK) {
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
#endif // !_WIN32
