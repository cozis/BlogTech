#include <assert.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include <json.h>
#include "jws.h"

#define CEIL(X, Y) (((X) + (Y) - 1) / (Y))

// Number of bytes required to encode
// N bytes as base64url
#define BASE64URL_LEN(N) (CEIL(N, 3) * 4)

// Translates the "len" bytes pointed by "buf" to Base64URL
// in the buffer itself and returns the number of written
// bytes. Note that the result is not null-terminated.
static int base64url_encode_inplace(uint8_t *buf, int len, int cap, bool pad)
{
    // The number of output bytes is equal to ceil(len/3)*4
    if (len > INT_MAX / 4 * 3)
        return -1;
    int olen = (len + 2) / 3 * 4;

    if (cap < olen)
        return -1;

    if (olen == 0)
        return 0;
    assert(len > 0);

    // Since the conversion happens in-place, we need to translate
    // left to right to avoid overwriting the input with the output
    int ridx = len; // Read index
    int widx = olen; // Write index

    static const char table[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-_";

    // First we handle the input bytes that don't form a full group
    int rem = len % 3;
    if (rem == 2) {
        uint8_t b = buf[--ridx];
        uint8_t a = buf[--ridx];
        buf[--widx] = '=';
        buf[--widx] = table[(b << 2) & 0x3F];
        buf[--widx] = table[((a << 4) | (b >> 4)) & 0x3F];
        buf[--widx] = table[a >> 2];
    } else if (rem == 1) {
        uint8_t a = buf[--ridx];
        buf[--widx] = '=';
        buf[--widx] = '=';
        buf[--widx] = table[(a << 4) & 0x3F];
        buf[--widx] = table[a >> 2];
    }

    while (ridx > 0) {
        ridx -= 3;
        widx -= 4;
        uint8_t a = buf[ridx+0] >> 2;
        uint8_t b = ((buf[ridx+0] << 4) | (buf[ridx+1] >> 4)) & 0x3F;
        uint8_t c = ((buf[ridx+1] << 2) | (buf[ridx+2] >> 6)) & 0x3F;
        uint8_t d = buf[ridx+2] & 0x3F;
        buf[widx+0] = table[a];
        buf[widx+1] = table[b];
        buf[widx+2] = table[c];
        buf[widx+3] = table[d];
    }

    if (!pad) {
        while (olen > 0 && buf[olen-1] == '=')
            olen--;
    }

    return olen;
}

static void
append(JWS_Builder *builder, char *str, int len)
{
    if (len < 0)
        len = strlen(str);

    if (builder->cap - builder->len < len) {
        builder->state = JWS_BUILDER_STATE_ERROR;
        builder->reason = JWS_ERROR_OOM;
    } else {
        memcpy(builder->dst + builder->len, str, len);
        builder->len += len;
    }
}

void jws_builder_init(JWS_Builder *builder,
    EVP_PKEY *private_key, bool flat,
    char *dst, int cap)
{
    builder->state = JWS_BUILDER_STATE_PROTECTED;
    builder->flat  = flat;
    builder->dst   = (uint8_t*) dst;
    builder->len   = 0;
    builder->cap   = cap;

    if (builder->flat)
        append(builder, "{\"protected\":\"", -1);

    builder->allow_none = false;
    builder->private_key = private_key;

    // append() may have failed
    if (builder->state == JWS_BUILDER_STATE_ERROR)
        return;

    builder->prot_off = builder->len;
    builder->prot_len = -1;
}

void jws_builder_allow_none(JWS_Builder *builder)
{
    builder->allow_none = true;
}

void jws_builder_write(JWS_Builder *builder, const char *str, int len)
{
    if (builder->state == JWS_BUILDER_STATE_COMPLETE ||
        builder->state == JWS_BUILDER_STATE_ERROR)
        return;
    append(builder, (char*)str, len);
}

static bool key_and_alg_compat(EVP_PKEY *key, JWS_Alg alg)
{
    int id = EVP_PKEY_base_id(key);
    switch (alg) {
    case JWS_ALG_NONE:
        if (key != NULL)
            return false;
        break;
    case JWS_ALG_HS256:
    case JWS_ALG_HS384:
    case JWS_ALG_HS512:
        // Note: The caller must have wrapped the secret
        //       using EVP_PKEY_new_mac_key
        if (id != EVP_PKEY_HMAC)
            return false;
        break;
    case JWS_ALG_RS256:
    case JWS_ALG_RS384:
    case JWS_ALG_RS512:
    case JWS_ALG_PS256:
    case JWS_ALG_PS384:
    case JWS_ALG_PS512:
        if (id != EVP_PKEY_RSA &&
            id != EVP_PKEY_RSA_PSS)
            return false;
        break;
    case JWS_ALG_ES256:
    case JWS_ALG_ES384:
    case JWS_ALG_ES512:
        if (id != EVP_PKEY_EC)
            return false;
        break;
    }
    return true;
}

static const EVP_MD *get_openssl_md(JWS_Alg alg)
{
    switch (alg) {
    case JWS_ALG_HS256:
    case JWS_ALG_RS256:
    case JWS_ALG_ES256:
    case JWS_ALG_PS256:
        return EVP_sha256();
    case JWS_ALG_HS384:
    case JWS_ALG_RS384:
    case JWS_ALG_ES384:
    case JWS_ALG_PS384:
        return EVP_sha384();
    case JWS_ALG_HS512:
    case JWS_ALG_RS512:
    case JWS_ALG_ES512:
    case JWS_ALG_PS512:
        return EVP_sha512();
    }
    return NULL;
}

static bool is_ec_alg(JWS_Alg alg)
{
    return alg == JWS_ALG_ES256
        || alg == JWS_ALG_ES384
        || alg == JWS_ALG_ES512;
}

// Check if algorithm requires PSS Padding
static bool is_pss_alg(JWS_Alg alg) {
    return alg == JWS_ALG_PS256
        || alg == JWS_ALG_PS384
        || alg == JWS_ALG_PS512;
}

static int get_ec_sig_component_len(JWS_Alg alg)
{
    switch (alg) {
    case JWS_ALG_ES256: return 32;
    case JWS_ALG_ES384: return 48;
    case JWS_ALG_ES512: return 66;
    }
    return -1;
}

// Convert DER-encoded ECDSA signature to raw R||S format required by JWS
// DER format: SEQUENCE { r INTEGER, s INTEGER }
// JWS format: R || S (concatenated, fixed-length)
//
// TODO: Test this function
static int der_to_raw_signature(const uint8_t *der,
    int der_len, uint8_t *raw, int component_len)
{
    if (der_len < 8) // Minimum valid DER signature size
        return -1;

    int pos = 0;

    // Check SEQUENCE tag
    if (der[pos++] != 0x30)
        return -1;

    // Parse SEQUENCE length
    int seq_len = der[pos++];
    if (seq_len & 0x80) {
        // Long form length (not expected for ECDSA signatures)
        return -1;
    }

    // Parse R INTEGER
    if (der[pos++] != 0x02)
        return -1;

    int r_len = der[pos++];
    if (r_len & 0x80 || r_len > component_len + 1)
        return -1;

    const uint8_t *r_data = &der[pos];
    pos += r_len;

    // Skip leading zero byte if present (DER adds it when high bit is set)
    if (r_len > component_len && r_data[0] == 0x00) {
        r_data++;
        r_len--;
    }

    if (r_len > component_len)
        return -1;

    // Parse S INTEGER
    if (pos >= der_len || der[pos++] != 0x02)
        return -1;

    int s_len = der[pos++];
    if (s_len & 0x80 || s_len > component_len + 1)
        return -1;

    const uint8_t *s_data = &der[pos];

    // Skip leading zero byte if present
    if (s_len > component_len && s_data[0] == 0x00) {
        s_data++;
        s_len--;
    }

    if (s_len > component_len)
        return -1;

    // Write R to output (left-padded with zeros if needed)
    memset(raw, 0, component_len);
    memcpy(raw + component_len - r_len, r_data, r_len);

    // Write S to output (left-padded with zeros if needed)
    memset(raw + component_len, 0, component_len);
    memcpy(raw + 2 * component_len - s_len, s_data, s_len);

    return 2 * component_len;
}

static int calculate_signature(
    JWS_Alg alg, EVP_PKEY *key,
    char *prot, int prot_len,
    char *pay, int pay_len,
    char *sign, int sign_cap)
{
    if (!key_and_alg_compat(key, alg))
        return JWS_ERROR_BADKEY;

    if (alg == JWS_ALG_NONE)
        return 0;

    const EVP_MD *md = get_openssl_md(alg);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return JWS_ERROR_UNSPEC;

    EVP_PKEY_CTX *pctx;
    if (EVP_DigestSignInit(ctx, &pctx, md, NULL, key) != 1) {
        EVP_MD_CTX_free(ctx);
        return JWS_ERROR_UNSPEC;
    }

    if (is_pss_alg(alg)) {
        if (pctx == NULL ||
            EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) <= 0) { // -1 sets salt len to digest len
            EVP_MD_CTX_free(ctx);
            return JWS_ERROR_UNSPEC;
        }
    }

    if (EVP_DigestSignUpdate(ctx, prot, prot_len) != 1 ||
        EVP_DigestSignUpdate(ctx, ".", 1) != 1 ||
        EVP_DigestSignUpdate(ctx, pay, pay_len) != 1) {
        EVP_MD_CTX_free(ctx);
        return JWS_ERROR_UNSPEC;
    }

    int result;
    if (is_ec_alg(alg)) {

        char der[256];

        size_t der_len;
        if (EVP_DigestSignFinal(ctx, NULL, &der_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return JWS_ERROR_UNSPEC;
        }

        if (der_len > sizeof(der)) {
            EVP_MD_CTX_free(ctx);
            return JWS_ERROR_OOM;
        }

        if (EVP_DigestSignFinal(ctx, (unsigned char*)der, &der_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return JWS_ERROR_UNSPEC;
        }

        int component_len = get_ec_sig_component_len(alg);
        if (component_len < 0)
            return JWS_ERROR_UNSPEC;

        int raw_len = 2 * component_len;
        if (raw_len > sign_cap)
            return JWS_ERROR_OOM;

        // Convert DER to raw R||S format
        result = der_to_raw_signature(der, (int)der_len, (uint8_t*)sign, component_len);
        if (result < 0)
            return JWS_ERROR_UNSPEC;

    } else {

        size_t required_len;
        if (EVP_DigestSignFinal(ctx, NULL, &required_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return JWS_ERROR_UNSPEC;
        }

        if (required_len > sign_cap) {
            EVP_MD_CTX_free(ctx);
            return JWS_ERROR_OOM;
        }

        if (EVP_DigestSignFinal(ctx, (unsigned char*)sign, &required_len) != 1) {
            EVP_MD_CTX_free(ctx);
            return JWS_ERROR_UNSPEC;
        }

        result = required_len;
    }

    EVP_MD_CTX_free(ctx);
    return result;
}

void jws_builder_flush(JWS_Builder *builder)
{
    switch (builder->state) {
    case JWS_BUILDER_STATE_PROTECTED:
        {
            char pool[1<<10];
            JSON_Error error;
            JSON_Arena arena = json_arena_init(pool, sizeof(pool));
            JSON *json = json_decode(
                builder->dst + builder->prot_off,
                builder->len - builder->prot_off,
                &arena,
                &error);
            if (json == NULL) {
                // JWS header is not valid JSON
                builder->state = JWS_BUILDER_STATE_ERROR;
                builder->reason = JWS_ERROR_BADJSON;
                return;
            }
            JSON_String alg = json_get_string(json_get_field(json, JSON_STR("alg")));

            if (alg.len == 4) {
                if (memcmp(alg.ptr, "NONE", 4)) {
                    // Invalid "alg" field
                    builder->state = JWS_BUILDER_STATE_ERROR;
                    builder->reason = JWS_ERROR_BADJSON;
                    return;
                }
                if (!builder->allow_none) {
                    builder->state = JWS_BUILDER_STATE_ERROR;
                    builder->reason = JWS_ERROR_ALGNONE;
                    return;
                }
                builder->alg = JWS_ALG_NONE;
            } else if (alg.len == 5) {
                if (0) {}
                else if (!memcmp(alg.ptr, "HS256", 5)) builder->alg = JWS_ALG_HS256;
                else if (!memcmp(alg.ptr, "HS384", 5)) builder->alg = JWS_ALG_HS384;
                else if (!memcmp(alg.ptr, "HS512", 5)) builder->alg = JWS_ALG_HS512;
                else if (!memcmp(alg.ptr, "RS256", 5)) builder->alg = JWS_ALG_RS256;
                else if (!memcmp(alg.ptr, "RS384", 5)) builder->alg = JWS_ALG_RS384;
                else if (!memcmp(alg.ptr, "RS512", 5)) builder->alg = JWS_ALG_RS512;
                else if (!memcmp(alg.ptr, "ES256", 5)) builder->alg = JWS_ALG_ES256;
                else if (!memcmp(alg.ptr, "ES384", 5)) builder->alg = JWS_ALG_ES384;
                else if (!memcmp(alg.ptr, "ES512", 5)) builder->alg = JWS_ALG_ES512;
                else if (!memcmp(alg.ptr, "PS256", 5)) builder->alg = JWS_ALG_PS256;
                else if (!memcmp(alg.ptr, "PS384", 5)) builder->alg = JWS_ALG_PS384;
                else if (!memcmp(alg.ptr, "PS512", 5)) builder->alg = JWS_ALG_PS512;
                else {
                    // Invalid "alg" field
                    builder->state = JWS_BUILDER_STATE_ERROR;
                    builder->reason = JWS_ERROR_BADJSON;
                    return;
                }
            } else {
                // Invalid "alg" field
                builder->state = JWS_BUILDER_STATE_ERROR;
                builder->reason = JWS_ERROR_BADJSON;
                return;
            }

            int prot_len = base64url_encode_inplace(
                builder->dst + builder->prot_off,
                builder->len - builder->prot_off,
                builder->cap - builder->prot_off,
                false);
            if (prot_len < 0) {
                // Buffer isn't large enough to hold
                // the Base64URL-encoded version of the
                // protected string.
                builder->state = JWS_BUILDER_STATE_ERROR;
                builder->reason = JWS_ERROR_OOM;
                return;
            }

            builder->len = builder->prot_off + prot_len;
            builder->prot_len = prot_len;

            if (builder->flat)
                append(builder, "\",\"payload\":\"", -1);
            else
                append(builder, ".", -1);

            // append() may have failed
            if (builder->state == JWS_BUILDER_STATE_ERROR)
                return;

            builder->pay_off = builder->len;
            builder->state = JWS_BUILDER_STATE_PAYLOAD;
        }
        break;
    case JWS_BUILDER_STATE_PAYLOAD:
        {
            int pay_len = base64url_encode_inplace(
                builder->dst + builder->pay_off,
                builder->len - builder->pay_off,
                builder->cap - builder->pay_off,
                false);
            if (pay_len < 0) {
                // Buffer isn't large enough to hold
                // the Base64URL-encoded version of the
                // payload string.
                builder->state = JWS_BUILDER_STATE_ERROR;
                builder->reason = JWS_ERROR_OOM;
                return;
            }

            builder->len = builder->pay_off + pay_len;
            builder->pay_len = pay_len;

            if (builder->flat)
                append(builder, "\",\"signature\":\"", -1);
            else
                append(builder, ".", -1);

            // append() may have failed
            if (builder->state == JWS_BUILDER_STATE_ERROR)
                return;

            // Append the signature
            int sign_off = builder->len;
            int ret = calculate_signature(

                // Algorithm and private key
                builder->alg,
                builder->private_key,

                // Protected string
                builder->dst + builder->prot_off,
                builder->prot_len,

                // Payload string
                builder->dst + builder->pay_off,
                builder->pay_len,

                // Output buffer
                builder->dst + sign_off,
                builder->cap - sign_off
            );
            if (ret < 0) {
                builder->state = JWS_BUILDER_STATE_ERROR;
                builder->reason = ret;
                return;
            }
            builder->len += ret;

            ret = base64url_encode_inplace(
                builder->dst + sign_off,
                builder->len - sign_off,
                builder->cap - sign_off,
                false);
            if (ret < 0) {
                // Signature didn't fit in the buffer
                builder->state = JWS_BUILDER_STATE_ERROR;
                builder->reason = JWS_ERROR_OOM;
                return;
            }

            builder->len = sign_off + ret;

            if (builder->flat)
                append(builder, "\"}", -1);

            // append() may have failed
            if (builder->state == JWS_BUILDER_STATE_ERROR)
                return;

            builder->state = JWS_BUILDER_STATE_COMPLETE;
        }
        break;
    case JWS_BUILDER_STATE_COMPLETE:
        // Do nothing
        break;
    case JWS_BUILDER_STATE_ERROR:
        // Do nothing
        break;
    default:
        // Unreachable
        break;
    }
}

int jws_builder_result(JWS_Builder *builder)
{
    if (builder->state != JWS_BUILDER_STATE_COMPLETE)
        return -1;
    return builder->len;
}

#define JWK_RSA_N_BITS 4096
#define JWK_RSA_E_BITS 24
#define JWK_EC_BITS 521

#define JWK_RSA_N_BYTES CEIL(JWK_RSA_N_BITS, 8)
#define JWK_RSA_E_BYTES CEIL(JWK_RSA_E_BITS, 8)

#define JWK_EC_BYTES CEIL(JWK_EC_BITS, 8)

#define JWK_RSA_N_BASE64_BYTES BASE64URL_LEN(JWK_RSA_N_BYTES)
#define JWK_RSA_E_BASE64_BYTES BASE64URL_LEN(JWK_RSA_E_BYTES)

#define JWK_EC_BASE64_BYTES BASE64URL_LEN(JWK_EC_BYTES)

typedef struct {
    bool is_rsa;
    union {
        struct {
            int nlen;
            int elen;
            uint8_t n[JWK_RSA_N_BASE64_BYTES];
            uint8_t e[JWK_RSA_E_BASE64_BYTES];
        } rsa;
        struct {
            const char *crv;
            int xlen;
            int ylen;
            uint8_t x[JWK_EC_BASE64_BYTES];
            uint8_t y[JWK_EC_BASE64_BYTES];
        } ec;
    };
} JWK;

static int parse_jwk(JWK *jwk, EVP_PKEY *pkey)
{
    int type = EVP_PKEY_id(pkey);
    if (type == EVP_PKEY_RSA) {

        jwk->is_rsa = true;

        // Get RSA modulus (n) using new OpenSSL 3.0 API
        BIGNUM *n = NULL, *e = NULL;
        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) || n == NULL)
            return -1;

        jwk->rsa.nlen = BN_num_bytes(n);
        if (jwk->rsa.nlen > (int) sizeof(jwk->rsa.n)) {
            BN_free(n);
            return -1;
        }
        if (BN_bn2bin(n, jwk->rsa.n) != jwk->rsa.nlen) {
            BN_free(n);
            return -1;
        }

        jwk->rsa.nlen = base64url_encode_inplace(jwk->rsa.n,
            jwk->rsa.nlen, (int) sizeof(jwk->rsa.n), false);
        if (jwk->rsa.nlen < 0) {
            BN_free(n);
            return -1;
        }
        BN_free(n);

        // Get RSA public exponent (e) using new OpenSSL 3.0 API
        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) || e == NULL)
            return -1;

        jwk->rsa.elen = BN_num_bytes(e);
        if (jwk->rsa.elen > (int) sizeof(jwk->rsa.e)) {
            BN_free(e);
            return -1;
        }
        if (BN_bn2bin(e, jwk->rsa.e) != jwk->rsa.elen) {
            BN_free(e);
            return -1;
        }

        jwk->rsa.elen = base64url_encode_inplace(jwk->rsa.e,
            jwk->rsa.elen, (int) sizeof(jwk->rsa.e), false);
        if (jwk->rsa.elen < 0) {
            BN_free(e);
            return -1;
        }
        BN_free(e);

    } else if (type == EVP_PKEY_EC) {

        jwk->is_rsa = false;

        // Get curve name using new OpenSSL 3.0 API
        char group_name[64];
        size_t group_name_len = 0;
        if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                           group_name, sizeof(group_name), &group_name_len))
            return -1;

        const char *crv;
        int coord_size;

        // Map OpenSSL curve names to JWK curve names
        if (strcmp(group_name, "prime256v1") == 0) {
            crv = "P-256";
            coord_size = CEIL(256, 8);
        } else if (strcmp(group_name, "secp384r1") == 0) {
            crv = "P-384";
            coord_size = CEIL(384, 8);
        } else if (strcmp(group_name, "secp521r1") == 0) {
            crv = "P-521";
            coord_size = CEIL(521, 8);
        } else {
            return -1;
        }
        jwk->ec.crv = crv;

        // Get EC public key coordinates using new OpenSSL 3.0 API
        BIGNUM *x = NULL, *y = NULL;
        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x) || x == NULL)
            return -1;

        if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y) || y == NULL) {
            BN_free(x);
            return -1;
        }

        // Curve P-521 has x,y fields that use 512 bits each,
        // therefore we need a buffer of ceil(512/8)=66 bytes
        // to store it. Other curves have smaller coordinates.
        #define MAX_COORD_SIZE 66

        assert(coord_size <= MAX_COORD_SIZE);

        jwk->ec.xlen = BN_num_bytes(x);
        if (jwk->ec.xlen > (int) sizeof(jwk->ec.x)) {
            BN_free(y);
            BN_free(x);
            return -1;
        }
        assert(jwk->ec.xlen <= sizeof(jwk->ec.x));

        // BN_bn2bin will drop any leading zeros for the number,
        // so if the coordinate needs a maximum of 521 bits but
        // it happens to be numerically small, it may use less
        // bits. The JWK spec wants the coordinates to be encoded
        // with precisely the same length, so we need to pad the
        // left side of the buffer with zeros.
        memset(jwk->ec.x, 0, coord_size - jwk->ec.xlen);
        if (BN_bn2bin(x, jwk->ec.x + coord_size - jwk->ec.xlen) != jwk->ec.xlen) {
            BN_free(y);
            BN_free(x);
            return -1;
        }
        jwk->ec.xlen = coord_size;

        jwk->ec.xlen = base64url_encode_inplace(jwk->ec.x, jwk->ec.xlen,
            (int) sizeof(jwk->ec.x), false);
        if (jwk->ec.xlen < 0) {
            BN_free(y);
            BN_free(x);
            return -1;
        }

        jwk->ec.ylen = BN_num_bytes(y);
        if (jwk->ec.ylen > (int) sizeof(jwk->ec.y)) {
            BN_free(y);
            BN_free(x);
            return -1;
        }

        memset(jwk->ec.y, 0, coord_size - jwk->ec.ylen);
        if (BN_bn2bin(y, jwk->ec.y + coord_size - jwk->ec.ylen) != jwk->ec.ylen) {
            BN_free(y);
            BN_free(x);
            return -1;
        }
        jwk->ec.ylen = coord_size;

        jwk->ec.ylen = base64url_encode_inplace(jwk->ec.y,
            jwk->ec.ylen, (int) sizeof(jwk->ec.y), false);
        if (jwk->ec.ylen < 0) {
            BN_free(y);
            BN_free(x);
            return -1;
        }

        BN_free(y);
        BN_free(x);

    } else {

        // Unknown key type
        return -1;
    }

    return 0;
}

int jws_write_jwk(JWS_Builder *jws_builder, EVP_PKEY *pkey)
{
    JWK jwk;
    if (parse_jwk(&jwk, pkey) < 0)
        return -1;

    if (jwk.is_rsa) {
        jws_builder_write(jws_builder, "{\"kty\":\"RSA\",\"n\":\"", -1);
        jws_builder_write(jws_builder, jwk.rsa.n, jwk.rsa.nlen);
        jws_builder_write(jws_builder, "\",\"e\":\"", -1);
        jws_builder_write(jws_builder, jwk.rsa.e, jwk.rsa.elen);
        jws_builder_write(jws_builder, "\"}", -1);
    } else {
        jws_builder_write(jws_builder, "{\"kty\":\"EC\",\"crv\":\"", -1);
        jws_builder_write(jws_builder, jwk.ec.crv, -1);
        jws_builder_write(jws_builder, "\",\"x\":\"", -1);
        jws_builder_write(jws_builder, jwk.ec.x, jwk.ec.xlen);
        jws_builder_write(jws_builder, "\",\"y\":\"", -1);
        jws_builder_write(jws_builder, jwk.ec.y, jwk.ec.ylen);
        jws_builder_write(jws_builder, "\"}", -1);
    }

    return 0;
}

int jwk_thumbprint(EVP_PKEY *key, char *dst, int cap)
{
    JWK jwk;
    if (parse_jwk(&jwk, key) < 0)
        return -1;

    char buf[1<<10]; // TODO: choose a proper capacity
    int len;

    if (jwk.is_rsa) {
        len = snprintf(buf, sizeof(buf),
            "{\"e\":\"%.*s\",\"kty\":\"RSA\",\"n\":\"%.*s\"}",
            jwk.rsa.elen, jwk.rsa.e,
            jwk.rsa.nlen, jwk.rsa.n);
    } else {
        len = snprintf(buf, sizeof(buf),
            "{\"crv\":\"%s\",\"kty\":\"EC\",\"x\":\"%.*s\",\"y\":\"%.*s\"}",
            jwk.ec.crv,
            jwk.ec.xlen, jwk.ec.x,
            jwk.ec.ylen, jwk.ec.y);
    }
    if (len < 0 || len >= (int) sizeof(buf))
        return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (ctx == NULL)
        return -1;

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (EVP_DigestUpdate(ctx, buf, len) != 1) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    if (cap < EVP_MAX_MD_SIZE) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }
    unsigned int hlen;
    if (EVP_DigestFinal(ctx, dst, &hlen) != 1 || hlen > INT_MAX) {
        EVP_MD_CTX_free(ctx);
        return -1;
    }

    EVP_MD_CTX_free(ctx);
    return base64url_encode_inplace(dst, (int) hlen, cap, false);
}
