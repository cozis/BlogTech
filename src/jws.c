#include <assert.h>
#include <limits.h>
#include <string.h>
#include <openssl/evp.h>

#include <json.h>
#include "jws.h"

// Translates the "len" bytes pointed by "buf" to Base64URL
// in the buffer itself and returns the number of written
// bytes. Note that the result is not null-terminated.
static int base64url_encode_inplace(uint8_t *buf, int len, int cap)
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
        buf[widx+0] = table[(buf[ridx+0] >> 2)];
        buf[widx+1] = table[((buf[ridx+0] << 4) | (buf[ridx+1] >> 4)) & 0x3F];
        buf[widx+2] = table[((buf[ridx+1] << 2) | (buf[ridx+2] >> 6)) & 0x3F];
        buf[widx+3] = table[buf[ridx+2] & 0x3F];
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

void jws_builder_write(JWS_Builder *builder, char *str, int len)
{
    if (builder->state == JWS_BUILDER_STATE_COMPLETE ||
        builder->state == JWS_BUILDER_STATE_ERROR)
        return;
    append(builder, str, len);
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

// Check if algorithm requires PSS Padding
static bool is_pss_alg(JWS_Alg alg) {
    return alg == JWS_ALG_PS256
        || alg == JWS_ALG_PS384
        || alg == JWS_ALG_PS512;
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

    EVP_MD_CTX_free(ctx);
    return (int) required_len;
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
                builder->cap - builder->prot_off);
            if (prot_len < 0) {
                // Buffer isn't large enough to hold
                // the Base64URL-encoded version of the
                // protected string.
                builder->state = JWS_BUILDER_STATE_ERROR;
                builder->reason = JWS_ERROR_OOM;
                return;
            }

            // Remove padding
            while (prot_len > 0 && builder->dst[builder->prot_off + prot_len - 1] == '=')
                prot_len--;

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
                builder->cap - builder->pay_off);
            if (pay_len < 0) {
                // Buffer isn't large enough to hold
                // the Base64URL-encoded version of the
                // payload string.
                builder->state = JWS_BUILDER_STATE_ERROR;
                builder->reason = JWS_ERROR_OOM;
                return;
            }

            // Remove padding
            while (pay_len > 0 && builder->dst[builder->pay_off + pay_len - 1] == '=')
                pay_len--;

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
                builder->cap - sign_off);
            if (ret < 0) {
                // Signature didn't fit in the buffer
                builder->state = JWS_BUILDER_STATE_ERROR;
                builder->reason = JWS_ERROR_OOM;
                return;
            }

            // Remove padding
            while (ret > 0 && builder->dst[sign_off + ret - 1] == '=')
                ret--;

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
