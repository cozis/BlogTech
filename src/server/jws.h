#ifndef JWS_INCLUDED
#define JWS_INCLUDED

#include <stdbool.h>
#include <stdint.h>
#include <openssl/evp.h>

typedef enum {
    JWS_BUILDER_STATE_PROTECTED,
    JWS_BUILDER_STATE_PAYLOAD,
    JWS_BUILDER_STATE_COMPLETE,
    JWS_BUILDER_STATE_ERROR,
} JWS_BuilderState;

enum {
    JWS_ERROR_UNSPEC  = -1,
    JWS_ERROR_OOM     = -2,
    JWS_ERROR_BADJSON = -3,
    JWS_ERROR_BADKEY  = -4,
    JWS_ERROR_ALGNONE = -5,
};

typedef enum {
    JWS_ALG_NONE,
    JWS_ALG_HS256, // HMAC using SHA-256
    JWS_ALG_HS384, // HMAC using SHA-384
    JWS_ALG_HS512, // HMAC using SHA-512
    JWS_ALG_RS256, // RSASSA-PKCS1-v1_5 using SHA-256
    JWS_ALG_RS384, // RSASSA-PKCS1-v1_5 using SHA-384
    JWS_ALG_RS512, // RSASSA-PKCS1-v1_5 using SHA-512
    JWS_ALG_ES256, // ECDSA using P-256 and SHA-256
    JWS_ALG_ES384, // ECDSA using P-384 and SHA-384
    JWS_ALG_ES512, // ECDSA using P-521 and SHA-512
    JWS_ALG_PS256, // RSASSA-PSS using SHA-256 and MGF1 with SHA-256
    JWS_ALG_PS384, // RSASSA-PSS using SHA-384 and MGF1 with SHA-384
    JWS_ALG_PS512, // RSASSA-PSS using SHA-512 and MGF1 with SHA-512
} JWS_Alg;

typedef struct {

    JWS_BuilderState state;

    int reason;

    bool flat;
    bool allow_none;

    EVP_PKEY *private_key;

    // Signing algorithm as inferred by the JWS header
    JWS_Alg alg;

    // Output buffer
    uint8_t *dst;
    int   len;
    int   cap;

    int prot_off;
    int prot_len;

    int pay_off;
    int pay_len;

} JWS_Builder;

void jws_builder_init(JWS_Builder *builder,
    EVP_PKEY *private_key, bool flat,
    char *dst, int cap);

void jws_builder_allow_none(JWS_Builder *builder);

void jws_builder_write(JWS_Builder *builder,
    const char *str, int len);

void jws_builder_flush(JWS_Builder *builder);

int jws_builder_result(JWS_Builder *builder);

int jws_write_jwk(JWS_Builder *jws_builder, EVP_PKEY *pkey);
int jwk_thumbprint(EVP_PKEY *key, char *dst, int cap);

int jws_base64url_encode_inplace(uint8_t *buf, int len, int cap, bool pad);

#endif // JWS_INCLUDED
