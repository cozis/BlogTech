#ifndef STATIC_CONFIG_INCLUDED
#define STATIC_CONFIG_INCLUDED

#define MAX_NONCES 32
#define MIN_PASSWORD_LEN 32
#define RAW_NONCE_LEN 32

#define ACME_DOMAIN_LIMIT 32

// RFC 8555 doesn't specify a length for a nonce string,
// but the Pebble client implemented by Let's Encrypt is
// 22 characters long. We allocate 100 bytes just to be
// safe.
#define ACME_NONCE_CAPACITY 100

#endif // STATIC_CONFIG_INCLUDED
