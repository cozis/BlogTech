#ifndef SERVER_CONFIG_INCLUDED
#define SERVER_CONFIG_INCLUDED

#include "acme.h"
#include "../common/config_reader.h"

typedef struct {
    string document_root;
    string http_addr;
    u16    http_port;
    b8     reuse_addr;
    b8     trace_bytes;
    string auth_password_file;
    b8     https_enabled;
    string https_addr;
    u16    https_port;
    string cert_file;
    string cert_key_file;
    b8     acme_enabled;
    string acme_key_file;
    b8     acme_agree_tos;
    string acme_url;
    string acme_email;
    string acme_country;
    string acme_org;
    string acme_domains[ACME_DOMAIN_LIMIT];
    int    num_acme_domains;
} ServerConfig;

int load_server_config(ConfigReader *reader, ServerConfig *config);

#endif // SERVER_CONFIG_INCLUDED
