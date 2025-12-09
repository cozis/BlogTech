#ifndef SERVER_CONFIG_INCLUDED
#define SERVER_CONFIG_INCLUDED

#include "acme.h"
#include "../common/config_reader.h"

typedef struct {
    HTTP_String document_root;
    HTTP_String http_addr;
    uint16_t    http_port;
    bool        reuse_addr;
    bool        trace_bytes;
    HTTP_String auth_password_file;
    bool        https_enabled;
    HTTP_String https_addr;
    uint16_t    https_port;
    HTTP_String cert_file;
    HTTP_String cert_key_file;
    bool        acme_enabled;
    HTTP_String acme_key_file;
    bool        acme_agree_tos;
    HTTP_String acme_url;
    HTTP_String acme_email;
    HTTP_String acme_country;
    HTTP_String acme_org;
    HTTP_String acme_domains[ACME_DOMAIN_LIMIT];
    int         num_acme_domains;
} ServerConfig;

int load_server_config(ConfigReader *reader, ServerConfig *config);

#endif // SERVER_CONFIG_INCLUDED
