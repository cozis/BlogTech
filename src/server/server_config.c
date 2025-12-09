#include "server_config.h"
#include "../common/print_usage.h"
#include "../lib/basic.h"

int load_server_config(ConfigReader *reader, ServerConfig *config)
{
    // Set default values
    config->http_addr = S("127.0.0.1");
    config->http_port = 8080;
    config->reuse_addr = true;
    config->trace_bytes = false;
    config->auth_password_file = S("");
    config->https_enabled = false;
    config->acme_enabled = false;

    bool have_document_root = false;

    bool bad_config = false;
    string name, value;
    while (config_reader_next(reader, &name, &value)) {
        if (streq(name, S("document-root"))) {
            if (value.len == 0) {
                printf("Config Error: Invalid document root\n");
                bad_config = true;
            } else {
                config->document_root = value;
                have_document_root = true;
            }
        } else if (streq(name, S("reuse-addr"))) {
            parse_config_value_yn(name, value, &config->reuse_addr, &bad_config);
        } else if (streq(name, S("trace-bytes"))) {
            parse_config_value_yn(name, value, &config->trace_bytes, &bad_config);
        } else if (streq(name, S("http-addr"))) {
            config->http_addr = value;
        } else if (streq(name, S("http-port"))) {
            parse_config_value_port(name, value, &config->http_port, &bad_config);
        } else if (streq(name, S("https-enabled"))) {
            parse_config_value_yn(name, value, &config->https_enabled, &bad_config);
        } else if (streq(name, S("acme-enabled"))) {
            parse_config_value_yn(name, value, &config->acme_enabled, &bad_config);
        } else if (streq(name, S("auth-password-file"))) {
            config->auth_password_file = value;
        } else if (streq(name, S("help")) || streq(name, S("h"))) {
            print_usage();
            return 0;
        }
    }

    if (!have_document_root) {
        printf("Config Error: You need to specify a web content directory. Use option 'document-root'\n");
        bad_config = true;
    }

    if (config->https_enabled) {

        config->https_addr = S("");
        config->https_port = 8443;

        bool have_cert_file     = false;
        bool have_cert_key_file = false;

        config_reader_rewind(reader);
        while (config_reader_next(reader, &name, &value)) {
            if (streq(name, S("https-addr"))) {
                config->https_addr = value;
            } else if (streq(name, S("https-port"))) {
                parse_config_value_port(name, value, &config->https_port, &bad_config);
            } else if (streq(name, S("cert-file"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid certificate file\n");
                    bad_config = true;
                } else {
                    config->cert_file = value;
                    have_cert_file = true;
                }
            } else if (streq(name, S("cert-key-file"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid certificate key file\n");
                    bad_config = true;
                } else {
                    config->cert_key_file = value;
                    have_cert_key_file = true;
                }
            }
        }

        if (!have_cert_file) {
            printf("Config Error: No HTTPS certificate file specified. Use option 'cert-file'.\n");
            bad_config = true;
        }
        if (!have_cert_key_file) {
            printf("Config Error: No HTTPS key file specified. Use option 'cert-key-file'.\n");
            bad_config = true;
        }
    }

    if (config->acme_enabled) {

        if (!config->https_enabled) {
            printf("Config Error: You need to enable HTTPS to use the ACME client. Use 'https-enabled' with 'acme-enabled'\n");
            bad_config = true;
        }

        config->acme_key_file  = S("acme_key.pem");
        config->acme_agree_tos = false;
        config->acme_url       = S("https://acme-v02.api.letsencrypt.org/directory");

        bool have_acme_email   = false;
        bool have_acme_country = false;
        bool have_acme_org     = false;

        config_reader_rewind(reader);
        while (config_reader_next(reader, &name, &value)) {
            if (streq(name, S("acme-key-file"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid ACME key file\n");
                    bad_config = true;
                } else {
                    config->acme_key_file = value;
                }
            } else if (streq(name, S("acme-agree-tos"))) {
                parse_config_value_yn(name, value, &config->acme_agree_tos, &bad_config);
            } else if (streq(name, S("acme-url"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid ACME server directory URL\n");
                    bad_config = true;
                } else {
                    config->acme_url = value;
                }
            } else if (streq(name, S("acme-email"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid ACME E-Mail\n");
                    bad_config = true;
                } else {
                    config->acme_email = value;
                    have_acme_email = true;
                }
            } else if (streq(name, S("acme-country"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid ACME country\n");
                    bad_config = true;
                } else {
                    config->acme_country = value;
                    have_acme_country = true;
                }
            } else if (streq(name, S("acme-org"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid ACME organization\n");
                    bad_config = true;
                } else {
                    config->acme_org = value;
                    have_acme_org = true;
                }
            } else if (streq(name, S("acme-domain"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid domain\n");
                    bad_config = true;
                } else {
                    if (config->num_acme_domains < ACME_DOMAIN_LIMIT)
                        config->acme_domains[config->num_acme_domains++] = value;
                    else {
                        printf("Config Error: Too many domains (limit is %d)\n", ACME_DOMAIN_LIMIT);
                        bad_config = true;
                    }
                }
            }
        }

        if (!have_acme_email) {
            printf("Config Error: No E-Mail specified for the ACME client. Use option 'acme-email'.\n");
            bad_config = true;
        }

        if (!have_acme_country) {
            printf("Config Error: No country specified for the ACME client. Use option 'acme-country'.\n");
            bad_config = true;
        }

        if (!have_acme_org) {
            printf("Config Error: No organization specified for the ACME client. Use option 'acme-org'.\n");
            bad_config = true;
        }
    }

    if (bad_config)
        return -1;
    return 1;
}
