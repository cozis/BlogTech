#include <signal.h>

#include "path.h"
#include "auth.h"
#include "acme.h"
#include "chttp.h"
#include "config.h"
#include "file_system.h"

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

sig_atomic_t running = 0;

static int pick_timeout(int *arr, int num)
{
    int ret = -1;
    for (int i = 0; i < num; i++)
        if (arr[i] > -1) {
            if (ret == -1 || ret > arr[i])
                ret = arr[i];
        }
    return ret;
}

int main(int argc, char **argv)
{
    HTTP_String document_root;
    HTTP_String http_addr;
    uint16_t    http_port;
    bool        reuse_addr;
    bool        trace_bytes;
    HTTP_String https_addr;
    uint16_t    https_port;
    HTTP_String cert_file;
    HTTP_String cert_key_file;
    bool        acme_enabled;

    HTTP_String config_text;
    HTTP_String config_file = HTTP_STR("blogtech.conf");
    int ret = file_read_all(config_file, &config_text);
    if (ret < 0) {
        printf("Couldn't load file");
        return -1;
    }

    ConfigTarget targets[] = {
        CONFIG_TARGET_STR ("document-root",  &document_root,  1, NULL),
        CONFIG_TARGET_BOOL("reuse-addr",     &reuse_addr,     1, NULL),
        CONFIG_TARGET_BOOL("trace-bytes",    &trace_bytes,    1, NULL),
        CONFIG_TARGET_STR ("http-addr",      &http_addr,      1, NULL),
        CONFIG_TARGET_U16 ("http-port",      &http_port,      1, NULL),
        CONFIG_TARGET_STR ("https-addr",     &https_addr,     1, NULL),
        CONFIG_TARGET_U16 ("https-port",     &https_port,     1, NULL),
        CONFIG_TARGET_STR ("cert-file",      &cert_file,      1, NULL),
        CONFIG_TARGET_STR ("cert-key-file",  &cert_key_file,  1, NULL),
        CONFIG_TARGET_BOOL("acme-enabled",   &acme_enabled,   1, NULL),
    };
    config_load(targets, HTTP_COUNT(targets), config_text.ptr, config_text.len, argc, argv);

    running = 1;

    HTTP_Client client;
    ret = http_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", http_strerror(ret));
        free(config_text.ptr);
        return -1;
    }

    HTTP_Server server;
    ret = http_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", http_strerror(ret));
        free(config_text.ptr);
        return -1;
    }
    http_server_set_reuse_addr(&server, reuse_addr);
    http_server_set_trace_bytes(&server, trace_bytes);

    ret = http_server_listen_tcp(&server, http_addr, http_port);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", http_strerror(ret));
        free(config_text.ptr);
        return -1;
    }

    ACME acme;
    if (acme_enabled) {

        HTTP_String acme_key_file;
        bool        acme_agree_tos;
        HTTP_String acme_url;
        HTTP_String acme_email;
        HTTP_String acme_country;
        HTTP_String acme_org;
        HTTP_String acme_domains[ACME_DOMAIN_LIMIT];
        int         num_acme_domains;

        ConfigTarget targets[] = {
            CONFIG_TARGET_STR ("acme-key-file",  &acme_key_file,  1, NULL),
            CONFIG_TARGET_BOOL("acme-agree-tos", &acme_agree_tos, 1, NULL),
            CONFIG_TARGET_STR ("acme-url",       &acme_url,       1, NULL),
            CONFIG_TARGET_STR ("acme-email",     &acme_email,     1, NULL),
            CONFIG_TARGET_STR ("acme-country",   &acme_country,   1, NULL),
            CONFIG_TARGET_STR ("acme-org",       &acme_org,       1, NULL),
            CONFIG_TARGET_STR ("acme-domain",    acme_domains,    ACME_DOMAIN_LIMIT, &num_acme_domains),
        };
        config_load(targets, HTTP_COUNT(targets), config_text.ptr, config_text.len, argc, argv);

        ACME_Config acme_config;
        acme_config_init(&acme_config, &client, acme_url, acme_email, acme_country, acme_org, acme_domains[0]);
        for (int i = 1; i < num_acme_domains; i++)
            acme_config_add_domain(&acme_config, acme_domains[i]);
        acme_config.agree_tos = acme_agree_tos;
        acme_config.account_key_file = acme_key_file;
        acme_config.certificate_file = cert_file;
        acme_config.certificate_key_file = cert_key_file;

        if (acme_init(&acme, &acme_config) < 0) {
            fprintf(stderr, "Couldn't initialize ACME client\n");
            free(config_text.ptr);
            return -1;
        }
    }

    if (file_exists(cert_file)) {
        ret = http_server_listen_tls(&server, https_addr, https_port, cert_file, cert_key_file);
        if (ret < 0) {
            fprintf(stderr, "Couldn't start listening (%s)\n", http_strerror(ret));
            free(config_text.ptr);
            return -1;
        }
    }

    Auth auth;
    if (auth_init(&auth) < 0) {
        fprintf(stderr, "Couldn't initialize authentication system\n");
        free(config_text.ptr);
        return -1;
    }

    free(config_text.ptr);
    bool restart = false;
    while (running) {

        void*           ptrs[HTTP_CLIENT_POLL_CAPACITY + HTTP_SERVER_POLL_CAPACITY];
        struct pollfd polled[HTTP_CLIENT_POLL_CAPACITY + HTTP_SERVER_POLL_CAPACITY];

        EventRegister server_reg = {
            ptrs,
            polled,
            0
        };
        http_server_register_events(&server, &server_reg);

        EventRegister client_reg = {
            ptrs   + server_reg.num_polled,
            polled + server_reg.num_polled,
            0
        };
        http_client_register_events(&client, &client_reg);

        int timeouts[3];
        timeouts[0] = -1; // Server timeout
        timeouts[1] = -1; // Client timeout
        timeouts[2] = acme_next_timeout(&acme); // Acme timeout
        int timeout = pick_timeout(timeouts, 3);

        if (server_reg.num_polled > 0 &&
            client_reg.num_polled > 0) {
            int num_polled = server_reg.num_polled
                            + client_reg.num_polled;
            POLL(polled, num_polled, timeout);
        }

        if (acme_enabled) {
            acme_process_timeout(&acme, &client); // This should not be called every iteration
        }

        int result;
        void *user;
        HTTP_Response *response;
        http_client_process_events(&client, client_reg);
        while (http_client_next_response(&client, &result, &user, &response)) {
            bool new_certificate = acme_process_response(&acme, result, response);
            http_free_response(response);
            if (new_certificate) {
                running = 0;
                restart = true;
            }
        }

        HTTP_Request *request;
        HTTP_ResponseBuilder response_builder;
        http_server_process_events(&server, server_reg);
        while (http_server_next_request(&server, &request, &response_builder)) {

            if (acme_enabled) {
                if (acme_process_request(&acme, request, response_builder))
                    continue;
            }

            switch (request->method) {
            case HTTP_METHOD_GET:
                {
                    char buf[1<<10];
                    int ret = translate_path(request->url.path, document_root, buf, (int) sizeof(buf));
                    if (ret < 0) {
                        http_response_builder_status(response_builder, 500); // TODO: better error code
                        http_response_builder_send(response_builder);
                        break;
                    }
                    HTTP_String file_path = { buf, ret };

                    http_response_builder_status(response_builder, 200); // TODO: better error code

                    // TODO: As file_open is currently implemented, when a
                    //       file isn't found it's created, which is very bad
                    Handle fd;
                    ret = file_open(file_path, &fd);
                    if (ret < 0) {
                        http_response_builder_status(response_builder, 500); // TODO: better error code
                        http_response_builder_send(response_builder);
                        break;
                    }
                    size_t len;
                    ret = file_size(fd, &len);
                    if (ret < 0) {
                        file_close(fd);
                        http_response_builder_status(response_builder, 500); // TODO: better error code
                        http_response_builder_send(response_builder);
                        break;
                    }
                    http_response_builder_body_cap(response_builder, len);

                    int dummy;
                    char *dst = http_response_builder_body_buf(response_builder, &dummy);
                    if (dst) {
                        for (int copied = 0; copied < len; ) {
                            ret = file_read(fd, dst + copied, len - copied);
                            if (ret <= 0) {
                                file_close(fd);
                                http_response_builder_status(response_builder, 500); // TODO: better error code
                                http_response_builder_send(response_builder);
                                break;
                            }
                            copied += ret;
                        }
                        http_response_builder_body_ack(response_builder, len);
                    }
                    file_close(fd);
                    http_response_builder_send(response_builder);
                }
                break;
            case HTTP_METHOD_PUT:
                {
                    int ret = auth_verify(&auth, request);
                    if (ret < 0) {
                        http_response_builder_status(response_builder, 500);
                        http_response_builder_send(response_builder);
                        break;
                    }
                    if (ret == 1) {
                        http_response_builder_status(response_builder, 401);
                        http_response_builder_send(response_builder);
                        break;
                    }

                    char buf[1<<10];
                    ret = translate_path(request->url.path, document_root, buf, (int) sizeof(buf));
                    if (ret < 0) {
                        http_response_builder_status(response_builder, 500); // TODO: better error code
                        http_response_builder_send(response_builder);
                        break;
                    }
                    HTTP_String file_path = { buf, ret };

                    // TODO: delete the previous version if it exists
                    Handle fd;
                    ret = file_open(file_path, &fd);
                    if (ret < 0) {
                        http_response_builder_status(response_builder, 500); // TODO: better error code
                        http_response_builder_send(response_builder);
                        break;
                    }
                    http_response_builder_status(response_builder, 200);
                    HTTP_String body = request->body;
                    for (int copied = 0; copied < body.len; ) {
                        ret = file_write(fd,
                            body.ptr + copied,
                            body.len - copied);
                        if (ret < 0) {
                            http_response_builder_status(response_builder, 500); // TODO: better error code
                            http_response_builder_send(response_builder);
                            break;
                        }
                        copied += ret;
                    }
                    http_response_builder_send(response_builder);
                    file_close(fd);
                }
                break;
            case HTTP_METHOD_DELETE:
                {
                    int ret = auth_verify(&auth, request);
                    if (ret < 0) {
                        http_response_builder_status(response_builder, 500);
                        http_response_builder_send(response_builder);
                        break;
                    }
                    if (ret == 1) {
                        http_response_builder_status(response_builder, 401);
                        http_response_builder_send(response_builder);
                        break;
                    }

                    char buf[1<<10];
                    ret = translate_path(request->url.path, document_root, buf, (int) sizeof(buf));
                    if (ret < 0) {
                        http_response_builder_status(response_builder, 500); // TODO: better error code
                        http_response_builder_send(response_builder);
                        break;
                    }
                    HTTP_String file_path = { buf, ret };

                    if (remove_file_or_dir(file_path) < 0) {
                        http_response_builder_status(response_builder, 500); // TODO: better error code
                        http_response_builder_send(response_builder);
                    } else {
                        http_response_builder_status(response_builder, 200); // TODO: better error code
                        http_response_builder_send(response_builder);
                    }
                }
                break;
            case HTTP_METHOD_OPTIONS:
                http_response_builder_status(response_builder, 200);
                http_response_builder_header(response_builder,
                    HTTP_STR("Allow: GET, POST, PUT, DELETE, OPTIONS"));
                http_response_builder_send(response_builder);
                break;
            default:
                http_response_builder_status(response_builder, 405);
                http_response_builder_header(response_builder,
                    HTTP_STR("Allow: GET, POST, PUT, DELETE, OPTIONS"));
                http_response_builder_send(response_builder);
                break;
            }
        }
    }

    auth_free(&auth);
    acme_free(&acme);
    http_server_free(&server);
    http_client_free(&client);
    if (restart)
        execv(argv[0], argv);
    return 0;
}
