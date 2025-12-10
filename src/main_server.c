#include <signal.h>

#include "auth.h"
#include "acme.h"
#include "config_reader.h"

#include "crash_logger.h"
#include "lib/http.h"
#include "lib/logger.h"
#include "lib/file_system.h"

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

sig_atomic_t running = 0;

typedef struct {
    string document_root;
    string http_addr;
    u16    http_port;
    b8     reuse_addr;
    b8     trace_bytes;
    string request_log_file;
    s32    request_log_buffer;
    s32    request_log_timeout;
    string auth_password_file;
    string auth_log_file;
    s32    auth_log_buffer;
    s32    auth_log_timeout;
    b8     https_enabled;
    string https_addr;
    u16    https_port;
    string cert_file;
    string cert_key_file;
    b8     acme_enabled;
    string acme_key_file;
    string acme_log_file;
    s32    acme_log_buffer;
    s32    acme_log_timeout;
    b8     acme_agree_tos;
    string acme_url;
    string acme_email;
    string acme_country;
    string acme_org;
    string acme_domains[ACME_DOMAIN_LIMIT];
    int    num_acme_domains;
} ServerConfig;

static int load_server_config(ConfigReader *reader, ServerConfig *config)
{
    // Set default values
    config->http_addr = S("127.0.0.1");
    config->http_port = 8080;
    config->reuse_addr = true;
    config->trace_bytes = false;
    config->auth_password_file = EMPTY_STRING;
    config->https_enabled = false;
    config->acme_enabled = false;
    config->auth_log_file = S("auth.log");
    config->auth_log_buffer = 1<<16;
    config->auth_log_timeout = 10000;
    config->request_log_file = S("request.log");
    config->request_log_buffer = 1<<10;
    config->request_log_timeout = 10000;

    b8 have_document_root = false;

    b8 bad_config = false;
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
            if (value.len == 0) {
                printf("Config Error: Invalid password file\n");
                bad_config = true;
            } else {
                config->auth_password_file = value;
            }
        } else if (streq(name, S("auth-log-file"))) {
            if (value.len == 0) {
                printf("Config Error: Invalid auth log file\n");
                bad_config = true;
            } else {
                config->auth_log_file = value;
            }
        } else if (streq(name, S("auth-log-buffer"))) {
            parse_config_value_buffer_size(name, value, &config->auth_log_buffer, &bad_config);
        } else if (streq(name, S("auth-log-timeout"))) {
            parse_config_value_time_ms(name, value, &config->auth_log_timeout, &bad_config);
        } else if (streq(name, S("request-log-file"))) {
            if (value.len == 0) {
                printf("Config Error: Invalid request log file\n");
                bad_config = true;
            } else {
                config->request_log_file = value;
            }
        } else if (streq(name, S("request-log-buffer"))) {
            parse_config_value_buffer_size(name, value, &config->request_log_buffer, &bad_config);
        } else if (streq(name, S("request-log-timeout"))) {
            parse_config_value_time_ms(name, value, &config->request_log_timeout, &bad_config);
        }
    }

    if (!have_document_root) {
        printf("Config Error: You need to specify a web content directory. Use option 'document-root'\n");
        bad_config = true;
    }

    if (config->https_enabled) {

        config->https_addr = EMPTY_STRING;
        config->https_port = 8443;

        b8 have_cert_file     = false;
        b8 have_cert_key_file = false;

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

        config->acme_key_file    = S("acme_key.pem");
        config->acme_log_file    = S("acme.log");
        config->acme_log_buffer  = 1<<16;
        config->acme_log_timeout = 10000;
        config->acme_agree_tos   = false;
        config->acme_url         = S("https://acme-v02.api.letsencrypt.org/directory");

        b8 have_acme_email   = false;
        b8 have_acme_country = false;
        b8 have_acme_org     = false;

        config_reader_rewind(reader);
        while (config_reader_next(reader, &name, &value)) {
            if (streq(name, S("acme-key-file"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid ACME key file\n");
                    bad_config = true;
                } else {
                    config->acme_key_file = value;
                }
            } else if (streq(name, S("acme-log-file"))) {
                if (value.len == 0) {
                    printf("Config Error: Invalid ACME log file\n");
                    bad_config = true;
                } else {
                    config->acme_log_file = value;
                }
            } else if (streq(name, S("acme-log-buffer"))) {
                parse_config_value_buffer_size(name, value, &config->acme_log_buffer, &bad_config);
            } else if (streq(name, S("acme-log-timeout"))) {
                parse_config_value_time_ms(name, value, &config->acme_log_timeout, &bad_config);
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

int main_server(int argc, char **argv)
{
    if (crash_logger_init() < 0)
        return -1;

    ConfigReader config_reader;
    int ret = config_reader_init(&config_reader, argc, argv);
    if (ret < 0) {
        crash_logger_free();
        return -1;
    }

    ServerConfig server_config;
    ret = load_server_config(&config_reader, &server_config);
    if (ret != 1) {
        config_reader_free(&config_reader);
        crash_logger_free();
        return ret;
    }

    running = 1;

    CHTTP_Client client;
    ret = chttp_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n",
            chttp_strerror(ret));
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }

    CHTTP_Server server;
    ret = chttp_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n",
            chttp_strerror(ret));
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }
    chttp_server_set_reuse_addr(&server,
        server_config.reuse_addr);
    chttp_server_set_trace_bytes(&server,
        server_config.trace_bytes);

    ret = chttp_server_listen_tcp(&server,
        server_config.http_addr,
        server_config.http_port);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n",
            chttp_strerror(ret));
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }
    printf("HTTP server on interface %.*s:%d\n",
        CHTTP_UNPACK(server_config.http_addr),
        server_config.http_port);

    ACME acme;
    Logger acme_logger;
    if (server_config.acme_enabled) {

        if (logger_init(&acme_logger,
            server_config.acme_log_buffer,
            server_config.acme_log_timeout,
            server_config.acme_log_file) < 0) {
            ASSERT(0);
        }

        ACME_Config acme_config;
        acme_config_init(&acme_config, &client,
            server_config.acme_url,
            server_config.acme_email,
            server_config.acme_country,
            server_config.acme_org,
            server_config.acme_domains[0]);
        for (int i = 1; i < server_config.num_acme_domains; i++) {
            acme_config_add_domain(&acme_config,
                server_config.acme_domains[i]);
        }
        acme_config.agree_tos = server_config.acme_agree_tos;
        acme_config.account_key_file = server_config.acme_key_file;
        acme_config.certificate_file = server_config.cert_file;
        acme_config.certificate_key_file = server_config.cert_key_file;
        if (acme_init(&acme, &acme_config) < 0) {
            fprintf(stderr, "Couldn't initialize ACME client\n");
            config_reader_free(&config_reader);
            crash_logger_free();
            return -1;
        }
    }

    if (server_config.https_enabled && file_exists(server_config.cert_file)) {
        ret = chttp_server_listen_tls(&server,
            server_config.https_addr,
            server_config.https_port,
            server_config.cert_file,
            server_config.cert_key_file);
        if (ret < 0) {
            fprintf(stderr, "Couldn't start listening (%s)\n",
                chttp_strerror(ret));
            config_reader_free(&config_reader);
            crash_logger_free();
            return -1;
        }
        printf("HTTPS server on interface %.*s:%d\n",
            CHTTP_UNPACK(server_config.https_addr),
            server_config.https_port);
    }

    Logger auth_logger;
    if (logger_init(&auth_logger,
        server_config.auth_log_buffer,
        server_config.auth_log_timeout,
        server_config.auth_log_file) < 0) {
        ASSERT(0);
    }

    Auth auth;
    if (auth_init(&auth, server_config.auth_password_file, &auth_logger) < 0) {
        fprintf(stderr, "Couldn't initialize authentication system\n");
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }

    Logger request_logger;
    if (logger_init(&request_logger,
        server_config.request_log_buffer,
        server_config.request_log_timeout,
        server_config.request_log_file) < 0) {
        ASSERT(0);
    }

    b8 restart = false;
    while (running) {

        void*           ptrs[CHTTP_CLIENT_POLL_CAPACITY + CHTTP_SERVER_POLL_CAPACITY];
        struct pollfd polled[CHTTP_CLIENT_POLL_CAPACITY + CHTTP_SERVER_POLL_CAPACITY];

        EventRegister server_reg = {
            ptrs,
            polled,
            0
        };
        chttp_server_register_events(&server, &server_reg);

        EventRegister client_reg = {
            ptrs   + server_reg.num_polled,
            polled + server_reg.num_polled,
            0
        };
        chttp_client_register_events(&client, &client_reg);

        int timeouts[] = {
            logger_next_timeout(&request_logger),
            logger_next_timeout(&auth_logger),
            server_config.acme_enabled ? acme_next_timeout(&acme) : -1,
            server_config.acme_enabled ? logger_next_timeout(&acme_logger) : -1,
        };
        int timeout = pick_timeout(timeouts, COUNT(timeouts));

        if (server_reg.num_polled > 0 &&
            client_reg.num_polled > 0) {
            int num_polled = server_reg.num_polled
                            + client_reg.num_polled;
            POLL(polled, num_polled, timeout);
        }

        // TODO: These should not be called at each iteration but when
        //       the timeout actually triggered
        {
            if (server_config.acme_enabled) {
                acme_process_timeout(&acme, &client);
                logger_flush(&acme_logger);
            }
            logger_flush(&request_logger);
            logger_flush(&auth_logger);
        }

        int result;
        void *user;
        CHTTP_Response *response;
        chttp_client_process_events(&client, client_reg);
        while (chttp_client_next_response(&client, &result, &user, &response)) {
            b8 new_certificate = acme_process_response(&acme, result, response);
            chttp_free_response(response);
            if (new_certificate) {
                running = 0;
                restart = true;
            }
        }

        CHTTP_Request *request;
        CHTTP_ResponseBuilder response_builder;
        chttp_server_process_events(&server, server_reg);
        while (chttp_server_next_request(&server, &request, &response_builder)) {

            string method_str = method_to_str(request->method);
            log(&request_logger, S("{} {}\n"), V(method_str, request->url.path)); // IMPROVE: add more information to the log

            if (server_config.acme_enabled) {
                if (acme_process_request(&acme, request, response_builder))
                    continue;
            }

            switch (request->method) {
            case CHTTP_METHOD_GET:
                {
                    char buf[1<<10];
                    int ret = translate_path(request->url.path, server_config.document_root, buf, (int) sizeof(buf));
                    if (ret < 0) {
                        chttp_response_builder_status(response_builder, 500); // TODO: better error code
                        chttp_response_builder_send(response_builder);
                        break;
                    }
                    string file_path = { buf, ret };

                    chttp_response_builder_status(response_builder, 200); // TODO: better error code

                    // TODO: As file_open is currently implemented, when a
                    //       file isn't found it's created, which is very bad
                    Handle fd;
                    ret = file_open(file_path, &fd, FILE_OPEN_READ);
                    if (ret < 0) {
                        if (ret == ERROR_FILE_NOT_FOUND) {
                            chttp_response_builder_status(response_builder, 404); // TODO: better error code
                            chttp_response_builder_send(response_builder);
                        } else {
                            chttp_response_builder_status(response_builder, 500); // TODO: better error code
                            chttp_response_builder_send(response_builder);
                        }
                        break;
                    }
                    u64 len;
                    ret = file_size(fd, &len);
                    if (ret < 0) {
                        file_close(fd);
                        chttp_response_builder_status(response_builder, 500); // TODO: better error code
                        chttp_response_builder_send(response_builder);
                        break;
                    }
                    chttp_response_builder_body_cap(response_builder, len);

                    int dummy;
                    char *dst = chttp_response_builder_body_buf(response_builder, &dummy);
                    if (dst) {
                        for (int copied = 0; copied < len; ) {
                            ret = file_read(fd, dst + copied, len - copied);
                            if (ret <= 0) {
                                file_close(fd);
                                chttp_response_builder_status(response_builder, 500); // TODO: better error code
                                chttp_response_builder_send(response_builder);
                                break;
                            }
                            copied += ret;
                        }
                        chttp_response_builder_body_ack(response_builder, len);
                    }
                    file_close(fd);
                    chttp_response_builder_send(response_builder);
                }
                break;
            case CHTTP_METHOD_PUT:
                {
                    int ret = auth_verify(&auth, request);
                    if (ret < 0) {
                        chttp_response_builder_status(response_builder, 500);
                        chttp_response_builder_send(response_builder);
                        break;
                    }
                    if (ret == 1) {
                        chttp_response_builder_status(response_builder, 401);
                        chttp_response_builder_send(response_builder);
                        break;
                    }

                    char buf[1<<10];
                    ret = translate_path(request->url.path, server_config.document_root, buf, (int) sizeof(buf));
                    if (ret < 0) {
                        chttp_response_builder_status(response_builder, 500); // TODO: better error code
                        chttp_response_builder_send(response_builder);
                        break;
                    }
                    string file_path = { buf, ret };

                    // TODO: delete the previous version if it exists
                    Handle fd;
                    ret = file_open(file_path, &fd, FILE_OPEN_WRITE);
                    if (ret < 0) {
                        chttp_response_builder_status(response_builder, 500); // TODO: better error code
                        chttp_response_builder_send(response_builder);
                        break;
                    }
                    chttp_response_builder_status(response_builder, 200);
                    string body = request->body;
                    for (int copied = 0; copied < body.len; ) {
                        ret = file_write(fd,
                            body.ptr + copied,
                            body.len - copied);
                        if (ret < 0) {
                            chttp_response_builder_status(response_builder, 500); // TODO: better error code
                            chttp_response_builder_send(response_builder);
                            break;
                        }
                        copied += ret;
                    }
                    chttp_response_builder_send(response_builder);
                    file_close(fd);
                }
                break;
            case CHTTP_METHOD_DELETE:
                {
                    int ret = auth_verify(&auth, request);
                    if (ret < 0) {
                        chttp_response_builder_status(response_builder, 500);
                        chttp_response_builder_send(response_builder);
                        break;
                    }
                    if (ret == 1) {
                        chttp_response_builder_status(response_builder, 401);
                        chttp_response_builder_send(response_builder);
                        break;
                    }

                    char buf[1<<10];
                    ret = translate_path(request->url.path, server_config.document_root, buf, (int) sizeof(buf));
                    if (ret < 0) {
                        chttp_response_builder_status(response_builder, 500); // TODO: better error code
                        chttp_response_builder_send(response_builder);
                        break;
                    }
                    string file_path = { buf, ret };

                    if (remove_file_or_dir(file_path) < 0) {
                        chttp_response_builder_status(response_builder, 500); // TODO: better error code
                        chttp_response_builder_send(response_builder);
                    } else {
                        chttp_response_builder_status(response_builder, 200); // TODO: better error code
                        chttp_response_builder_send(response_builder);
                    }
                }
                break;
            case CHTTP_METHOD_OPTIONS:
                chttp_response_builder_status(response_builder, 200);
                chttp_response_builder_header(response_builder,
                    CHTTP_STR("Allow: GET, POST, PUT, DELETE, OPTIONS"));
                chttp_response_builder_send(response_builder);
                break;
            default:
                chttp_response_builder_status(response_builder, 405);
                chttp_response_builder_header(response_builder,
                    CHTTP_STR("Allow: GET, POST, PUT, DELETE, OPTIONS"));
                chttp_response_builder_send(response_builder);
                break;
            }
        }
    }

    logger_free(&request_logger);
    auth_free(&auth);
    logger_free(&auth_logger);
    if (server_config.acme_enabled) {
        acme_free(&acme);
        logger_free(&acme_logger);
    }
    chttp_server_free(&server);
    chttp_client_free(&client);
    config_reader_free(&config_reader);
    crash_logger_free();
    if (restart)
        execv(argv[0], argv);
    return 0;
}
