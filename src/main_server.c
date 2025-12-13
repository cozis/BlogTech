#include <signal.h>

#include "auth.h"
#include "acme.h"
#include "config_reader.h"
#include "crash_logger.h"
#include "crash_reader.h"
#include "process_request.h"
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
    int    num_extra_certs;
    string extra_domains[HTTPS_CERT_LIMIT];
    string extra_cert_files[HTTPS_CERT_LIMIT];
    string extra_cert_key_files[HTTPS_CERT_LIMIT];
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
        config->num_extra_certs = 0;

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
            } else if (streq(name, S("extra-cert"))) {
                if (config->num_extra_certs == HTTPS_CERT_LIMIT) {
                    printf("Config Error: HTTPS certificate limit (%d) reached\n", HTTPS_CERT_LIMIT);
                } else {
                    string extra_domain;
                    string extra_cert_file;
                    string extra_cert_key_file;
                    parse_config_extra_cert(name, value, &extra_domain, &extra_cert_file, &extra_cert_key_file, &bad_config);
                    config->extra_domains[config->num_extra_certs] = extra_domain;
                    config->extra_cert_files[config->num_extra_certs] = extra_cert_file;
                    config->extra_cert_key_files[config->num_extra_certs] = extra_cert_key_file;
                    config->num_extra_certs++;
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
    ///////////////////////////////////////////////////////////////////////////////
    // PROCESS CRASHES
    ///////////////////////////////////////////////////////////////////////////////

#ifdef _WIN32
    string debug_info_file = S("blogtech.exe");
#else
    string debug_info_file = S("blogtech");
#endif

    CrashReader crash_reader;
    int ret = crash_reader_init(&crash_reader, S("crash.bin"), debug_info_file);
    if (ret < 0)
        return -1;

    for (CrashInfo crash; crash_reader_next(&crash_reader, &crash); ) {

        char buf[1<<12];
        StringBuilder sb;
        sb_init(&sb, buf, SIZEOF(buf));

        sb_write_str(&sb, S("Crash type: "));
        sb_write_str(&sb, crash.type);
        sb_write_str(&sb, S("\n"));

        sb_write_str(&sb, S("Process ID: "));
        sb_write_u32(&sb, crash.process_id);
        sb_write_str(&sb, S("\n"));

        sb_write_str(&sb, S("Timestamp: "));
        sb_write_u64(&sb, crash.timestamp);
        sb_write_str(&sb, S("\n"));

        sb_write_str(&sb, S("Stack trace:\n"));
        for (int i = 0; i < crash.num_frames; i++) {
            if (crash.frames[i].line > -1) {
                sb_write_fmt(&sb,
                    S("  #{} {} (in {}:{})\n"),
                    V(i, crash.frames[i].func, crash.frames[i].file, crash.frames[i].line)
                );
            } else {
                sb_write_fmt(&sb,
                    S("  #{} {} (in {})\n"),
                    V(i, crash.frames[i].func, crash.frames[i].file)
                );
            }
        }

        sb_write_str(&sb, S("---------------------------------\n"));

        if (sb.status != 0 || sb.len >= SIZEOF(buf)) {
            ASSERT(0);
        }

        FileHandle fd;
        ret = file_open(S("crash.log"), FS_OPEN_LOG, &fd);
        if (ret < 0) {
            ASSERT(0);
        }

        if (file_write_lp(fd, sb.dst, sb.len) < 0) {
            ASSERT(0);
        }

        file_close(fd);
    }

    crash_reader_free(&crash_reader);
    file_delete(S("crash.bin"));

    if (crash_logger_init() < 0) {
        fprintf(stderr, "Couldn't set up crash logger\n");
        return -1;
    }

    ///////////////////////////////////////////////////////////////////////////////
    // LOAD CONFIGURATION
    ///////////////////////////////////////////////////////////////////////////////

    ConfigReader config_reader;
    ret = config_reader_init(&config_reader, argc, argv);
    if (ret < 0) {
        fprintf(stderr, "Couldn't read configuration\n");
        crash_logger_free();
        return -1;
    }

    ServerConfig server_config;
    ret = load_server_config(&config_reader, &server_config);
    if (ret != 1) {
        fprintf(stderr, "Invalid configuration\n");
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }

    ///////////////////////////////////////////////////////////////////////////////
    // INITIALIZE
    ///////////////////////////////////////////////////////////////////////////////

    running = 1;

    CHTTP_Client client;
    ret = chttp_client_init(&client);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize HTTP client\n");
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }

    CHTTP_Server server;
    ret = chttp_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize HTTP server\n");
        chttp_client_free(&client);
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }
    chttp_server_set_reuse_addr(&server, server_config.reuse_addr);
    chttp_server_set_trace_bytes(&server, server_config.trace_bytes);

    ret = chttp_server_listen_tcp(&server,
        server_config.http_addr,
        server_config.http_port);
    if (ret < 0) {
        fprintf(stderr, "Couldn't listen for TCP connections\n");
        chttp_server_free(&server);
        chttp_client_free(&client);
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }

    if (server_config.https_enabled) {
#ifdef HTTPS_ENABLED
        ret = file_exists(server_config.cert_file);
        if (ret < 0) {
            fprintf(stderr, "Couldn't check for the existance of '%.*s'\n",
                UNPACK(server_config.cert_file));
            chttp_server_free(&server);
            chttp_client_free(&client);
            config_reader_free(&config_reader);
            crash_logger_free();
            return -1;
        }

        if (ret == 0) {
            ret = chttp_server_listen_tls(&server,
                server_config.https_addr,
                server_config.https_port,
                server_config.cert_file,
                server_config.cert_key_file);
            if (ret < 0) {
                fprintf(stderr, "Couldn't listen for TLS connections\n");
                chttp_server_free(&server);
                chttp_client_free(&client);
                config_reader_free(&config_reader);
                crash_logger_free();
                return -1;
            }

            if (ret == 0) {
                for (int i = 0; i < server_config.num_extra_certs; i++) {
                    ret = chttp_server_add_certificate(&server,
                        server_config.extra_domains[i],
                        server_config.extra_cert_files[i],
                        server_config.extra_cert_key_files[i]
                    );
                    if (ret < 0) {
                        fprintf(stderr, "Couldn't add certificate '%.*s'\n",
                            UNPACK(server_config.extra_cert_files[i]));
                        chttp_server_free(&server);
                        chttp_client_free(&client);
                        config_reader_free(&config_reader);
                        crash_logger_free();
                        return -1;
                    }
                }
            }
        }
#else
        fprintf(stderr, "Couldn't listen for TLS connections\n");
        chttp_server_free(&server);
        chttp_client_free(&client);
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
#endif
    }

#ifdef HTTPS_ENABLED
    ACME acme;
    Logger acme_logger;
    if (server_config.acme_enabled) {

        if (logger_init(&acme_logger,
            server_config.acme_log_buffer,
            server_config.acme_log_timeout,
            server_config.acme_log_file) < 0) {
            fprintf(stderr, "Couldn't setup the ACME logger\n");
            chttp_server_free(&server);
            chttp_client_free(&client);
            config_reader_free(&config_reader);
            crash_logger_free();
            return -1;
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
            fprintf(stderr, "Couldn't setup the ACME client\n");
            logger_free(&acme_logger);
            chttp_server_free(&server);
            chttp_client_free(&client);
            config_reader_free(&config_reader);
            crash_logger_free();
            return -1;
        }
    }
#else
    if (server_config.acme_enabled) {
        fprintf(stderr, "ACME is not built-in\n");
        chttp_server_free(&server);
        chttp_client_free(&client);
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }
#endif // HTTPS_ENABLED

    Logger auth_logger;
    if (logger_init(&auth_logger,
        server_config.auth_log_buffer,
        server_config.auth_log_timeout,
        server_config.auth_log_file) < 0) {
        fprintf(stderr, "Couldn't setup the auth logger\n");
#ifdef HTTPS_ENABLED
        if (server_config.acme_enabled) {
            acme_free(&acme);
            logger_free(&acme_logger);
        }
#endif
        chttp_server_free(&server);
        chttp_client_free(&client);
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }

    Auth auth;
    if (auth_init(&auth, server_config.auth_password_file, &auth_logger) < 0) {
        fprintf(stderr, "Couldn't setup the auth system\n");
        logger_free(&auth_logger);
#ifdef HTTPS_ENABLED
        if (server_config.acme_enabled) {
            acme_free(&acme);
            logger_free(&acme_logger);
        }
#endif
        chttp_server_free(&server);
        chttp_client_free(&client);
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }

    Logger request_logger;
    if (logger_init(&request_logger,
        server_config.request_log_buffer,
        server_config.request_log_timeout,
        server_config.request_log_file) < 0) {
        fprintf(stderr, "Couldn't setup the request logger\n");
        auth_free(&auth);
        logger_free(&auth_logger);
#ifdef HTTPS_ENABLED
        if (server_config.acme_enabled) {
            acme_free(&acme);
            logger_free(&acme_logger);
        }
#endif
        chttp_server_free(&server);
        chttp_client_free(&client);
        config_reader_free(&config_reader);
        crash_logger_free();
        return -1;
    }

    fprintf(stderr, "Setup complete\n");

    ///////////////////////////////////////////////////////////////////////////////
    // MAIN LOOP
    ///////////////////////////////////////////////////////////////////////////////

    b8 restart = false;
    while (running) {

        void*           ptrs[CHTTP_CLIENT_POLL_CAPACITY + CHTTP_SERVER_POLL_CAPACITY];
        struct pollfd polled[CHTTP_CLIENT_POLL_CAPACITY + CHTTP_SERVER_POLL_CAPACITY];

        EventRegister server_reg = {
            ptrs,
            polled,
            0,
            -1
        };
        chttp_server_register_events(&server, &server_reg);

        EventRegister client_reg = {
            ptrs   + server_reg.num_polled,
            polled + server_reg.num_polled,
            0,
            -1
        };
        chttp_client_register_events(&client, &client_reg);

        int timeouts[] = {
            server_reg.timeout,
            client_reg.timeout,
            logger_next_timeout(&request_logger),
            logger_next_timeout(&auth_logger),
#ifdef HTTPS_ENABLED
            server_config.acme_enabled ? acme_next_timeout(&acme) : -1,
            server_config.acme_enabled ? logger_next_timeout(&acme_logger) : -1,
#endif // HTTPS_ENABLED
        };
        int timeout = pick_timeout(timeouts, COUNT(timeouts));

        POLL(polled, server_reg.num_polled + client_reg.num_polled, timeout);

        // TODO: These should not be called at each iteration but when
        //       the timeout actually triggered
        {
#ifdef HTTPS_ENABLED
            if (server_config.acme_enabled) {
                acme_process_timeout(&acme, &client);
                logger_flush(&acme_logger);
            }
#endif // HTTPS_ENABLED
            logger_flush(&request_logger);
            logger_flush(&auth_logger);
        }

        chttp_client_process_events(&client, client_reg);
        chttp_server_process_events(&server, server_reg);

        int result;
        void *user;
        CHTTP_Response *response;
        while (chttp_client_next_response(&client, &result, &user, &response)) {
            b8 new_certificate = false;
#ifdef HTTPS_ENABLED
            new_certificate = acme_process_response(&acme, result, response);
#endif
            chttp_free_response(response);
            if (new_certificate) {
                running = 0;
                restart = true;
            }
        }

        CHTTP_Request *request;
        CHTTP_ResponseBuilder builder;
        while (chttp_server_next_request(&server, &request, &builder)) {

            string method_str = method_to_str(request->method);
            log(&request_logger, S("{} {}\n"), V(method_str, request->url.path)); // IMPROVE: add more information to the log

#ifdef HTTPS_ENABLED
            if (server_config.acme_enabled) {
                if (acme_process_request(&acme, request, builder))
                    continue;
            }
#endif // HTTPS_ENABLED
            process_request(server_config.document_root, request, builder, &auth);
        }
    }

    ///////////////////////////////////////////////////////////////////////////////
    // CLEANUP
    ///////////////////////////////////////////////////////////////////////////////

    auth_free(&auth);
    logger_free(&auth_logger);
#ifdef HTTPS_ENABLED
    if (server_config.acme_enabled) {
        acme_free(&acme);
        logger_free(&acme_logger);
    }
#endif
    chttp_server_free(&server);
    chttp_client_free(&client);
    config_reader_free(&config_reader);
    crash_logger_free();

    ///////////////////////////////////////////////////////////////////////////////
    // EXIT OR RESTART
    ///////////////////////////////////////////////////////////////////////////////
#ifdef HTTPS_ENABLED
    if (restart)
        execv(argv[0], argv);
#endif
    return 0;
}
