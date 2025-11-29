#include <chttp.h>

#ifdef _WIN32
#define POLL WSAPoll
#else
#define POLL poll
#endif

#include "path.h"
#include "auth.h"
#include "acme.h"
#include "file_system.h"

int main(void)
{
    HTTP_String document_root = HTTP_STR("docroot");
    HTTP_String listen_addr   = HTTP_STR("127.0.0.1");
    uint16_t    listen_port   = 8080;
    bool        reuse_addr    = true;
    bool        trace_bytes   = true;
    bool        agree_to_terms_of_service = true;

    HTTP_String email = HTTP_STR("some@email.com");
    HTTP_String domains[] = {
        HTTP_STR("example.com"),
        HTTP_STR("*.example.com"),
    };

    HTTP_Client client;
    int ret = http_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", http_strerror(ret));
        return -1;
    }

    HTTP_Server server;
    ret = http_server_init(&server);
    if (ret < 0) {
        fprintf(stderr, "Couldn't initialize server (%s)\n", http_strerror(ret));
        return -1;
    }
    http_server_set_reuse_addr(&server, reuse_addr);
    http_server_set_trace_bytes(&server, trace_bytes);

    ret = http_server_listen_tcp(&server, listen_addr, listen_port);
    if (ret < 0) {
        fprintf(stderr, "Couldn't start listening (%s)\n", http_strerror(ret));
        return -1;
    }

    Auth auth;
    if (auth_init(&auth) < 0) {
        fprintf(stderr, "Couldn't initialize authentication system\n");
        return -1;
    }

    ACME acme;
    if (acme_init(&acme, email, domains, HTTP_COUNT(domains), &client) < 0) {
        fprintf(stderr, "Couldn't initialize ACME client\n");
        return -1;
    }
    if (agree_to_terms_of_service)
        acme_agree_to_terms_of_service(&acme);

    for (;;) {

        #define POLL_CAPACITY (HTTP_CLIENT_POLL_CAPACITY + HTTP_SERVER_POLL_CAPACITY)

        void *ptrs[POLL_CAPACITY];
        struct pollfd polled[POLL_CAPACITY];

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

        if (server_reg.num_polled > 0 &&
            client_reg.num_polled > 0) {
            int num_polled = server_reg.num_polled
                            + client_reg.num_polled;
            POLL(polled, num_polled, -1);
        }

        int result;
        void *user;
        HTTP_Response *response;
        http_client_process_events(&client, client_reg);
        while (http_client_next_response(&client, &result, &user, &response)) {
            acme_process_response(&acme, result, response, &client, &server);
            http_free_response(response);
        }

        HTTP_Request *request;
        HTTP_ResponseBuilder response_builder;
        http_server_process_events(&server, server_reg);
        while (http_server_next_request(&server, &request, &response_builder)) {

            if (acme_process_request(&acme, request,
                response_builder, &client, &server))
                continue;

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
                    string file_path = { buf, ret };

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
                    string file_path = { buf, ret };

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
                    string file_path = { buf, ret };

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
    return 0;
}
