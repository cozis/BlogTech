#include <chttp.h>

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

    HTTP_Server server;
    int ret = http_server_init(&server);
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
    if (acme_init(&acme) < 0) {
        fprintf(stderr, "Couldn't initialize ACME client\n");
        return -1;
    }

    for (;;) {

        HTTP_Request *request;
        HTTP_ResponseBuilder builder;
        http_server_wait_request(&server, &request, &builder);

        if (acme_process_request(&acme, request, builder))
            continue;

        switch (request->method) {
        case HTTP_METHOD_GET:
            {
                char buf[1<<10];
                int ret = translate_path(request->url.path, document_root, buf, (int) sizeof(buf));
                if (ret < 0) {
                    http_response_builder_status(builder, 500); // TODO: better error code
                    http_response_builder_send(builder);
                    break;
                }
                string file_path = { buf, ret };

                http_response_builder_status(builder, 200); // TODO: better error code

                // TODO: As file_open is currently implemented, when a
                //       file isn't found it's created, which is very bad
                Handle fd;
                ret = file_open(file_path, &fd);
                if (ret < 0) {
                    http_response_builder_status(builder, 500); // TODO: better error code
                    http_response_builder_send(builder);
                    break;
                }
                size_t len;
                ret = file_size(fd, &len);
                if (ret < 0) {
                    file_close(fd);
                    http_response_builder_status(builder, 500); // TODO: better error code
                    http_response_builder_send(builder);
                    break;
                }
                http_response_builder_body_cap(builder, len);

                int dummy;
                char *dst = http_response_builder_body_buf(builder, &dummy);
                if (dst) {
                    for (int copied = 0; copied < len; ) {
                        ret = file_read(fd, dst + copied, len - copied);
                        if (ret <= 0) {
                            file_close(fd);
                            http_response_builder_status(builder, 500); // TODO: better error code
                            http_response_builder_send(builder);
                            break;
                        }
                        copied += ret;
                    }
                    http_response_builder_body_ack(builder, len);
                }
                file_close(fd);
                http_response_builder_send(builder);
            }
            break;
        case HTTP_METHOD_PUT:
            if (!is_request_signed(request)) {
                http_response_builder_status(builder, 401);
                http_response_builder_send(builder);
            } else {
                char buf[1<<10];
                int ret = translate_path(request->url.path, document_root, buf, (int) sizeof(buf));
                if (ret < 0) {
                    http_response_builder_status(builder, 500); // TODO: better error code
                    http_response_builder_send(builder);
                    break;
                }
                string file_path = { buf, ret };

                // TODO: delete the previous version if it exists
                Handle fd;
                ret = file_open(file_path, &fd);
                if (ret < 0) {
                    http_response_builder_status(builder, 500); // TODO: better error code
                    http_response_builder_send(builder);
                    break;
                }
                http_response_builder_status(builder, 200);
                HTTP_String body = request->body;
                for (int copied = 0; copied < body.len; ) {
                    ret = file_write(fd,
                        body.ptr + copied,
                        body.len - copied);
                    if (ret < 0) {
                        http_response_builder_status(builder, 500); // TODO: better error code
                        http_response_builder_send(builder);
                        break;
                    }
                    copied += ret;
                }
                http_response_builder_send(builder);
                file_close(fd);
            }
            break;
        case HTTP_METHOD_DELETE:
            if (!is_request_signed(request)) {
                http_response_builder_status(builder, 401);
                http_response_builder_send(builder);
            } else {
                char buf[1<<10];
                int ret = translate_path(request->url.path, document_root, buf, (int) sizeof(buf));
                if (ret < 0) {
                    http_response_builder_status(builder, 500); // TODO: better error code
                    http_response_builder_send(builder);
                    break;
                }
                string file_path = { buf, ret };

                if (remove_file_or_dir(file_path) < 0) {
                    http_response_builder_status(builder, 500); // TODO: better error code
                    http_response_builder_send(builder);
                } else {
                    http_response_builder_status(builder, 200); // TODO: better error code
                    http_response_builder_send(builder);
                }
            }
            break;
        case HTTP_METHOD_OPTIONS:
            http_response_builder_status(builder, 200);
            http_response_builder_header(builder,
                HTTP_STR("Allow: GET, POST, PUT, DELETE, OPTIONS"));
            http_response_builder_send(builder);
            break;
        default:
            http_response_builder_status(builder, 405);
            http_response_builder_header(builder,
                HTTP_STR("Allow: GET, POST, PUT, DELETE, OPTIONS"));
            http_response_builder_send(builder);
            break;
        }
    }

    auth_free(&auth);
    acme_free(&acme);
    http_server_free(&server);
    return 0;
}
