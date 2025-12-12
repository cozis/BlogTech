#include "process_request.h"
#include "lib/file_system.h"

static void
process_request_get(string document_root, CHTTP_Request *request,
    CHTTP_ResponseBuilder builder, Auth *auth)
{
    char buf[PATH_LIMIT];
    int ret = translate_path(request->url.path, document_root, buf, (int) sizeof(buf));
    if (ret < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }
    string file_path = { buf, ret };

    chttp_response_builder_status(builder, 200);

    FileHandle fd;
    ret = file_open(file_path, FS_OPEN_READ, &fd);
    if (ret < 0) {

        if (ret == FS_ERROR_NOTFOUND) {
            chttp_response_builder_status(builder, 404);
            chttp_response_builder_send(builder);
            return;
        }

        ret = is_dir(file_path);
        if (ret != 1) {
            chttp_response_builder_status(builder, 500);
            chttp_response_builder_send(builder);
            return;
        }

        if (file_path.len > 0 && file_path.ptr[file_path.len-1] == '/')
            file_path.len--;

        char index_file[] = "/index.html";
        if (file_path.len + sizeof(index_file) - 1 >= sizeof(buf)) {
            chttp_response_builder_status(builder, 500);
            chttp_response_builder_send(builder);
            return;
        }
        memcpy(buf + file_path.len, index_file, sizeof(index_file)-1);
        file_path.len += sizeof(index_file)-1;

        ret = file_open(file_path, FS_OPEN_READ, &fd);
        if (ret < 0) {
            if (ret == FS_ERROR_NOTFOUND) {
                chttp_response_builder_status(builder, 404);
                chttp_response_builder_send(builder);
                return;
            }
            chttp_response_builder_status(builder, 500);
            chttp_response_builder_send(builder);
            return;
        }
    }
    u64 len;
    ret = file_size(fd, &len);
    if (ret < 0) {
        file_close(fd);
        chttp_response_builder_status(builder, 500);
        chttp_response_builder_send(builder);
        return;
    }
    chttp_response_builder_body_cap(builder, len);

    int dummy;
    char *dst = chttp_response_builder_body_buf(builder, &dummy);
    if (dst) {
        for (int copied = 0; copied < len; ) {
            ret = file_read(fd, dst + copied, len - copied);
            if (ret <= 0) {
                file_close(fd);
                chttp_response_builder_body_ack(builder, 0);
                chttp_response_builder_status(builder, 500);
                chttp_response_builder_send(builder);
                return;
            }
            copied += ret;
        }
        chttp_response_builder_body_ack(builder, len);
    }
    file_close(fd);
    chttp_response_builder_send(builder);
}

static void
process_request_put(string document_root, CHTTP_Request *request,
    CHTTP_ResponseBuilder builder, Auth *auth)
{
    int ret = auth_verify(auth, request);
    if (ret < 0) {
        chttp_response_builder_status(builder, 500);
        chttp_response_builder_send(builder);
        return;
    }
    if (ret == 1) {
        chttp_response_builder_status(builder, 401);
        chttp_response_builder_send(builder);
        return;
    }

    char buf[1<<10];
    ret = translate_path(request->url.path, document_root, buf, (int) sizeof(buf));
    if (ret < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }
    string file_path = { buf, ret };

    FileHandle fd;
    ret = file_open(file_path, FS_OPEN_WRITE, &fd);
    if (ret < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }
    chttp_response_builder_status(builder, 200);
    string body = request->body;
    for (int copied = 0; copied < body.len; ) {
        ret = file_write(fd,
            body.ptr + copied,
            body.len - copied);
        if (ret < 0) {
            chttp_response_builder_status(builder, 500); // TODO: better error code
            chttp_response_builder_send(builder);
            file_close(fd);
            return;
        }
        copied += ret;
    }
    chttp_response_builder_send(builder);
    file_close(fd);
}

static void
process_request_delete(string document_root, CHTTP_Request *request,
    CHTTP_ResponseBuilder builder, Auth *auth)
{
    int ret = auth_verify(auth, request);
    if (ret < 0) {
        chttp_response_builder_status(builder, 500);
        chttp_response_builder_send(builder);
        return;
    }
    if (ret == 1) {
        chttp_response_builder_status(builder, 401);
        chttp_response_builder_send(builder);
        return;
    }

    char buf[1<<10];
    ret = translate_path(request->url.path, document_root, buf, (int) sizeof(buf));
    if (ret < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }
    string file_path = { buf, ret };

    if (file_delete(file_path) < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
    } else {
        chttp_response_builder_status(builder, 200); // TODO: better error code
        chttp_response_builder_send(builder);
    }
}

void process_request(string document_root, CHTTP_Request *request,
    CHTTP_ResponseBuilder builder, Auth *auth)
{
    switch (request->method) {
    case CHTTP_METHOD_GET:
        process_request_get(document_root, request, builder, auth);
        break;
    case CHTTP_METHOD_PUT:
        process_request_put(document_root, request, builder, auth);
        break;
    case CHTTP_METHOD_DELETE:
        process_request_delete(document_root, request, builder, auth);
        break;
    case CHTTP_METHOD_OPTIONS:
        chttp_response_builder_status(builder, 200);
        chttp_response_builder_header(builder,
            CHTTP_STR("Allow: GET, PUT, DELETE, OPTIONS"));
        chttp_response_builder_send(builder);
        break;
    default:
        chttp_response_builder_status(builder, 405);
        chttp_response_builder_header(builder,
            CHTTP_STR("Allow: GET, PUT, DELETE, OPTIONS"));
        chttp_response_builder_send(builder);
        break;
    }
}
