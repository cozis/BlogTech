#include "process_request.h"
#include "lib/chttp.h"
#include "lib/file_system.h"

static int translate_path(
    string request_path,
    string document_root,
    string host_dir,
    char *dst, int cap)
{
    int num_comps = 0;
    string comps[PATH_COMP_LIMIT];

    // Parse the document root
    int ret = parse_path(document_root, comps, PATH_COMP_LIMIT, 0);
    if (ret < 0) {
        ASSERT(0);
    }
    num_comps += ret;

    // Append the host directory
    if (num_comps == PATH_COMP_LIMIT) {
        ASSERT(0);
    }
    comps[num_comps++] = host_dir;

    // Then, parse the request path in the remaining space
    //
    // NOTE: It's important that the last argument is 0 here.
    //       This means that the parsing of the path will not
    //       be able to move upwards with .. components
    ret = parse_path(request_path, comps + num_comps, PATH_COMP_LIMIT - num_comps, 0);
    if (ret < 0) {
        ASSERT(0);
    }
    num_comps += ret;

    int len = 0;
    if (document_root.len == 0 || document_root.ptr[0] != '/')
        len++;
    for (int i = 0; i < num_comps; i++)
        len += 1 + comps[i].len;
    if (len >= cap)
        return -1;

    int num = 0;
    if (document_root.len == 0 || document_root.ptr[0] != '/')
        dst[num++] = '.';
    for (int i = 0; i < num_comps; i++) {
        dst[num++] = '/';
        memcpy_(dst + num, comps[i].ptr, comps[i].len);
        num += comps[i].len;
    }

    return num;
}

static void process_request_get(
    string document_root,
    string host_dir,
    CHTTP_Request *request,
    CHTTP_ResponseBuilder builder,
    Auth *auth)
{
    char buf[PATH_LIMIT];
    int ret = translate_path(request->url.path, document_root, host_dir, buf, (int) sizeof(buf));
    if (ret < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }
    string file_path = { buf, ret };

    chttp_response_builder_status(builder, 200);

    FileHandle fd;
    ret = file_open(file_path, FS_OPEN_READ, &fd);

    if (ret == FS_ERROR_ISDIR) {

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
    if (ret < 0) {
        if (ret == FS_ERROR_NOTFOUND) {
            chttp_response_builder_status(builder, 404);
            chttp_response_builder_send(builder);
        } else {
            chttp_response_builder_status(builder, 500);
            chttp_response_builder_send(builder);
        }
        return;
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

static void process_request_put(
    string document_root,
    string host_dir,
    CHTTP_Request *request,
    CHTTP_ResponseBuilder builder,
    Auth *auth)
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
    ret = translate_path(request->url.path, document_root, host_dir, buf, (int) sizeof(buf));
    if (ret < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }
    string file_path = { buf, ret };

    ret = create_parent_dirs(file_path);
    if (ret < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }

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

static void process_request_delete(
    string document_root,
    string host_dir,
    CHTTP_Request *request,
    CHTTP_ResponseBuilder builder,
    Auth *auth)
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
    ret = translate_path(request->url.path, document_root, host_dir, buf, (int) sizeof(buf));
    if (ret < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }
    string file_path = { buf, ret };

    if (is_dir(file_path)) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }

    if (file_delete(file_path) < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }

    int ign = 2; // Ignore the document root and the host dir
    ret = delete_empty_parent_dirs(file_path, ign);
    if (ret < 0) {
        chttp_response_builder_status(builder, 500); // TODO: better error code
        chttp_response_builder_send(builder);
        return;
    }

    chttp_response_builder_status(builder, 200); // TODO: better error code
    chttp_response_builder_send(builder);
}

void process_request(
    string document_root,
    string host_dir,
    CHTTP_Request *request,
    CHTTP_ResponseBuilder builder,
    Auth *auth)
{
    switch (request->method) {
    case CHTTP_METHOD_GET:
        process_request_get(document_root, host_dir, request, builder, auth);
        break;
    case CHTTP_METHOD_PUT:
        process_request_put(document_root, host_dir, request, builder, auth);
        break;
    case CHTTP_METHOD_DELETE:
        process_request_delete(document_root, host_dir, request, builder, auth);
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
