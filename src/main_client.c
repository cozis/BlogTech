#include <stdio.h>

#include "lib/chttp.h"
#include "static_config.h"
#include "config_reader.h"
#include "request_signature.h"

#include "lib/basic.h"
#include "lib/http.h"
#include "lib/time.h"
#include "lib/random.h"
#include "lib/file_system.h"
#include "lib/string_builder.h"

#define MAX_FILES 128

typedef struct {
    b8           used;
    CHTTP_Method method;
    char         url_buf[1<<10];
    string       url;
    char         path_buf[1<<10];
    string       path;
} Pending;

typedef struct {

    string remote;
    string password;
    b8     trace_bytes;
    b8     skip_auth_check;

    CHTTP_Client client;

    int count;
    Pending pool[MAX_FILES];

} Batch;

static string pop_first(string s, char c)
{
    if (s.len > 0 && s.ptr[0] == c) {
        s.ptr++;
        s.len--;
    }
    return s;
}

static string get_host_from_url(string url)
{
    CHTTP_URL parsed_url;
    int ret = chttp_parse_url(url.ptr, url.len, &parsed_url);
    if (ret < 0)
        return EMPTY_STRING;
    return parsed_url.authority.host.text; // TODO: will this work for IPv6?
}

static int batch_init(Batch *batch, string remote, string password)
{
    batch->remote = remote;
    batch->password = password;
    batch->trace_bytes = false;
    batch->skip_auth_check = false;

    int ret = chttp_client_init(&batch->client);
    if (ret < 0)
        return -1;

    batch->count = 0;
    for (int i = 0; i < MAX_FILES; i++)
        batch->pool[i].used = false;

    return 0;
}

static void batch_free(Batch *batch)
{
    chttp_client_free(&batch->client);
}

static void batch_trace(Batch *batch, b8 trace)
{
    batch->trace_bytes = trace;
}

static void batch_skip_auth(Batch *batch, b8 skip)
{
    batch->skip_auth_check = skip;
}

static int find_free_struct(Batch *batch)
{
    if (batch->count == MAX_FILES)
        return -1;

    int i = 0;
    while (batch->pool[i].used) {
        i++;
        ASSERT(i < MAX_FILES);
    }

    return i;
}

static int add_auth_headers(
    CHTTP_RequestBuilder builder,
    CHTTP_Method method,
    string path,
    string url,
    string content,
    string password)
{
    char timestamp_buf[32];
    string timestamp = fmtorempty(S("{}"), V(get_current_unix_time()), timestamp_buf, sizeof(timestamp_buf));

    s32 expire = 300; // 5 minutes

    char nonce_buf[BASE64_LEN(NONCE_RAW_LEN)];
    int ret = generate_random_bytes(nonce_buf, NONCE_RAW_LEN);
    if (ret < 0)
        return -1;
    assert(ret == 0);

    ret = encode_inplace(nonce_buf, NONCE_RAW_LEN, 0, sizeof(nonce_buf), ENCODING_B64);
    if (ret < 0)
        return -1;
    assert(ret == BASE64_LEN(NONCE_RAW_LEN));
    string nonce = { nonce_buf, ret };

    char signature_buf[64];
    ret = calculate_request_signature(
        method,
        path,
        get_host_from_url(url),
        timestamp,
        expire,
        nonce,
        content,
        password,
        signature_buf,
        sizeof(signature_buf)
    );
    if (ret < 0)
        return -1;
    string signature = { signature_buf, ret };

    char header_buf[1<<8];
    chttp_request_builder_header(builder, fmtorempty(S("X-BlogTech-Nonce: {}"),     V(nonce),     header_buf, sizeof(header_buf)));
    chttp_request_builder_header(builder, fmtorempty(S("X-BlogTech-Timestamp: {}"), V(timestamp), header_buf, sizeof(header_buf)));
    chttp_request_builder_header(builder, fmtorempty(S("X-BlogTech-Expire: {}"),    V(expire),    header_buf, sizeof(header_buf)));
    chttp_request_builder_header(builder, fmtorempty(S("X-BlogTech-Signature: {}"), V(signature), header_buf, sizeof(header_buf)));
    return 0;
}

// Returns:
//    0 on success
//   -1 if the batch is full
//   -2 if the operation completed early
static int batch_add(Batch *batch, CHTTP_Method method, string path)
{
    int idx = find_free_struct(batch);
    if (idx < 0)
        return -1;
    Pending *p = &batch->pool[idx];

    path = pop_first(path, '/');

    p->url  = fmtorempty(S("{}/{}"), V(batch->remote, path), p->url_buf,  sizeof(p->url_buf));
    p->path = fmtorempty(S("{}"),    V(path),                p->path_buf, sizeof(p->path_buf));

    string content = EMPTY_STRING;
    if (method == CHTTP_METHOD_PUT) {
        int ret = file_read_all(path, &content);
        if (ret < 0) {
            fprintf(stdout, "%.*s %.*s .. aborted\n  Couldn't open file '%.*s'\n",
                UNPACK(method_to_str(method)),
                UNPACK(p->url),
                UNPACK(p->path));
            return -2;
        }
    }

    CHTTP_RequestBuilder builder = chttp_client_get_builder(&batch->client);
    chttp_request_builder_set_user(builder, p);
    chttp_request_builder_trace(builder, batch->trace_bytes);
    chttp_request_builder_method(builder, method);
    chttp_request_builder_target(builder, p->url);
    if (!batch->skip_auth_check) {

        int ret = add_auth_headers(builder, method, path, p->url, content, batch->password);
        if (ret < 0) {

            if (content.len > 0)
                free(content.ptr);

            fprintf(stdout, "%.*s %.*s .. aborted\n  Couldn't sign request\n",
                UNPACK(method_to_str(method)),
                UNPACK(p->url));
            return -2;
        }
    }
    chttp_request_builder_body(builder, content);
    int ret = chttp_request_builder_send(builder);
    if (ret < 0) {

        if (content.len > 0)
            free(content.ptr);

        if (ret == CHTTP_ERROR_REQLIMIT)
            return -1;

        fprintf(stdout, "%.*s %.*s .. aborted\n  %s\n",
            UNPACK(method_to_str(method)),
            UNPACK(p->url),
            chttp_strerror(ret));

        return -2;
    }

    if (content.len > 0)
        free(content.ptr);

    p->used = true;
    p->method = method;

    batch->count++;
    return 0;
}

static void batch_wait(Batch *batch)
{
    ASSERT(batch->count > 0);

    int result;
    void *user;
    CHTTP_Response *response;
    chttp_client_wait_response(&batch->client, &result, &user, &response);

    ASSERT(user);
    Pending *pending = user;

    int expected_status;
    switch (pending->method) {
    case CHTTP_METHOD_GET   : expected_status = 200; break;
    case CHTTP_METHOD_PUT   : expected_status = 201; break;
    case CHTTP_METHOD_DELETE: expected_status = 204; break;
    default:
        UNREACHABLE;
    }

    if (result == CHTTP_OK) {
        if (response->status >= 200 && response->status < 300) {

            b8 write_failed = false;
            if (pending->method == CHTTP_METHOD_GET) {
                int ret = file_write_all(pending->path, response->body);
                if (ret < 0) {
                    fprintf(stdout, "%.*s %.*s .. failed\n  Couldn't write file '%.*s'\n",
                        UNPACK(method_to_str(pending->method)),
                        UNPACK(pending->url),
                        UNPACK(pending->path));
                    write_failed = true;
                }
            }

            if (!write_failed) {
                if (response->status == expected_status) {
                    fprintf(stdout, "%.*s %.*s .. ok\n",
                        UNPACK(method_to_str(pending->method)),
                        UNPACK(pending->url));
                } else {
                    fprintf(stdout, "%.*s %.*s .. ok\n  Unexpected status code (%d)\n",
                        UNPACK(method_to_str(pending->method)),
                        UNPACK(pending->url),
                        response->status);
                }
            }

        } else {
            fprintf(stdout, "%.*s %.*s .. rejected\n  Status code %d\n",
                UNPACK(method_to_str(pending->method)),
                UNPACK(pending->url),
                response->status);
        }
        chttp_free_response(response);
    } else {
        fprintf(stdout, "%.*s %.*s .. aborted\n  %s\n",
            UNPACK(method_to_str(pending->method)),
            UNPACK(pending->url),
            chttp_strerror(result));
    }

    pending->used = false;
    batch->count--;
}

int main_client(int argc, char **argv)
{
    ConfigReader config_reader;
    int ret = config_reader_init(&config_reader, argc, argv);
    if (ret < 0)
        return -1;

    b8     is_put    = false;
    b8     is_get    = false;
    b8     is_delete = false;
    b8     verbose   = false; // TODO: use this flag
    b8     skip_auth_check = false;
    b8     trace_bytes = false;

    string remote;
    string auth_password_file;

    string files[MAX_FILES];
    int    num_files = 0;

    b8 have_remote = false;
    b8 have_auth_password_file = false;

    b8 bad_config = false;
    string name, value;
    while (config_reader_next(&config_reader, &name, &value)) {
        if (streq(name, S("put")) || streq(name, S("p"))) {
            is_put = true;
        } else if (streq(name, S("get")) || streq(name, S("g"))) {
            is_get = true;
        } else if (streq(name, S("delete"))) {
            is_delete = true;
        } else if (streq(name, S("verbose"))) {
            verbose = true;
        } else if (streq(name, S("remote"))) {
            if (value.len == 0) {
                printf("Config Error: Invalid remote\n");
                bad_config = true;
            } else {
                if (value.ptr[value.len-1] == '/')
                    value.len--;
                remote = value;
                have_remote = true;
            }
        } else if (streq(name, S("auth-password-file"))) {
            if (value.len == 0) {
                printf("Config Error: Invalid password file\n");
                bad_config = true;
            } else {
                auth_password_file = value;
                have_auth_password_file = true;
            }
        } else if (streq(name, S("trace-bytes"))) {
            parse_config_value_yn(name, value, &trace_bytes, &bad_config);
        } else if (streq(name, S("skip-auth-check"))) {
            parse_config_value_yn(name, value, &skip_auth_check, &bad_config);
        } else if (streq(name, EMPTY_STRING)) {
            if (num_files == MAX_FILES) {
                printf("Config Error: File limit of %d reached\n", MAX_FILES);
                bad_config = true;
            } else {
                files[num_files++] = value;
            }
        }
    }

    if (!have_remote) {
        printf("Config Error: No upload target specified. Use option 'remote'\n");
        bad_config = true;
    }

    if (!have_auth_password_file && !skip_auth_check) {
        printf("Config Error: No password file specified. Use option 'auth-password-file'\n");
        bad_config = true;
    }

    if (is_get + is_put + is_delete > 1) {
        printf("Config Error: Options '--get', '--put', '--delete' can't be used together\n");
        bad_config = true;
    }
    if (is_get + is_put + is_delete == 0) {
        printf("Config Error: You should specify at least on of '--get', '--put', '--delete'\n");
        bad_config = true;
    }

    if (bad_config) {
        config_reader_free(&config_reader);
        return -1;
    }

    // Translate the mode flag to a method
    CHTTP_Method method;
    if (is_get) {
        method = CHTTP_METHOD_GET;
    } else if (is_put) {
        method = CHTTP_METHOD_PUT;
    } else {
        ASSERT(is_delete);
        method = CHTTP_METHOD_DELETE;
    }

    // Load the password
    string auth_password = EMPTY_STRING;
    void *auth_password_original = NULL;
    if (!skip_auth_check) {
        ret = file_read_all(auth_password_file, &auth_password);
        if (ret < 0) {
            printf("Couldn't read password file\n");
            return -1;
        }
        auth_password_original = auth_password.ptr;
        auth_password = trim(auth_password);
    }

    // Initialize the parallel operation batch object
    Batch batch;
    if (batch_init(&batch, remote, auth_password) < 0) {
        ASSERT(0);
    }
    batch_trace(&batch, trace_bytes);
    batch_skip_auth(&batch, skip_auth_check);

    // Begin as many operations as possible in parallel
    int started = 0;
    int completed = 0;
    for (int i = 0; i < num_files; i++) {
        int ret = batch_add(&batch, method, files[i]);
        if (ret == 0)
            started++;
        if (ret == -1)
            break;
        if (ret == -2)
            completed++;
        ASSERT(started == batch.count);
    }

    // If we had more files than we could upload in parallel,
    // upload the rest after waiting for old ones to complete
    while (started + completed < num_files) {
        batch_wait(&batch);
        int ret = batch_add(&batch, method, files[started]);
        if (ret == 0)
            started++;
        if (ret == -1)
            break;
        if (ret == -2)
            completed++;
        ASSERT(started == batch.count);
    }

    // Now wait for all remaining uploads to complete
    while (completed < num_files) {
        batch_wait(&batch);
        completed++;
    }

    // Free resources
    batch_free(&batch);
    if (auth_password_original)
        free(auth_password_original);
    config_reader_free(&config_reader);
    return ret;
}
