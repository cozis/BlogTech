#include "print_usage.h"
#include "config_reader.h"
#include "request_signature.h"

#include "lib/chttp.h"
#include "lib/file_system.h"

#define MAX_FILES (1<<7)

typedef struct {
    b8     pending;
    string file;
    string url;
    char   filebuf[1<<10];
    char   urlbuf[1<<10];
} Upload;

static void init_upload_struct(Upload *upload, string file, string url)
{
    if (file.len >= sizeof(upload->filebuf))
        file.len = (int) sizeof(upload->filebuf);
    memcpy(upload->filebuf, file.ptr, file.len);
    upload->file = (string) { upload->filebuf, file.len };

    if (url.len >= sizeof(upload->urlbuf))
        url.len = (int) sizeof(upload->urlbuf);
    memcpy(upload->urlbuf, url.ptr, url.len);
    upload->url = (string) { upload->urlbuf, url.len };

    upload->pending = true;
}

static void wait_completion(CHTTP_Client *client)
{
    int result;
    void *user;
    CHTTP_Response *response;
    chttp_client_wait_response(client, &result, &user, &response);

    ASSERT(user);
    Upload *completed_upload = user;

    if (result == CHTTP_OK) {
        if (response->status >= 200 && response->status < 300) {
            printf("Upload completed %.*s -> %.*s\n",
                UNPACK(completed_upload->file),
                UNPACK(completed_upload->url));
        } else {
            printf(
                "Upload failed %.*s -> %.*s\n"
                "  Server rejected the request\n",
                UNPACK(completed_upload->file),
                UNPACK(completed_upload->url)
            );
        }
    } else {
        printf(
            "Upload failed %.*s -> %.*s\n"
            "  %s\n",
            UNPACK(completed_upload->file),
            UNPACK(completed_upload->url),
            chttp_strerror(result)
        );
    }
    completed_upload->pending = false;
}

int main_client(int argc, char **argv)
{
    ConfigReader config_reader;
    int ret = config_reader_init(&config_reader, argc, argv);
    if (ret < 0)
        return -1;

    string remote;
    b8     trace_bytes;
    string admin_password_file;
    string files[MAX_FILES];
    int    num_files = 0;

    b8 have_remote = false;
    b8 have_admin_password_file = false;

    // TODO: set default values for optional parameters
    //       and check that necessary parameters are set.
    b8 bad_config = false;
    string name, value;
    while (config_reader_next(&config_reader, &name, &value)) {
        if (streq(name, S("remote"))) {
            if (value.len == 0) {
                printf("Config Error: Invalid remote\n");
                bad_config = true;
            } else {
                remote = value;
                have_remote = true;
            }
        } else if (streq(name, S("admin-password-file"))) {
            if (value.len == 0) {
                printf("Config Error: Invalid password file\n");
                bad_config = true;
            } else {
                admin_password_file = value;
                have_admin_password_file = true;
            }
        } else if (streq(name, S("trace-bytes"))) {
            parse_config_value_yn(name, value, &trace_bytes, &bad_config);
        } else if (streq(name, S("help")) || streq(name, S("h"))) {
            print_usage();
            config_reader_free(&config_reader);
            return 0;
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

    if (!have_admin_password_file) {
        printf("Config Error: No password file specified. Use option 'admin-password-file'\n");
        bad_config = true;
    }

    if (bad_config) {
        config_reader_free(&config_reader);
        return -1;
    }

    if (num_files == 0) {
        config_reader_free(&config_reader);
        return 0;
    }

    string remote_host;
    {
        CHTTP_URL parsed_url;
        ret = chttp_parse_url(remote.ptr, remote.len, &parsed_url);
        if (ret < 0) {
            printf("Config Error: Invalid remote\n");
            return -1;
        }
        remote_host = parsed_url.authority.host.name; // TODO: will this work for IPv6?
    }

    string admin_password;
    ret = file_read_all(admin_password_file, &admin_password);
    if (ret < 0) {
        printf("Couldn't read password file\n");
        return -1;
    }

    CHTTP_Client client;
    ret = chttp_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", chttp_strerror(ret));
        free(admin_password.ptr);
        return -1;
    }

    Upload uploads[CHTTP_CLIENT_CAPACITY];
    for (int i = 0; i < CHTTP_CLIENT_CAPACITY; i++)
        uploads[i].pending = false;

    for (int i = 0; i < num_files; i++) {

        Upload *u = uploads;
        while (u->pending) {
            u++;
            ASSERT(u < uploads + CHTTP_CLIENT_CAPACITY);
        }

        char urlbuf[1<<10];
        int urllen = snprintf(urlbuf, sizeof(urlbuf), "%.*s/%.*s",
            UNPACK(remote), UNPACK(files[i]));
        if (urllen < 0 || urllen >= (int) sizeof(urlbuf)) {
            printf("Error: URL is too long\n");
            continue;
        }
        string url = { urlbuf, urllen };

        string data;
        int ret = file_read_all(files[i], &data);
        if (ret < 0) {
            printf("Error: Couldn't read '%.*s'\n", UNPACK(files[i]));
            continue;
        }

        string timestamp = { NULL, 0 }; // TODO: implement
        u32 expire = 0; // TODO: implement
        string nonce = { NULL, 0 }; // TODO: implement

        char signature[64];
        ret = calculate_request_signature(
            CHTTP_METHOD_PUT,
            files[i],
            remote_host,
            timestamp,
            expire,
            nonce,
            data,
            admin_password,
            signature);
        if (ret < 0) {
            ASSERT(0); // TODO
        }

        CHTTP_RequestBuilder builder = chttp_client_get_builder(&client);
        chttp_request_builder_set_user(builder, u);
        chttp_request_builder_trace(builder, trace_bytes);
        chttp_request_builder_method(builder, CHTTP_METHOD_PUT);
        chttp_request_builder_target(builder, url);

        char hdrbuf[1<<9];
        ret = snprintf(hdrbuf, sizeof(hdrbuf),
            "X-BlogTech-Nonce: %.*s", UNPACK(nonce));
        if (ret < 0 || ret >= (int) sizeof(hdrbuf)) {
            ASSERT(0); // TODO
        }
        chttp_request_builder_header(builder, (CHTTP_String) { hdrbuf, ret });

        ret = snprintf(hdrbuf, sizeof(hdrbuf),
            "X-BlogTech-Timestamp: %.*s", UNPACK(timestamp));
        if (ret < 0 || ret >= (int) sizeof(hdrbuf)) {
            ASSERT(0); // TODO
        }
        chttp_request_builder_header(builder, (CHTTP_String) { hdrbuf, ret });

        ret = snprintf(hdrbuf, sizeof(hdrbuf),
            "X-BlogTech-Expire: %u", expire);
        if (ret < 0 || ret >= (int) sizeof(hdrbuf)) {
            ASSERT(0); // TODO
        }
        chttp_request_builder_header(builder, (CHTTP_String) { hdrbuf, ret });

        ret = snprintf(hdrbuf, sizeof(hdrbuf),
            "X-BlogTech-Signature: %.*s", (int) sizeof(signature), signature);
        if (ret < 0 || ret >= (int) sizeof(hdrbuf)) {
            ASSERT(0); // TODO
        }
        chttp_request_builder_header(builder, (CHTTP_String) { hdrbuf, ret });

        chttp_request_builder_body(builder, data);

        ret = chttp_request_builder_send(builder);
        if (ret < 0) {
            if (ret == CHTTP_ERROR_REQLIMIT) {
                wait_completion(&client);
                i--;
            } else {
                printf("Error: Couldn't upload '%.*s' (%s)\n",
                    UNPACK(files[i]), chttp_strerror(ret));
            }
        } else {
            init_upload_struct(u, files[i], url);
        }

        free(data.ptr);
    }

    for (;;) {

        b8 completed = true;
        for (int i = 0; i < MAX_FILES; i++)
            if (uploads[i].pending) {
                completed = false;
                break;
            }

        if (completed)
            break;

        wait_completion(&client);
    }

    chttp_client_free(&client);
    free(admin_password.ptr);
    config_reader_free(&config_reader);
    return 0;
}
