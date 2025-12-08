#include "../common/chttp.h"
#include "../common/print_usage.h"
#include "../common/file_system.h"
#include "../common/config_reader.h"

#define MAX_FILES (1<<7)

typedef struct {
    bool        pending;
    HTTP_String file;
    HTTP_String url;
    char        filebuf[1<<10];
    char        urlbuf[1<<10];
} Upload;

static void init_upload_struct(Upload *upload, HTTP_String file, HTTP_String url)
{
    if (file.len >= sizeof(upload->filebuf))
        file.len = (int) sizeof(upload->filebuf);
    memcpy(upload->filebuf, file.ptr, file.len);
    upload->file = (HTTP_String) { upload->filebuf, file.len };

    if (url.len >= sizeof(upload->urlbuf))
        url.len = (int) sizeof(upload->urlbuf);
    memcpy(upload->urlbuf, url.ptr, url.len);
    upload->url = (HTTP_String) { upload->urlbuf, url.len };

    upload->pending = true;
}

static void wait_completion(HTTP_Client *client)
{
    int result;
    void *user;
    HTTP_Response *response;
    http_client_wait_response(client, &result, &user, &response);

    assert(user);
    Upload *completed_upload = user;

    if (result == HTTP_OK) {
        if (response->status >= 200 && response->status < 300) {
            printf("Upload completed %.*s -> %.*s\n",
                HTTP_UNPACK(completed_upload->file),
                HTTP_UNPACK(completed_upload->url));
        } else {
            printf(
                "Upload failed %.*s -> %.*s\n"
                "  Server rejected the request\n",
                HTTP_UNPACK(completed_upload->file),
                HTTP_UNPACK(completed_upload->url)
            );
        }
    } else {
        printf(
            "Upload failed %.*s -> %.*s\n"
            "  %s\n",
            HTTP_UNPACK(completed_upload->file),
            HTTP_UNPACK(completed_upload->url),
            http_strerror(result)
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

    HTTP_String remote;
    bool        trace_bytes;
    HTTP_String files[MAX_FILES];
    int         num_files = 0;

    bool have_remote = false;

    // TODO: set default values for optional parameters
    //       and check that necessary parameters are set.
    bool bad_config = false;
    HTTP_String name, value;
    while (config_reader_next(&config_reader, &name, &value)) {
        if (http_streq(name, HTTP_STR("remote"))) {
            if (value.len == 0) {
                printf("Config Error: Invalid remote\n");
                bad_config = true;
            } else {
                remote = value;
                have_remote = true;
            }
        } else if (http_streq(name, HTTP_STR("trace-bytes"))) {
            parse_config_value_yn(name, value, &trace_bytes, &bad_config);
        } else if (http_streq(name, HTTP_STR("help")) || http_streq(name, HTTP_STR("h"))) {
            print_usage();
            config_reader_free(&config_reader);
            return 0;
        } else if (http_streq(name, HTTP_STR(""))) {
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

    if (bad_config) {
        config_reader_free(&config_reader);
        return -1;
    }

    if (num_files == 0) {
        config_reader_free(&config_reader);
        return 0;
    }

    HTTP_Client client;
    ret = http_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", http_strerror(ret));
        return -1;
    }

    Upload uploads[HTTP_CLIENT_CAPACITY];
    for (int i = 0; i < HTTP_CLIENT_CAPACITY; i++)
        uploads[i].pending = false;

    for (int i = 0; i < num_files; i++) {

        Upload *u = uploads;
        while (u->pending) {
            u++;
            assert(u < uploads + HTTP_CLIENT_CAPACITY);
        }

        char urlbuf[1<<10];
        int urllen = snprintf(urlbuf, sizeof(urlbuf), "%.*s/%.*s",
            HTTP_UNPACK(remote), HTTP_UNPACK(files[i]));
        if (urllen < 0 || urllen >= (int) sizeof(urlbuf)) {
            printf("Error: URL is too long\n");
            continue;
        }
        HTTP_String url = { urlbuf, urllen };

        HTTP_String data;
        int ret = file_read_all(files[i], &data);
        if (ret < 0) {
            printf("Error: Couldn't read '%.*s'\n", HTTP_UNPACK(files[i]));
            continue;
        }

        HTTP_RequestBuilder builder = http_client_get_builder(&client);
        http_request_builder_set_user(builder, u);
        http_request_builder_trace(builder, trace_bytes);
        http_request_builder_method(builder, HTTP_METHOD_PUT);
        http_request_builder_target(builder, url);
        http_request_builder_body(builder, data);

        ret = http_request_builder_send(builder);
        if (ret < 0) {
            if (ret ==  HTTP_ERROR_REQLIMIT) {
                wait_completion(&client);
                i--;
            } else {
                printf("Error: Couldn't upload '%.*s' (%s)\n",
                    HTTP_UNPACK(files[i]), strerror(ret));
            }
        } else {
            init_upload_struct(u, files[i], url);
        }

        free(data.ptr);
    }

    for (;;) {

        bool completed = true;
        for (int i = 0; i < MAX_FILES; i++)
            if (uploads[i].pending) {
                completed = false;
                break;
            }

        if (completed)
            break;

        wait_completion(&client);
    }

    http_client_free(&client);
    config_reader_free(&config_reader);
    return 0;
}
