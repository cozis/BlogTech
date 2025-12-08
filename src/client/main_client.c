#include "../common/chttp.h"
#include "../common/print_usage.h"
#include "../common/file_system.h"
#include "../common/config_reader.h"

#if 0

typedef struct {
    bool        pending;
    HTTP_String file;
    HTTP_String url;
    char        filebuf[1<<10];
    char        urlbuf[1<<10];
} Upload;

HTTP_Client client;
Upload      uploads[HTTP_CLIENT_CAPACITY];

static bool all_complete(void)
{
    for (int i = 0; i < HTTP_CLIENT_CAPACITY; i++)
        if (uploads[i].pending)
            return false;
    return true;
}

static Upload *init_upload_struct(HTTP_String file, HTTP_String url)
{
    int i = 0;
    while (i < HTTP_CLIENT_CAPACITY && !uploads[i].pending)
        i++;

    if (i == HTTP_CLIENT_CAPACITY)
        return NULL;

    Upload *upload = &uploads[i];

    if (file.len >= sizeof(upload->filebuf)) {
        return NULL;
    }
    memcpy(upload->filebuf, file.ptr, file.len);
    upload->file = (HTTP_String) { upload->filebuf, file.len };

    if (url.len >= sizeof(upload->urlbuf)) {
        return NULL;
    }
    memcpy(upload->urlbuf, url.ptr, url.len);
    upload->url = (HTTP_String) { upload->urlbuf, url.len };

    upload->pending = true;
    return upload;
}

static void wait_completion(void)
{
    int result;
    void *user;
    HTTP_Response *response;
    http_client_wait_response(&client, &result, &user, &response);

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

static void upload_file(HTTP_String file, HTTP_String url)
{
    // Find a pending upload structure
    Upload *upload = init_upload_struct(file, url);
    if (upload == NULL) {

        wait_completion();

        upload = init_upload_struct(file, url);
        if (upload == NULL) {
            printf(
                "Upload failed %.*s -> %.*s\n"
                "  File path or URL are too long\n",
                HTTP_UNPACK(file),
                HTTP_UNPACK(url)
            );
            return;
        }
    }

    HTTP_RequestBuilder builder = http_client_get_builder(&client);
    http_request_builder_set_user(builder, upload);
    http_request_builder_method(builder, HTTP_METHOD_PUT);
    http_request_builder_target(builder, url);
    // TODO: write file bytes
    int ret = http_request_builder_send(builder);

    if (ret < 0) {

        // Deallocate the struct
        upload->pending = false;

        // If we failed due to the client parallelization
        // limit being reached, wait for a completion and
        // try again. If some other error occurred, abort
        // the upload.
        if (ret == HTTP_ERROR_REQLIMIT) {
            wait_completion();
            upload_file(file, url);
        } else {
            printf(
                "Upload failed %.*s -> %.*s\n"
                "  %s\n",
                HTTP_UNPACK(file),
                HTTP_UNPACK(url),
                http_strerror(ret)
            );
        }
        return;
    }

    // Upload started
}

static void upload_file_or_dir(HTTP_String file);

static void upload_dir(HTTP_String dir)
{
    if (dir.len > 0 && dir.ptr[dir.len-1] == '/')
        dir.len--;

    char full_path_buf[1<<12];
    if (dir.len + 1 >= (int) sizeof(full_path_buf)) {
        printf("File path is too long\n");
        return;
    }
    memcpy(full_path_buf, dir.ptr, dir.len);
    full_path_buf[dir.len] = '/';

    DirectoryScanner scanner;
    int ret = directory_scanner_init(&scanner, dir);

    for (;;) {

        HTTP_String name;
        ret = directory_scanner_next(&scanner, &name);
        if (ret == 1)
            break; // No more file
        if (ret < 0)
            break; // Error
        assert(ret == 0);

        if (name.len > 0 && name.ptr[0] == '/') {
            name.ptr++;
            name.len--;
        }

        if (dir.len + name.len + 1 >= sizeof(full_path_buf)) {
            printf("File path is too long\n");
            directory_scanner_free(&scanner);
            return;
        }
        memcpy(full_path_buf + dir.len + 1, name.ptr, name.len);
        HTTP_String full_path = { full_path_buf, dir.len + name.len + 1 };

        upload_file_or_dir(full_path);
    }

    directory_scanner_free(&scanner);
}

static void upload_file_or_dir(HTTP_String file)
{
    if (is_dir(file)) {
        upload_dir(file);
    } else {

        char *file = files[i];
        if (file[0] == '/')
            file++;

        char urlbuf[1<<10];
        int urllen = snprintf(urlbuf, sizeof(urlbuf), "%s/%s", remote, file);
        if (urllen < 0 || urllen >= (int) sizeof(urlbuf)) {
            assert(0); // TODO
        }
        HTTP_String url = { urlbuf, urllen };

        upload_file(&client, file, url);
    }
}

int main(int argc, char **argv)
{
    HTTP_String config_text;
    int ret = read_config_file(argc, argv, &config_text);
    if (ret != 0)
        return ret;

    HTTP_String remote;
    bool        trace_bytes;

    ConfigTarget targets[] = {
        CONFIG_TARGET_STR ("remote",      &remote,      1, NULL),
        CONFIG_TARGET_BOOL("trace-bytes", &trace_bytes, 1, NULL),
    };
    config_load(targets, HTTP_COUNT(targets),
        config_text.ptr, config_text.len, argc, argv);

    char *files[] = {
        "file_1.txt",
        "file_2.txt",
        "file_3.txt",
    };

    int ret = http_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", http_strerror(ret));
        return -1;
    }

    for (int i = 0; i < HTTP_COUNT(files); i++)
        upload_file_or_dir(files[i]);

    while (!all_complete())
        wait_completion(&client);

    http_client_free(&client);
    return 0;
}

#endif

int main_client(int argc, char **argv)
{
    ConfigReader config_reader;
    int ret = config_reader_init(&config_reader, argc, argv);
    if (ret < 0)
        return -1;

    HTTP_String remote;
    bool        trace_bytes;

    // TODO: set default values for optional parameters
    //       and check that necessary parameters are set.
    bool bad_config = false;
    HTTP_String name, value;
    while (config_reader_next(&config_reader, &name, &value)) {
        if (http_streq(name, HTTP_STR("remote"))) {
            remote = value;
        } else if (http_streq(name, HTTP_STR("trace-bytes"))) {
            parse_config_value_yn(name, value, &trace_bytes, &bad_config);
        } else if (http_streq(name, HTTP_STR("help")) || http_streq(name, HTTP_STR("h"))) {
            print_usage();
            config_reader_free(&config_reader);
            return 0;
        }
    }
    if (bad_config) {
        config_reader_free(&config_reader);
        return -1;
    }

    HTTP_Client client;
    ret = http_client_init(&client);
    if (ret < 0) {
        printf("Couldn't initialize client (%s)\n", http_strerror(ret));
        return -1;
    }

    printf("(Not implemented yet)\n");

    http_client_free(&client);
    config_reader_free(&config_reader);
    return 0;
}
