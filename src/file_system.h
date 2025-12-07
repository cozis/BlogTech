#ifndef FILE_SYSTEM_INCLUDED
#define FILE_SYSTEM_INCLUDED

#include <chttp.h>
#include <stdint.h>
#include <stdbool.h>

#ifndef _WIN32
#include <dirent.h>
#endif

#define ERROR_GENERIC        -1
#define ERROR_FILE_NOT_FOUND -2

typedef struct {
    uint64_t data;
} Handle;

#ifdef _WIN32
typedef struct {
    HANDLE handle;
    WIN32_FIND_DATA find_data;
    bool first;
    bool done;
} DirectoryScanner;
#else
typedef struct {
    DIR *d;
    struct dirent *e;
    bool done;
} DirectoryScanner;
#endif

int  file_open(HTTP_String path, Handle *fd);
void file_close(Handle fd);
int  file_set_offset(Handle fd, int off);
int  file_get_offset(Handle fd, int *off);
int  file_lock(Handle fd);
int  file_unlock(Handle fd);
int  file_sync(Handle fd);
int  file_read(Handle fd, char *dst, int max);
int  file_write(Handle fd, char *src, int len);
int  file_size(Handle fd, size_t *len);
int  file_write_atomic(HTTP_String path, HTTP_String content);
int  create_dir(HTTP_String path);
int  rename_file_or_dir(HTTP_String oldpath, HTTP_String newpath);
int  remove_file_or_dir(HTTP_String path);
int  get_full_path(HTTP_String path, char *dst);
int  file_read_all(HTTP_String path, HTTP_String *data);
int  file_write_all(HTTP_String path, HTTP_String data);

int  directory_scanner_init(DirectoryScanner *scanner, HTTP_String path);
int  directory_scanner_next(DirectoryScanner *scanner, HTTP_String *name);
void directory_scanner_free(DirectoryScanner *scanner);

#endif // FILE_SYSTEM_INCLUDED
