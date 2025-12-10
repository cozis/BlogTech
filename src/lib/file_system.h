#ifndef FILE_SYSTEM_INCLUDED
#define FILE_SYSTEM_INCLUDED

#ifdef _WIN32
#include <windows.h>
#else
#include <dirent.h>
#endif

#include "basic.h"

#define ERROR_GENERIC   -1
#define FILE_SYSTEM_NOT_FOUND -2

typedef struct {
    u64 data;
} Handle;

#ifdef _WIN32
typedef struct {
    HANDLE handle;
    WIN32_FIND_DATA find_data;
    b8 first;
    b8 done;
} DirectoryScanner;
#else
typedef struct {
    DIR *d;
    struct dirent *e;
    b8 done;
} DirectoryScanner;
#endif

typedef enum {
    FILE_OPEN_WRITE,
    FILE_OPEN_READ,
} FileOpenMode;

b8   file_exists(string path);
int  file_open(string path, Handle *fd, FileOpenMode mode);
void file_close(Handle fd);
int  file_set_offset(Handle fd, int off);
int  file_get_offset(Handle fd, int *off);
int  file_lock(Handle fd);
int  file_unlock(Handle fd);
int  file_sync(Handle fd);
int  file_read(Handle fd, char *dst, int max);
int  file_write(Handle fd, char *src, int len);
int  file_size(Handle fd, u64 *len);
int  file_write_atomic(string path, string content);
int  create_dir(string path);
int  rename_file_or_dir(string oldpath, string newpath);
int  remove_file_or_dir(string path);
int  get_full_path(string path, char *dst);
int  file_read_all(string path, string *data);
int  file_write_all(string path, string data);

int  directory_scanner_init(DirectoryScanner *scanner, string path);
int  directory_scanner_next(DirectoryScanner *scanner, string *name);
void directory_scanner_free(DirectoryScanner *scanner);

int parse_path(string path, string *comps, int max);
int translate_path(string path, string root, char *dst, int cap);

#endif // FILE_SYSTEM_INCLUDED
