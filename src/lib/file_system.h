#ifndef FILE_SYSTEM_INCLUDED
#define FILE_SYSTEM_INCLUDED

#include "basic.h"

#define PATH_LIMIT      1024
#define PATH_COMP_LIMIT 32

enum {
    FS_ERROR_UNSPECIFIED = -1,
    FS_ERROR_PATHTOOLONG = -2,
    FS_ERROR_BADPATH     = -3,
    FS_ERROR_NOTFOUND    = -4,
    FS_ERROR_OUTOFMEM    = -5,
};

typedef struct {
    u64 data;
} FileHandle;

typedef enum {

    // Open for reading
    FS_OPEN_READ,

    // Open for writing by overwriting
    // any existing file
    FS_OPEN_WRITE,

    // Open file for logging
    FS_OPEN_LOG,
} FileOpenMode;

int file_open(string path, FileOpenMode mode,
    FileHandle *handle);

// Signal-safe and doesn't use a lot of stack
//
// Normal code should use "file_open" instead of this
// function. It's only meant to be called from signal
// handlers.
int file_open_zt(char *path_zt, FileOpenMode mode,
    FileHandle *handle);

void file_close(FileHandle fd);

// Signal-safe
int file_read(FileHandle fd, char *dst, int max);

// Signal-safe
int file_write(FileHandle fd, char *src, int len);

int file_size(FileHandle fd, u64 *len);

int file_exists(string path);

int file_delete(string path);

int file_read_all(string path, string *data);

int file_write_all(string path, string data);

int parse_path(string path, string *comps, int max_comps, int num_comps);

int translate_path(string path, string root, char *dst, int cap);

#endif // FILE_SYSTEM_INCLUDED