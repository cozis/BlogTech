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
    FS_ERROR_ISDIR       = -6,
    FS_ERROR_EXISTS      = -7,
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

// Reads up to "max" bytes into "dst" from the specified
// file. Returns the number of bytes read on success or
// a negative error code on failure
//
// Notes:
//   - It's Signal-safe
//   - Reduces partial reads by calling read() multiple times
int file_read_lp(FileHandle fd, char *dst, int max);

// Writes all "len" bytes in "src" to the specified file.
// On success returns 0, else a negative error code.
//
// Notes:
//   - It's Signal-safe
//   - The difference with file_write is that it doesn't
//     allow partial writes
int file_write_lp(FileHandle fd, char *src, int len);

int file_size(FileHandle fd, u64 *len);

int file_exists(string path);

int file_delete(string path);

int is_dir(string path);

// Returns:
//   1  Directory is empty
//   0  Directory is full
//  -1  Error
int dir_is_empty(string path);

int create_dir(string path);

int file_read_all(string path, string *data);

int file_write_all(string path, string data);

int parse_path(string path, string *comps, int max_comps, int num_comps);

// Creates all parent directories to the provided entity.
// For instance, if path equals /dir1/dir2/file.txt, this
// function will create the dir1 and dir2 directories.
int create_parent_dirs(string path);

// Deletes any empty parents for the specified file.
// Note that the file is assumed to be deleted already,
// or none of the parents will be considered empty.
// The "ign" argument tells how many components should
// be ignored from (from the root). For instance,
// if dir1/dir2/file.txt was provided with ign=1,
// the dir1 folder would not be deleted.
//
// NOTE: Of course be very careful with this since
//       it has the potential to delete your entire
//       drive.
int delete_empty_parent_dirs(string path, int ign);

#endif // FILE_SYSTEM_INCLUDED