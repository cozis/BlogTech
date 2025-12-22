
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <direct.h> // _mkdir
#else
#include <dirent.h>
#include <sys/stat.h>
#endif

#include "file_system.h"

int file_open(string path, FileOpenMode mode,
    FileHandle *handle)
{
    char path_zt[PATH_LIMIT];
    if (path.len >= SIZEOF(path_zt))
        return FS_ERROR_PATHTOOLONG;
    memcpy(path_zt, path.ptr, path.len);
    path_zt[path.len] = '\0';

    return file_open_zt(path_zt, mode, handle);
}

// Signal-safe and doesn't use a lot of stack
int file_open_zt(char *path_zt, FileOpenMode mode,
    FileHandle *handle)
{
#ifdef _WIN32
    DWORD dwDesiredAccess = 0;
    DWORD dwShareMode = 0;
    DWORD dwCreationDisposition = 0;
    switch (mode) {
    case FS_OPEN_READ:
        dwDesiredAccess = GENERIC_READ;
        dwShareMode = FILE_SHARE_READ | FILE_SHARE_WRITE;
        dwCreationDisposition = OPEN_EXISTING;
        break;
    case FS_OPEN_WRITE:
        dwDesiredAccess = GENERIC_WRITE;
        dwCreationDisposition = CREATE_ALWAYS;
        break;
    case FS_OPEN_LOG:
        dwDesiredAccess = FILE_APPEND_DATA;
        dwShareMode = FILE_SHARE_READ;
        dwCreationDisposition = OPEN_ALWAYS;
        break;
    }
    HANDLE h = CreateFileA(
        path_zt,
        dwDesiredAccess,
        dwShareMode,
        NULL,
        dwCreationDisposition,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND ||
            err == ERROR_PATH_NOT_FOUND)
            return FS_ERROR_NOTFOUND;

        DWORD attr = GetFileAttributes(path_zt);
        if (attr == INVALID_FILE_ATTRIBUTES)
            return FS_ERROR_UNSPECIFIED;

        if (attr & FILE_ATTRIBUTE_DIRECTORY)
            return FS_ERROR_ISDIR;

        return FS_ERROR_UNSPECIFIED;
    }
    *handle = (FileHandle) { (u64) h };
#else
    int perm = 0;
    int flags = 0;
    switch (mode) {
    case FS_OPEN_READ:
        flags = O_CLOEXEC | O_RDONLY;
        break;
    case FS_OPEN_WRITE:
        perm = 0644;
        flags = O_CLOEXEC | O_WRONLY | O_CREAT | O_TRUNC;
        break;
    case FS_OPEN_LOG:
        perm = 0644;
        flags = O_CLOEXEC | O_WRONLY | O_CREAT | O_APPEND;
        break;
    }
    int fd = openat(AT_FDCWD, path_zt, flags, perm);
    if (fd < 0) {
        if (errno == ENOENT)
            return FS_ERROR_NOTFOUND;
        if (errno == EISDIR)
            return FS_ERROR_ISDIR;
        return FS_ERROR_UNSPECIFIED;
    }

    // Calling open() with O_RDONLY will allow
    // opening directories, which we don't want
    if (mode == FS_OPEN_READ) {

        struct stat buf;
        if (fstat(fd, &buf) < 0) {
            close(fd);
            return FS_ERROR_UNSPECIFIED;
        }

        if (S_ISDIR(buf.st_mode)) {
            close(fd);
            return FS_ERROR_ISDIR;
        }
    }

    *handle = (FileHandle) { (u64) fd };
#endif
    return 0;
}

// Signal-safe
void file_close(FileHandle fd)
{
#ifdef _WIN32
    CloseHandle((HANDLE) fd.data);
#else
    close((int) fd.data);
#endif
}

// Signal-safe
int file_read(FileHandle fd, char *dst, int max)
{
#ifdef _WIN32
    DWORD num;
    BOOL ok = ReadFile((HANDLE) fd.data, dst, max, &num, NULL);
    if (!ok)
        return FS_ERROR_UNSPECIFIED;
    return num;
#else
    int ret = read((int) fd.data, dst, max);
    if (ret < 0)
        return FS_ERROR_UNSPECIFIED;
    return ret;
#endif
}

// Signal-safe
int file_write(FileHandle fd, char *src, int len)
{
#ifdef _WIN32
    DWORD num;
    BOOL ok = WriteFile((HANDLE) fd.data, src, len, &num, NULL);
    if (!ok)
        return FS_ERROR_UNSPECIFIED;
    return num;
#else
    int ret = write((int) fd.data, src, len);
    if (ret < 0)
        return FS_ERROR_UNSPECIFIED;
    return ret;
#endif
}

int file_read_lp(FileHandle fd, char *dst, int max)
{
    int copied = 0;
    while (copied < max) {
        int ret = file_read(fd, dst + copied, max - copied);
        if (ret < 0)
            return ret;
        if (ret == 0)
            break;
        copied += ret;
    }
    return copied;
}

int file_write_lp(FileHandle fd, char *src, int len)
{
    for (int copied = 0; copied < len; ) {
        int ret = file_write(fd, src + copied, len - copied);
        if (ret < 0)
            return ret;
        copied += ret;
    }
    return 0;
}

int file_size(FileHandle fd, u64 *len)
{
#ifdef _WIN32
    LARGE_INTEGER buf;
    if (!GetFileSizeEx((HANDLE) fd.data, &buf))
        return FS_ERROR_UNSPECIFIED;

    if (buf.QuadPart < 0)
        return FS_ERROR_UNSPECIFIED;

    *len = buf.QuadPart;
    return 0;
#else
    struct stat buf;
    if (fstat((int) fd.data, &buf) < 0)
        return FS_ERROR_UNSPECIFIED;

    if (buf.st_size < 0)
        return FS_ERROR_UNSPECIFIED;

    *len = (u64) buf.st_size;
    return 0;
#endif
}

int file_exists(string path)
{
    char path_zt[PATH_LIMIT];
    if (path.len >= SIZEOF(path_zt))
        return FS_ERROR_PATHTOOLONG;
    memcpy(path_zt, path.ptr, path.len);
    path_zt[path.len] = '\0';

#ifdef _WIN32
    DWORD attrs = GetFileAttributesA(path_zt);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        DWORD err = GetLastError();
        if (err == ERROR_FILE_NOT_FOUND ||
            err == ERROR_PATH_NOT_FOUND)
            return FS_ERROR_NOTFOUND;
        return FS_ERROR_UNSPECIFIED;
    }
    return 0;
#else
    if (access(path_zt, F_OK) == 0)
        return 0; // File exists
    if (errno == ENOENT)
        return FS_ERROR_NOTFOUND;
    return FS_ERROR_UNSPECIFIED;
#endif
}

int file_delete(string path)
{
    char path_zt[PATH_LIMIT];
    if (path.len >= SIZEOF(path_zt))
        return FS_ERROR_PATHTOOLONG;
    memcpy(path_zt, path.ptr, path.len);
    path_zt[path.len] = '\0';

    if (remove(path_zt))
        return FS_ERROR_UNSPECIFIED;

    return 0;
}

int is_dir(string path)
{
    char path_zt[PATH_LIMIT];
    if (path.len >= SIZEOF(path_zt))
        return FS_ERROR_PATHTOOLONG;
    memcpy(path_zt, path.ptr, path.len);
    path_zt[path.len] = '\0';

#ifdef _WIN32
    DWORD attrs = GetFileAttributesA(path_zt);
    if (attrs == INVALID_FILE_ATTRIBUTES)
        return FS_ERROR_UNSPECIFIED;

    if (attrs & FILE_ATTRIBUTE_DIRECTORY)
        return 1;

    return 0;
#else
    struct stat buf;
    if (stat(path_zt, &buf) < 0)
        return FS_ERROR_UNSPECIFIED;

    if (S_ISDIR(buf.st_mode))
        return 1;

    return 0;
#endif
}

int dir_is_empty(string path)
{
    char path_zt[PATH_LIMIT];
    if (path.len >= SIZEOF(path_zt))
        return FS_ERROR_PATHTOOLONG;
    memcpy(path_zt, path.ptr, path.len);
    path_zt[path.len] = '\0';

#ifdef _WIN32
    WIN32_FIND_DATAA find_data;
    HANDLE hFind = FindFirstFileA(path_zt, &find_data);
    if (hFind == INVALID_HANDLE_VALUE)
        return FS_ERROR_UNSPECIFIED;
    do {
        string name = ZT2S(find_data.cFileName);
        if (streq(name, S(".")) || streq(name, S("..")))
            continue;
        FindClose(hFind);
        return 0;
    } while (FindNextFileA(hFind, &find_data));
    FindClose(hFind);
    return 1;
#else
    DIR *dir = opendir(path_zt);
    if (dir == NULL)
        return -1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        string name = ZT2S(entry->d_name); // TODO: is d_name null-terminated?
        if (streq(name, S(".")) || streq(name, S("..")))
            continue;
        closedir(dir);
        return 0;
    }
    closedir(dir);
    return 1;
#endif
}

int create_dir(string path)
{
    char path_zt[PATH_LIMIT];
    if (path.len >= (int) sizeof(path_zt))
        return FS_ERROR_PATHTOOLONG;
    memcpy(path_zt, path.ptr, path.len);
    path_zt[path.len] = '\0';

#ifdef _WIN32
    if (_mkdir(path_zt) < 0) {
        if (errno == EEXIST)
            return FS_ERROR_EXISTS;
        return FS_ERROR_UNSPECIFIED;
    }
#else
    if (mkdir(path_zt, 0766)) { // TODO: check permissions
        if (errno == EEXIST)
            return FS_ERROR_EXISTS;
        return FS_ERROR_UNSPECIFIED;
    }
#endif

    return 0;
}

int file_read_all(string path, string *data)
{
    FileHandle fd;
    int ret = file_open(path, FS_OPEN_READ, &fd);
    if (ret < 0)
        return ret;

    u64 len;
    ret = file_size(fd, &len);
    if (ret < 0) {
        file_close(fd);
        return ret;
    }

    char *dst = malloc(len);
    if (dst == NULL) {
        file_close(fd);
        return FS_ERROR_OUTOFMEM;
    }

    int copied = 0;
    while ((size_t) copied < len) {
        ret = file_read(fd, dst + copied, len - copied);
        if (ret < 0) {
            free(dst);
            file_close(fd);
            return ret;
        }
        copied += ret;
    }

    *data = (string) { dst, len };
    file_close(fd);
    return 0;
}

int file_write_all(string path, string data)
{
    char *src = data.ptr;
    int   len = data.len;

    FileHandle fd;
    int ret = file_open(path, FS_OPEN_WRITE, &fd);
    if (ret < 0)
        return ret;

    int copied = 0;
    while (copied < len) {
        ret = file_write(fd, src + copied, len - copied);
        if (ret < 0) {
            file_close(fd);
            return ret;
        }
        copied += ret;
    }

    file_close(fd);
    return 0;
}

int parse_path(string path, string *comps, int max_comps, int num_comps)
{
    char *src = path.ptr;
    int   len = path.len;
    int   cur = 0;

    for (;;) {

        int off = cur;

        while (cur < len && src[cur] != '/')
            cur++;

        string comp = { src + off, cur - off };

        if (streq(comp, S(".."))) {
            if (num_comps == 0)
                return FS_ERROR_BADPATH;
            num_comps--;
        } else if (!streq(comp, S("")) && !streq(comp, S("."))) {
            if (num_comps == max_comps)
                return FS_ERROR_PATHTOOLONG;
            comps[num_comps++] = comp;
        }

        if (cur == len)
            break;

        ASSERT(src[cur] == '/');
        cur++;
    }

    return num_comps;
}

// Splits the path into an array of subdirectories
//
// For instance
//   dir1/dir2/dir3/file.txt
// becomes:
//   dir1
//   dir1/dir2
//   dir1/dir2/dir3
static int parse_parent_subdirs(string path, string *subdirs, int max)
{
    // First, split the path into components
    int ret = parse_path(path, subdirs, max, 0);
    if (ret < 0)
        return FS_ERROR_UNSPECIFIED;
    int num_subdirs = ret;

    // Pop the last component (the file name)
    if (num_subdirs == 0)
        return FS_ERROR_UNSPECIFIED;
    num_subdirs--;

    // Then, translate each subcomponent into
    // a subdirectory
    for (int i = 0; i < num_subdirs; i++)
        subdirs[i] = (string) {
            path.ptr,
            subdirs[i].ptr + subdirs[i].len - path.ptr
        };

    return num_subdirs;
}

int create_parent_dirs(string path)
{
    string subdirs[PATH_COMP_LIMIT];

    int ret = parse_parent_subdirs(path, subdirs, PATH_COMP_LIMIT);
    if (ret < 0)
        return ret;
    int num_subdirs = ret;

    for (int i = 0; i < num_subdirs; i++) {
        ret = create_dir(subdirs[i]);
        if (ret < 0 && ret != FS_ERROR_EXISTS)
            return ret;
    }

    return 0;
}

int delete_empty_parent_dirs(string path, int ign)
{
    string subdirs[PATH_COMP_LIMIT];

    int ret = parse_parent_subdirs(path, subdirs, PATH_COMP_LIMIT);
    if (ret < 0)
        return ret;
    int num_subdirs = ret;

    for (int i = num_subdirs-1; i >= ign; i--) {

        ret = dir_is_empty(subdirs[i]);

        if (ret < 0)
            return ret; // Error

        if (ret == 0)
            break; // Not empty

        // Empty
        ret = file_delete(subdirs[i]);
        if (ret < 0)
            return ret;
    }

    return 0;
}

#ifdef _WIN32

int directory_scanner_init(DirectoryScanner *scanner, string path)
{
    char pattern[PATH_LIMIT];
    int ret = snprintf(pattern, sizeof(pattern), "%.*s\\*", path.len, path.ptr);
    if (ret < 0 || ret >= (int) sizeof(pattern))
        return -1;

    scanner->handle = FindFirstFileA(pattern, &scanner->find_data);
    if (scanner->handle == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_FILE_NOT_FOUND) {
            scanner->done = true;
            return 0;
        }
        return -1;
    }

    scanner->done = false;
    scanner->first = true;
    return 0;
}

int directory_scanner_next(DirectoryScanner *scanner, string *name)
{
    if (scanner->done)
        return 1;

    if (!scanner->first) {
        BOOL ok = FindNextFileA(scanner->handle, &scanner->find_data);
        if (!ok) {
            scanner->done = true;
            if (GetLastError() == ERROR_NO_MORE_FILES)
                return 1;
            return -1;
        }
    } else {
        scanner->first = false;
    }

    char *p = scanner->find_data.cFileName;
    *name = (string) { p, strlen(p) };
    return 0;
}

void directory_scanner_free(DirectoryScanner *scanner)
{
    FindClose(scanner->handle);
}

#else

int directory_scanner_init(DirectoryScanner *scanner, string path)
{
    char path_copy[PATH_LIMIT];
    if (path.len >= PATH_LIMIT)
        return -1;
    memcpy(path_copy, path.ptr, path.len);
    path_copy[path.len] = '\0';

    scanner->d = opendir(path_copy);
    if (scanner->d == NULL) {
        scanner->done = true;
        return -1;
    }

    scanner->done = false;
    return 0;
}

int directory_scanner_next(DirectoryScanner *scanner, string *name)
{
    if (scanner->done)
        return 1;

    scanner->e = readdir(scanner->d);
    if (scanner->e == NULL) {
        scanner->done = true;
        return 1;
    }

    *name = (string) { scanner->e->d_name, strlen(scanner->e->d_name) };
    return 0;
}

void directory_scanner_free(DirectoryScanner *scanner)
{
    closedir(scanner->d);
}

#endif
