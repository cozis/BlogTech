
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#else
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
    int ret = openat(AT_FDCWD, path_zt, flags, perm);
    if (ret < 0) {
        if (errno == ENOENT)
            return FS_ERROR_NOTFOUND;
        return FS_ERROR_UNSPECIFIED;
    }

    *handle = (FileHandle) { (u64) ret };
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
    struct stat sb;
    if (stat(path, &sb) <)
        return FS_ERROR_UNSPECIFIED;

    if (S_ISDIR(sb.st_mode))
        return 1;

    return 0;
#endif
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

int translate_path(string path, string root, char *dst, int cap)
{
    int num_comps = 0;
    string comps[PATH_COMP_LIMIT];

    int ret = parse_path(root, comps + num_comps, PATH_COMP_LIMIT - num_comps, 0);
    if (ret < 0)
        return -1;
    num_comps += ret;

    ret = parse_path(path, comps + num_comps, PATH_COMP_LIMIT - num_comps, 0);
    if (ret < 0)
        return -1;
    num_comps += ret;

    int len = 0;
    if (root.len == 0 || root.ptr[0] != '/')
        len++;
    for (int i = 0; i < num_comps; i++)
        len += 1 + comps[i].len;
    if (len >= cap)
        return -1;

    int num = 0;
    if (root.len == 0 || root.ptr[0] != '/')
        dst[num++] = '.';
    for (int i = 0; i < num_comps; i++) {
        dst[num++] = '/';
        memcpy_(dst + num, comps[i].ptr, comps[i].len);
        num += comps[i].len;
    }

    return num;
}
