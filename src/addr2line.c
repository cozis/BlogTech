#ifndef _WIN32

#include <sys/wait.h>

#include "addr2line.h"
#include "lib/basic.h"

typedef struct {
    pid_t pid;
    int   fd;
} Process;

static int process_spawn(Process *process, char **args)
{
    int pipefd[2];
    if (pipe(pipefd) < 0)
        return -1;

    pid_t pid = fork();
    if (pid < 0)
        return -1;

    if (pid == 0) {
        // Child
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO); // TODO: error?
        close(pipefd[1]);
        execvp(args[0], args);
        exit(1);
    } else {
        // Parent
        close(pipefd[1]);
        process->fd = pipefd[0];
        process->pid = pid;
        return 0;
    }
}

static void process_free(Process *process)
{
    close(process->fd);
    waitpid(process->pid, NULL, 0); // TODO: error?
}

static int
parse_output_line(char *src, int len, int *pcur, Addr2LineItem *item)
{
    int cur = *pcur;

    // Get function name

    int off = cur;
    while (cur < len && src[cur] != '\n')
        cur++;

    item->func = (string) { src + off, cur - off };

    if (cur == len)
        return -1;
    cur++;

    off = cur;
    while (cur < len && src[cur] != ' ' && src[cur] != ':' && src[cur] != '\n')
        cur++;

    item->file = (string) { src + off, cur - off };

    int line = -1;
    if (cur < len && src[cur] == ':') {
        cur++;

        if (cur < len && is_digit(src[cur])) {
            line = src[cur] - '0';
            cur++;

            while (cur < len && is_digit(src[cur])) {

                int n = src[cur] - '0';
                cur++;

                if (line > (INT_MAX - n) / 10)
                    return -1;
                line = line * 10 + n;
            }
        }
    }

    item->line = line;

    // Skip any remaining characters up to the next \n
    while (cur < len && src[cur] != '\n')
        cur++;

    ASSERT(cur == len || src[cur] == '\n');
    if (cur < len)
        cur++;

    *pcur = cur;
    return 0;
}

static int read_into_buffer(int fd, string *output)
{
    int cap = 1<<10;
    int len = 0;

    char *buf = malloc(cap);
    if (buf == NULL)
        return -1;

    for (;;) {
        if (len == cap) {
            cap *= 2;
            buf = realloc(buf, cap);
            if (buf == NULL)
                return -1;
        }

        int ret = read(fd, buf + len, cap - len);
        if (ret < 0) {
            free(buf);
            return -1;
        }
        if (ret == 0)
            break;

        ASSERT(ret > 0);
        len += ret;
    }

    *output = (string) { buf, len };
    return 0;
}

int addr2line(string executable, u64 *ptrs, int num_ptrs,
    Addr2LineResult *result)
{
    int   pcap = 1<<14;
    char *pool = malloc(pcap);
    if (pool == NULL)
        return -1;
    int used = 0;

    if (executable.len >= pcap - used) {
        free(pool);
        return -1;
    }
    memcpy(pool + used, executable.ptr, executable.len);
    pool[executable.len] = '\0';
    char *executable_zt = pool + used;
    used += executable.len+1;

    char *args[128];
    args[0] = "addr2line";
    args[1] = "-e";
    args[2] = executable_zt;
    args[3] = "-f";
    for (int i = 0; i < num_ptrs; i++) {
        int ret = snprintf(pool + used, pcap - used, "0x%llx", ptrs[i]);
        if (ret < 0 || ret >= pcap - used) {
            free(pool);
            return -1;
        }
        char *hexptr_zt = pool + used;
        pool[used + ret] = '\0';
        used += ret+1;

        args[4+i] = hexptr_zt;
    }
    args[4+num_ptrs] = NULL;

    Process process;
    int ret = process_spawn(&process, args);
    if (ret < 0) {
        free(pool);
        return ret;
    }

    string output;
    ret = read_into_buffer(process.fd, &output);
    if (ret < 0) {
        free(pool);
        process_free(&process);
        return -1;
    }

    // The output uses the following format:
    //   function_name\n
    //   filename:line\n
    //   function-name\n
    //   filename:line\n
    //   ... and so on until EOF ...

    result->ptr = output.ptr;
    result->count = 0;

    char *src = output.ptr;
    int   len = output.len;
    int   cur = 0;

    while (cur < len) {

        Addr2LineItem item;
        int ret = parse_output_line(src, len, &cur, &item);
        if (ret < 0) {
            free(pool);
            return ret;
        }

        if (result->count < ADDR2LINE_ITEM_LIMIT)
            result->items[result->count++] = item;
    }

    free(pool);
    process_free(&process);
    return 0;
}

void addr2line_free_result(Addr2LineResult *result)
{
    if (result->ptr)
        free(result->ptr);
}

#endif // !_WIN32

///////////////////////////////////////////////////////////////////////////////
// WINDOWS
///////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <dbghelp.h>

#include "addr2line.h"
#include "lib/basic.h"

// Buffer size for symbol name and file path
#define MAX_SYM_NAME_LEN 256
#define MAX_FILE_PATH_LEN 512

int addr2line(string debug_info_file, u64 *ptrs, int num_ptrs,
    Addr2LineResult *result)
{
    if (num_ptrs > ADDR2LINE_ITEM_LIMIT)
        num_ptrs = ADDR2LINE_ITEM_LIMIT;

    // Allocate a buffer pool for all strings
    // Each item needs: function name + file path
    int pool_size = num_ptrs * (MAX_SYM_NAME_LEN + MAX_FILE_PATH_LEN);
    char *pool = malloc(pool_size);
    if (pool == NULL)
        return -1;

    int pool_used = 0;

    // Create null-terminated path from the provided debug info file
    // On Windows this should be the path to the .exe file (DbgHelp finds the PDB automatically)
    char exe_path[MAX_PATH];
    if (debug_info_file.len >= MAX_PATH) {
        free(pool);
        return -1;
    }
    memcpy_(exe_path, debug_info_file.ptr, debug_info_file.len);
    exe_path[debug_info_file.len] = '\0';

    // Use a unique fake handle for symbol operations
    // Don't use GetCurrentProcess() as it may conflict with crash_logger's SymInitialize
    static DWORD64 fake_handle_counter = 0x12340000;
    HANDLE hFakeProcess = (HANDLE)(fake_handle_counter++);

    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_LOAD_LINES | SYMOPT_DEBUG);
    if (!SymInitialize(hFakeProcess, NULL, FALSE)) {
        free(pool);
        return -1;
    }

    // Set symbol search path to the executable's directory
    char *last_slash = exe_path;
    for (char *p = exe_path; *p; p++) {
        if (*p == '\\' || *p == '/')
            last_slash = p;
    }
    if (last_slash != exe_path) {
        char search_path[MAX_PATH];
        int dir_len = (int)(last_slash - exe_path);
        memcpy_(search_path, exe_path, dir_len);
        search_path[dir_len] = '\0';
        SymSetSearchPath(hFakeProcess, search_path);
    }

    // Load the module's symbols from the executable
    // DbgHelp will automatically find the PDB based on debug info in the exe
    // Use a fake base address (0x10000) since we're working with RVAs
    DWORD64 module_base = 0x10000;
    DWORD64 loaded_base = SymLoadModuleEx(hFakeProcess, NULL, exe_path, NULL,
                                           module_base, 0, NULL, 0);
    if (loaded_base == 0) {
        SymCleanup(hFakeProcess);
        free(pool);
        return -1;
    }

    result->ptr = pool;
    result->count = 0;

    // Buffer for SYMBOL_INFO (needs extra space for name)
    char sym_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME_LEN];
    SYMBOL_INFO *symbol = (SYMBOL_INFO*) sym_buffer;
    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME_LEN;

    IMAGEHLP_LINE64 line_info;
    line_info.SizeOfStruct = sizeof(IMAGEHLP_LINE64);

    for (int i = 0; i < num_ptrs; i++) {
        Addr2LineItem *item = &result->items[result->count];

        // Convert RVA to virtual address by adding module base
        DWORD64 address = module_base + ptrs[i];
        DWORD64 displacement = 0;
        DWORD line_displacement = 0;

        // Get function name
        char *func_dst = pool + pool_used;
        if (SymFromAddr(hFakeProcess, address, &displacement, symbol)) {
            int name_len = strlen_(symbol->Name);
            if (pool_used + name_len + 1 > pool_size) {
                // Out of pool space, use placeholder
                item->func = S("?");
            } else {
                memcpy_(func_dst, symbol->Name, name_len);
                func_dst[name_len] = '\0';
                item->func = (string) { func_dst, name_len };
                pool_used += name_len + 1;
            }
        } else {
            item->func = S("??");
        }

        // Get file and line info
        char *file_dst = pool + pool_used;
        if (SymGetLineFromAddr64(hFakeProcess, address, &line_displacement, &line_info)) {
            int file_len = strlen_(line_info.FileName);
            if (pool_used + file_len + 1 > pool_size) {
                item->file = S("?");
                item->line = -1;
            } else {
                memcpy_(file_dst, line_info.FileName, file_len);
                file_dst[file_len] = '\0';
                item->file = (string) { file_dst, file_len };
                pool_used += file_len + 1;
                item->line = (int) line_info.LineNumber;
            }
        } else {
            item->file = S("??");
            item->line = -1;
        }

        result->count++;
    }

    // Cleanup
    SymUnloadModule64(hFakeProcess, loaded_base);
    SymCleanup(hFakeProcess);

    return 0;
}

void addr2line_free_result(Addr2LineResult *result)
{
    if (result->ptr)
        free(result->ptr);
}

#endif // _WIN32