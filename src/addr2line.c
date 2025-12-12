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
            int line = src[cur] - '0';
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