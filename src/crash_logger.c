#ifdef _WIN32
#include <windows.h>
#else
#define _GNU_SOURCE
#include <signal.h>
#include <stdlib.h>
#include <unwind.h> // GCC/Clang unwind API
#endif

#include "lib/basic.h"
#include "lib/file_system.h"
#include "lib/string_builder.h"

#define MAX_FRAMES 32

// Requires the flag -funwind-tables

static void handler(void **stack, int depth)
{
    Handle fd;
    int ret = file_open(S("crash.log"), &fd, FILE_OPEN_WRITE); // TODO: make this signal-safe
    if (ret < 0)
        return;

    // TODO: note on why this is static
    static char buf[1<<12];

    StringBuilder sb;
    sb_init(&sb, buf, sizeof(buf));
    for (int i = 0; i < depth; i++)
        sb_write_fmt(&sb, S("Frame {}: {}\n"), V(i, (u8*) stack[i]));
    if (sb.status < 0 || sb.len > SIZEOF(buf))
        return;
    int len = sb.len;

    for (int copied = 0; copied < len; ) {
        int ret = file_write(fd, buf + copied, len - copied);
        if (ret < 0)
            return;
        copied = ret;
    }

    file_close(fd);
}

#ifdef _WIN32

static LONG WINAPI
handler_windows(EXCEPTION_POINTERS *pep)
{
    // TODO: note on why this is static
    static void *stack[MAX_FRAMES];
    WORD frames = RtlCaptureStackBackTrace(0, MAX_FRAMES, stack, NULL);
    handler(stack, frames);
    return EXCEPTION_EXECUTE_HANDLER;
}

int crash_logger_init(void)
{
    SetUnhandledExceptionFilter(handler_windows); // TODO: can this function fail?
    return 0;
}

void crash_logger_free(void)
{
    // Nothing to be done
}

#else

typedef struct {
    int count;
    int capacity;
    void **stack;
} UnwindBacktraceContext;

static _Unwind_Reason_Code
unwind_callback(struct _Unwind_Context *ctx, void *arg)
{
    UnwindBacktraceContext *ubctx = (UnwindBacktraceContext*) arg;
    if (ubctx->count == ubctx->capacity)
        return _URC_END_OF_STACK;
    ubctx->stack[ubctx->count++] = (void*) _Unwind_GetIP(ctx);
    return _URC_NO_REASON;
}

static void handler_linux(int sig, siginfo_t *info, void *ucontext)
{
    void *stack[MAX_FRAMES];
    UnwindBacktraceContext context = {
        .stack=stack,
        .count=0,
        .capacity=COUNT(stack),
    };
    _Unwind_Backtrace(unwind_callback, &context);
    handler(stack, context.count);
    signal(sig, SIG_DFL);
    raise(sig);
}

static char *stack;

int crash_logger_init(void)
{
    // Set up alternate signal stack
    {
        stack = malloc(SIGSTKSZ);
        if (stack == NULL)
            return -1;

        stack_t ss;
        ss.ss_sp = stack;
        ss.ss_size = SIGSTKSZ;
        ss.ss_flags = 0;
        if (sigaltstack(&ss, NULL) < 0) {
            free(stack);
            return -1;
        }
    }

    {
        // Register the crash handler
        struct sigaction sa;
        sa.sa_sigaction = handler_linux;
        sa.sa_flags = SA_SIGINFO | SA_ONSTACK;  // Add SA_ONSTACK flag
        sigemptyset(&sa.sa_mask);

        // Memory errors
        sigaction(SIGSEGV, &sa, NULL);  // Segmentation fault (invalid memory access)
        sigaction(SIGBUS, &sa, NULL);   // Bus error (misaligned access, hardware error)

        // Execution errors
        sigaction(SIGILL, &sa, NULL);   // Illegal instruction
        sigaction(SIGFPE, &sa, NULL);   // Floating point exception
        sigaction(SIGTRAP, &sa, NULL);  // Trace trap

        // System/resource errors
        sigaction(SIGSYS, &sa, NULL);   // Bad system call
        sigaction(SIGABRT, &sa, NULL);  // Abort (from assert, abort(), etc.)

        // Optional: Resource limit violations
        sigaction(SIGXCPU, &sa, NULL);  // CPU time limit exceeded
        sigaction(SIGXFSZ, &sa, NULL);  // File size limit exceeded
    }

    return 0;
}

void crash_logger_free(void)
{
    free(stack);
}

#endif
