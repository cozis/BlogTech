#include "crash_logger.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h> // GetCurrentProcessId
#include <dbghelp.h> // SymInitialize, StackWalk64
#include <signal.h>

// Define missing signal constants for Windows
// (These are used by the cross-platform handler function)
#ifndef SIGBUS
#define SIGBUS  10
#endif
#ifndef SIGTRAP
#define SIGTRAP 5
#endif
#ifndef SIGSYS
#define SIGSYS  31
#endif
#else
#include <signal.h>
#include <unwind.h>
#endif

///////////////////////////////////////////////////////////////////////////////
// CROSS-PLATFORM
///////////////////////////////////////////////////////////////////////////////

// Signal-safe
u32 current_process_id(void)
{
#ifdef _WIN32
    return GetCurrentProcessId();
#else
    return getpid();
#endif
}

static void handler(int sig, u64 *stack, int depth)
{
    FileHandle fd;
    int ret = file_open_zt("crash.bin", FS_OPEN_LOG, &fd);
    if (ret < 0)
        return;

    if (depth > U8_MAX)
        depth = U8_MAX;

    u8 type;
    switch (sig) {
        case SIGSEGV: type = CRASH_TYPE_SEGV; break;
        case SIGBUS : type = CRASH_TYPE_BUS;  break;
        case SIGILL : type = CRASH_TYPE_ILL;  break;
        case SIGFPE : type = CRASH_TYPE_FPE;  break;
        case SIGTRAP: type = CRASH_TYPE_TRAP; break;
        case SIGSYS : type = CRASH_TYPE_SYS;  break;
        case SIGABRT: type = CRASH_TYPE_ABRT; break;
        default: type = CRASH_TYPE_OTH; break;
    }

    UnixTime timestamp = get_current_unix_time();
    if (timestamp == INVALID_UNIX_TIME)
        return;

    CrashHeader header;
    header.version = CRASH_LOGGER_VERSION;
    header.type = type;
    header.frames = (u8) depth;
    header.process_id = current_process_id();
    header.timestamp = timestamp;

    ret = file_write_lp(fd, (char*) &header, SIZEOF(header));
    if (ret < 0)
        return;

    for (int i = 0; i < depth; i++) {
        ret = file_write_lp(fd, (char*) &stack[i], SIZEOF(stack[i]));
        if (ret < 0)
            return;
    }

    file_close(fd);
}
///////////////////////////////////////////////////////////////////////////////
// LINUX
///////////////////////////////////////////////////////////////////////////////
#ifndef _WIN32

#define MAP_LIMIT 128

typedef struct {
    u64 beg;
    u64 end;
    u64 off;
} Map;

typedef struct {
    int count;
    Map items[MAP_LIMIT];
} Maps;

static Maps  maps___;
static char *stack___;

static u64 addr_to_offset(u64 addr)
{
    Maps *maps = &maps___;
    for (int i = 0; i < maps->count; i++) {
        Map map = maps->items[i];
        if (map.beg <= addr && addr < map.end)
            return addr - map.beg + map.off;
    }
    return U64_MAX;
}

static b8 is_hex(char c)
{
    return (c >= 'A' && c <= 'F')
        || (c >= 'a' && c <= 'f')
        || (c >= '0' && c <= '9');
}

static int hex_char_to_int(char c)
{
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= '0' && c <= '9') return c - '0';
    return -1;
}

static int parse_map_addr(char *src, int len, int *pcur, u64 *out)
{
    int cur = *pcur;

    if (cur == len)
        return -1;
    int n = hex_char_to_int(src[cur]);
    if (n < 0)
        return -1;
    cur++;

    u64 buf = n;
    while (cur < len) {

        int n = hex_char_to_int(src[cur]);
        if (n < 0)
            break;
        cur++;

        if (buf > (U64_MAX - n) / 16)
            return -1;
        buf = buf * 16 + n;
    }

    *out = buf;
    *pcur = cur;
    return 0;
}

static int parse_map(char *src, int len, int *pcur, Map *map, string *path)
{
    int cur = *pcur;

    // An entry uses the following format:
    //   640425aab000-640425aad000 r--p 00000000 08:30 6164                       /usr/bin/cat

    u64 beg;
    int ret = parse_map_addr(src, len, &cur, &beg);
    if (ret < 0)
        return -1;

    if (cur == len || src[cur] != '-')
        return -1;
    cur++;

    u64 end;
    ret = parse_map_addr(src, len, &cur, &end);
    if (ret < 0)
        return -1;

    if (cur == len || src[cur] != ' ')
        return -1;
    cur++;

    if (len - cur < 4
        || (src[cur+0] != '-' && src[cur+0] != 'r')
        || (src[cur+1] != '-' && src[cur+1] != 'w')
        || (src[cur+2] != '-' && src[cur+2] != 'x')
        || (src[cur+3] != 'p' && src[cur+3] != 's'))
        return -1;
    cur += 4;

    if (cur == len || src[cur] != ' ')
        return -1;
    cur++;

    u64 off;
    ret = parse_map_addr(src, len, &cur, &off);
    if (ret < 0)
        return -1;

    if (cur == len || src[cur] != ' ')
        return -1;
    cur++;

    if (cur == len || !is_hex(src[cur]))
        return -1;
    cur++;

    while (cur < len && (is_hex(src[cur]) || src[cur] == ':'))
        cur++;

    if (cur == len || src[cur] != ' ')
        return -1;
    cur++;

    // Skip inode
    if (cur == len || !is_digit(src[cur]))
        return -1;
    cur++;

    while (cur < len && is_digit(src[cur]))
        cur++;

    if (cur == len || src[cur] != ' ')
        return -1;
    cur++;

    while (cur < len && src[cur] == ' ')
        cur++;

    int tmp = cur;
    while (cur < len && src[cur] != '\n')
        cur++;

    *path = (string) { src + tmp, cur - tmp };

    if (cur < len) {
        assert(src[cur] == '\n');
        cur++;
    }

    map->beg = beg;
    map->end = end;
    map->off = off;

    *pcur = cur;
    return 0;
}

static int parse_maps(char *src, int len, Maps *out)
{
    out->count = 0;

    string first_path = EMPTY_STRING;

    int cur = 0;
    while (cur < len) {

        Map map;
        string path;
        int ret = parse_map(src, len, &cur, &map, &path);
        if (ret < 0)
            return -1;

        if (path.len == 0)
            continue;

        if (first_path.len == 0)
            first_path = path;
        else {
            if (!streq(first_path, path))
                continue;
        }

        if (out->count == MAP_LIMIT)
            return -1;
        out->items[out->count++] = map;
    }

    return 0;
}

static int load_maps(Maps *out)
{
    // Note that we can't use file_read_all here since
    // virtual files have a size of 0.
    int fd = open("/proc/self/maps", O_RDONLY);
    if (fd < 0)
        return -1;

    int   len = 0;
    int   cap = 1<<12;
    char *buf = malloc(cap);
    if (buf == NULL) {
        close(fd);
        return -1;
    }

    for (;;) {

        if (len == cap) {
            cap *= 2;
            buf = realloc(buf, cap);
            if (buf == NULL) {
                close(fd);
                return -1;
            }
        }

        int ret = read(fd, buf + len, cap - len);
        if (ret < 0) {
            free(buf);
            close(fd);
            return -1;
        }
        if (ret == 0)
            break;

        len += ret;
    }

    int ret = parse_maps(buf, len, out);
    if (ret < 0) {
        free(buf);
        close(fd);
        return ret;
    }

    free(buf);
    close(fd);
    return 0;
}

typedef struct {
    int count;
    int capacity;
    u64 *stack;
} UnwindBacktraceContext;

static _Unwind_Reason_Code
unwind_callback(struct _Unwind_Context *ctx, void *arg)
{
    UnwindBacktraceContext *ubctx = (UnwindBacktraceContext*) arg;
    if (ubctx->count == ubctx->capacity)
        return _URC_END_OF_STACK;

    int is_before;
    u64 ip = _Unwind_GetIPInfo(ctx, &is_before);
    if (!is_before)
        ip--;

    ubctx->stack[ubctx->count++] = ip;
    return _URC_NO_REASON;
}

static void handler_linux(int sig, siginfo_t *info, void *ucontext)
{
    static u64 stack[CRASH_FRAME_LIMIT]; // TODO: comment on why this is statuc
    UnwindBacktraceContext context = {
        .stack=stack,
        .count=0,
        .capacity=COUNT(stack),
    };
    _Unwind_Backtrace(unwind_callback, &context);

    for (int i = 0; i < context.count; i++)
        stack[i] = addr_to_offset(stack[i]);

    handler(sig, stack, context.count);
    signal(sig, SIG_DFL);
    raise(sig);
}

int crash_logger_init(void)
{
    int ret = load_maps(&maps___);
    if (ret < 0)
        return -1;

    // Set up alternate signal stack
    {
        stack___ = malloc(SIGSTKSZ);
        if (stack___ == NULL)
            return -1;

        stack_t ss;
        ss.ss_sp = stack___;
        ss.ss_size = SIGSTKSZ;
        ss.ss_flags = 0;
        if (sigaltstack(&ss, NULL) < 0) {
            free(stack___);
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
    free(stack___);
}

#endif
///////////////////////////////////////////////////////////////////////////////
// WINDOWS
///////////////////////////////////////////////////////////////////////////////
#ifdef _WIN32

// Convert Windows exception code to a signal-like value for the
// cross-platform handler
static int exception_code_to_signal(DWORD code)
{
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
        case EXCEPTION_STACK_OVERFLOW:
        case EXCEPTION_GUARD_PAGE:
        case EXCEPTION_IN_PAGE_ERROR:
            return SIGSEGV;

        case EXCEPTION_DATATYPE_MISALIGNMENT:
            return SIGBUS;

        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_PRIV_INSTRUCTION:
            return SIGILL;

        case EXCEPTION_FLT_DENORMAL_OPERAND:
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:
        case EXCEPTION_FLT_INEXACT_RESULT:
        case EXCEPTION_FLT_INVALID_OPERATION:
        case EXCEPTION_FLT_OVERFLOW:
        case EXCEPTION_FLT_STACK_CHECK:
        case EXCEPTION_FLT_UNDERFLOW:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_INT_OVERFLOW:
            return SIGFPE;

        case EXCEPTION_BREAKPOINT:
        case EXCEPTION_SINGLE_STEP:
            return SIGTRAP;

        default:
            return SIGABRT;
    }
}

// Convert runtime address to file offset (RVA)
// On Windows, this is: address - module_base_address
static u64 addr_to_offset_win(u64 addr)
{
    // Get the base address of the main module (our executable)
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule == NULL)
        return U64_MAX;

    u64 base = (u64) hModule;
    if (addr < base)
        return U64_MAX;

    return addr - base;
}

static LONG WINAPI
handler_windows(EXCEPTION_POINTERS *pep)
{
    // Static buffer since we're in an exception handler
    // and dynamic allocation may not be safe
    static u64 stack[CRASH_FRAME_LIMIT];

    // Capture the stack using StackWalk64 for accurate results
    // from the exception context
    int depth = 0;

#if defined(_M_X64) || defined(_M_AMD64)
    // 64-bit Windows
    CONTEXT *ctx = pep->ContextRecord;
    STACKFRAME64 frame;
    memset(&frame, 0, sizeof(frame));
    frame.AddrPC.Offset = ctx->Rip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = ctx->Rbp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = ctx->Rsp;
    frame.AddrStack.Mode = AddrModeFlat;

    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();
    DWORD machineType = IMAGE_FILE_MACHINE_AMD64;

    while (depth < CRASH_FRAME_LIMIT) {
        if (!StackWalk64(machineType, hProcess, hThread, &frame,
                         ctx, NULL, SymFunctionTableAccess64,
                         SymGetModuleBase64, NULL))
            break;

        if (frame.AddrPC.Offset == 0)
            break;

        stack[depth++] = addr_to_offset_win(frame.AddrPC.Offset);
    }
#elif defined(_M_IX86)
    // 32-bit Windows
    CONTEXT *ctx = pep->ContextRecord;
    STACKFRAME64 frame;
    memset(&frame, 0, sizeof(frame));
    frame.AddrPC.Offset = ctx->Eip;
    frame.AddrPC.Mode = AddrModeFlat;
    frame.AddrFrame.Offset = ctx->Ebp;
    frame.AddrFrame.Mode = AddrModeFlat;
    frame.AddrStack.Offset = ctx->Esp;
    frame.AddrStack.Mode = AddrModeFlat;

    HANDLE hProcess = GetCurrentProcess();
    HANDLE hThread = GetCurrentThread();
    DWORD machineType = IMAGE_FILE_MACHINE_I386;

    while (depth < CRASH_FRAME_LIMIT) {
        if (!StackWalk64(machineType, hProcess, hThread, &frame,
                         ctx, NULL, SymFunctionTableAccess64,
                         SymGetModuleBase64, NULL))
            break;

        if (frame.AddrPC.Offset == 0)
            break;

        stack[depth++] = addr_to_offset_win((u64) frame.AddrPC.Offset);
    }
#else
    // Fallback: use RtlCaptureStackBackTrace (less accurate but works)
    void *raw_stack[CRASH_FRAME_LIMIT];
    WORD frames = RtlCaptureStackBackTrace(0, CRASH_FRAME_LIMIT, raw_stack, NULL);
    for (int i = 0; i < frames && depth < CRASH_FRAME_LIMIT; i++)
        stack[depth++] = addr_to_offset_win((u64) raw_stack[i]);
#endif

    int sig = exception_code_to_signal(pep->ExceptionRecord->ExceptionCode);
    handler(sig, stack, depth);
    return EXCEPTION_EXECUTE_HANDLER;
}

int crash_logger_init(void)
{
    // Initialize symbol handler for StackWalk64
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    SymInitialize(GetCurrentProcess(), NULL, TRUE);

    SetUnhandledExceptionFilter(handler_windows);
    return 0;
}

void crash_logger_free(void)
{
    SymCleanup(GetCurrentProcess());
}

#endif
///////////////////////////////////////////////////////////////////////////////
// END
///////////////////////////////////////////////////////////////////////////////