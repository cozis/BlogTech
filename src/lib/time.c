#include "time.h"

#ifdef _WIN32
#include <windows.h>
#endif

Time get_current_time(void)
{
#ifdef _WIN32
    {
        s64 count;
        s64 freq;
        int ok;

        ok = QueryPerformanceCounter((LARGE_INTEGER*) &count);
        if (!ok) return INVALID_TIME;

        ok = QueryPerformanceFrequency((LARGE_INTEGER*) &freq);
        if (!ok) return INVALID_TIME;

        u64 res = 1000 * (double) count / freq;
        return res;
    }
#else
    {
        struct timespec time;

        if (clock_gettime(CLOCK_REALTIME, &time))
            return INVALID_TIME;

        u64 res;

        u64 sec = time.tv_sec;
        if (sec > U64_MAX / 1000)
            return INVALID_TIME;
        res = sec * 1000;

        u64 nsec = time.tv_nsec;
        if (res > U64_MAX - nsec / 1000000)
            return INVALID_TIME;
        res += nsec / 1000000;

        return res;
    }
#endif
}

// Signal-safe
UnixTime get_current_unix_time(void)
{
#ifdef _WIN32
    // Code from:
    //   https://stackoverflow.com/questions/20370920/convert-current-time-from-windows-to-unix-timestamp

    // January 1, 1970 (start of Unix epoch) in "ticks"
    s64 UNIX_TIME_START = 0x019DB1DED53E8000;

    // A tick is 100ns
    s64 TICKS_PER_SECOND = 10000000;

    FILETIME ft;
    GetSystemTimeAsFileTime(&ft); // Returns ticks in UTC

    // Copy the low and high parts of FILETIME into a LARGE_INTEGER
    // This is so we can access the full 64-bits as an Int64 without
    // causing an alignment fault
    LARGE_INTEGER li;
    li.LowPart  = ft.dwLowDateTime;
    li.HighPart = ft.dwHighDateTime;

    // Convert ticks since 1/1/1970 into seconds
    return (li.QuadPart - UNIX_TIME_START) / TICKS_PER_SECOND;
#else
    struct timespec ts;
    int ret = clock_gettime(CLOCK_REALTIME, &ts);
    if (ret < 0)
        return INVALID_UNIX_TIME;
    return ts.tv_sec;
#endif
}
