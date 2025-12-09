#include "time.h"

#ifndef _WIN32
#include <time.h>
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
