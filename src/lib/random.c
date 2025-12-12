#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <errno.h>
#include <sys/random.h>
#endif

#include "random.h"

int generate_random_bytes(char *dst, int cap)
{
#ifdef __linux__
    int copied = 0;
    while (copied < cap) {
        int ret = getrandom(dst, (size_t) cap, 0);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        copied += ret;
    }
    return 0;
#endif

#ifdef _WIN32
    NTSTATUS status = BCryptGenRandom(NULL, (unsigned char*) dst, (ULONG) cap, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return BCRYPT_SUCCESS(status) ? 0 : -1;
#endif
}
