#include <string.h>
#include <stdlib.h>
#include "basic.h"

b8 streq(string s1, string s2)
{
	if (s1.len != s2.len)
		return false;

    for (int i = 0; i < s1.len; i++)
		if (s1.ptr[i] != s2.ptr[i])
			return false;

	return true;
}

static char to_lower(char c)
{
	if (c >= 'A' && c <= 'Z')
		return c - 'A' + 'a';
	return c;
}

b8 streqcase(string s1, string s2)
{
	if (s1.len != s2.len)
		return false;

	for (int i = 0; i < s1.len; i++)
		if (to_lower(s1.ptr[i]) != to_lower(s2.ptr[i]))
			return false;

	return true;
}

string allocstr(string s)
{
    if (s.len == 0)
        return EMPTY_STRING;

    char *p = malloc(s.len);
    if (p == NULL)
        return EMPTY_STRING;

    memcpy_(p, s.ptr, s.len);
    return (string) { p, s.len };
}

string trim(string s)
{
	int i = 0;
	while (i < s.len && (s.ptr[i] == ' ' || s.ptr[i] == '\t' || s.ptr[i] == '\r' || s.ptr[i] == '\n'))
		i++;

	if (i == s.len) {
		s.ptr = NULL;
		s.len = 0;
	} else {
		s.ptr += i;
		s.len -= i;
		while (s.ptr[s.len-1] == ' '
		    || s.ptr[s.len-1] == '\t'
			|| s.ptr[s.len-1] == '\r'
			|| s.ptr[s.len-1] == '\n')
			s.len--;
	}

	return s;
}

int strlen_(char *p)
{
    ASSERT(p);
    int n = 0;
    while (p[n] != '\0')
        n++;
    return n;
}

void memcpy_(char *dst, char *src, int len)
{
#if defined(__GNUC__) || defined(__clang__)
    __builtin_memcpy(dst, src, len);
#else
    for (int i = 0; i < len; i++)
        dst[i] = src[i];
#endif
}
