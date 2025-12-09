#include "basic.h"
#include <stdlib.h>
#include <string.h>

bool streq(string s1, string s2)
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

bool streqcase(string s1, string s2)
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
        return (string) { NULL, 0 };

    char *p = malloc(s.len);
    if (p == NULL)
        return (string) { NULL, 0 };

    memcpy(p, s.ptr, s.len);
    return (string) { p, s.len };
}
