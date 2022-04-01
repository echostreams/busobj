/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "alloc-util.h"
#include "escape.h"
#include "hexdecoct.h"
#include "macro.h"
#include "strv.h"
#include "utf8.h"

char octchar(int x) {   // from hexdecoct.c
    return '0' + (x & 7);
}

char decchar(int x) {
    return '0' + (x % 10);
}

int undecchar(char c) {

    if (c >= '0' && c <= '9')
        return c - '0';

    return -EINVAL;
}

char hexchar(int x) {   // from hexdecoct.c
    static const char table[16] = "0123456789abcdef";

    return table[x & 15];
}

int unhexchar(char c) {

    if (c >= '0' && c <= '9')
        return c - '0';

    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;

    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;

    return -EINVAL;
}


int cescape_char(char c, char* buf) {
    char* buf_old = buf;

    /* Needs space for 4 characters in the buffer */

    switch (c) {

    case '\a':
        *(buf++) = '\\';
        *(buf++) = 'a';
        break;
    case '\b':
        *(buf++) = '\\';
        *(buf++) = 'b';
        break;
    case '\f':
        *(buf++) = '\\';
        *(buf++) = 'f';
        break;
    case '\n':
        *(buf++) = '\\';
        *(buf++) = 'n';
        break;
    case '\r':
        *(buf++) = '\\';
        *(buf++) = 'r';
        break;
    case '\t':
        *(buf++) = '\\';
        *(buf++) = 't';
        break;
    case '\v':
        *(buf++) = '\\';
        *(buf++) = 'v';
        break;
    case '\\':
        *(buf++) = '\\';
        *(buf++) = '\\';
        break;
    case '"':
        *(buf++) = '\\';
        *(buf++) = '"';
        break;
    case '\'':
        *(buf++) = '\\';
        *(buf++) = '\'';
        break;

    default:
        /* For special chars we prefer octal over
         * hexadecimal encoding, simply because glib's
         * g_strescape() does the same */
        if ((c < ' ') || (c >= 127)) {
            *(buf++) = '\\';
            *(buf++) = octchar((unsigned char)c >> 6);
            *(buf++) = octchar((unsigned char)c >> 3);
            *(buf++) = octchar((unsigned char)c);
        }
        else
            *(buf++) = c;
        break;
    }

    return buf - buf_old;
}

char* cescape_length(const char* s, size_t n) {
    const char* f;
    char* r, * t;

    assert(s || n == 0);

    /* Does C style string escaping. May be reversed with
     * cunescape(). */

    r = new(char, n * 4 + 1);
    if (!r)
        return NULL;

    for (f = s, t = r; f < s + n; f++)
        t += cescape_char(*f, t);

    *t = 0;

    return r;
}

char* cescape(const char* s) {
    assert(s);

    return cescape_length(s, strlen(s));
}