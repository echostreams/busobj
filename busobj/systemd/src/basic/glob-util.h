/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if defined(__linux__)
#include <glob.h>
#endif

#include <stdbool.h>

#include "macro.h"
#include "string-util.h"

#if defined(__linux__)

/* Note: this function modifies pglob to set various functions. */
int safe_glob(const char *path, int flags, glob_t *pglob);

int glob_exists(const char *path);
int glob_extend(char ***strv, const char *path, int flags);

int glob_non_glob_prefix(const char *path, char **ret);

#define _cleanup_globfree_ _cleanup_(globfree)

_pure_ static inline bool string_is_glob(const char *p) {
        /* Check if a string contains any glob patterns. */
        return !!strpbrk(p, GLOB_CHARS);
}

#endif
