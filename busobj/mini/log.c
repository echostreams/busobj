/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#if defined(__linux__)
#include <sys/time.h>
#else
#include <time.h>
#endif

#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "sd-messages.h"

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "ratelimit.h"
#include "signal-util.h"
#include "socket-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "syslog-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "utf8.h"

#define SNDBUF_SIZE (8*1024*1024)

#ifdef WIN32
#define LINE_MAX 2048
#endif

static int log_max_level = LOG_INFO;

/* Akin to glibc's __abort_msg; which is private and we hence cannot
 * use here. */
static char* log_abort_msg = NULL;

void log_set_max_level(int level) {
    assert(level == LOG_NULL || (level & LOG_PRIMASK) == level);

    log_max_level = level;
}

int log_get_max_level(void) {
    return log_max_level;
}

int log_dispatch_internal(
    int level,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* object_field,
    const char* object,
    const char* extra_field,
    const char* extra,
    char* buffer) {

    printf("%s\n", buffer);
   
}

int log_internalv(
    int level,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* format,
    va_list ap) {

    char buffer[LINE_MAX];
    PROTECT_ERRNO;

    if (_likely_(LOG_PRI(level) > log_max_level))
        return -ERRNO_VALUE(error);

    /* Make sure that %m maps to the specified error (or "Success"). */
    errno = ERRNO_VALUE(error);

    (void)vsnprintf(buffer, sizeof buffer, format, ap);

    return log_dispatch_internal(level, error, file, line, func, NULL, NULL, NULL, NULL, buffer);
}

int log_internal(
    int level,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* format, ...) {

    va_list ap;
    int r;

    va_start(ap, format);
    r = log_internalv(level, error, file, line, func, format, ap);
    va_end(ap);

    return r;
}

int log_object_internalv(
    int level,
    int error,
    const char* file,
    int line,
    const char* func,
    const char* object_field,
    const char* object,
    const char* extra_field,
    const char* extra,
    const char* format,
    va_list ap) {

    PROTECT_ERRNO;
    char* buffer, * b;

    if (_likely_(LOG_PRI(level) > log_max_level))
        return -ERRNO_VALUE(error);

    /* Make sure that %m maps to the specified error (or "Success"). */
    errno = ERRNO_VALUE(error);

    /* Prepend the object name before the message */
    if (object) {
        size_t n;

        n = strlen(object);
        //buffer = newa(char, n + 2 + LINE_MAX);
        buffer = alloca(n + 2 + LINE_MAX);
        b = stpcpy(stpcpy(buffer, object), ": ");
    }
    else
        //b = buffer = newa(char, LINE_MAX);
        b = buffer = alloca(LINE_MAX);

    (void)vsnprintf(b, LINE_MAX, format, ap);

    return log_dispatch_internal(level, error, file, line, func,
        object_field, object, extra_field, extra, buffer);
}

static void log_assert(
    int level,
    const char* text,
    const char* file,
    int line,
    const char* func,
    const char* format) {

    static char buffer[LINE_MAX];

    if (_likely_(LOG_PRI(level) > log_max_level))
        return;

    DISABLE_WARNING_FORMAT_NONLITERAL;
    (void)snprintf(buffer, sizeof buffer, format, text, file, line, func);
    REENABLE_WARNING;

    log_abort_msg = buffer;

    //log_dispatch_internal(level, 0, file, line, func, NULL, NULL, NULL, NULL, buffer);
    printf("%s\n", buffer);
}


_noreturn_ void log_assert_failed(
    const char* text,
    const char* file,
    int line,
    const char* func) {
    log_assert(LOG_CRIT, text, file, line, func,
        "Assertion '%s' failed at %s:%u, function %s(). Aborting.");
    abort();
}

_noreturn_ void log_assert_failed_unreachable(
    const char* file,
    int line,
    const char* func) {
    log_assert(LOG_CRIT, "Code should not be reached", file, line, func,
        "%s at %s:%u, function %s(). Aborting.");
    abort();
}

void log_assert_failed_return(
    const char* text,
    const char* file,
    int line,
    const char* func) {
    PROTECT_ERRNO;
    log_assert(LOG_DEBUG, text, file, line, func,
        "Assertion '%s' failed at %s:%u, function %s(). Ignoring.");
}

int log_oom_internal(int level, const char* file, int line, const char* func) {
    return log_internal(level, ENOMEM, file, line, func, "Out of memory.");
}