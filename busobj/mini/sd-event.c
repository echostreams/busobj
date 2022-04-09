/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/epoll.h>
#if defined(__linux__)
#include <sys/timerfd.h>
#endif
#include <sys/wait.h>

#include "sd-daemon.h"
#include "sd-event.h"
#include "sd-id128.h"

#include "alloc-util.h"
#include "env-util.h"
#include "../systemd/src/libsystemd/sd-event/event-source.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "list.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "prioq.h"
#include "process-util.h"
#include "set.h"
#include "signal-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "time-util.h"

struct sd_event {
    unsigned n_ref;

    int epoll_fd;
    int watchdog_fd;

    Prioq* pending;
    Prioq* prepare;

    /* timerfd_create() only supports these five clocks so far. We
     * can add support for more clocks when the kernel learns to
     * deal with them, too. */
    struct clock_data realtime;
    struct clock_data boottime;
    struct clock_data monotonic;
    struct clock_data realtime_alarm;
    struct clock_data boottime_alarm;

    usec_t perturb;

    sd_event_source** signal_sources; /* indexed by signal number */
    Hashmap* signal_data; /* indexed by priority */

    Hashmap* child_sources;
    unsigned n_online_child_sources;

    Set* post_sources;

    Prioq* exit;

    Hashmap* inotify_data; /* indexed by priority */

    /* A list of inode structures that still have an fd open, that we need to close before the next loop iteration */
    LIST_HEAD(struct inode_data, inode_data_to_close);

    /* A list of inotify objects that already have events buffered which aren't processed yet */
    LIST_HEAD(struct inotify_data, inotify_data_buffered);

    pid_t original_pid;

    uint64_t iteration;
    triple_timestamp timestamp;
    int state;

    bool exit_requested : 1;
    bool need_process_child : 1;
    bool watchdog : 1;
    bool profile_delays : 1;

    int exit_code;

    pid_t tid;
    sd_event** default_event_ptr;

    usec_t watchdog_last, watchdog_period;

    unsigned n_sources;

    struct epoll_event* event_queue;

    LIST_HEAD(sd_event_source, sources);

    usec_t last_run_usec, last_log_usec;
    unsigned delays[sizeof(usec_t) * 8];
};

static thread_local sd_event* default_event = NULL;

static sd_event* event_resolve(sd_event* e) {
    return e == SD_EVENT_DEFAULT ? default_event : e;
}

_public_ sd_event_source* sd_event_source_disable_unref(sd_event_source* s) {
    //if (s)
    //    (void)sd_event_source_set_enabled(s, SD_EVENT_OFF);
    //return sd_event_source_unref(s);
    return NULL;
}

static bool event_pid_changed(sd_event* e) {
    assert(e);

    /* We don't support people creating an event loop and keeping
     * it around over a fork(). Let's complain. */

    //return e->original_pid != getpid_cached();
    return 0;
}

_public_ int sd_event_exit(sd_event* e, int code) {
    assert_return(e, -EINVAL);
    assert_return(e = event_resolve(e), -ENOPKG);
    assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
    assert_return(!event_pid_changed(e), -ECHILD);

    e->exit_requested = true;
    e->exit_code = code;

    return 0;
}

sd_event* sd_event_unref(sd_event* e) {
    return NULL;
}