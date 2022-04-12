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

#ifdef WIN32
#include <wepoll/wepoll.h>
#endif

#define DEFAULT_ACCURACY_USEC (250 * USEC_PER_MSEC)

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

#define _EVENT_SOURCE_IS_TIME(t)                   \
        ((t) ==      SOURCE_TIME_REALTIME       || \
         (t) ==      SOURCE_TIME_BOOTTIME       || \
         (t) ==      SOURCE_TIME_MONOTONIC      || \
         (t) ==      SOURCE_TIME_REALTIME_ALARM || \
         (t) ==      SOURCE_TIME_BOOTTIME_ALARM)

#define _EVENT_SOURCE_CAN_RATE_LIMIT(t)          \
        ((t) ==      SOURCE_IO ||                       \
         (t) ==      SOURCE_TIME_REALTIME ||            \
         (t) ==      SOURCE_TIME_BOOTTIME ||            \
         (t) ==      SOURCE_TIME_MONOTONIC ||           \
         (t) ==      SOURCE_TIME_REALTIME_ALARM ||      \
         (t) ==      SOURCE_TIME_BOOTTIME_ALARM ||      \
         (t) ==      SOURCE_SIGNAL ||                   \
         (t) ==      SOURCE_DEFER ||                    \
         (t) ==      SOURCE_INOTIFY)

/* This is used to assert that we didn't pass an unexpected source type to event_source_time_prioq_put().
 * Time sources and ratelimited sources can be passed, so effectively this is the same as the
 * EVENT_SOURCE_CAN_RATE_LIMIT() macro. */
#define EVENT_SOURCE_USES_TIME_PRIOQ(t) _EVENT_SOURCE_CAN_RATE_LIMIT(t)

static EventSourceType clock_to_event_source_type(clockid_t clock) {

    switch (clock) {

    case CLOCK_REALTIME:
        return SOURCE_TIME_REALTIME;

    case CLOCK_BOOTTIME:
        return SOURCE_TIME_BOOTTIME;

    case CLOCK_MONOTONIC:
        return SOURCE_TIME_MONOTONIC;

    case CLOCK_REALTIME_ALARM:
        return SOURCE_TIME_REALTIME_ALARM;

    case CLOCK_BOOTTIME_ALARM:
        return SOURCE_TIME_BOOTTIME_ALARM;

    default:
        return _SOURCE_EVENT_SOURCE_TYPE_INVALID;
    }
}

static bool event_source_is_online(sd_event_source* s) {
    assert(s);
    return s->enabled != SD_EVENT_OFF && !s->ratelimited;
}

static bool event_source_is_offline(sd_event_source* s) {
    assert(s);
    return s->enabled == SD_EVENT_OFF || s->ratelimited;
}

static const char* const event_source_type_table[_SOURCE_EVENT_SOURCE_TYPE_MAX] = {
        [SOURCE_IO] = "io",
        [SOURCE_TIME_REALTIME] = "realtime",
        [SOURCE_TIME_BOOTTIME] = "bootime",
        [SOURCE_TIME_MONOTONIC] = "monotonic",
        [SOURCE_TIME_REALTIME_ALARM] = "realtime-alarm",
        [SOURCE_TIME_BOOTTIME_ALARM] = "boottime-alarm",
        [SOURCE_SIGNAL] = "signal",
        [SOURCE_CHILD] = "child",
        [SOURCE_DEFER] = "defer",
        [SOURCE_POST] = "post",
        [SOURCE_EXIT] = "exit",
        [SOURCE_WATCHDOG] = "watchdog",
        [SOURCE_INOTIFY] = "inotify",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(event_source_type, int);

static void source_disconnect(sd_event_source* s);
static void event_gc_inode_data(sd_event* e, struct inode_data* d);

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

static void source_io_unregister(sd_event_source* s) {
    assert(s);
    assert(s->type == SOURCE_IO);

    if (event_pid_changed(s->event))
        return;

    if (!s->io.registered)
        return;

    if (epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, s->io.fd, NULL) < 0)
        log_debug_errno(errno, "Failed to remove source %s (type %s) from epoll, ignoring: %m",
            strna(s->description), event_source_type_to_string(s->type));

    s->io.registered = false;
}

static int source_io_register(
    sd_event_source* s,
    int enabled,
    uint32_t events) {

    assert(s);
    assert(s->type == SOURCE_IO);
    assert(enabled != SD_EVENT_OFF);

    struct epoll_event ev = {
            .events = events | (enabled == SD_EVENT_ONESHOT ? EPOLLONESHOT : 0),
            .data.ptr = s,
    };

    if (epoll_ctl(s->event->epoll_fd,
        s->io.registered ? EPOLL_CTL_MOD : EPOLL_CTL_ADD,
        s->io.fd, &ev) < 0)
        return -errno;

    s->io.registered = true;

    return 0;
}

static int exit_prioq_compare(const void* a, const void* b) {
    const sd_event_source* x = a, * y = b;
    int r;

    assert(x->type == SOURCE_EXIT);
    assert(y->type == SOURCE_EXIT);

    /* Enabled ones first */
    r = CMP(x->enabled == SD_EVENT_OFF, y->enabled == SD_EVENT_OFF);
    if (r != 0)
        return r;

    /* Lower priority values first */
    return CMP(x->priority, y->priority);
}

static void free_clock_data(struct clock_data* d) {
    assert(d);
    assert(d->wakeup == WAKEUP_CLOCK_DATA);

    safe_close(d->fd);
    prioq_free(d->earliest);
    prioq_free(d->latest);
}

static sd_event* event_free(sd_event* e) {
    sd_event_source* s;

    assert(e);

    while ((s = e->sources)) {
        assert(s->floating);
        source_disconnect(s);
        sd_event_source_unref(s);
    }

    assert(e->n_sources == 0);

    if (e->default_event_ptr)
        *(e->default_event_ptr) = NULL;

    safe_close(e->epoll_fd);
    safe_close(e->watchdog_fd);

    free_clock_data(&e->realtime);
    free_clock_data(&e->boottime);
    free_clock_data(&e->monotonic);
    free_clock_data(&e->realtime_alarm);
    free_clock_data(&e->boottime_alarm);

    prioq_free(e->pending);
    prioq_free(e->prepare);
    prioq_free(e->exit);

    free(e->signal_sources);
    hashmap_free(e->signal_data);

    hashmap_free(e->inotify_data);

    hashmap_free(e->child_sources);
    set_free(e->post_sources);

    free(e->event_queue);

    //return mfree(e);
    free(e);
    return NULL;
}


static void source_disconnect(sd_event_source* s) {
    sd_event* event;

    assert(s);

    if (!s->event)
        return;

    assert(s->event->n_sources > 0);

    switch (s->type) {

    case SOURCE_IO:
        if (s->io.fd >= 0)
            source_io_unregister(s);

        break;

    case SOURCE_TIME_REALTIME:
    case SOURCE_TIME_BOOTTIME:
    case SOURCE_TIME_MONOTONIC:
    case SOURCE_TIME_REALTIME_ALARM:
    case SOURCE_TIME_BOOTTIME_ALARM:
        /* Only remove this event source from the time event source here if it is not ratelimited. If
         * it is ratelimited, we'll remove it below, separately. Why? Because the clock used might
         * differ: ratelimiting always uses CLOCK_MONOTONIC, but timer events might use any clock */

        if (!s->ratelimited) {
#if 0
            struct clock_data* d;
            assert_se(d = event_get_clock_data(s->event, s->type));
            event_source_time_prioq_remove(s, d);
#endif
        }

        break;

    case SOURCE_SIGNAL:
#if 0
        if (s->signal.sig > 0) {

            if (s->event->signal_sources)
                s->event->signal_sources[s->signal.sig] = NULL;

            event_gc_signal_data(s->event, &s->priority, s->signal.sig);
        }
#endif
        break;

    case SOURCE_CHILD:
#if 0
        if (s->child.pid > 0) {
            if (event_source_is_online(s)) {
                assert(s->event->n_online_child_sources > 0);
                s->event->n_online_child_sources--;
            }

            (void)hashmap_remove(s->event->child_sources, PID_TO_PTR(s->child.pid));
        }

        if (EVENT_SOURCE_WATCH_PIDFD(s))
            source_child_pidfd_unregister(s);
        else
            event_gc_signal_data(s->event, &s->priority, SIGCHLD);
#endif
        break;

    case SOURCE_DEFER:
        /* nothing */
        break;

    case SOURCE_POST:
        set_remove(s->event->post_sources, s);
        break;

    case SOURCE_EXIT:
        prioq_remove(s->event->exit, s, &s->exit.prioq_index);
        break;
#if 0
    case SOURCE_INOTIFY: {

        struct inode_data* inode_data;

        inode_data = s->inotify.inode_data;
        if (inode_data) {
            struct inotify_data* inotify_data;
            assert_se(inotify_data = inode_data->inotify_data);

            /* Detach this event source from the inode object */
            LIST_REMOVE(inotify.by_inode_data, sd_event_source, inode_data->event_sources, s);
            s->inotify.inode_data = NULL;

            if (s->pending) {
                assert(inotify_data->n_pending > 0);
                inotify_data->n_pending--;
            }

            /* Note that we don't reduce the inotify mask for the watch descriptor here if the inode is
             * continued to being watched. That's because inotify doesn't really have an API for that: we
             * can only change watch masks with access to the original inode either by fd or by path. But
             * paths aren't stable, and keeping an O_PATH fd open all the time would mean wasting an fd
             * continuously and keeping the mount busy which we can't really do. We could reconstruct the
             * original inode from /proc/self/fdinfo/$INOTIFY_FD (as all watch descriptors are listed
             * there), but given the need for open_by_handle_at() which is privileged and not universally
             * available this would be quite an incomplete solution. Hence we go the other way, leave the
             * mask set, even if it is not minimized now, and ignore all events we aren't interested in
             * anymore after reception. Yes, this sucks, but … Linux … */

             /* Maybe release the inode data (and its inotify) */
            event_gc_inode_data(s->event, inode_data);

        }

        break;
    }
#endif

    default:
        assert_not_reached();
    }

    if (s->pending)
        prioq_remove(s->event->pending, s, &s->pending_index);

    if (s->prepare)
        prioq_remove(s->event->prepare, s, &s->prepare_index);
#if 0
    if (s->ratelimited)
        event_source_time_prioq_remove(s, &s->event->monotonic);
#endif
    //event = TAKE_PTR(s->event);
    event = s->event;
    s->event = NULL;

    LIST_REMOVE(sources, sd_event_source, event->sources, s);
    event->n_sources--;

    /* Note that we don't invalidate the type here, since we still need it in order to close the fd or
     * pidfd associated with this event source, which we'll do only on source_free(). */

    if (!s->floating)
        sd_event_unref(event);
}

static sd_event_source* source_free(sd_event_source* s) {
    assert(s);

    source_disconnect(s);

    if (s->type == SOURCE_IO && s->io.owned)
        s->io.fd = safe_close(s->io.fd);

#if 0
    if (s->type == SOURCE_CHILD) {
        /* Eventually the kernel will do this automatically for us, but for now let's emulate this (unreliably) in userspace. */

        if (s->child.process_owned) {

            if (!s->child.exited) {
                bool sent = false;

                if (s->child.pidfd >= 0) {
                    if (pidfd_send_signal(s->child.pidfd, SIGKILL, NULL, 0) < 0) {
                        if (errno == ESRCH) /* Already dead */
                            sent = true;
                        else if (!ERRNO_IS_NOT_SUPPORTED(errno))
                            log_debug_errno(errno, "Failed to kill process " PID_FMT " via pidfd_send_signal(), re-trying via kill(): %m",
                                s->child.pid);
                    }
                    else
                        sent = true;
                }

                if (!sent)
                    if (kill(s->child.pid, SIGKILL) < 0)
                        if (errno != ESRCH) /* Already dead */
                            log_debug_errno(errno, "Failed to kill process " PID_FMT " via kill(), ignoring: %m",
                                s->child.pid);
            }

            if (!s->child.waited) {
                siginfo_t si = { 0 };

                /* Reap the child if we can */
                (void)waitid(P_PID, s->child.pid, &si, WEXITED);
            }
        }

        if (s->child.pidfd_owned)
            s->child.pidfd = safe_close(s->child.pidfd);
    }
#endif
    if (s->destroy_callback)
        s->destroy_callback(s->userdata);

    free(s->description);
    //return mfree(s);
    free(s);
    return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_event_source*, source_free);

static sd_event_source* event_source_free(sd_event_source* s) {
    if (!s)
        return NULL;

    /* Here's a special hack: when we are called from a
     * dispatch handler we won't free the event source
     * immediately, but we will detach the fd from the
     * epoll. This way it is safe for the caller to unref
     * the event source and immediately close the fd, but
     * we still retain a valid event source object after
     * the callback. */

    if (s->dispatching) {
        if (s->type == SOURCE_IO)
            source_io_unregister(s);

        source_disconnect(s);
    }
    else
        source_free(s);

    return NULL;
}

static int pending_prioq_compare(const void* a, const void* b) {
    const sd_event_source* x = a, * y = b;
    int r;

    assert(x->pending);
    assert(y->pending);

    /* Enabled ones first */
    r = CMP(x->enabled == SD_EVENT_OFF, y->enabled == SD_EVENT_OFF);
    if (r != 0)
        return r;

    /* Non rate-limited ones first. */
    r = CMP(!!x->ratelimited, !!y->ratelimited);
    if (r != 0)
        return r;

    /* Lower priority values first */
    r = CMP(x->priority, y->priority);
    if (r != 0)
        return r;

    /* Older entries first */
    return CMP(x->pending_iteration, y->pending_iteration);
}

static int prepare_prioq_compare(const void* a, const void* b) {
    const sd_event_source* x = a, * y = b;
    int r;

    assert(x->prepare);
    assert(y->prepare);

    /* Enabled ones first */
    r = CMP(x->enabled == SD_EVENT_OFF, y->enabled == SD_EVENT_OFF);
    if (r != 0)
        return r;

    /* Non rate-limited ones first. */
    r = CMP(!!x->ratelimited, !!y->ratelimited);
    if (r != 0)
        return r;

    /* Move most recently prepared ones last, so that we can stop
     * preparing as soon as we hit one that has already been
     * prepared in the current iteration */
    r = CMP(x->prepare_iteration, y->prepare_iteration);
    if (r != 0)
        return r;

    /* Lower priority values first */
    return CMP(x->priority, y->priority);
}


_public_ int sd_event_new(sd_event** ret) {
    sd_event* e;
    int r;

    assert_return(ret, -EINVAL);

    e = new(sd_event, 1);
    if (!e)
        return -ENOMEM;

    *e = (sd_event){
            .n_ref = 1,
            .epoll_fd = -1,
            .watchdog_fd = -1,
            .realtime.wakeup = WAKEUP_CLOCK_DATA,
            .realtime.fd = -1,
            .realtime.next = USEC_INFINITY,
            .boottime.wakeup = WAKEUP_CLOCK_DATA,
            .boottime.fd = -1,
            .boottime.next = USEC_INFINITY,
            .monotonic.wakeup = WAKEUP_CLOCK_DATA,
            .monotonic.fd = -1,
            .monotonic.next = USEC_INFINITY,
            .realtime_alarm.wakeup = WAKEUP_CLOCK_DATA,
            .realtime_alarm.fd = -1,
            .realtime_alarm.next = USEC_INFINITY,
            .boottime_alarm.wakeup = WAKEUP_CLOCK_DATA,
            .boottime_alarm.fd = -1,
            .boottime_alarm.next = USEC_INFINITY,
            .perturb = USEC_INFINITY,
            .original_pid = getpid_cached(),
    };

    r = prioq_ensure_allocated(&e->pending, pending_prioq_compare);
    if (r < 0)
        goto fail;

#ifdef WIN32
    e->epoll_fd = epoll_create1(0);
#else
    e->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
#endif
    if (e->epoll_fd < 0) {
        r = -errno;
        goto fail;
    }

    e->epoll_fd = fd_move_above_stdio(e->epoll_fd);

    if (secure_getenv("SD_EVENT_PROFILE_DELAYS")) {
        log_debug("Event loop profiling enabled. Logarithmic histogram of event loop iterations in the range 2^0 … 2^63 us will be logged every 5s.");
        e->profile_delays = true;
    }

    *ret = e;
    return 0;

fail:
    event_free(e);
    return r;
}

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_event_source, sd_event_source, event_source_free);

DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_event, sd_event, event_free);

static struct clock_data* event_get_clock_data(sd_event* e, EventSourceType t) {
    assert(e);

    switch (t) {

    case SOURCE_TIME_REALTIME:
        return &e->realtime;

    case SOURCE_TIME_BOOTTIME:
        return &e->boottime;

    case SOURCE_TIME_MONOTONIC:
        return &e->monotonic;

    case SOURCE_TIME_REALTIME_ALARM:
        return &e->realtime_alarm;

    case SOURCE_TIME_BOOTTIME_ALARM:
        return &e->boottime_alarm;

    default:
        return NULL;
    }
}

static void event_source_time_prioq_reshuffle(sd_event_source* s) {
    struct clock_data* d;

    assert(s);

    /* Called whenever the event source's timer ordering properties changed, i.e. time, accuracy,
     * pending, enable state, and ratelimiting state. Makes sure the two prioq's are ordered
     * properly again. */

    if (s->ratelimited)
        d = &s->event->monotonic;
    else if (_EVENT_SOURCE_IS_TIME(s->type))
        assert_se(d = event_get_clock_data(s->event, s->type));
    else
        return; /* no-op for an event source which is neither a timer nor ratelimited. */

    prioq_reshuffle(d->earliest, s, &s->earliest_index);
    prioq_reshuffle(d->latest, s, &s->latest_index);
    d->needs_rearm = true;
}

static int source_set_pending(sd_event_source* s, bool b) {
    int r;

    assert(s);
    assert(s->type != SOURCE_EXIT);

    if (s->pending == b)
        return 0;

    s->pending = b;

    if (b) {
        s->pending_iteration = s->event->iteration;

        r = prioq_put(s->event->pending, s, &s->pending_index);
        if (r < 0) {
            s->pending = false;
            return r;
        }
    }
    else
        assert_se(prioq_remove(s->event->pending, s, &s->pending_index));

    if (_EVENT_SOURCE_IS_TIME(s->type))
        event_source_time_prioq_reshuffle(s);

    if (s->type == SOURCE_SIGNAL && !b) {
        struct signal_data* d;

        d = hashmap_get(s->event->signal_data, &s->priority);
        if (d && d->current == s)
            d->current = NULL;
    }

    if (s->type == SOURCE_INOTIFY) {

        assert(s->inotify.inode_data);
        assert(s->inotify.inode_data->inotify_data);

        if (b)
            s->inotify.inode_data->inotify_data->n_pending++;
        else {
            assert(s->inotify.inode_data->inotify_data->n_pending > 0);
            s->inotify.inode_data->inotify_data->n_pending--;
        }
    }

    return 1;
}


static sd_event_source* source_new(sd_event* e, bool floating, EventSourceType type) {
    sd_event_source* s;

    assert(e);

    s = new(sd_event_source, 1);
    if (!s)
        return NULL;

    *s = (struct sd_event_source){
            .n_ref = 1,
            .event = e,
            .floating = floating,
            .type = type,
            .pending_index = PRIOQ_IDX_NULL,
            .prepare_index = PRIOQ_IDX_NULL,
    };

    if (!floating)
        sd_event_ref(e);

    LIST_PREPEND(sources, sd_event_source, e->sources, s);
    e->n_sources++;

    return s;
}

static int io_exit_callback(sd_event_source* s, int fd, uint32_t revents, void* userdata) {
    assert(s);

    return sd_event_exit(sd_event_source_get_event(s), PTR_TO_INT(userdata));
}

_public_ int sd_event_add_io(
    sd_event* e,
    sd_event_source** ret,
    int fd,
    uint32_t events,
    sd_event_io_handler_t callback,
    void* userdata) {

    _cleanup_(source_freep) sd_event_source* s = NULL;
    int r;

    assert_return(e, -EINVAL);
    assert_return(e = event_resolve(e), -ENOPKG);
    assert_return(fd >= 0, -EBADF);
    assert_return(!(events & ~(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET)), -EINVAL);
    assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
    assert_return(!event_pid_changed(e), -ECHILD);

    if (!callback)
        callback = io_exit_callback;

    s = source_new(e, !ret, SOURCE_IO);
    if (!s)
        return -ENOMEM;

    s->wakeup = WAKEUP_EVENT_SOURCE;
    s->io.fd = fd;
    s->io.events = events;
    s->io.callback = callback;
    s->userdata = userdata;
    s->enabled = SD_EVENT_ON;

    r = source_io_register(s, s->enabled, events);
    if (r < 0)
        return r;

    if (ret)
        *ret = s;
    //TAKE_PTR(s);
    s = NULL;

    return 0;
}

_public_ sd_event* sd_event_source_get_event(sd_event_source* s) {
    assert_return(s, NULL);

    return s->event;
}

_public_ int sd_event_source_set_description(sd_event_source* s, const char* description) {
    assert_return(s, -EINVAL);
    assert_return(!event_pid_changed(s->event), -ECHILD);

    return free_and_strdup(&s->description, description);
}

_public_ int sd_event_source_set_io_fd(sd_event_source* s, int fd) {
    int r;

    assert_return(s, -EINVAL);
    assert_return(fd >= 0, -EBADF);
    assert_return(s->type == SOURCE_IO, -EDOM);
    assert_return(!event_pid_changed(s->event), -ECHILD);

    if (s->io.fd == fd)
        return 0;

    if (event_source_is_offline(s)) {
        s->io.fd = fd;
        s->io.registered = false;
    }
    else {
        int saved_fd;

        saved_fd = s->io.fd;
        assert(s->io.registered);

        s->io.fd = fd;
        s->io.registered = false;

        r = source_io_register(s, s->enabled, s->io.events);
        if (r < 0) {
            s->io.fd = saved_fd;
            s->io.registered = true;
            return r;
        }

        (void)epoll_ctl(s->event->epoll_fd, EPOLL_CTL_DEL, saved_fd, NULL);
    }

    return 0;
}



_public_ int sd_event_source_set_prepare(sd_event_source* s, sd_event_handler_t callback) {
    int r;

    assert_return(s, -EINVAL);
    assert_return(s->type != SOURCE_EXIT, -EDOM);
    assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
    assert_return(!event_pid_changed(s->event), -ECHILD);

    if (s->prepare == callback)
        return 0;

    if (callback && s->prepare) {
        s->prepare = callback;
        return 0;
    }

    r = prioq_ensure_allocated(&s->event->prepare, prepare_prioq_compare);
    if (r < 0)
        return r;

    s->prepare = callback;

    if (callback) {
        r = prioq_put(s->event->prepare, s, &s->prepare_index);
        if (r < 0)
            return r;
    }
    else
        prioq_remove(s->event->prepare, s, &s->prepare_index);

    return 0;
}

static void event_source_pp_prioq_reshuffle(sd_event_source* s) {
    assert(s);

    /* Reshuffles the pending + prepare prioqs. Called whenever the dispatch order changes, i.e. when
     * they are enabled/disabled or marked pending and such. */

    if (s->pending)
        prioq_reshuffle(s->event->pending, s, &s->pending_index);

    if (s->prepare)
        prioq_reshuffle(s->event->prepare, s, &s->prepare_index);
}

_public_ int sd_event_source_set_priority(sd_event_source* s, int64_t priority) {
    bool rm_inotify = false, rm_inode = false;
    struct inotify_data* new_inotify_data = NULL;
    struct inode_data* new_inode_data = NULL;
    int r;

    assert_return(s, -EINVAL);
    assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
    assert_return(!event_pid_changed(s->event), -ECHILD);

    if (s->priority == priority)
        return 0;

    if (s->type == SOURCE_INOTIFY) {
#if 0
        struct inode_data* old_inode_data;

        assert(s->inotify.inode_data);
        old_inode_data = s->inotify.inode_data;

        /* We need the original fd to change the priority. If we don't have it we can't change the priority,
         * anymore. Note that we close any fds when entering the next event loop iteration, i.e. for inotify
         * events we allow priority changes only until the first following iteration. */
        if (old_inode_data->fd < 0)
            return -EOPNOTSUPP;

        r = event_make_inotify_data(s->event, priority, &new_inotify_data);
        if (r < 0)
            return r;
        rm_inotify = r > 0;

        r = event_make_inode_data(s->event, new_inotify_data, old_inode_data->dev, old_inode_data->ino, &new_inode_data);
        if (r < 0)
            goto fail;
        rm_inode = r > 0;

        if (new_inode_data->fd < 0) {
            /* Duplicate the fd for the new inode object if we don't have any yet */
            new_inode_data->fd = fcntl(old_inode_data->fd, F_DUPFD_CLOEXEC, 3);
            if (new_inode_data->fd < 0) {
                r = -errno;
                goto fail;
            }

            LIST_PREPEND(to_close, struct inode_data, s->event->inode_data_to_close, new_inode_data);
        }

        /* Move the event source to the new inode data structure */
        LIST_REMOVE(inotify.by_inode_data, sd_event_source, old_inode_data->event_sources, s);
        LIST_PREPEND(inotify.by_inode_data, sd_event_source, new_inode_data->event_sources, s);
        s->inotify.inode_data = new_inode_data;

        /* Now create the new watch */
        r = inode_data_realize_watch(s->event, new_inode_data);
        if (r < 0) {
            /* Move it back */
            LIST_REMOVE(inotify.by_inode_data, sd_event_source, new_inode_data->event_sources, s);
            LIST_PREPEND(inotify.by_inode_data, sd_event_source, old_inode_data->event_sources, s);
            s->inotify.inode_data = old_inode_data;
            goto fail;
        }

        s->priority = priority;

        event_gc_inode_data(s->event, old_inode_data);
#endif
    }
    else if (s->type == SOURCE_SIGNAL && event_source_is_online(s)) {
#if 0
        struct signal_data* old, * d;

        /* Move us from the signalfd belonging to the old
         * priority to the signalfd of the new priority */

        assert_se(old = hashmap_get(s->event->signal_data, &s->priority));

        s->priority = priority;

        r = event_make_signal_data(s->event, s->signal.sig, &d);
        if (r < 0) {
            s->priority = old->priority;
            return r;
        }

        event_unmask_signal_data(s->event, old, s->signal.sig);
#endif
    }
    else
        s->priority = priority;

    event_source_pp_prioq_reshuffle(s);

    if (s->type == SOURCE_EXIT)
        prioq_reshuffle(s->event->exit, s, &s->exit.prioq_index);

    return 0;

fail:
#if 0
    if (rm_inode)
        event_free_inode_data(s->event, new_inode_data);

    if (rm_inotify)
        event_free_inotify_data(s->event, new_inotify_data);
#endif
    return r;
}

static int event_source_offline(
    sd_event_source* s,
    int enabled,
    bool ratelimited) {

    bool was_offline;
    int r;

    assert(s);
    assert(enabled == SD_EVENT_OFF || ratelimited);

    /* Unset the pending flag when this event source is disabled */
    if (s->enabled != SD_EVENT_OFF &&
        enabled == SD_EVENT_OFF &&
        //!IN_SET(s->type, SOURCE_DEFER, SOURCE_EXIT)
        !(s->type == SOURCE_DEFER || s->type == SOURCE_EXIT)
        ) {
        r = source_set_pending(s, false);
        if (r < 0)
            return r;
    }

    was_offline = event_source_is_offline(s);
    s->enabled = enabled;
    s->ratelimited = ratelimited;

    switch (s->type) {

    case SOURCE_IO:
        source_io_unregister(s);
        break;

    case SOURCE_SIGNAL:
#if 0
        event_gc_signal_data(s->event, &s->priority, s->signal.sig);
#endif
        break;

    case SOURCE_CHILD:
#if 0
        if (!was_offline) {
            assert(s->event->n_online_child_sources > 0);
            s->event->n_online_child_sources--;
        }

        if (EVENT_SOURCE_WATCH_PIDFD(s))
            source_child_pidfd_unregister(s);
        else
            event_gc_signal_data(s->event, &s->priority, SIGCHLD);
#endif
        break;

    case SOURCE_EXIT:
        prioq_reshuffle(s->event->exit, s, &s->exit.prioq_index);
        break;

    case SOURCE_TIME_REALTIME:
    case SOURCE_TIME_BOOTTIME:
    case SOURCE_TIME_MONOTONIC:
    case SOURCE_TIME_REALTIME_ALARM:
    case SOURCE_TIME_BOOTTIME_ALARM:
    case SOURCE_DEFER:
    case SOURCE_POST:
    case SOURCE_INOTIFY:
        break;

    default:
        assert_not_reached();
    }

    /* Always reshuffle time prioq, as the ratelimited flag may be changed. */
    event_source_time_prioq_reshuffle(s);

    return 1;
}

static int event_source_online(
    sd_event_source* s,
    int enabled,
    bool ratelimited) {

    bool was_online;
    int r;

    assert(s);
    assert(enabled != SD_EVENT_OFF || !ratelimited);

    /* Unset the pending flag when this event source is enabled */
    if (s->enabled == SD_EVENT_OFF &&
        enabled != SD_EVENT_OFF &&
        //!IN_SET(s->type, SOURCE_DEFER, SOURCE_EXIT)
        !(s->type == SOURCE_DEFER || s->type == SOURCE_EXIT)
        ) {
        r = source_set_pending(s, false);
        if (r < 0)
            return r;
    }

    /* Are we really ready for onlining? */
    if (enabled == SD_EVENT_OFF || ratelimited) {
        /* Nope, we are not ready for onlining, then just update the precise state and exit */
        s->enabled = enabled;
        s->ratelimited = ratelimited;
        return 0;
    }

    was_online = event_source_is_online(s);

    switch (s->type) {
    case SOURCE_IO:
        r = source_io_register(s, enabled, s->io.events);
        if (r < 0)
            return r;
        break;

    case SOURCE_SIGNAL:
#if 0
        r = event_make_signal_data(s->event, s->signal.sig, NULL);
        if (r < 0) {
            event_gc_signal_data(s->event, &s->priority, s->signal.sig);
            return r;
        }
#endif
        break;

    case SOURCE_CHILD:
#if 0
        if (EVENT_SOURCE_WATCH_PIDFD(s)) {
            /* yes, we have pidfd */

            r = source_child_pidfd_register(s, enabled);
            if (r < 0)
                return r;
        }
        else {
            /* no pidfd, or something other to watch for than WEXITED */

            r = event_make_signal_data(s->event, SIGCHLD, NULL);
            if (r < 0) {
                event_gc_signal_data(s->event, &s->priority, SIGCHLD);
                return r;
            }
        }

        if (!was_online)
            s->event->n_online_child_sources++;
#endif
        break;

    case SOURCE_TIME_REALTIME:
    case SOURCE_TIME_BOOTTIME:
    case SOURCE_TIME_MONOTONIC:
    case SOURCE_TIME_REALTIME_ALARM:
    case SOURCE_TIME_BOOTTIME_ALARM:
    case SOURCE_EXIT:
    case SOURCE_DEFER:
    case SOURCE_POST:
    case SOURCE_INOTIFY:
        break;

    default:
        assert_not_reached();
    }

    s->enabled = enabled;
    s->ratelimited = ratelimited;

    /* Non-failing operations below */
    if (s->type == SOURCE_EXIT)
        prioq_reshuffle(s->event->exit, s, &s->exit.prioq_index);

    /* Always reshuffle time prioq, as the ratelimited flag may be changed. */
    event_source_time_prioq_reshuffle(s);

    return 1;
}

_public_ int sd_event_source_set_enabled(sd_event_source* s, int m) {
    int r;

    assert_return(s, -EINVAL);
    //assert_return(IN_SET(m, SD_EVENT_OFF, SD_EVENT_ON, SD_EVENT_ONESHOT), -EINVAL);
    assert_return((m == SD_EVENT_OFF || m == SD_EVENT_ON || m == SD_EVENT_ONESHOT), -EINVAL);
    assert_return(!event_pid_changed(s->event), -ECHILD);

    /* If we are dead anyway, we are fine with turning off sources, but everything else needs to fail. */
    if (s->event->state == SD_EVENT_FINISHED)
        return m == SD_EVENT_OFF ? 0 : -ESTALE;

    if (s->enabled == m) /* No change? */
        return 0;

    if (m == SD_EVENT_OFF)
        r = event_source_offline(s, m, s->ratelimited);
    else {
        if (s->enabled != SD_EVENT_OFF) {
            /* Switching from "on" to "oneshot" or back? If that's the case, we can take a shortcut, the
             * event source is already enabled after all. */
            s->enabled = m;
            return 0;
        }

        r = event_source_online(s, m, s->ratelimited);
    }
    if (r < 0)
        return r;

    event_source_pp_prioq_reshuffle(s);
    return 0;
}

_public_ int sd_event_source_set_io_events(sd_event_source* s, uint32_t events) {
    int r;

    assert_return(s, -EINVAL);
    assert_return(s->type == SOURCE_IO, -EDOM);
    assert_return(!(events & ~(EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET)), -EINVAL);
    assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
    assert_return(!event_pid_changed(s->event), -ECHILD);

    /* edge-triggered updates are never skipped, so we can reset edges */
    if (s->io.events == events && !(events & EPOLLET))
        return 0;

    r = source_set_pending(s, false);
    if (r < 0)
        return r;

    if (event_source_is_online(s)) {
        r = source_io_register(s, s->enabled, events);
        if (r < 0)
            return r;
    }

    s->io.events = events;

    return 0;
}

_public_ int sd_event_source_set_time(sd_event_source* s, uint64_t usec) {
    int r;

    assert_return(s, -EINVAL);
    assert_return(_EVENT_SOURCE_IS_TIME(s->type), -EDOM);
    assert_return(s->event->state != SD_EVENT_FINISHED, -ESTALE);
    assert_return(!event_pid_changed(s->event), -ECHILD);

    r = source_set_pending(s, false);
    if (r < 0)
        return r;

    s->time.next = usec;

    event_source_time_prioq_reshuffle(s);
    return 0;
}

_public_ int sd_event_default(sd_event** ret) {
    sd_event* e = NULL;
    int r;

    if (!ret)
        return !!default_event;

    if (default_event) {
        *ret = sd_event_ref(default_event);
        return 0;
    }

    r = sd_event_new(&e);
    if (r < 0)
        return r;

    e->default_event_ptr = &default_event;
    e->tid = gettid();
    default_event = e;

    *ret = e;
    return 1;
}

static usec_t time_event_source_next(const sd_event_source* s) {
    assert(s);

    /* We have two kinds of event sources that have elapsation times associated with them: the actual
     * time based ones and the ones for which a ratelimit can be in effect (where we want to be notified
     * once the ratelimit time window ends). Let's return the next elapsing time depending on what we are
     * looking at here. */

    if (s->ratelimited) { /* If rate-limited the next elapsation is when the ratelimit time window ends */
        assert(s->rate_limit.begin != 0);
        assert(s->rate_limit.interval != 0);
        return usec_add(s->rate_limit.begin, s->rate_limit.interval);
    }

    /* Otherwise this must be a time event source, if not ratelimited */
    if (_EVENT_SOURCE_IS_TIME(s->type))
        return s->time.next;

    return USEC_INFINITY;
}

static usec_t time_event_source_latest(const sd_event_source* s) {
    assert(s);

    if (s->ratelimited) { /* For ratelimited stuff the earliest and the latest time shall actually be the
                           * same, as we should avoid adding additional inaccuracy on an inaccuracy time
                           * window */
        assert(s->rate_limit.begin != 0);
        assert(s->rate_limit.interval != 0);
        return usec_add(s->rate_limit.begin, s->rate_limit.interval);
    }

    /* Must be a time event source, if not ratelimited */
    if (_EVENT_SOURCE_IS_TIME(s->type))
        return usec_add(s->time.next, s->time.accuracy);

    return USEC_INFINITY;
}

static bool event_source_timer_candidate(const sd_event_source* s) {
    assert(s);

    /* Returns true for event sources that either are not pending yet (i.e. where it's worth to mark them pending)
     * or which are currently ratelimited (i.e. where it's worth leaving the ratelimited state) */
    return !s->pending || s->ratelimited;
}

static int time_prioq_compare(const void* a, const void* b, usec_t(*time_func)(const sd_event_source* s)) {
    const sd_event_source* x = a, * y = b;
    int r;

    /* Enabled ones first */
    r = CMP(x->enabled == SD_EVENT_OFF, y->enabled == SD_EVENT_OFF);
    if (r != 0)
        return r;

    /* Order "non-pending OR ratelimited" before "pending AND not-ratelimited" */
    r = CMP(!event_source_timer_candidate(x), !event_source_timer_candidate(y));
    if (r != 0)
        return r;

    /* Order by time */
    return CMP(time_func(x), time_func(y));
}

static int earliest_time_prioq_compare(const void* a, const void* b) {
    return time_prioq_compare(a, b, time_event_source_next);
}

static int latest_time_prioq_compare(const void* a, const void* b) {
    return time_prioq_compare(a, b, time_event_source_latest);
}

static int event_setup_timer_fd(
    sd_event* e,
    struct clock_data* d,
    clockid_t clock) {

    assert(e);
    assert(d);

    if (_likely_(d->fd >= 0))
        return 0;

    _cleanup_close_ int fd = -1;
#if defined(__linux__)
    fd = timerfd_create(clock, TFD_NONBLOCK | TFD_CLOEXEC);
#endif
    if (fd < 0)
        return -errno;

    fd = fd_move_above_stdio(fd);

    struct epoll_event ev = {
            .events = EPOLLIN,
            .data.ptr = d,
    };

    if (epoll_ctl(e->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0)
        return -errno;

    //d->fd = TAKE_FD(fd);
    d->fd = fd;
    fd = -1;

    return 0;
}

static int time_exit_callback(sd_event_source* s, uint64_t usec, void* userdata) {
    assert(s);

    return sd_event_exit(sd_event_source_get_event(s), PTR_TO_INT(userdata));
}

static int setup_clock_data(sd_event* e, struct clock_data* d, clockid_t clock) {
    int r;

    assert(d);

    if (d->fd < 0) {
        r = event_setup_timer_fd(e, d, clock);
        if (r < 0)
            return r;
    }

    r = prioq_ensure_allocated(&d->earliest, earliest_time_prioq_compare);
    if (r < 0)
        return r;

    r = prioq_ensure_allocated(&d->latest, latest_time_prioq_compare);
    if (r < 0)
        return r;

    return 0;
}

static int event_source_time_prioq_put(
    sd_event_source* s,
    struct clock_data* d) {

    int r;

    assert(s);
    assert(d);
    assert(EVENT_SOURCE_USES_TIME_PRIOQ(s->type));

    r = prioq_put(d->earliest, s, &s->earliest_index);
    if (r < 0)
        return r;

    r = prioq_put(d->latest, s, &s->latest_index);
    if (r < 0) {
        assert_se(prioq_remove(d->earliest, s, &s->earliest_index) > 0);
        s->earliest_index = PRIOQ_IDX_NULL;
        return r;
    }

    d->needs_rearm = true;
    return 0;
}

_public_ int sd_event_add_time(
    sd_event* e,
    sd_event_source** ret,
    clockid_t clock,
    uint64_t usec,
    uint64_t accuracy,
    sd_event_time_handler_t callback,
    void* userdata) {

    EventSourceType type;
    _cleanup_(source_freep) sd_event_source* s = NULL;
    struct clock_data* d;
    int r;

    assert_return(e, -EINVAL);
    assert_return(e = event_resolve(e), -ENOPKG);
    assert_return(accuracy != UINT64_MAX, -EINVAL);
    assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
    assert_return(!event_pid_changed(e), -ECHILD);

    if (!clock_supported(clock)) /* Checks whether the kernel supports the clock */
        return -EOPNOTSUPP;

    type = clock_to_event_source_type(clock); /* checks whether sd-event supports this clock */
    if (type < 0)
        return -EOPNOTSUPP;

    if (!callback)
        callback = time_exit_callback;

    assert_se(d = event_get_clock_data(e, type));

    r = setup_clock_data(e, d, clock);
    if (r < 0)
        return r;

    s = source_new(e, !ret, type);
    if (!s)
        return -ENOMEM;

    s->time.next = usec;
    s->time.accuracy = accuracy == 0 ? DEFAULT_ACCURACY_USEC : accuracy;
    s->time.callback = callback;
    s->earliest_index = s->latest_index = PRIOQ_IDX_NULL;
    s->userdata = userdata;
    s->enabled = SD_EVENT_ONESHOT;

    r = event_source_time_prioq_put(s, d);
    if (r < 0)
        return r;

    if (ret)
        *ret = s;
    //TAKE_PTR(s);
    s = NULL;

    return 0;
}

_public_ int sd_event_add_exit(
    sd_event* e,
    sd_event_source** ret,
    sd_event_handler_t callback,
    void* userdata) {

    _cleanup_(source_freep) sd_event_source* s = NULL;
    int r;

    assert_return(e, -EINVAL);
    assert_return(e = event_resolve(e), -ENOPKG);
    assert_return(callback, -EINVAL);
    assert_return(e->state != SD_EVENT_FINISHED, -ESTALE);
    assert_return(!event_pid_changed(e), -ECHILD);

    r = prioq_ensure_allocated(&e->exit, exit_prioq_compare);
    if (r < 0)
        return r;

    s = source_new(e, !ret, SOURCE_EXIT);
    if (!s)
        return -ENOMEM;

    s->exit.callback = callback;
    s->userdata = userdata;
    s->exit.prioq_index = PRIOQ_IDX_NULL;
    s->enabled = SD_EVENT_ONESHOT;

    r = prioq_put(s->event->exit, s, &s->exit.prioq_index);
    if (r < 0)
        return r;

    if (ret)
        *ret = s;
    //TAKE_PTR(s);
    s = NULL;

    return 0;
}

