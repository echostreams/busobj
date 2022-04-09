/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <endian.h>
#include <netdb.h>
#if defined(__linux__)
#include <pthread.h>
#endif
#include <signal.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include "sd-bus.h"

#include "af-list.h"
#include "alloc-util.h"
#include "bus-container.h"
#include "bus-control.h"
#include "bus-internal.h"
#include "bus-kernel.h"
#include "bus-label.h"
#include "bus-message.h"
#include "bus-objects.h"
#include "bus-protocol.h"
#include "bus-slot.h"
#include "bus-socket.h"
#include "bus-track.h"
#include "bus-type.h"
#if defined(__linux__)
#include "cgroup-util.h"
#endif
#include "def.h"
#include "errno-util.h"
#include "fd-util.h"
#include "hexdecoct.h"
#include "hostname-util.h"
#include "io-util.h"
#include "macro.h"
#include "memory-util.h"
#include "missing_syscall.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "user-util.h"

#ifdef WIN32
#define	EUNATCH		49	/* Protocol driver not attached */
#define	ENOMEDIUM	123	/* No medium found */
#define EAI_SYSTEM  11  /* system error returned in errno */
char* secure_getenv(char*);
#endif

#define log_debug_bus_message(m)                                         \
        do {                                                             \
                sd_bus_message *_mm = (m);                               \
                log_debug("Got message type=%s sender=%s destination=%s path=%s interface=%s member=%s cookie=%" PRIu64 " reply_cookie=%" PRIu64 " signature=%s error-name=%s error-message=%s", \
                          bus_message_type_to_string(_mm->header->type), \
                          strna(sd_bus_message_get_sender(_mm)),         \
                          strna(sd_bus_message_get_destination(_mm)),    \
                          strna(sd_bus_message_get_path(_mm)),           \
                          strna(sd_bus_message_get_interface(_mm)),      \
                          strna(sd_bus_message_get_member(_mm)),         \
                          BUS_MESSAGE_COOKIE(_mm),                       \
                          _mm->reply_cookie,                             \
                          strna(_mm->root_container.signature),          \
                          strna(_mm->error.name),                        \
                          strna(_mm->error.message));                    \
        } while (false)

// forward defined


static void bus_detach_io_events(sd_bus* bus) {
    assert(bus);

    bus->input_io_event_source = sd_event_source_disable_unref(bus->input_io_event_source);
    bus->output_io_event_source = sd_event_source_disable_unref(bus->output_io_event_source);
}

int bus_seal_synthetic_message(sd_bus* b, sd_bus_message* m) {
    assert(b);
    assert(m);

    /* Fake some timestamps, if they were requested, and not
     * already initialized */
    if (b->attach_timestamp) {
        if (m->realtime <= 0)
            m->realtime = now(CLOCK_REALTIME);

        if (m->monotonic <= 0)
            m->monotonic = now(CLOCK_MONOTONIC);
    }

    /* The bus specification says the serial number cannot be 0,
     * hence let's fill something in for synthetic messages. Since
     * synthetic messages might have a fake sender and we don't
     * want to interfere with the real sender's serial numbers we
     * pick a fixed, artificial one. We use UINT32_MAX rather
     * than UINT64_MAX since dbus1 only had 32bit identifiers,
     * even though kdbus can do 64bit. */
    return sd_bus_message_seal(m, 0xFFFFFFFFULL, 0);
}

void bus_close_io_fds(sd_bus* b) {
    assert(b);

    bus_detach_io_events(b);

    if (b->input_fd != b->output_fd)
        safe_close(b->output_fd);
    b->output_fd = b->input_fd = safe_close(b->input_fd);
}

void bus_close_inotify_fd(sd_bus* b) {
    assert(b);

    b->inotify_event_source = sd_event_source_disable_unref(b->inotify_event_source);

    b->inotify_fd = safe_close(b->inotify_fd);
    //b->inotify_watches = mfree(b->inotify_watches);
    free(b->inotify_watches);
    b->inotify_watches = NULL;
    b->n_inotify_watches = 0;
}


static int parse_address_key(const char** p, const char* key, char** value) {
    _cleanup_free_ char* r = NULL;
    size_t l, n = 0;
    const char* a;

    assert(p);
    assert(*p);
    assert(value);

    if (key) {
        l = strlen(key);
        if (strncmp(*p, key, l) != 0)
            return 0;

        if ((*p)[l] != '=')
            return 0;

        if (*value)
            return -EINVAL;

        a = *p + l + 1;
    }
    else
        a = *p;

    //while (!IN_SET(*a, ';', ',', 0)) 
    while (!(*a == ';' || *a == ',' || *a == 0))
    {
        char c;

        if (*a == '%') {
            int x, y;

            x = unhexchar(a[1]);
            if (x < 0)
                return x;

            y = unhexchar(a[2]);
            if (y < 0)
                return y;

            c = (char)((x << 4) | y);
            a += 3;
        }
        else {
            c = *a;
            a++;
        }

        if (!GREEDY_REALLOC(r, n + 2))
            return -ENOMEM;

        r[n++] = c;
    }

    if (!r) {
        r = strdup("");
        if (!r)
            return -ENOMEM;
    }
    else
        r[n] = 0;

    if (*a == ',')
        a++;

    *p = a;

    //free_and_replace(*value, r);
    free(*value);
    *value = r;
    r = NULL;

    return 1;
}

static void skip_address_key(const char** p) {
    assert(p);
    assert(*p);

    *p += strcspn(*p, ",");

    if (**p == ',')
        (*p)++;
}

static int parse_unix_address(sd_bus* b, const char** p, char** guid) {
    _cleanup_free_ char* path = NULL, * abstract = NULL;
    size_t l;
    int r;

    assert(b);
    assert(p);
    assert(*p);
    assert(guid);

    //while (!IN_SET(**p, 0, ';')) 
    while (!(**p == 0 || **p == ';'))
    {
        r = parse_address_key(p, "guid", guid);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        r = parse_address_key(p, "path", &path);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        r = parse_address_key(p, "abstract", &abstract);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        skip_address_key(p);
    }

    if (!path && !abstract)
        return -EINVAL;

    if (path && abstract)
        return -EINVAL;

    if (path) {
        l = strlen(path);
        if (l >= sizeof(b->sockaddr.un.sun_path)) /* We insist on NUL termination */
            return -E2BIG;

        b->sockaddr.un = (struct sockaddr_un){
                .sun_family = AF_UNIX,
        };

        memcpy(b->sockaddr.un.sun_path, path, l);
        b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + l + 1;

    }
    else {
        assert(abstract);

        l = strlen(abstract);
        if (l >= sizeof(b->sockaddr.un.sun_path) - 1) /* We insist on NUL termination */
            return -E2BIG;

        b->sockaddr.un = (struct sockaddr_un){
                .sun_family = AF_UNIX,
        };

        memcpy(b->sockaddr.un.sun_path + 1, abstract, l);
        b->sockaddr_size = offsetof(struct sockaddr_un, sun_path) + 1 + l;
    }

    b->is_local = true;

    return 0;
}

static int parse_tcp_address(sd_bus* b, const char** p, char** guid) {
    _cleanup_free_ char* host = NULL, * port = NULL, * family = NULL;
    int r;
    struct addrinfo* result, hints = {
            .ai_socktype = SOCK_STREAM,
    };

    assert(b);
    assert(p);
    assert(*p);
    assert(guid);

    //while (!IN_SET(**p, 0, ';')) {
    while (!(**p == 0 || **p == ';')) {
        r = parse_address_key(p, "guid", guid);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        r = parse_address_key(p, "host", &host);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        r = parse_address_key(p, "port", &port);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        r = parse_address_key(p, "family", &family);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        skip_address_key(p);
    }

    if (!host || !port)
        return -EINVAL;

    if (family) {
        //hints.ai_family = af_from_ipv4_ipv6(family);
        hints.ai_family = streq_ptr(family, "ipv4") ? AF_INET :
                          streq_ptr(family, "ipv6") ? AF_INET6 : AF_UNSPEC;
        if (hints.ai_family == AF_UNSPEC)
            return -EINVAL;
    }

    r = getaddrinfo(host, port, &hints, &result);
    if (r == EAI_SYSTEM)
        return -errno;
    else if (r != 0)
        return -EADDRNOTAVAIL;

    memcpy(&b->sockaddr, result->ai_addr, result->ai_addrlen);
    b->sockaddr_size = result->ai_addrlen;

    freeaddrinfo(result);

    b->is_local = false;

    return 0;
}

static int parse_exec_address(sd_bus* b, const char** p, char** guid) {
    char* path = NULL;
    unsigned n_argv = 0, j;
    char** argv = NULL;
    int r;

    assert(b);
    assert(p);
    assert(*p);
    assert(guid);

    //while (!IN_SET(**p, 0, ';')) 
    while (!(**p == 0 || **p == ';'))
    {
        r = parse_address_key(p, "guid", guid);
        if (r < 0)
            goto fail;
        else if (r > 0)
            continue;

        r = parse_address_key(p, "path", &path);
        if (r < 0)
            goto fail;
        else if (r > 0)
            continue;

        if (startswith(*p, "argv")) {
            unsigned ul;

            errno = 0;
            ul = strtoul(*p + 4, (char**)p, 10);
            if (errno > 0 || **p != '=' || ul > 256) {
                r = -EINVAL;
                goto fail;
            }

            (*p)++;

            if (ul >= n_argv) {
                if (!GREEDY_REALLOC0(argv, ul + 2)) {
                    r = -ENOMEM;
                    goto fail;
                }

                n_argv = ul + 1;
            }

            r = parse_address_key(p, NULL, argv + ul);
            if (r < 0)
                goto fail;

            continue;
        }

        skip_address_key(p);
    }

    if (!path) {
        r = -EINVAL;
        goto fail;
    }

    /* Make sure there are no holes in the array, with the
     * exception of argv[0] */
    for (j = 1; j < n_argv; j++)
        if (!argv[j]) {
            r = -EINVAL;
            goto fail;
        }

    if (argv && argv[0] == NULL) {
        argv[0] = strdup(path);
        if (!argv[0]) {
            r = -ENOMEM;
            goto fail;
        }
    }

    b->exec_path = path;
    b->exec_argv = argv;

    b->is_local = false;

    return 0;

fail:
    for (j = 0; j < n_argv; j++)
        free(argv[j]);

    free(argv);
    free(path);
    return r;
}

static int parse_container_unix_address(sd_bus* b, const char** p, char** guid) {
    _cleanup_free_ char* machine = NULL, * pid = NULL;
    int r;

    assert(b);
    assert(p);
    assert(*p);
    assert(guid);

    //while (!IN_SET(**p, 0, ';')) {
    while (!(**p == 0 || **p == ';')) {
        r = parse_address_key(p, "guid", guid);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        r = parse_address_key(p, "machine", &machine);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        r = parse_address_key(p, "pid", &pid);
        if (r < 0)
            return r;
        else if (r > 0)
            continue;

        skip_address_key(p);
    }

    if (!machine == !pid)
        return -EINVAL;

    if (machine) {

#ifdef ENABLE_HOSTNAME_CHECK
        if (!hostname_is_valid(machine, VALID_HOSTNAME_DOT_HOST))
            return -EINVAL;
#endif

        //free_and_replace(b->machine, machine);
        free(b->machine);
        b->machine = machine;
        machine = NULL;
    }
    else {
        //b->machine = mfree(b->machine);
        free(b->machine);
        b->machine = NULL;
    }
    if (pid) {
        r = parse_pid(pid, &b->nspid);
        if (r < 0)
            return r;
    }
    else
        b->nspid = 0;

    b->sockaddr.un = (struct sockaddr_un){
            .sun_family = AF_UNIX,
            /* Note that we use the old /var/run prefix here, to increase compatibility with really old containers */
            .sun_path = "/var/run/dbus/system_bus_socket",
    };
    b->sockaddr_size = __SOCKADDR_UN_LEN(b->sockaddr.un);
    b->is_local = false;

    return 0;
}

static void bus_reset_parsed_address(sd_bus* b) {
    assert(b);

    zero(b->sockaddr);
    b->sockaddr_size = 0;
    b->exec_argv = strv_free(b->exec_argv);
    //b->exec_path = mfree(b->exec_path);
    free(b->exec_path);
    b->exec_path = NULL;
    b->server_id = SD_ID128_NULL;
    //b->machine = mfree(b->machine);
    free(b->machine);
    b->machine = NULL;
    b->nspid = 0;
}

static int bus_parse_next_address(sd_bus* b) {
    _cleanup_free_ char* guid = NULL;
    const char* a;
    int r;

    assert(b);

    if (!b->address)
        return 0;
    if (b->address[b->address_index] == 0)
        return 0;

    bus_reset_parsed_address(b);

    a = b->address + b->address_index;

    while (*a != 0) {

        if (*a == ';') {
            a++;
            continue;
        }

        if (startswith(a, "unix:")) {
            a += 5;

            r = parse_unix_address(b, &a, &guid);
            if (r < 0)
                return r;
            break;

        }
        else if (startswith(a, "tcp:")) {

            a += 4;
            r = parse_tcp_address(b, &a, &guid);
            if (r < 0)
                return r;

            break;

        }
        else if (startswith(a, "unixexec:")) {

            a += 9;
            r = parse_exec_address(b, &a, &guid);
            if (r < 0)
                return r;

            break;

        }
        else if (startswith(a, "x-machine-unix:")) {

            a += 15;
            r = parse_container_unix_address(b, &a, &guid);
            if (r < 0)
                return r;

            break;
        }

        a = strchr(a, ';');
        if (!a)
            return 0;
    }

    if (guid) {
        r = sd_id128_from_string(guid, &b->server_id);
        if (r < 0)
            return r;
    }

    b->address_index = a - b->address;
    return 1;
}

static void bus_kill_exec(sd_bus* bus) {
    if (!pid_is_valid(bus->busexec_pid))
        return;

#if defined(__linux__)
    //sigterm_wait(__TAKE_PID(bus->busexec_pid));
#endif

}

static void bus_reset_queues(sd_bus* b) {
    assert(b);

    while (b->rqueue_size > 0)
        bus_message_unref_queued(b->rqueue[--b->rqueue_size], b);

    //b->rqueue = mfree(b->rqueue);
    free(b->rqueue);
    b->rqueue = NULL;

    while (b->wqueue_size > 0)
        bus_message_unref_queued(b->wqueue[--b->wqueue_size], b);

    //b->wqueue = mfree(b->wqueue);
    free(b->wqueue);
    b->wqueue = NULL;
}

static sd_bus* bus_free(sd_bus* b) {
    sd_bus_slot* s;

    assert(b);
    assert(!b->track_queue);
    assert(!b->tracks);

    b->state = BUS_CLOSED;

    //sd_bus_detach_event(b);

    while ((s = b->slots)) {
        /* At this point only floating slots can still be
         * around, because the non-floating ones keep a
         * reference to the bus, and we thus couldn't be
         * destructing right now... We forcibly disconnect the
         * slots here, so that they still can be referenced by
         * apps, but are dead. */

        assert(s->floating);
        bus_slot_disconnect(s, true);
    }

    if (b->default_bus_ptr)
        *b->default_bus_ptr = NULL;

    //bus_close_io_fds(b);
    //bus_close_inotify_fd(b);

    free(b->label);
    free(b->groups);
    free(b->rbuffer);
    free(b->unique_name);
    free(b->auth_buffer);
    free(b->address);
    free(b->machine);
    free(b->description);
    free(b->patch_sender);

    free(b->exec_path);
    strv_free(b->exec_argv);

    close_many(b->fds, b->n_fds);
    free(b->fds);

    bus_reset_queues(b);

    ordered_hashmap_free_free(b->reply_callbacks);
    prioq_free(b->reply_callbacks_prioq);

    assert(b->match_callbacks.type == BUS_MATCH_ROOT);
    bus_match_free(&b->match_callbacks);

    hashmap_free_free(b->vtable_methods);
    hashmap_free_free(b->vtable_properties);

    assert(hashmap_isempty(b->nodes));
    hashmap_free(b->nodes);

#if defined (__linux__)
    //bus_flush_memfd(b);
    assert_se(pthread_mutex_destroy(&b->memfd_cache_mutex) == 0);
#endif

    //return mfree(b);
    free(b);
    return NULL;
}

DEFINE_TRIVIAL_CLEANUP_FUNC(sd_bus*, bus_free);
DEFINE_PUBLIC_TRIVIAL_REF_UNREF_FUNC(sd_bus, sd_bus, bus_free);

_public_ int sd_bus_new(sd_bus** ret) {
    _cleanup_free_ sd_bus* b = NULL;

    assert_return(ret, -EINVAL);

    b = new(sd_bus, 1);
    if (!b)
        return -ENOMEM;

    *b = (sd_bus){
            .n_ref = 1,
            .input_fd = -1,
            .output_fd = -1,
            .inotify_fd = -1,
            .message_version = 1,
            .creds_mask = SD_BUS_CREDS_WELL_KNOWN_NAMES | SD_BUS_CREDS_UNIQUE_NAME,
            .accept_fd = true,
            //.original_pid = getpid_cached(),
            .original_pid = 0,
            .n_groups = SIZE_MAX,
            .close_on_exit = true,
            .ucred = UCRED_INVALID,
    };

    /* We guarantee that wqueue always has space for at least one entry */
    if (!GREEDY_REALLOC(b->wqueue, 1))
        return -ENOMEM;
#if defined (__linux__)
    assert_se(pthread_mutex_init(&b->memfd_cache_mutex, NULL) == 0);
#endif

    //*ret = TAKE_PTR(b);
    *ret = b;
    b = NULL;
    return 0;
}


_public_ int sd_bus_add_match(
    sd_bus* bus,
    sd_bus_slot** slot,
    const char* match,
    sd_bus_message_handler_t callback,
    void* userdata) {

    return 0;// bus_add_match_full(bus, slot, false, match, callback, NULL, userdata);
}

_public_ int sd_bus_add_match_async(
    sd_bus* bus,
    sd_bus_slot** slot,
    const char* match,
    sd_bus_message_handler_t callback,
    sd_bus_message_handler_t install_callback,
    void* userdata) {

    return 0;// bus_add_match_full(bus, slot, true, match, callback, install_callback, userdata);
}


bool bus_pid_changed(sd_bus* bus) {
    assert(bus);

    /* We don't support people creating a bus connection and
     * keeping it around over a fork(). Let's complain. */

     //return bus->original_pid != getpid_cached();
    return false;
}

_public_ int sd_bus_can_send(sd_bus* bus, char type) {
    int r;

    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(bus->state != BUS_UNSET, -ENOTCONN);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    if (bus->is_monitor)
        return 0;

    if (type == SD_BUS_TYPE_UNIX_FD) {
        if (!bus->accept_fd)
            return 0;

        //r = bus_ensure_running(bus);
        r = 1;
        if (r < 0)
            return r;

        return bus->can_fds;
    }

    return bus_type_is_valid(type);
}

#define COOKIE_CYCLED (UINT32_C(1) << 31)

static uint64_t cookie_inc(uint64_t cookie) {

    /* Stay within the 32bit range, since classic D-Bus can't deal with more */
    if (cookie >= UINT32_MAX)
        return COOKIE_CYCLED; /* Don't go back to zero, but use the highest bit for checking
                               * whether we are looping. */

    return cookie + 1;
}

static int next_cookie(sd_bus* b) {
    uint64_t new_cookie;

    assert(b);

    new_cookie = cookie_inc(b->cookie);

    /* Small optimization: don't bother with checking for cookie reuse until we overran cookiespace at
     * least once, but then do it thorougly. */
    if (FLAGS_SET(new_cookie, COOKIE_CYCLED)) {
        uint32_t i;

        /* Check if the cookie is currently in use. If so, pick the next one */
        for (i = 0; i < COOKIE_CYCLED; i++) {
            if (!ordered_hashmap_contains(b->reply_callbacks, &new_cookie))
                goto good;

            new_cookie = cookie_inc(new_cookie);
        }

        /* Can't fulfill request */
        return -EBUSY;
    }

good:
    b->cookie = new_cookie;
    return 0;
}

static int bus_seal_message(sd_bus* b, sd_bus_message* m, usec_t timeout) {
    int r;

    assert(b);
    assert(m);

    if (m->sealed) {
        /* If we copy the same message to multiple
         * destinations, avoid using the same cookie
         * numbers. */
        b->cookie = MAX(b->cookie, BUS_MESSAGE_COOKIE(m));
        return 0;
    }

    if (timeout == 0) {
        r = sd_bus_get_method_call_timeout(b, &timeout);
        if (r < 0)
            return r;
    }

    if (!m->sender && b->patch_sender) {
        r = sd_bus_message_set_sender(m, b->patch_sender);
        if (r < 0)
            return r;
    }

    r = next_cookie(b);
    if (r < 0)
        return r;

    return sd_bus_message_seal(m, b->cookie, timeout);
}

static int bus_remarshal_message(sd_bus* b, sd_bus_message** m) {
    bool remarshal = false;

    assert(b);

    /* wrong packet version */
    if (b->message_version != 0 && b->message_version != (*m)->header->version)
        remarshal = true;

    /* wrong packet endianness */
    if (b->message_endian != 0 && b->message_endian != (*m)->header->endian)
        remarshal = true;

    return remarshal ? bus_message_remarshal(b, m) : 0;
}

static int bus_write_message(sd_bus* bus, sd_bus_message* m, size_t* idx) {
    int r;

    assert(bus);
    assert(m);

    //r = bus_socket_write_message(bus, m, idx);
    sd_bus_message_dump(m, NULL, SD_BUS_MESSAGE_DUMP_WITH_HEADER);
    *idx = BUS_MESSAGE_SIZE(m); // update written size
    r = 1;

    if (r <= 0)
        return r;

    if (*idx >= BUS_MESSAGE_SIZE(m))
        log_debug("Sent message type=%s sender=%s destination=%s path=%s interface=%s member=%s cookie=%" PRIu64 " reply_cookie=%" PRIu64 " signature=%s error-name=%s error-message=%s",
            bus_message_type_to_string(m->header->type),
            strna(sd_bus_message_get_sender(m)),
            strna(sd_bus_message_get_destination(m)),
            strna(sd_bus_message_get_path(m)),
            strna(sd_bus_message_get_interface(m)),
            strna(sd_bus_message_get_member(m)),
            BUS_MESSAGE_COOKIE(m),
            m->reply_cookie,
            strna(m->root_container.signature),
            strna(m->error.name),
            strna(m->error.message));

    return r;
}

_public_ int sd_bus_send(sd_bus* bus, sd_bus_message* _m, uint64_t* cookie) {
    // TODO...................    
    printf("sd_bus_send: %s\n", _m->destination);
    
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = sd_bus_message_ref(_m);
    int r;

    assert_return(m, -EINVAL);

    if (bus)
        assert_return(bus = bus_resolve(bus), -ENOPKG);
    else
        assert_return(bus = m->bus, -ENOTCONN);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    if (!BUS_IS_OPEN(bus->state))
        return -ENOTCONN;
#if defined(__linux__)
    if (m->n_fds > 0) {
        r = sd_bus_can_send(bus, SD_BUS_TYPE_UNIX_FD);
        if (r < 0)
            return r;
        if (r == 0)
            return -EOPNOTSUPP;
    }
#endif

    /* If the cookie number isn't kept, then we know that no reply
     * is expected */
    if (!cookie && !m->sealed)
        m->header->flags |= BUS_MESSAGE_NO_REPLY_EXPECTED;

    r = bus_seal_message(bus, m, 0);
    if (r < 0)
        return r;

    /* Remarshall if we have to. This will possibly unref the
     * message and place a replacement in m */
    r = bus_remarshal_message(bus, &m);
    if (r < 0)
        return r;

    /* If this is a reply and no reply was requested, then let's
     * suppress this, if we can */
    if (m->dont_send)
        goto finish;

    //if (IN_SET(bus->state, BUS_RUNNING, BUS_HELLO) 
    if ((bus->state == BUS_RUNNING || bus->state == BUS_HELLO)
        && bus->wqueue_size <= 0) {
        size_t idx = 0;

        r = bus_write_message(bus, m, &idx);
        if (r < 0) {
            if (ERRNO_IS_DISCONNECT(r)) {
                bus_enter_closing(bus);
                return -ECONNRESET;
            }

            return r;
        }

        if (idx < BUS_MESSAGE_SIZE(m)) {
            /* Wasn't fully written. So let's remember how
             * much was written. Note that the first entry
             * of the wqueue array is always allocated so
             * that we always can remember how much was
             * written. */
            bus->wqueue[0] = bus_message_ref_queued(m, bus);
            bus->wqueue_size = 1;
            bus->windex = idx;
        }

    }
    else {
        /* Just append it to the queue. */

        if (bus->wqueue_size >= BUS_WQUEUE_MAX)
            return -ENOBUFS;

        if (!GREEDY_REALLOC(bus->wqueue, bus->wqueue_size + 1))
            return -ENOMEM;

        bus->wqueue[bus->wqueue_size++] = bus_message_ref_queued(m, bus);
    }

finish:
    if (cookie)
        *cookie = BUS_MESSAGE_COOKIE(m);

    return 1;

}

sd_bus* bus_resolve(sd_bus* bus) {
    switch ((uintptr_t)bus) {
    case (uintptr_t)SD_BUS_DEFAULT:
        //return *(bus_choose_default(NULL));
        return NULL;
    case (uintptr_t)SD_BUS_DEFAULT_USER:
        //return default_user_bus;
        return NULL;
    case (uintptr_t)SD_BUS_DEFAULT_SYSTEM:
        //return default_system_bus;
        return NULL;
    default:
        return bus;
    }
}

_public_ int sd_bus_call(
    sd_bus* bus,
    sd_bus_message* _m,
    uint64_t usec,
    sd_bus_error* error,
    sd_bus_message** reply) {
    //////////////////////////
    return 0;
}

_public_ int sd_bus_call_async(
    sd_bus* bus,
    sd_bus_slot** slot,
    sd_bus_message* _m,
    sd_bus_message_handler_t callback,
    void* userdata,
    uint64_t usec) {

    return 0;
}

_public_ int sd_bus_get_method_call_timeout(sd_bus* bus, uint64_t* ret) {
    //const char* e;
    //usec_t usec;

    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(ret, -EINVAL);

    if (bus->method_call_timeout != 0) {
        *ret = bus->method_call_timeout;
        return 0;
    }
        
    //e = secure_getenv("SYSTEMD_BUS_TIMEOUT");
    //if (e && parse_sec(e, &usec) >= 0 && usec != 0) {
    //    /* Save the parsed value to avoid multiple parsing. To change the timeout value,
    //     * use sd_bus_set_method_call_timeout() instead of setenv(). */
    //    *ret = bus->method_call_timeout = usec;
    //    return 0;
    //}

    *ret = bus->method_call_timeout = BUS_DEFAULT_TIMEOUT;
    return 0;
}

#define append_eavesdrop(bus, m)                                        \
        ((bus)->is_monitor                                              \
         ? (isempty(m) ? "eavesdrop='true'" : strjoina((m), ",eavesdrop='true'")) \
         : (m))


static char* __strjoina(const char *a, const char *b)                                                \
{
        const char* _appendees_[] = { a, b };         
        char* _d_,* _p_;                                        
        size_t _len_ = 0;                                       
        size_t _i_;                                             
        for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) 
                _len_ += strlen(_appendees_[_i_]);              
        _p_ = _d_ = //newa(char, _len_ + 1);                      
            alloca(_len_ + 1);
        for (_i_ = 0; _i_ < ELEMENTSOF(_appendees_) && _appendees_[_i_]; _i_++) 
                _p_ = stpcpy(_p_, _appendees_[_i_]);            
        *_p_ = 0; 
        return _d_;                                                    
}


const char* __append_eavesdrop(sd_bus* bus, const char* match)
{


    return ((bus)->is_monitor                                              
        ? (isempty(match) ? "eavesdrop='true'" : __strjoina((match), ",eavesdrop='true'")) 
        : (match));
}

int bus_remove_match_internal(
    sd_bus* bus,
    const char* match) {

    const char* e;

    assert(bus);
    assert(match);

    if (!bus->bus_client)
        return -EINVAL;

    e = __append_eavesdrop(bus, match);

    /* Fire and forget */

    return sd_bus_call_method_async(
        bus,
        NULL,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "RemoveMatch",
        NULL,
        NULL,
        "s",
        e);
}

void bus_creds_done(sd_bus_creds* c) {
    assert(c);

    /* For internal bus cred structures that are allocated by
     * something else */

    free(c->session);
    free(c->unit);
    free(c->user_unit);
    free(c->slice);
    free(c->user_slice);
    free(c->unescaped_description);
    free(c->supplementary_gids);
    free(c->tty);

    free(c->well_known_names); /* note that this is an strv, but
                                * we only free the array, not the
                                * strings the array points to. The
                                * full strv we only free if
                                * c->allocated is set, see
                                * below. */

    strv_free(c->cmdline_array);
}

_public_ sd_bus_creds* sd_bus_creds_ref(sd_bus_creds* c) {

    if (!c)
        return NULL;

    if (c->allocated) {
        assert(c->n_ref > 0);
        c->n_ref++;
    }
    else {
        sd_bus_message* m;

        /* If this is an embedded creds structure, then
         * forward ref counting to the message */
        m = container_of(c, sd_bus_message, creds);
        sd_bus_message_ref(m);
    }

    return c;
}

_public_ sd_bus_creds* sd_bus_creds_unref(sd_bus_creds* c) {

    if (!c)
        return NULL;

    if (c->allocated) {
        assert(c->n_ref > 0);
        c->n_ref--;

        if (c->n_ref == 0) {
            free(c->comm);
            free(c->tid_comm);
            free(c->exe);
            free(c->cmdline);
            free(c->cgroup);
            free(c->capability);
            free(c->label);
            free(c->unique_name);
            free(c->cgroup_root);
            free(c->description);

            //c->supplementary_gids = mfree(c->supplementary_gids);
            free(c->supplementary_gids);
            c->supplementary_gids = NULL;

            c->well_known_names = strv_free(c->well_known_names);

            bus_creds_done(c);

            free(c);
        }
    }
    else {
        sd_bus_message* m;

        m = container_of(c, sd_bus_message, creds);
        sd_bus_message_unref(m);
    }

    return NULL;
}


int memfd_set_sealed(int fd) {
    assert(fd >= 0);

    return 0;// RET_NERRNO(fcntl(fd, F_ADD_SEALS, F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_SEAL));
}

int memfd_get_size(int fd, uint64_t* sz) {
    struct stat stat;

    assert(fd >= 0);
    assert(sz);

    if (fstat(fd, &stat) < 0)
        return -errno;

    *sz = stat.st_size;
    return 0;
}

int memfd_set_size(int fd, uint64_t sz) {

#if defined(__linux__)
    assert(fd >= 0);

    return RET_NERRNO(ftruncate(fd, sz));
#else
    return 0;
#endif
}

_public_ int sd_bus_creds_get_uid(sd_bus_creds* c, uid_t* uid) {
    assert_return(c, -EINVAL);
    assert_return(uid, -EINVAL);

    if (!(c->mask & SD_BUS_CREDS_UID))
        return -ENODATA;

    *uid = c->uid;
    return 0;
}

_public_ int sd_bus_creds_get_euid(sd_bus_creds* c, uid_t* euid) {
    assert_return(c, -EINVAL);
    assert_return(euid, -EINVAL);

    if (!(c->mask & SD_BUS_CREDS_EUID))
        return -ENODATA;

    *euid = c->euid;
    return 0;
}

_public_ uint64_t sd_bus_creds_get_mask(const sd_bus_creds* c) {
    assert_return(c, 0);

    return c->mask;
}

_public_ uint64_t sd_bus_creds_get_augmented_mask(const sd_bus_creds* c) {
    assert_return(c, 0);

    return c->augmented;
}

_public_ int sd_bus_creds_has_effective_cap(sd_bus_creds* c, int capability) {
    /*
    assert_return(c, -EINVAL);
    assert_return(capability >= 0, -EINVAL);

    if (!(c->mask & SD_BUS_CREDS_EFFECTIVE_CAPS))
        return -ENODATA;

    return has_cap(c, CAP_OFFSET_EFFECTIVE, capability);
    */
    return 1;
}

_public_ int sd_bus_get_owner_creds(sd_bus* bus, uint64_t mask, sd_bus_creds** ret) {
    
    return 0;
}

int bus_creds_extend_by_pid(sd_bus_creds* c, uint64_t mask, sd_bus_creds** ret) {
    return 0;
}

_public_ int sd_bus_get_name_creds(
    sd_bus* bus,
    const char* name,
    uint64_t mask,
    sd_bus_creds** creds) {
    return 0;
}



_public_ int sd_bus_path_encode(const char* prefix, const char* external_id, char** ret_path) {
    _cleanup_free_ char* e = NULL;
    char* ret;

    assert_return(object_path_is_valid(prefix), -EINVAL);
    assert_return(external_id, -EINVAL);
    assert_return(ret_path, -EINVAL);

    e = bus_label_escape(external_id);
    if (!e)
        return -ENOMEM;

    ret = path_join(prefix, e);
    if (!ret)
        return -ENOMEM;

    *ret_path = ret;
    return 0;
}

_public_ int sd_bus_path_decode(const char* path, const char* prefix, char** external_id) {
    const char* e;
    char* ret;

    assert_return(object_path_is_valid(path), -EINVAL);
    assert_return(object_path_is_valid(prefix), -EINVAL);
    assert_return(external_id, -EINVAL);

    e = object_path_startswith(path, prefix);
    if (!e) {
        *external_id = NULL;
        return 0;
    }

    ret = bus_label_unescape(e);
    if (!ret)
        return -ENOMEM;

    *external_id = ret;
    return 1;
}

_public_ int sd_bus_path_encode_many(char** out, const char* path_template, ...) {
    _cleanup_strv_free_ char** labels = NULL;
    char* path, * path_pos, ** label_pos;
    const char* sep, * template_pos;
    size_t path_length;
    va_list list;
    int r;

    assert_return(out, -EINVAL);
    assert_return(path_template, -EINVAL);

    path_length = strlen(path_template);

    va_start(list, path_template);
    for (sep = strchr(path_template, '%'); sep; sep = strchr(sep + 1, '%')) {
        const char* arg;
        char* label;

        arg = va_arg(list, const char*);
        if (!arg) {
            va_end(list);
            return -EINVAL;
        }

        label = bus_label_escape(arg);
        if (!label) {
            va_end(list);
            return -ENOMEM;
        }

        r = strv_consume(&labels, label);
        if (r < 0) {
            va_end(list);
            return r;
        }

        /* add label length, but account for the format character */
        path_length += strlen(label) - 1;
    }
    va_end(list);

    path = malloc(path_length + 1);
    if (!path)
        return -ENOMEM;

    path_pos = path;
    label_pos = labels;

    for (template_pos = path_template; *template_pos; ) {
        sep = strchrnul(template_pos, '%');
        path_pos = mempcpy(path_pos, template_pos, sep - template_pos);
        if (!*sep)
            break;

        path_pos = stpcpy(path_pos, *label_pos++);
        template_pos = sep + 1;
    }

    *path_pos = 0;
    *out = path;
    return 0;
}

_public_ int sd_bus_path_decode_many(const char* path, const char* path_template, ...) {
    _cleanup_strv_free_ char** labels = NULL;
    const char* template_pos, * path_pos;
    char** label_pos;
    va_list list;
    int r;

    /*
     * This decodes an object-path based on a template argument. The
     * template consists of a verbatim path, optionally including special
     * directives:
     *
     *   - Each occurrence of '%' in the template matches an arbitrary
     *     substring of a label in the given path. At most one such
     *     directive is allowed per label. For each such directive, the
     *     caller must provide an output parameter (char **) via va_arg. If
     *     NULL is passed, the given label is verified, but not returned.
     *     For each matched label, the *decoded* label is stored in the
     *     passed output argument, and the caller is responsible to free
     *     it. Note that the output arguments are only modified if the
     *     actually path matched the template. Otherwise, they're left
     *     untouched.
     *
     * This function returns <0 on error, 0 if the path does not match the
     * template, 1 if it matched.
     */

    assert_return(path, -EINVAL);
    assert_return(path_template, -EINVAL);

    path_pos = path;

    for (template_pos = path_template; *template_pos; ) {
        const char* sep;
        size_t length;
        char* label;

        /* verify everything until the next '%' matches verbatim */
        sep = strchrnul(template_pos, '%');
        length = sep - template_pos;
        if (strncmp(path_pos, template_pos, length))
            return 0;

        path_pos += length;
        template_pos += length;

        if (!*template_pos)
            break;

        /* We found the next '%' character. Everything up until here
         * matched. We now skip ahead to the end of this label and make
         * sure it matches the tail of the label in the path. Then we
         * decode the string in-between and save it for later use. */

        ++template_pos; /* skip over '%' */

        sep = strchrnul(template_pos, '/');
        length = sep - template_pos; /* length of suffix to match verbatim */

        /* verify the suffixes match */
        sep = strchrnul(path_pos, '/');
        if (sep - path_pos < (ssize_t)length ||
            strncmp(sep - length, template_pos, length))
            return 0;

        template_pos += length; /* skip over matched label */
        length = sep - path_pos - length; /* length of sub-label to decode */

        /* store unescaped label for later use */
        label = bus_label_unescape_n(path_pos, length);
        if (!label)
            return -ENOMEM;

        r = strv_consume(&labels, label);
        if (r < 0)
            return r;

        path_pos = sep; /* skip decoded label and suffix */
    }

    /* end of template must match end of path */
    if (*path_pos)
        return 0;

    /* copy the labels over to the caller */
    va_start(list, path_template);
    for (label_pos = labels; label_pos && *label_pos; ++label_pos) {
        char** arg;

        arg = va_arg(list, char**);
        if (arg)
            *arg = *label_pos;
        else
            free(*label_pos);
    }
    va_end(list);

    //labels = mfree(labels);
    free(labels);
    labels = NULL;
    return 1;
}


/**
 * bus_path_encode_unique() - encode unique object path
 * @b: bus connection or NULL
 * @prefix: object path prefix
 * @sender_id: unique-name of client, or NULL
 * @external_id: external ID to be chosen by client, or NULL
 * @ret_path: storage for encoded object path pointer
 *
 * Whenever we provide a bus API that allows clients to create and manage
 * server-side objects, we need to provide a unique name for these objects. If
 * we let the server choose the name, we suffer from a race condition: If a
 * client creates an object asynchronously, it cannot destroy that object until
 * it received the method reply. It cannot know the name of the new object,
 * thus, it cannot destroy it. Furthermore, it enforces a round-trip.
 *
 * Therefore, many APIs allow the client to choose the unique name for newly
 * created objects. There're two problems to solve, though:
 *    1) Object names are usually defined via dbus object paths, which are
 *       usually globally namespaced. Therefore, multiple clients must be able
 *       to choose unique object names without interference.
 *    2) If multiple libraries share the same bus connection, they must be
 *       able to choose unique object names without interference.
 * The first problem is solved easily by prefixing a name with the
 * unique-bus-name of a connection. The server side must enforce this and
 * reject any other name. The second problem is solved by providing unique
 * suffixes from within sd-bus.
 *
 * This helper allows clients to create unique object-paths. It uses the
 * template '/prefix/sender_id/external_id' and returns the new path in
 * @ret_path (must be freed by the caller).
 * If @sender_id is NULL, the unique-name of @b is used. If @external_id is
 * NULL, this function allocates a unique suffix via @b (by requesting a new
 * cookie). If both @sender_id and @external_id are given, @b can be passed as
 * NULL.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int bus_path_encode_unique(sd_bus* b, const char* prefix, const char* sender_id, const char* external_id, char** ret_path) {
    _cleanup_free_ char* sender_label = NULL, * external_label = NULL;
#ifdef WIN32
    char external_buf[24];
#else
    char external_buf[DECIMAL_STR_MAX(uint64_t)];
#endif
    char *p;
    //int r;

    assert_return(b || (sender_id && external_id), -EINVAL);
    assert_return(sd_bus_object_path_is_valid(prefix), -EINVAL);
    assert_return(ret_path, -EINVAL);

/*
    if (!sender_id) {
        r = sd_bus_get_unique_name(b, &sender_id);
        if (r < 0)
            return r;
    }
*/
    if (!external_id) {
#ifdef WIN32
        sprintf(external_buf, "%"PRIu64, ++b->cookie);
#else
        xsprintf(external_buf, "%"PRIu64, ++b->cookie);
#endif
        external_id = external_buf;
    }

    sender_label = bus_label_escape(sender_id);
    if (!sender_label)
        return -ENOMEM;

    external_label = bus_label_escape(external_id);
    if (!external_label)
        return -ENOMEM;

    p = path_join(prefix, sender_label, external_label);
    if (!p)
        return -ENOMEM;

    *ret_path = p;
    return 0;
}

/**
 * bus_path_decode_unique() - decode unique object path
 * @path: object path to decode
 * @prefix: object path prefix
 * @ret_sender: output parameter for sender-id label
 * @ret_external: output parameter for external-id label
 *
 * This does the reverse of bus_path_encode_unique() (see its description for
 * details). Both trailing labels, sender-id and external-id, are unescaped and
 * returned in the given output parameters (the caller must free them).
 *
 * Note that this function returns 0 if the path does not match the template
 * (see bus_path_encode_unique()), 1 if it matched.
 *
 * Returns: Negative error code on failure, 0 if the given object path does not
 *          match the template (return parameters are set to NULL), 1 if it was
 *          parsed successfully (return parameters contain allocated labels).
 */
int bus_path_decode_unique(const char* path, const char* prefix, char** ret_sender, char** ret_external) {
    const char* p, * q;
    char* sender, * external;

    assert(sd_bus_object_path_is_valid(path));
    assert(sd_bus_object_path_is_valid(prefix));
    assert(ret_sender);
    assert(ret_external);

    p = object_path_startswith(path, prefix);
    if (!p) {
        *ret_sender = NULL;
        *ret_external = NULL;
        return 0;
    }

    q = strchr(p, '/');
    if (!q) {
        *ret_sender = NULL;
        *ret_external = NULL;
        return 0;
    }

    sender = bus_label_unescape_n(p, q - p);
    external = bus_label_unescape(q + 1);
    if (!sender || !external) {
        free(sender);
        free(external);
        return -ENOMEM;
    }

    *ret_sender = sender;
    *ret_external = external;
    return 1;
}



int bus_set_address_user(sd_bus* b) {
    const char* a;
    _cleanup_free_ char* _a = NULL;
    int r;

    assert(b);

    a = secure_getenv("DBUS_SESSION_BUS_ADDRESS");
    if (!a) {
        const char* e;
        _cleanup_free_ char* ee = NULL;

        e = secure_getenv("XDG_RUNTIME_DIR");
        if (!e)
            return log_debug_errno(SYNTHETIC_ERRNO(ENOMEDIUM),
                "sd-bus: $XDG_RUNTIME_DIR not set, cannot connect to user bus.");

        ee = bus_address_escape(e);
        if (!ee)
            return -ENOMEM;

        if (asprintf(&_a, DEFAULT_USER_BUS_ADDRESS_FMT, ee) < 0)
            return -ENOMEM;
        a = _a;
    }

    r = sd_bus_set_address(b, a);
    if (r >= 0)
        b->is_user = true;
    return r;
}

_public_ int sd_bus_open_user_with_description(sd_bus** ret, const char* description) {
    _cleanup_(bus_freep) sd_bus* b = NULL;
    int r;

    assert_return(ret, -EINVAL);

    r = sd_bus_new(&b);
    if (r < 0)
        return r;

    if (description) {
        r = sd_bus_set_description(b, description);
        if (r < 0)
            return r;
    }

    r = bus_set_address_user(b);
    if (r < 0)
        return r;

    b->bus_client = true;

    /* We don't do any per-method access control on the user bus. */
    b->trusted = true;
    b->is_local = true;

    r = sd_bus_start(b);
    if (r < 0)
        return r;

    //*ret = TAKE_PTR(b);
    *ret = b;
    b = NULL;
    return 0;
}

_public_ int sd_bus_open_user(sd_bus** ret) {
    return sd_bus_open_user_with_description(ret, NULL);
}

_public_ int sd_bus_set_description(sd_bus* bus, const char* description) {
    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(bus->state == BUS_UNSET, -EPERM);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    return free_and_strdup(&bus->description, description);
}

_public_ int sd_bus_set_address(sd_bus* bus, const char* address) {
    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(bus->state == BUS_UNSET, -EPERM);
    assert_return(address, -EINVAL);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    return free_and_strdup(&bus->address, address);
}

int bus_ensure_running(sd_bus* bus) {
    int r;

    assert(bus);

    if (bus->state == BUS_RUNNING)
        return 1;

    for (;;) {
        //if (IN_SET(bus->state, BUS_UNSET, BUS_CLOSED, BUS_CLOSING))
        if ((bus->state == BUS_UNSET || bus->state == BUS_CLOSED || bus->state == BUS_CLOSING))
            return -ENOTCONN;

        r = sd_bus_process(bus, NULL);
        if (r < 0)
            return r;
        if (bus->state == BUS_RUNNING)
            return 1;
        if (r > 0)
            continue;

        r = sd_bus_wait(bus, UINT64_MAX);
        if (r < 0)
            return r;
    }
}

static int bus_poll(sd_bus* bus, bool need_more, uint64_t timeout_usec) {
    struct pollfd p[2] = { -1, -1 };
    usec_t m = USEC_INFINITY;
    int r, n;

    assert(bus);

    if (bus->state == BUS_CLOSING)
        return 1;

    if (!BUS_IS_OPEN(bus->state))
        return -ENOTCONN;

    if (bus->state == BUS_WATCH_BIND) {
        assert(bus->inotify_fd >= 0);

        p[0].events = POLLIN;
        p[0].fd = bus->inotify_fd;
        n = 1;
    }
    else {
        int e;

        e = sd_bus_get_events(bus);
        if (e < 0)
            return e;

        if (need_more)
            /* The caller really needs some more data, they don't
             * care about what's already read, or any timeouts
             * except its own. */
            e |= POLLIN;
        else {
            usec_t until;
            /* The caller wants to process if there's something to
             * process, but doesn't care otherwise */

            r = sd_bus_get_timeout(bus, &until);
            if (r < 0)
                return r;
            if (r > 0)
                m = usec_sub_unsigned(until, now(CLOCK_MONOTONIC));
        }

        p[0].fd = bus->input_fd;
        if (bus->output_fd == bus->input_fd) {
            p[0].events = e;
            n = 1;
        }
        else {
            p[0].events = e & POLLIN;
            p[1].fd = bus->output_fd;
            p[1].events = e & POLLOUT;
            n = 2;
        }
    }

    if (timeout_usec != UINT64_MAX && (m == USEC_INFINITY || timeout_usec < m))
        m = timeout_usec;

    r = ppoll_usec(p, n, m);
    if (r <= 0)
        return r;

    return 1;
}

_public_ int sd_bus_wait(sd_bus* bus, uint64_t timeout_usec) {

    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    if (bus->state == BUS_CLOSING)
        return 0;

    if (!BUS_IS_OPEN(bus->state))
        return -ENOTCONN;

    if (bus->rqueue_size > 0)
        return 0;

    return bus_poll(bus, false, timeout_usec);
}


void bus_set_state(sd_bus* bus, enum bus_state state) {
    static const char* const table[_BUS_STATE_MAX] = {
            [BUS_UNSET] = "UNSET",
            [BUS_WATCH_BIND] = "WATCH_BIND",
            [BUS_OPENING] = "OPENING",
            [BUS_AUTHENTICATING] = "AUTHENTICATING",
            [BUS_HELLO] = "HELLO",
            [BUS_RUNNING] = "RUNNING",
            [BUS_CLOSING] = "CLOSING",
            [BUS_CLOSED] = "CLOSED",
    };

    assert(bus);
    assert(state < _BUS_STATE_MAX);

    if (state == bus->state)
        return;

    log_debug("Bus %s: changing state %s -> %s", strna(bus->description), table[bus->state], table[state]);
    bus->state = state;
}

void bus_enter_closing(sd_bus* bus) {
    assert(bus);

    //if (!IN_SET(bus->state, BUS_WATCH_BIND, BUS_OPENING, BUS_AUTHENTICATING, BUS_HELLO, BUS_RUNNING))
    if (!(bus->state == BUS_WATCH_BIND || bus->state == BUS_OPENING ||
        bus->state == BUS_AUTHENTICATING || bus->state == BUS_HELLO, BUS_RUNNING))
        return;

    bus_set_state(bus, BUS_CLOSING);
}

void bus_iteration_counter_increase(sd_bus* bus)
{
    bus->iteration_counter++;
}

_public_ int sd_bus_set_fd(sd_bus* bus, int input_fd, int output_fd) {
    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(bus->state == BUS_UNSET, -EPERM);
    assert_return(input_fd >= 0, -EBADF);
    assert_return(output_fd >= 0, -EBADF);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    bus->input_fd = input_fd;
    bus->output_fd = output_fd;
    return 0;
}

_public_ int sd_bus_set_server(sd_bus* bus, int b, sd_id128_t server_id) {
    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(b || sd_id128_equal(server_id, SD_ID128_NULL), -EINVAL);
    assert_return(bus->state == BUS_UNSET, -EPERM);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    bus->is_server = !!b;
    bus->server_id = server_id;
    return 0;
}

_public_ int sd_bus_set_anonymous(sd_bus* bus, int b) {
    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(bus->state == BUS_UNSET, -EPERM);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    bus->anonymous_auth = !!b;
    return 0;
}

_public_ int sd_bus_set_trusted(sd_bus* bus, int b) {
    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(bus->state == BUS_UNSET, -EPERM);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    bus->trusted = !!b;
    return 0;
}

_public_ int sd_bus_negotiate_fds(sd_bus* bus, int b) {
    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(bus->state == BUS_UNSET, -EPERM);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    bus->accept_fd = !!b;
    return 0;
}

static int dispatch_wqueue(sd_bus* bus) {
    int r, ret = 0;

    assert(bus);
    //assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));
    assert((bus->state == BUS_RUNNING || bus->state == BUS_HELLO));

    while (bus->wqueue_size > 0) {

        r = bus_write_message(bus, bus->wqueue[0], &bus->windex);
        if (r < 0)
            return r;
        else if (r == 0)
            /* Didn't do anything this time */
            return ret;
        else if (bus->windex >= BUS_MESSAGE_SIZE(bus->wqueue[0])) {
            /* Fully written. Let's drop the entry from
             * the queue.
             *
             * This isn't particularly optimized, but
             * well, this is supposed to be our worst-case
             * buffer only, and the socket buffer is
             * supposed to be our primary buffer, and if
             * it got full, then all bets are off
             * anyway. */

            bus->wqueue_size--;
            bus_message_unref_queued(bus->wqueue[0], bus);
            memmove(bus->wqueue, bus->wqueue + 1, sizeof(sd_bus_message*) * bus->wqueue_size);
            bus->windex = 0;

            ret = 1;
        }
    }

    return ret;
}

_public_ int sd_bus_flush(sd_bus* bus) {
    int r;

    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    if (bus->state == BUS_CLOSING)
        return 0;

    if (!BUS_IS_OPEN(bus->state))
        return -ENOTCONN;

    /* We never were connected? Don't hang in inotify for good, as there's no timeout set for it */
    if (bus->state == BUS_WATCH_BIND)
        return -EUNATCH;

    r = bus_ensure_running(bus);
    if (r < 0)
        return r;

    if (bus->wqueue_size <= 0)
        return 0;

    for (;;) {
        r = dispatch_wqueue(bus);
        if (r < 0) {
            if (ERRNO_IS_DISCONNECT(r)) {
                bus_enter_closing(bus);
                return -ECONNRESET;
            }

            return r;
        }

        if (bus->wqueue_size <= 0)
            return 0;

        r = bus_poll(bus, false, UINT64_MAX);
        if (r < 0)
            return r;
    }
}

static int synthesize_connected_signal(sd_bus* bus) {
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL;
    int r;

    assert(bus);

    /* If enabled, synthesizes a local "Connected" signal mirroring the local "Disconnected" signal. This is called
     * whenever we fully established a connection, i.e. after the authorization phase, and after receiving the
     * Hello() reply. Or in other words, whenever we enter BUS_RUNNING state.
     *
     * This is useful so that clients can start doing stuff whenever the connection is fully established in a way
     * that works independently from whether we connected to a full bus or just a direct connection. */

    if (!bus->connected_signal)
        return 0;

    r = sd_bus_message_new_signal(
        bus,
        &m,
        "/org/freedesktop/DBus/Local",
        "org.freedesktop.DBus.Local",
        "Connected");
    if (r < 0)
        return r;

    bus_message_set_sender_local(bus, m);
    m->read_counter = ++bus->read_counter;

    r = bus_seal_synthetic_message(bus, m);
    if (r < 0)
        return r;

    r = bus_rqueue_make_room(bus);
    if (r < 0)
        return r;

    /* Insert at the very front */
    memmove(bus->rqueue + 1, bus->rqueue, sizeof(sd_bus_message*) * bus->rqueue_size);
    bus->rqueue[0] = bus_message_ref_queued(m, bus);
    bus->rqueue_size++;

    return 0;
}

static int hello_callback(sd_bus_message* reply, void* userdata, sd_bus_error* error) {
    const char* s;
    sd_bus* bus;
    int r;

    assert(reply);
    bus = reply->bus;
    assert(bus);
    //assert(IN_SET(bus->state, BUS_HELLO, BUS_CLOSING));
    assert((bus->state == BUS_HELLO || bus->state == BUS_CLOSING));

    r = sd_bus_message_get_errno(reply);
    if (r > 0) {
        r = -r;
        goto fail;
    }

    r = sd_bus_message_read(reply, "s", &s);
    if (r < 0)
        goto fail;

    if (!service_name_is_valid(s) || s[0] != ':') {
        r = -EBADMSG;
        goto fail;
    }

    r = free_and_strdup(&bus->unique_name, s);
    if (r < 0)
        goto fail;

    if (bus->state == BUS_HELLO) {
        bus_set_state(bus, BUS_RUNNING);

        r = synthesize_connected_signal(bus);
        if (r < 0)
            goto fail;
    }

    return 1;

fail:
    /* When Hello() failed, let's propagate this in two ways: first we return the error immediately here,
     * which is the propagated up towards the event loop. Let's also invalidate the connection, so that
     * if the user then calls back into us again we won't wait any longer. */

    bus_set_state(bus, BUS_CLOSING);
    return r;
}

static int bus_send_hello(sd_bus* bus) {
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL;
    int r;

    assert(bus);

    if (!bus->bus_client)
        return 0;

    r = sd_bus_message_new_method_call(
        bus,
        &m,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
        "Hello");
    if (r < 0)
        return r;

    return sd_bus_call_async(bus, NULL, m, hello_callback, NULL, 0);
}

int bus_start_running(sd_bus* bus) {
    struct reply_callback* c;
    usec_t n;
    int r;

    assert(bus);
    assert(bus->state < BUS_HELLO);

    /* We start all method call timeouts when we enter BUS_HELLO or BUS_RUNNING mode. At this point let's convert
     * all relative to absolute timestamps. Note that we do not reshuffle the reply callback priority queue since
     * adding a fixed value to all entries should not alter the internal order. */

    n = now(CLOCK_MONOTONIC);
    ORDERED_HASHMAP_FOREACH(c, bus->reply_callbacks) {
        if (c->timeout_usec == 0)
            continue;

        c->timeout_usec = usec_add(n, c->timeout_usec);
    }

    if (bus->bus_client) {
        bus_set_state(bus, BUS_HELLO);
        return 1;
    }

    bus_set_state(bus, BUS_RUNNING);

    r = synthesize_connected_signal(bus);
    if (r < 0)
        return r;

    return 1;
}

static int bus_start_fd(sd_bus* b) {
    struct stat st;
    int r;

    assert(b);
    assert(b->input_fd >= 0);
    assert(b->output_fd >= 0);

    if (DEBUG_LOGGING) {
        _cleanup_free_ char* pi = NULL, * po = NULL;
        (void)fd_get_path(b->input_fd, &pi);
        (void)fd_get_path(b->output_fd, &po);
        log_debug("sd-bus: starting bus%s%s on fds %d/%d (%s, %s)...",
            b->description ? " " : "", strempty(b->description),
            b->input_fd, b->output_fd,
            pi ? pi : "???", po ? po : "???");
    }

    r = fd_nonblock(b->input_fd, true);
    if (r < 0)
        return r;
#if defined(__linux__)
    r = fd_cloexec(b->input_fd, true);
    if (r < 0)
        return r;
#endif
    if (b->input_fd != b->output_fd) {
        r = fd_nonblock(b->output_fd, true);
        if (r < 0)
            return r;
#if defined(__linux__)
        r = fd_cloexec(b->output_fd, true);
        if (r < 0)
            return r;
#endif
    }

#ifdef WIN32
    int fd = _open_osfhandle(b->input_fd, _O_RDONLY);
    if (fstat(fd, &st) < 0)
        return -errno;
#else

    if (fstat(b->input_fd, &st) < 0)
        return -errno;
#endif

    return bus_socket_take_fd(b);
}

static int bus_start_address(sd_bus* b) {
    int r;

    assert(b);

    for (;;) {
        bus_close_io_fds(b);
        bus_close_inotify_fd(b);

        bus_kill_exec(b);

        /* If you provide multiple different bus-addresses, we
         * try all of them in order and use the first one that
         * succeeds. */

        if (b->exec_path)
            r = bus_socket_exec(b);
#if ENABLE_BUS_CONTAINER
        else if ((b->nspid > 0 || b->machine) && b->sockaddr.sa.sa_family != AF_UNSPEC)
            r = bus_container_connect_socket(b);
#endif
        else if (b->sockaddr.sa.sa_family != AF_UNSPEC)
            r = bus_socket_connect(b);
        else
            goto next;

        if (r >= 0) {
            int q;

            q = bus_attach_io_events(b);
            if (q < 0)
                return q;

            q = bus_attach_inotify_event(b);
            if (q < 0)
                return q;

            return r;
        }

        b->last_connect_error = -r;

    next:
        r = bus_parse_next_address(b);
        if (r < 0)
            return r;
        if (r == 0)
            return b->last_connect_error > 0 ? -b->last_connect_error : -ECONNREFUSED;
    }
}

_public_ int sd_bus_start(sd_bus* bus) {
    int r;

    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(bus->state == BUS_UNSET, -EPERM);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    bus_set_state(bus, BUS_OPENING);

    if (bus->is_server && bus->bus_client)
        return -EINVAL;

    if (bus->input_fd >= 0)
        r = bus_start_fd(bus);
    else if (bus->address || bus->sockaddr.sa.sa_family != AF_UNSPEC || bus->exec_path || bus->machine)
        r = bus_start_address(bus);
    else
        return -EINVAL;

    if (r < 0) {
        sd_bus_close(bus);
        return r;
    }

    return bus_send_hello(bus);
}

static int process_timeout(sd_bus* bus) {
    _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL;
    struct reply_callback* c;
    sd_bus_slot* slot;
    bool is_hello;
    usec_t n;
    int r;

    assert(bus);
    //assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));
    assert((bus->state == BUS_RUNNING || bus->state == BUS_HELLO));

    c = prioq_peek(bus->reply_callbacks_prioq);
    if (!c)
        return 0;

    n = now(CLOCK_MONOTONIC);
    if (c->timeout_usec > n)
        return 0;

    r = bus_message_new_synthetic_error(
        bus,
        c->cookie,
        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Method call timed out"),
        &m);
    if (r < 0)
        return r;

    m->read_counter = ++bus->read_counter;

    r = bus_seal_synthetic_message(bus, m);
    if (r < 0)
        return r;

    assert_se(prioq_pop(bus->reply_callbacks_prioq) == c);
    c->timeout_usec = 0;

    ordered_hashmap_remove(bus->reply_callbacks, &c->cookie);
    c->cookie = 0;

    slot = container_of(c, sd_bus_slot, reply_callback);

    bus->iteration_counter++;

    is_hello = bus->state == BUS_HELLO && c->callback == hello_callback;

    bus->current_message = m;
    bus->current_slot = sd_bus_slot_ref(slot);
    bus->current_handler = c->callback;
    bus->current_userdata = slot->userdata;
    r = c->callback(m, slot->userdata, &error_buffer);
    bus->current_userdata = NULL;
    bus->current_handler = NULL;
    bus->current_slot = NULL;
    bus->current_message = NULL;

    if (slot->floating)
        bus_slot_disconnect(slot, true);

    sd_bus_slot_unref(slot);

    /* When this is the hello message and it timed out, then make sure to propagate the error up, don't just log
     * and ignore the callback handler's return value. */
    if (is_hello)
        return r;

    return bus_maybe_reply_error(m, r, &error_buffer);
}

static int process_hello(sd_bus* bus, sd_bus_message* m) {
    assert(bus);
    assert(m);

    if (bus->state != BUS_HELLO)
        return 0;

    /* Let's make sure the first message on the bus is the HELLO
     * reply. But note that we don't actually parse the message
     * here (we leave that to the usual handling), we just verify
     * we don't let any earlier msg through. */

     //if (!IN_SET(m->header->type, SD_BUS_MESSAGE_METHOD_RETURN, SD_BUS_MESSAGE_METHOD_ERROR))
    if (!(m->header->type == SD_BUS_MESSAGE_METHOD_RETURN || m->header->type == SD_BUS_MESSAGE_METHOD_ERROR))
        return -EIO;

    if (m->reply_cookie != 1)
        return -EIO;

    return 0;
}

static int process_reply(sd_bus* bus, sd_bus_message* m) {
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* synthetic_reply = NULL;
    _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
    struct reply_callback* c;
    sd_bus_slot* slot;
    bool is_hello;
    int r;

    assert(bus);
    assert(m);

    //if (!IN_SET(m->header->type, SD_BUS_MESSAGE_METHOD_RETURN, SD_BUS_MESSAGE_METHOD_ERROR))
    if (!(m->header->type == SD_BUS_MESSAGE_METHOD_RETURN || m->header->type == SD_BUS_MESSAGE_METHOD_ERROR))
        return 0;

    if (m->destination && bus->unique_name && !streq_ptr(m->destination, bus->unique_name))
        return 0;

    c = ordered_hashmap_remove(bus->reply_callbacks, &m->reply_cookie);
    if (!c)
        return 0;

    c->cookie = 0;

    slot = container_of(c, sd_bus_slot, reply_callback);

    if (m->n_fds > 0 && !bus->accept_fd) {

        /* If the reply contained a file descriptor which we
         * didn't want we pass an error instead. */

        r = bus_message_new_synthetic_error(
            bus,
            m->reply_cookie,
            &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_INCONSISTENT_MESSAGE, "Reply message contained file descriptor"),
            &synthetic_reply);
        if (r < 0)
            return r;

        /* Copy over original timestamp */
        synthetic_reply->realtime = m->realtime;
        synthetic_reply->monotonic = m->monotonic;
        synthetic_reply->seqnum = m->seqnum;
        synthetic_reply->read_counter = m->read_counter;

        r = bus_seal_synthetic_message(bus, synthetic_reply);
        if (r < 0)
            return r;

        m = synthetic_reply;
    }
    else {
        r = sd_bus_message_rewind(m, true);
        if (r < 0)
            return r;
    }

    if (c->timeout_usec != 0) {
        prioq_remove(bus->reply_callbacks_prioq, c, &c->prioq_idx);
        c->timeout_usec = 0;
    }

    is_hello = bus->state == BUS_HELLO && c->callback == hello_callback;

    bus->current_slot = sd_bus_slot_ref(slot);
    bus->current_handler = c->callback;
    bus->current_userdata = slot->userdata;
    r = c->callback(m, slot->userdata, &error_buffer);
    bus->current_userdata = NULL;
    bus->current_handler = NULL;
    bus->current_slot = NULL;

    if (slot->floating)
        bus_slot_disconnect(slot, true);

    sd_bus_slot_unref(slot);

    /* When this is the hello message and it failed, then make sure to propagate the error up, don't just log and
     * ignore the callback handler's return value. */
    if (is_hello)
        return r;

    return bus_maybe_reply_error(m, r, &error_buffer);
}

static int process_filter(sd_bus* bus, sd_bus_message* m) {
    _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
    struct filter_callback* l;
    int r;

    assert(bus);
    assert(m);

    do {
        bus->filter_callbacks_modified = false;

        LIST_FOREACH(callbacks, l, bus->filter_callbacks) {
            sd_bus_slot* slot;

            if (bus->filter_callbacks_modified)
                break;

            /* Don't run this more than once per iteration */
            if (l->last_iteration == bus->iteration_counter)
                continue;

            l->last_iteration = bus->iteration_counter;

            r = sd_bus_message_rewind(m, true);
            if (r < 0)
                return r;

            slot = container_of(l, sd_bus_slot, filter_callback);

            bus->current_slot = sd_bus_slot_ref(slot);
            bus->current_handler = l->callback;
            bus->current_userdata = slot->userdata;
            r = l->callback(m, slot->userdata, &error_buffer);
            bus->current_userdata = NULL;
            bus->current_handler = NULL;
            bus->current_slot = sd_bus_slot_unref(slot);

            r = bus_maybe_reply_error(m, r, &error_buffer);
            if (r != 0)
                return r;

        }

    } while (bus->filter_callbacks_modified);

    return 0;
}

static int process_match(sd_bus* bus, sd_bus_message* m) {
    int r;

    assert(bus);
    assert(m);

    do {
        bus->match_callbacks_modified = false;

        r = bus_match_run(bus, &bus->match_callbacks, m);
        if (r != 0)
            return r;

    } while (bus->match_callbacks_modified);

    return 0;
}

static int process_builtin(sd_bus* bus, sd_bus_message* m) {
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* reply = NULL;
    int r;

    assert(bus);
    assert(m);

    if (bus->is_monitor)
        return 0;

    if (bus->manual_peer_interface)
        return 0;

    if (m->header->type != SD_BUS_MESSAGE_METHOD_CALL)
        return 0;

    if (!streq_ptr(m->interface, "org.freedesktop.DBus.Peer"))
        return 0;

    if (m->header->flags & BUS_MESSAGE_NO_REPLY_EXPECTED)
        return 1;

    if (streq_ptr(m->member, "Ping"))
        r = sd_bus_message_new_method_return(m, &reply);
    else if (streq_ptr(m->member, "GetMachineId")) {
        sd_id128_t id;

        r = sd_id128_get_machine(&id);
        if (r < 0)
            return r;

        r = sd_bus_message_new_method_return(m, &reply);
        if (r < 0)
            return r;

        //r = sd_bus_message_append(reply, "s", SD_ID128_TO_STRING(id));
        char idbuf[SD_ID128_STRING_MAX];
        char* id128 = sd_id128_to_string(id, idbuf);
        sd_bus_message_append(reply, "s", id128);

    }
    else {
        r = sd_bus_message_new_method_errorf(
            m, &reply,
            SD_BUS_ERROR_UNKNOWN_METHOD,
            "Unknown method '%s' on interface '%s'.", m->member, m->interface);
    }
    if (r < 0)
        return r;

    r = sd_bus_send(bus, reply, NULL);
    if (r < 0)
        return r;

    return 1;
}

static int process_fd_check(sd_bus* bus, sd_bus_message* m) {
    assert(bus);
    assert(m);

    /* If we got a message with a file descriptor which we didn't
     * want to accept, then let's drop it. How can this even
     * happen? For example, when the kernel queues a message into
     * an activatable names's queue which allows fds, and then is
     * delivered to us later even though we ourselves did not
     * negotiate it. */

    if (bus->is_monitor)
        return 0;

    if (m->n_fds <= 0)
        return 0;

    if (bus->accept_fd)
        return 0;

    if (m->header->type != SD_BUS_MESSAGE_METHOD_CALL)
        return 1; /* just eat it up */

    return sd_bus_reply_method_errorf(m, SD_BUS_ERROR_INCONSISTENT_MESSAGE, "Message contains file descriptors, which I cannot accept. Sorry.");
}

static int process_message(sd_bus* bus, sd_bus_message* m) {
    int r;

    assert(bus);
    assert(m);

    bus->current_message = m;
    bus->iteration_counter++;

    log_debug_bus_message(m);

    r = process_hello(bus, m);
    if (r != 0)
        goto finish;

    r = process_reply(bus, m);
    if (r != 0)
        goto finish;

    r = process_fd_check(bus, m);
    if (r != 0)
        goto finish;

    r = process_filter(bus, m);
    if (r != 0)
        goto finish;

    r = process_match(bus, m);
    if (r != 0)
        goto finish;

    r = process_builtin(bus, m);
    if (r != 0)
        goto finish;

    r = bus_process_object(bus, m);

finish:
    bus->current_message = NULL;
    return r;
}

static int dispatch_track(sd_bus* bus) {
    assert(bus);

    if (!bus->track_queue)
        return 0;

    bus_track_dispatch(bus->track_queue);
    return 1;
}

static int bus_read_message(sd_bus* bus) {
    assert(bus);

    return bus_socket_read_message(bus);
}

static void rqueue_drop_one(sd_bus* bus, size_t i) {
    assert(bus);
    assert(i < bus->rqueue_size);

    bus_message_unref_queued(bus->rqueue[i], bus);
    memmove(bus->rqueue + i, bus->rqueue + i + 1, sizeof(sd_bus_message*) * (bus->rqueue_size - i - 1));
    bus->rqueue_size--;
}

static int dispatch_rqueue(sd_bus* bus, sd_bus_message** m) {
    int r, ret = 0;

    assert(bus);
    assert(m);
    //assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));
    assert((bus->state == BUS_RUNNING || bus->state == BUS_HELLO));

    for (;;) {
        if (bus->rqueue_size > 0) {
            /* Dispatch a queued message */
            *m = sd_bus_message_ref(bus->rqueue[0]);
            rqueue_drop_one(bus, 0);
            return 1;
        }

        /* Try to read a new message */
        r = bus_read_message(bus);
        if (r < 0)
            return r;
        if (r == 0) {
            *m = NULL;
            return ret;
        }

        ret = 1;
    }
}

static int process_running(sd_bus* bus, sd_bus_message** ret) {
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL;
    int r;

    assert(bus);
    //assert(IN_SET(bus->state, BUS_RUNNING, BUS_HELLO));
    assert((bus->state == BUS_RUNNING || bus->state == BUS_HELLO));

    r = process_timeout(bus);
    if (r != 0)
        goto null_message;

    r = dispatch_wqueue(bus);
    if (r != 0)
        goto null_message;

    r = dispatch_track(bus);
    if (r != 0)
        goto null_message;

    r = dispatch_rqueue(bus, &m);
    if (r < 0)
        return r;
    if (!m)
        goto null_message;

    r = process_message(bus, m);
    if (r != 0)
        goto null_message;

    if (ret) {
        r = sd_bus_message_rewind(m, true);
        if (r < 0)
            return r;

        //*ret = TAKE_PTR(m);
        *ret = m;
        m = NULL;
        return 1;
    }

    if (m->header->type == SD_BUS_MESSAGE_METHOD_CALL) {

        log_debug("Unprocessed message call sender=%s object=%s interface=%s member=%s",
            strna(sd_bus_message_get_sender(m)),
            strna(sd_bus_message_get_path(m)),
            strna(sd_bus_message_get_interface(m)),
            strna(sd_bus_message_get_member(m)));

        r = sd_bus_reply_method_errorf(
            m,
            SD_BUS_ERROR_UNKNOWN_OBJECT,
            "Unknown object '%s'.", m->path);
        if (r < 0)
            return r;
    }

    return 1;

null_message:
    if (r >= 0 && ret)
        *ret = NULL;

    return r;
}

static int bus_exit_now(sd_bus* bus) {
    assert(bus);

    /* Exit due to close, if this is requested. If this is bus object is attached to an event source, invokes
     * sd_event_exit(), otherwise invokes libc exit(). */

    if (bus->exited) /* did we already exit? */
        return 0;
    if (!bus->exit_triggered) /* was the exit condition triggered? */
        return 0;
    if (!bus->exit_on_disconnect) /* Shall we actually exit on disconnection? */
        return 0;

    bus->exited = true; /* never exit more than once */

    log_debug("Bus connection disconnected, exiting.");

    if (bus->event)
        return sd_event_exit(bus->event, EXIT_FAILURE);
    else
        exit(EXIT_FAILURE);

    assert_not_reached();
}

static int process_closing_reply_callback(sd_bus* bus, struct reply_callback* c) {
    _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL;
    sd_bus_slot* slot;
    int r;

    assert(bus);
    assert(c);

    r = bus_message_new_synthetic_error(
        bus,
        c->cookie,
        &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_NO_REPLY, "Connection terminated"),
        &m);
    if (r < 0)
        return r;

    m->read_counter = ++bus->read_counter;

    r = bus_seal_synthetic_message(bus, m);
    if (r < 0)
        return r;

    if (c->timeout_usec != 0) {
        prioq_remove(bus->reply_callbacks_prioq, c, &c->prioq_idx);
        c->timeout_usec = 0;
    }

    ordered_hashmap_remove(bus->reply_callbacks, &c->cookie);
    c->cookie = 0;

    slot = container_of(c, sd_bus_slot, reply_callback);

    bus->iteration_counter++;

    bus->current_message = m;
    bus->current_slot = sd_bus_slot_ref(slot);
    bus->current_handler = c->callback;
    bus->current_userdata = slot->userdata;
    r = c->callback(m, slot->userdata, &error_buffer);
    bus->current_userdata = NULL;
    bus->current_handler = NULL;
    bus->current_slot = NULL;
    bus->current_message = NULL;

    if (slot->floating)
        bus_slot_disconnect(slot, true);

    sd_bus_slot_unref(slot);

    return bus_maybe_reply_error(m, r, &error_buffer);
}

static int process_closing(sd_bus* bus, sd_bus_message** ret) {
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL;
    struct reply_callback* c;
    int r;

    assert(bus);
    assert(bus->state == BUS_CLOSING);

    /* First, fail all outstanding method calls */
    c = ordered_hashmap_first(bus->reply_callbacks);
    if (c)
        return process_closing_reply_callback(bus, c);

    /* Then, fake-drop all remaining bus tracking references */
    if (bus->tracks) {
        bus_track_close(bus->tracks);
        return 1;
    }

    /* Then, synthesize a Disconnected message */
    r = sd_bus_message_new_signal(
        bus,
        &m,
        "/org/freedesktop/DBus/Local",
        "org.freedesktop.DBus.Local",
        "Disconnected");
    if (r < 0)
        return r;

    bus_message_set_sender_local(bus, m);
    m->read_counter = ++bus->read_counter;

    r = bus_seal_synthetic_message(bus, m);
    if (r < 0)
        return r;

    sd_bus_close(bus);

    bus->current_message = m;
    bus->iteration_counter++;

    r = process_filter(bus, m);
    if (r != 0)
        goto finish;

    r = process_match(bus, m);
    if (r != 0)
        goto finish;

    /* Nothing else to do, exit now, if the condition holds */
    bus->exit_triggered = true;
    (void)bus_exit_now(bus);

    if (ret) {
        //*ret = TAKE_PTR(m);
        *ret = m;
        m = NULL;
    }
    r = 1;

finish:
    bus->current_message = NULL;

    return r;
}

static int bus_process_internal(sd_bus* bus, sd_bus_message** ret) {
    int r;

    /* Returns 0 when we didn't do anything. This should cause the
     * caller to invoke sd_bus_wait() before returning the next
     * time. Returns > 0 when we did something, which possibly
     * means *ret is filled in with an unprocessed message. */

    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    /* We don't allow recursively invoking sd_bus_process(). */
    assert_return(!bus->current_message, -EBUSY);
    assert(!bus->current_slot); /* This should be NULL whenever bus->current_message is */

    BUS_DONT_DESTROY(bus);

    switch (bus->state) {

    case BUS_UNSET:
        return -ENOTCONN;

    case BUS_CLOSED:
        return -ECONNRESET;

    case BUS_WATCH_BIND:
        r = bus_socket_process_watch_bind(bus);
        break;

    case BUS_OPENING:
        r = bus_socket_process_opening(bus);
        break;

    case BUS_AUTHENTICATING:
        r = bus_socket_process_authenticating(bus);
        break;

    case BUS_RUNNING:
    case BUS_HELLO:
        r = process_running(bus, ret);
        if (r >= 0)
            return r;

        /* This branch initializes *ret, hence we don't use the generic error checking below */
        break;

    case BUS_CLOSING:
        return process_closing(bus, ret);

    default:
        assert_not_reached();
    }

    if (ERRNO_IS_DISCONNECT(r)) {
        bus_enter_closing(bus);
        r = 1;
    }
    else if (r < 0)
        return r;

    if (ret)
        *ret = NULL;

    return r;
}

_public_ int sd_bus_process(sd_bus* bus, sd_bus_message** ret) {
    return bus_process_internal(bus, ret);
}



int bus_rqueue_make_room(sd_bus* bus) {
    assert(bus);

    if (bus->rqueue_size >= BUS_RQUEUE_MAX)
        return -ENOBUFS;

    if (!GREEDY_REALLOC(bus->rqueue, bus->rqueue_size + 1))
        return -ENOMEM;

    return 0;
}



_public_ int sd_bus_get_events(sd_bus* bus) {
    int flags = 0;

    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    switch (bus->state) {

    case BUS_UNSET:
    case BUS_CLOSED:
        return -ENOTCONN;

    case BUS_WATCH_BIND:
        flags |= POLLIN;
        break;

    case BUS_OPENING:
        flags |= POLLOUT;
        break;

    case BUS_AUTHENTICATING:
        if (bus_socket_auth_needs_write(bus))
            flags |= POLLOUT;

        flags |= POLLIN;
        break;

    case BUS_RUNNING:
    case BUS_HELLO:
        if (bus->rqueue_size <= 0)
            flags |= POLLIN;
        if (bus->wqueue_size > 0)
            flags |= POLLOUT;
        break;

    case BUS_CLOSING:
        break;

    default:
        assert_not_reached();
    }

    return flags;
}



int bus_next_address(sd_bus* b) {
    assert(b);

    bus_reset_parsed_address(b);
    return bus_start_address(b);
}

_public_ int sd_bus_get_timeout(sd_bus* bus, uint64_t* timeout_usec) {
    struct reply_callback* c;

    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);
    assert_return(timeout_usec, -EINVAL);
    assert_return(!bus_pid_changed(bus), -ECHILD);

    if (!BUS_IS_OPEN(bus->state) && bus->state != BUS_CLOSING)
        return -ENOTCONN;

    if (bus->track_queue) {
        *timeout_usec = 0;
        return 1;
    }

    switch (bus->state) {

    case BUS_AUTHENTICATING:
        *timeout_usec = bus->auth_timeout;
        return 1;

    case BUS_RUNNING:
    case BUS_HELLO:
        if (bus->rqueue_size > 0) {
            *timeout_usec = 0;
            return 1;
        }

        c = prioq_peek(bus->reply_callbacks_prioq);
        if (!c) {
            *timeout_usec = UINT64_MAX;
            return 0;
        }

        if (c->timeout_usec == 0) {
            *timeout_usec = UINT64_MAX;
            return 0;
        }

        *timeout_usec = c->timeout_usec;
        return 1;

    case BUS_CLOSING:
        *timeout_usec = 0;
        return 1;

    case BUS_WATCH_BIND:
    case BUS_OPENING:
        *timeout_usec = UINT64_MAX;
        return 0;

    default:
        assert_not_reached();
    }
}

_public_ void sd_bus_close(sd_bus* bus) {
    if (!bus)
        return;
    if (bus->state == BUS_CLOSED)
        return;
    if (bus_pid_changed(bus))
        return;

    /* Don't leave ssh hanging around */
    bus_kill_exec(bus);

    bus_set_state(bus, BUS_CLOSED);

    sd_bus_detach_event(bus);

    /* Drop all queued messages so that they drop references to
     * the bus object and the bus may be freed */
    bus_reset_queues(bus);

    bus_close_io_fds(bus);
    bus_close_inotify_fd(bus);
}

_public_ int sd_bus_detach_event(sd_bus* bus) {
    assert_return(bus, -EINVAL);
    assert_return(bus = bus_resolve(bus), -ENOPKG);

    if (!bus->event)
        return 0;

    bus_detach_io_events(bus);
    bus->inotify_event_source = sd_event_source_disable_unref(bus->inotify_event_source);
    bus->time_event_source = sd_event_source_disable_unref(bus->time_event_source);
    bus->quit_event_source = sd_event_source_disable_unref(bus->quit_event_source);

    bus->event = sd_event_unref(bus->event);
    return 1;
}

int bus_attach_io_events(sd_bus* bus) {

#if ENABLE_IO_EVENTS
    int r;

    assert(bus);

    if (bus->input_fd < 0)
        return 0;

    if (!bus->event)
        return 0;

    if (!bus->input_io_event_source) {
        r = sd_event_add_io(bus->event, &bus->input_io_event_source, bus->input_fd, 0, io_callback, bus);
        if (r < 0)
            return r;

        r = sd_event_source_set_prepare(bus->input_io_event_source, prepare_callback);
        if (r < 0)
            return r;

        r = sd_event_source_set_priority(bus->input_io_event_source, bus->event_priority);
        if (r < 0)
            return r;

        r = sd_event_source_set_description(bus->input_io_event_source, "bus-input");
    }
    else
        r = sd_event_source_set_io_fd(bus->input_io_event_source, bus->input_fd);

    if (r < 0)
        return r;

    if (bus->output_fd != bus->input_fd) {
        assert(bus->output_fd >= 0);

        if (!bus->output_io_event_source) {
            r = sd_event_add_io(bus->event, &bus->output_io_event_source, bus->output_fd, 0, io_callback, bus);
            if (r < 0)
                return r;

            r = sd_event_source_set_priority(bus->output_io_event_source, bus->event_priority);
            if (r < 0)
                return r;

            r = sd_event_source_set_description(bus->input_io_event_source, "bus-output");
        }
        else
            r = sd_event_source_set_io_fd(bus->output_io_event_source, bus->output_fd);

        if (r < 0)
            return r;
    }
#endif
    return 0;
}

int bus_attach_inotify_event(sd_bus* bus) {
#if ENABLE_INOTIFY_EVENT
    int r;

    assert(bus);

    if (bus->inotify_fd < 0)
        return 0;

    if (!bus->event)
        return 0;

    if (!bus->inotify_event_source) {
        r = sd_event_add_io(bus->event, &bus->inotify_event_source, bus->inotify_fd, EPOLLIN, io_callback, bus);
        if (r < 0)
            return r;

        r = sd_event_source_set_priority(bus->inotify_event_source, bus->event_priority);
        if (r < 0)
            return r;

        r = sd_event_source_set_description(bus->inotify_event_source, "bus-inotify");
    }
    else
        r = sd_event_source_set_io_fd(bus->inotify_event_source, bus->inotify_fd);
    if (r < 0)
        return r;
#endif
    return 0;
}