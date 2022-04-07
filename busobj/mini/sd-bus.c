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
#define	ENOMEDIUM	123	/* No medium found */
#endif

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

    //bus_reset_queues(b);

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

#if 0

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

#endif

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
