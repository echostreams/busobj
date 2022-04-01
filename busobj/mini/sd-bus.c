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
    //prioq_free(b->reply_callbacks_prioq);

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


_public_ int sd_bus_send(sd_bus* bus, sd_bus_message* _m, uint64_t* cookie) {
    // TODO...................
    printf("sd_bus_send: %s\n", _m->destination);
    return 0;
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
    const char* e;
    usec_t usec;

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

int prioq_remove(Prioq* q, void* data, unsigned* idx) {
    /*
    struct prioq_item* i;

    if (!q)
        return 0;

    i = find_item(q, data, idx);
    if (!i)
        return 0;

    remove_item(q, i);
    */
    return 1;
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
    assert_return(c, -EINVAL);
    assert_return(capability >= 0, -EINVAL);

    if (!(c->mask & SD_BUS_CREDS_EFFECTIVE_CAPS))
        return -ENODATA;

    return 0;// has_cap(c, CAP_OFFSET_EFFECTIVE, capability);
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
    int r;

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