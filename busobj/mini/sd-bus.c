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


char* utf8_is_valid_n(const char* str, size_t len_bytes) {
    /* Check if the string is composed of valid utf8 characters. If length len_bytes is given, stop after
     * len_bytes. Otherwise, stop at NUL. */

    assert(str);

    for (const char* p = str; len_bytes != SIZE_MAX ? (size_t)(p - str) < len_bytes : *p != '\0'; ) {
        int len;

        if (_unlikely_(*p == '\0') && len_bytes != SIZE_MAX)
            return NULL; /* embedded NUL */

        //len = utf8_encoded_valid_unichar(p,
        //    len_bytes != SIZE_MAX ? len_bytes - (p - str) : SIZE_MAX);
        //if (_unlikely_(len < 0))
        //    return NULL; /* invalid character */

        p += len;
    }

    return (char*)str;
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