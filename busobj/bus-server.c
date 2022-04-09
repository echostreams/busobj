/* SPDX-License-Identifier: LGPL-2.1-or-later */

#if defined(__linux__)
#include <pthread.h>
#endif

#ifdef WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>
#include <process.h>    /* _beginthread, _endthread */
#endif

#include <stdlib.h>

#include "sd-bus.h"

#include "bus-internal.h"
#include "log.h"
#include "macro.h"
#include "memory-util.h"
#include "string-util.h"

struct context {
    int fds[2];

    bool client_negotiate_unix_fds;
    bool server_negotiate_unix_fds;

    bool client_anonymous_auth;
    bool server_anonymous_auth;
};

static void* server(void* p) {
    struct context* c = p;
    sd_bus* bus = NULL;
    sd_id128_t id;
    bool quit = false;
    int r;

    assert_se(sd_id128_randomize(&id) >= 0);

    assert_se(sd_bus_new(&bus) >= 0);
    assert_se(sd_bus_set_description(bus, "server") >= 0);
    assert_se(sd_bus_set_fd(bus, c->fds[0], c->fds[0]) >= 0);
    assert_se(sd_bus_set_server(bus, 1, id) >= 0);
    assert_se(sd_bus_set_anonymous(bus, c->server_anonymous_auth) >= 0);
    assert_se(sd_bus_negotiate_fds(bus, c->server_negotiate_unix_fds) >= 0);
    assert_se(sd_bus_start(bus) >= 0);

    while (!quit) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL, * reply = NULL;

        r = sd_bus_process(bus, &m);
        if (r < 0) {
            log_error_errno(r, "Failed to process requests: %m");
            goto fail;
        }

        if (r == 0) {
            r = sd_bus_wait(bus, UINT64_MAX);
            if (r < 0) {
                log_error_errno(r, "Failed to wait: %m");
                goto fail;
            }

            continue;
        }

        if (!m)
            continue;

        log_info("Got message! member=%s", strna(sd_bus_message_get_member(m)));

        if (sd_bus_message_is_method_call(m, "org.freedesktop.systemd.test", "Exit")) {

            assert_se((sd_bus_can_send(bus, 'h') >= 1) ==
                (c->server_negotiate_unix_fds && c->client_negotiate_unix_fds));

            r = sd_bus_message_new_method_return(m, &reply);
            if (r < 0) {
                log_error_errno(r, "Failed to allocate return: %m");
                goto fail;
            }

            quit = true;

        }
        else if (sd_bus_message_is_method_call(m, NULL, NULL)) {
            r = sd_bus_message_new_method_error(
                m,
                &reply,
                &SD_BUS_ERROR_MAKE_CONST(SD_BUS_ERROR_UNKNOWN_METHOD, "Unknown method."));
            if (r < 0) {
                log_error_errno(r, "Failed to allocate return: %m");
                goto fail;
            }
        }

        if (reply) {
            r = sd_bus_send(bus, reply, NULL);
            if (r < 0) {
                log_error_errno(r, "Failed to send reply: %m");
                goto fail;
            }
        }
    }

    r = 0;

fail:
    if (bus) {
        sd_bus_flush(bus);
        sd_bus_unref(bus);
    }

    return INT_TO_PTR(r);
}

static int client(struct context* c) {
    _cleanup_(sd_bus_message_unrefp) sd_bus_message* m = NULL, * reply = NULL;
    _cleanup_(sd_bus_unrefp) sd_bus* bus = NULL;
    _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
    int r;

    assert_se(sd_bus_new(&bus) >= 0);
    assert_se(sd_bus_set_description(bus, "client") >= 0);
    assert_se(sd_bus_set_fd(bus, c->fds[1], c->fds[1]) >= 0);
    assert_se(sd_bus_negotiate_fds(bus, c->client_negotiate_unix_fds) >= 0);
    assert_se(sd_bus_set_anonymous(bus, c->client_anonymous_auth) >= 0);
    assert_se(sd_bus_start(bus) >= 0);

    r = sd_bus_message_new_method_call(
        bus,
        &m,
        "org.freedesktop.systemd.test",
        "/",
        "org.freedesktop.systemd.test",
        "Exit");
    if (r < 0)
        return log_error_errno(r, "Failed to allocate method call: %m");

    r = sd_bus_call(bus, m, 0, &error, &reply);
    if (r < 0)
        return log_error_errno(r, "Failed to issue method call: %s", bus_error_message(&error, r));

    return 0;
}

static int test_one(bool client_negotiate_unix_fds, bool server_negotiate_unix_fds,
    bool client_anonymous_auth, bool server_anonymous_auth) {

    struct context c;
#ifdef WIN32
    HANDLE s[2];
    DWORD dwThreadId[2];
#else
    pthread_t s;
#endif
    void* p;
    int r, q;

    zero(c);

    assert_se(socketpair(AF_UNIX, SOCK_STREAM, 0, c.fds) >= 0);

    c.client_negotiate_unix_fds = client_negotiate_unix_fds;
    c.server_negotiate_unix_fds = server_negotiate_unix_fds;
    c.client_anonymous_auth = client_anonymous_auth;
    c.server_anonymous_auth = server_anonymous_auth;

#ifdef WIN32
    s[0] = _beginthread(server, 0, &c);
    s[1] = _beginthread(client, 0, &c);
    /*
    s = CreateThread(NULL,      // default security attributes
        0,                      // use default stack size  
        server,                 // thread function name
        &c,                     // argument to thread function 
        0,                      // use default creation flags 
        &dwThreadId);
    */
    if (s[0] == INVALID_HANDLE_VALUE)
        return -1;
    if (s[1] == INVALID_HANDLE_VALUE)
        return -1;

#else    

    r = pthread_create(&s, NULL, server, &c);
    if (r != 0)
        return -r;


    r = client(&c);

#endif

#ifdef WIN32
    
    
    // Wait until all threads have terminated.

    WaitForMultipleObjects(2, s, TRUE, INFINITE);
    GetExitCodeThread(s[0], &r);
    GetExitCodeThread(s[1], &p);
    CloseHandle(s[0]);
    CloseHandle(s[1]);

#else

    q = pthread_join(s, &p);
    if (q != 0)
        return -q;
#endif

    if (r < 0)
        return r;

    if (PTR_TO_INT(p) < 0)
        return PTR_TO_INT(p);

    return 0;
}

int main(int argc, char* argv[]) {
    int r;

    log_set_max_level(LOG_DEBUG);

    r = test_one(true, true, false, false);
    assert_se(r >= 0);

    r = test_one(true, false, false, false);
    assert_se(r >= 0);

    r = test_one(false, true, false, false);
    assert_se(r >= 0);

    r = test_one(false, false, false, false);
    assert_se(r >= 0);

    r = test_one(true, true, true, true);
    assert_se(r >= 0);

    r = test_one(true, true, false, true);
    assert_se(r >= 0);

    printf("=========================\n");
    r = test_one(true, true, true, false);
    assert_se(r == -EPERM);

    return EXIT_SUCCESS;
}
