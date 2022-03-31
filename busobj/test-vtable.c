/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdbool.h>
#include <stddef.h>

/* We use system assert.h here, because we don't want to keep macro.h and log.h C++ compatible */
#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdio.h>

#include "systemd/src/systemd/sd-bus-vtable.h"

#include "hashmap.h"
#include "set.h"
#include "strv.h"
#include "xml.h"
#include "path-util.h"
#include "systemd/src/busctl/busctl-introspect.h"

#ifndef __cplusplus
#  include "systemd/src/libsystemd/sd-bus/bus-objects.h"
#endif

#include "systemd/src/libsystemd/sd-bus/test-vtable-data.h"

#define DEFAULT_BUS_PATH "unix:path=/run/dbus/system_bus_socket"

static struct context c;// = {};
static int happy_finder_object = 0;

static int happy_finder(sd_bus* bus, const char* path, const char* interface, void* userdata, void** found, sd_bus_error* error) {
    assert(userdata);
    assert(userdata == &c);

#ifndef __cplusplus
    //log_info
    printf
    ("%s called", __func__);
#endif

    happy_finder_object++;
    *found = &happy_finder_object;
    return 1; /* found */
}

static void print_subtree(const char* prefix, const char* path, char** l) {
    const char* vertical, * space;
    char** n;

    /* We assume the list is sorted. Let's first skip over the
     * entry we are looking at. */
    for (;;) {
        if (!*l)
            return;

        if (!streq(*l, path))
            break;

        l++;
    }

    //vertical = strjoina(prefix, special_glyph(SPECIAL_GLYPH_TREE_VERTICAL));
    vertical = prefix;
    //space = strjoina(prefix, special_glyph(SPECIAL_GLYPH_TREE_SPACE));
    space = prefix;

    for (;;) {
        bool has_more = false;

        if (!*l || !path_startswith(*l, path))
            break;

        n = l + 1;
        for (;;) {
            if (!*n || !path_startswith(*n, path))
                break;

            if (!path_startswith(*n, *l)) {
                has_more = true;
                break;
            }

            n++;
        }

        //printf("%s%s%s\n",
        //    prefix,
        //    special_glyph(has_more ? SPECIAL_GLYPH_TREE_BRANCH : SPECIAL_GLYPH_TREE_RIGHT),
        //    *l);
        printf("%s %s\n", prefix, *l);

        print_subtree(has_more ? vertical : space, *l, l);
        l = n;
    }
}
bool arg_list = false;
static void print_tree(char** l) {
    if (arg_list)
        strv_print(l);
    else if (strv_isempty(l))
        printf("No objects discovered.\n");
    else if (streq(l[0], "/") && !l[1])
        printf("Only root object discovered.\n");
    else
        print_subtree("", "/", l);
}

static int on_path(const char* path, void* userdata) {
    Set* paths = userdata;
    int r;

    assert(paths);

    r = set_put_strdup(&paths, path);
    if (r < 0)
        return log_oom();

    return 0;
}

static int find_nodes(sd_bus* bus, const char* service, const char* path, Set* paths) {
    static const XMLIntrospectOps ops = {
            .on_path = on_path,
    };

    _cleanup_(sd_bus_message_unrefp) sd_bus_message* reply = NULL;
    _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
    char* xml;
    int r;

    //r = sd_bus_call_method(bus, service, path,
    //    "org.freedesktop.DBus.Introspectable", "Introspect",
    //    &error, &reply, NULL);

    r = introspect_path(bus, path, NULL, false, true, NULL, &xml, NULL);
    if (r <= 0) {
        printf("Failed to introspect object %s of service %s: %s\n",
            path, service, bus_error_message(&error, r));
        return r;
    }

    //r = sd_bus_message_read(reply, "s", &xml);
    //if (r < 0)
    //    return bus_log_parse_error(r);

    return parse_xml_introspect(path, xml, &ops, paths);
}

static int tree_one(sd_bus* bus, const char* service) {
    /*_cleanup_set_free_*/ Set* paths = NULL, * done = NULL, * failed = NULL;
    _cleanup_free_ char** l = NULL;
    int r;

    r = set_put_strdup(&paths, "/");
    if (r < 0)
        return log_oom();

    for (;;) {
        _cleanup_free_ char* p = NULL;
        int q;

        p = set_steal_first(paths);
        
        if (!p)
            break;

        if (set_contains(done, p) ||
            set_contains(failed, p))
            continue;

        q = find_nodes(bus, service, p, paths);
        printf("*** find_nodes: %d\n", q);
        if (q < 0 && r >= 0)
            r = q;

        //q = set_ensure_consume(q < 0 ? &failed : &done, & string_hash_ops_free, TAKE_PTR(p));
        printf("*** p = %s\n", p);
        q = set_ensure_consume(q < 0 ? &failed : &done, & string_hash_ops_free, /*TAKE_PTR*/(p));
        p = NULL;
        printf("*** set_ensure_consume: %d\n", q);
        assert(q != 0);
        if (q < 0)
            return log_oom();
    }

    //pager_open(arg_pager_flags);

    l = set_get_strv(done);
    if (!l)
        return log_oom();

    strv_sort(l);
    print_tree(l);

    fflush(stdout);

    return r;
}

static void test_vtable(void) {
    sd_bus* bus = NULL;
    int r;

    assert(sd_bus_new(&bus) >= 0);

    
    //sd_bus_add_object_manager(bus, NULL, "/");

    assert(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.testVtable", test_vtable_2, &c) >= 0);
    assert(sd_bus_add_object_vtable(bus, NULL, "/foo", "org.freedesktop.systemd.testVtable2", test_vtable_2, &c) >= 0);
    /* the cast on the line below is needed to test with the old version of the table */
    assert(sd_bus_add_object_vtable(bus, NULL, "/foo/bar", "org.freedesktop.systemd.testVtable221",
        (const sd_bus_vtable*)vtable_format_221, &c) >= 0);

    assert(sd_bus_add_fallback_vtable(bus, NULL, "/fallback", "org.freedesktop.systemd.testVtable2", test_vtable_2, happy_finder, &c) >= 0);
        
    //assert(sd_bus_set_address(bus, DEFAULT_BUS_PATH) >= 0);
    //r = sd_bus_start(bus);
    //assert(r == 0 ||     /* success */
    //    r == -ENOENT  /* dbus is inactive */);

#ifndef __cplusplus
    /*_cleanup_free_*/ char* s = NULL, * s2 = NULL, * s3 = NULL;

    assert_se(introspect_path(bus, "/foo", NULL, false, true, NULL, &s, NULL) == 1);
    fputs(s, stdout);

    assert_se(introspect_path(bus, "/fallback", NULL, false, true, NULL, &s2, NULL) == 1);    
    fputs(s2, stdout);

    
    

    int n = introspect_path(bus, "/", NULL, false, true, NULL, &s3, NULL);
    printf("'/' = %d\n", n);
    if (s3 != NULL)
        fputs(s3, stdout);

    if (s != NULL)
        free(s);
    if (s2 != NULL)
        free(s2);
    if (s3 != NULL)
        free(s3);

    assert_se(happy_finder_object == 1);

    printf("--------------\n");
    bus->nodes_modified = false;
    tree_one(bus, "test.service");

    
#endif

    sd_bus_unref(bus);
}

void test_set_ensure_consume() {
    _cleanup_set_free_ Set* m = NULL;
    char* s, * t;

    assert_se(s = strdup("a"));
    assert_se(set_ensure_consume(&m, &string_hash_ops_free, s) == 1);

    assert_se(t = strdup("a"));
    assert_se(set_ensure_consume(&m, &string_hash_ops_free, t) == 0);

    assert_se(t = strdup("a"));
    assert_se(set_ensure_consume(&m, &string_hash_ops_free, t) == 0);

    assert_se(t = strdup("b"));
    assert_se(set_ensure_consume(&m, &string_hash_ops_free, t) == 1);

    assert_se(t = strdup("b"));
    assert_se(set_ensure_consume(&m, &string_hash_ops_free, t) == 0);

    assert_se(set_size(m) == 2);
}

void test_hashmap_remove1() {
    _cleanup_hashmap_free_ Hashmap* m = NULL;
    char* r;

    r = hashmap_remove(NULL, "key 1");
    assert_se(r == NULL);

    m = hashmap_new(&string_hash_ops);
    assert_se(m);

    r = hashmap_remove(m, "no such key");
    assert_se(r == NULL);

    hashmap_put(m, "key 1", (void*)"val 1");
    hashmap_put(m, "key 2", (void*)"val 2");

    r = hashmap_remove(m, "key 1");
    assert_se(streq(r, "val 1"));

    r = hashmap_get(m, "key 2");
    assert_se(streq(r, "val 2"));
    assert_se(!hashmap_get(m, "key 1"));
}


int main(int argc, char** argv) {
    //test_hashmap_remove1();
    //test_set_ensure_consume();
    test_vtable();

    return 0;
}
