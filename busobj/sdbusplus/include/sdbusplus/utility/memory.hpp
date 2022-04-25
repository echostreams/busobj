#pragma once

#include <cstdlib>

static inline void* mfree(void* memory)
{
    free(memory);
    return NULL;
}

static inline void freep(void* p)
{
    *(void**)p = mfree(*(void**)p);
}
#define _cleanup_(x) __attribute__((__cleanup__(x)))
#define _cleanup_free_ _cleanup_(freep)
