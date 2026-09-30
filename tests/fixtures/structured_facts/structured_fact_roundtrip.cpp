#include <cstddef>
#include <cstring>
#include <pthread.h>

struct FixtureOwner {
    int state;

    __attribute__((noinline)) void Release(int *out)
    {
        if (out != nullptr) {
            *out += state;
        }
    }
};

static FixtureOwner *g_registry[8];
static pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

extern "C" __attribute__((noinline, visibility("default"), used))
void framework_fixture_clear(FixtureOwner **slots, int index)
{
    slots[index & 7] = nullptr;
}

extern "C" __attribute__((noinline, visibility("default"), used))
int framework_structured_fact_entry(int key, char *dst, const char *src, size_t len)
{
    FixtureOwner owner;
    owner.state = key;
    int value = key;
    int slot = key & 7;

    pthread_mutex_lock(&g_mutex);
    g_registry[slot] = &owner;
    FixtureOwner *selected = g_registry[slot];
    selected->Release(&value);
    std::memcpy(dst, src, len);
    framework_fixture_clear(g_registry, slot);
    pthread_mutex_unlock(&g_mutex);

    return value;
}

extern "C" __attribute__((noinline, visibility("default"), used))
int framework_structured_fact_partial_strip(char *dst, const char *src, size_t len)
{
    if (len > 64) {
        len = 64;
    }
    std::memmove(dst, src, len);
    return static_cast<int>(len);
}
