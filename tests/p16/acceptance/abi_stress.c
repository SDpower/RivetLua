#include "lua.h"
#include "lauxlib.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { STRESS_ITERATIONS = 1024, STRESS_WARMUP = 128 };
static const uint32_t stress_seed = UINT32_C(0x16c0ffee);
static const uint64_t stress_magic = UINT64_C(0x16a110ca7e5afe55);

extern int rivetlua_capi_configure_load_limits_b3(
    lua_State *state, size_t source, size_t encoded, size_t module,
    size_t temporary, size_t work, size_t chunks, size_t paths);

typedef struct stress_record {
  void *pointer;
  size_t size;
  uint64_t token;
  int active;
  struct stress_record *next;
} stress_record;
typedef struct stress_header {
  max_align_t alignment;
  uint64_t magic;
  uint64_t token;
  size_t size;
} stress_header;
typedef struct stress_tracker {
  stress_record *records;
  uint64_t next_token;
  size_t issued_tokens;
  size_t refunded_tokens;
  size_t active_tokens;
  size_t live_bytes;
  size_t peak_bytes;
  size_t invalid_pairs;
  size_t duplicate_refunds;
} stress_tracker;

static stress_record *stress_find(stress_tracker *tracker, void *pointer) {
  stress_record *record;
  for (record = tracker->records; record != NULL; record = record->next)
    if (record->pointer == pointer && record->active) return record;
  for (record = tracker->records; record != NULL; record = record->next)
    if (record->pointer == pointer) {
      tracker->duplicate_refunds++;
      return NULL;
    }
  tracker->invalid_pairs++;
  return NULL;
}

static void *stress_alloc(void *ud, void *pointer, size_t old_size, size_t new_size) {
  stress_tracker *tracker = (stress_tracker *)ud;
  stress_record *old = NULL;
  stress_header *header;
  if (pointer != NULL) {
    old = stress_find(tracker, pointer);
    if (old == NULL) return NULL;
    header = ((stress_header *)pointer) - 1;
    if (old->size != old_size || header->magic != stress_magic ||
        header->token != old->token || header->size != old_size) {
      tracker->invalid_pairs++;
      return NULL;
    }
    if (tracker->live_bytes < old_size) {
      tracker->invalid_pairs++;
      return NULL;
    }
  }
  if (new_size == 0) {
    if (old != NULL) {
      old->active = 0;
      tracker->active_tokens--;
      tracker->refunded_tokens++;
      tracker->live_bytes -= old_size;
      header->magic = 0;
      free(header);
    }
    return NULL;
  }
  if (new_size > SIZE_MAX - sizeof(stress_header) ||
      new_size > SIZE_MAX - (tracker->live_bytes - (old == NULL ? 0 : old_size)))
    return NULL;
  stress_record *record = (stress_record *)malloc(sizeof(*record));
  if (record == NULL) return NULL;
  if (old == NULL) {
    header = (stress_header *)malloc(sizeof(*header) + new_size);
  } else {
    header = (stress_header *)realloc(header, sizeof(*header) + new_size);
  }
  if (header == NULL) {
    free(record);
    return NULL;
  }
  if (old != NULL) {
    old->active = 0;
    tracker->active_tokens--;
    tracker->refunded_tokens++;
    tracker->live_bytes -= old_size;
  }
  record->pointer = header + 1;
  record->size = new_size;
  record->token = ++tracker->next_token;
  record->active = 1;
  record->next = tracker->records;
  tracker->records = record;
  header->magic = stress_magic;
  header->token = record->token;
  header->size = new_size;
  tracker->issued_tokens++;
  tracker->active_tokens++;
  tracker->live_bytes += new_size;
  if (tracker->live_bytes > tracker->peak_bytes)
    tracker->peak_bytes = tracker->live_bytes;
  return header + 1;
}

static lua_State *stress_newstate(stress_tracker *tracker) {
#if LUA_VERSION_NUM >= 505
  return lua_newstate(stress_alloc, tracker, 0U);
#else
  return lua_newstate(stress_alloc, tracker);
#endif
}

static int stress_inner_error(lua_State *state) {
  return luaL_error(state, "p16-stress-inner");
}

static int stress_outer_callback(lua_State *state) {
  lua_Integer input = lua_tointeger(state, 1);
  lua_pushcfunction(state, stress_inner_error);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN ||
      lua_type(state, -1) != LUA_TSTRING) return luaL_error(state, "nested error failed");
  lua_pop(state, 1);
  lua_pushinteger(state, input + 1);
  return 1;
}

static int stress_yield(lua_State *state) {
  lua_pushinteger(state, lua_tointeger(state, 1));
  return lua_yield(state, 1);
}

static int stress_debug(lua_State *state) {
  lua_Debug frame;
  int top = lua_gettop(state);
  if (!lua_getstack(state, 0, &frame) || !lua_getinfo(state, "S", &frame) ||
      frame.what == NULL || strcmp(frame.what, "C") != 0)
    return luaL_error(state, "debug frame failed");
  const char *name = lua_getlocal(state, &frame, 1);
  if (name == NULL || lua_gettop(state) != top + 1 ||
      lua_tointeger(state, -1) != 33)
    return luaL_error(state, "debug local failed");
  lua_pop(state, 1);
  lua_pushinteger(state, 34);
  return 1;
}

static uint32_t stress_next(uint32_t *seed) {
  *seed = *seed * UINT32_C(1664525) + UINT32_C(1013904223);
  return *seed;
}

int main(void) {
  stress_tracker tracker = {0};
  lua_State *state = stress_newstate(&tracker);
  if (state == NULL) return 1;
  uint32_t sequence = stress_seed;
  int callback_count = 0, gc_count = 0, coroutine_count = 0, debug_ref_count = 0;
  size_t warm_active = 0;
  size_t warm_bytes = 0;
  int stable_samples = 0;
  lua_pushcfunction(state, stress_debug);
  lua_setglobal(state, "stress_observe");
  if (rivetlua_capi_configure_load_limits_b3(
          state, 64 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
          1024 * 1024, 2 * 1000 * 1000, 256, 256) != 1) return 20;
  if (luaL_loadstring(state, "local value = 33; return stress_observe(value)") != LUA_OK) {
    fprintf(stderr, "P16_STRESS load failed: %s active=%zu issued=%zu refunded=%zu invalid=%zu duplicate=%zu\n",
            lua_tostring(state, -1), tracker.active_tokens, tracker.issued_tokens,
            tracker.refunded_tokens, tracker.invalid_pairs, tracker.duplicate_refunds);
    return 14;
  }
  int debug_chunk = luaL_ref(state, LUA_REGISTRYINDEX);
  if (debug_chunk < 0) return 15;
  for (int index = 0; index < STRESS_ITERATIONS; index++) {
    lua_Integer value = (lua_Integer)(stress_next(&sequence) & UINT32_C(0x7fffffff));
    lua_pushcfunction(state, stress_outer_callback);
    lua_pushinteger(state, value);
    if (lua_pcall(state, 1, 1, 0) != LUA_OK ||
        lua_tointeger(state, -1) != value + 1) return 2;
    lua_pop(state, 1);
    callback_count++;

    if (lua_gc(state, LUA_GCCOLLECT) != 0) return 3;
    gc_count++;

    lua_State *child = lua_newthread(state);
    if (child == NULL) return 4;
    lua_pushcfunction(child, stress_yield);
    lua_pushinteger(child, value);
    int results = -1;
    if (lua_resume(child, state, 1, &results) != LUA_YIELD || results != 1 ||
        lua_tointeger(child, -1) != value) return 5;
    lua_pop(child, 1);
    lua_pushinteger(child, value + 1);
    if (lua_resume(child, state, 1, &results) != LUA_OK || results != 1 ||
        lua_tointeger(child, -1) != value + 1) return 6;
    if (lua_resetthread(child) != LUA_OK || lua_gettop(child) != 0) return 7;
    lua_pop(state, 1);
    coroutine_count++;

    if (lua_rawgeti(state, LUA_REGISTRYINDEX, debug_chunk) != LUA_TFUNCTION ||
        lua_pcall(state, 0, 1, 0) != LUA_OK || lua_tointeger(state, -1) != 34) {
      fprintf(stderr, "P16_STRESS debug failed at %d: %s\n", index,
              lua_tostring(state, -1));
      return 8;
    }
    lua_pop(state, 1);
    lua_newtable(state);
    lua_pushinteger(state, value);
    lua_rawseti(state, -2, 1);
    int reference = luaL_ref(state, LUA_REGISTRYINDEX);
    if (reference < 0 || lua_gc(state, LUA_GCCOLLECT) != 0 ||
        lua_rawgeti(state, LUA_REGISTRYINDEX, reference) != LUA_TTABLE)
      return 9;
    lua_rawgeti(state, -1, 1);
    if (lua_tointeger(state, -1) != value) return 10;
    lua_pop(state, 2);
    luaL_unref(state, LUA_REGISTRYINDEX, reference);
    if (lua_gettop(state) != 0) return 11;
    if (lua_gc(state, LUA_GCCOLLECT) != 0) return 16;
    if (index == STRESS_WARMUP - 1) {
      warm_active = tracker.active_tokens;
      warm_bytes = tracker.live_bytes;
    }
    if (index >= STRESS_WARMUP) {
      if (tracker.active_tokens != warm_active || tracker.live_bytes != warm_bytes)
        return 17;
      stable_samples++;
    }
    debug_ref_count++;
  }
  if (callback_count != STRESS_ITERATIONS || gc_count != STRESS_ITERATIONS ||
      coroutine_count != STRESS_ITERATIONS || debug_ref_count != STRESS_ITERATIONS ||
      stable_samples != STRESS_ITERATIONS - STRESS_WARMUP)
    return 12;
  luaL_unref(state, LUA_REGISTRYINDEX, debug_chunk);
  if (lua_gc(state, LUA_GCCOLLECT) != 0) return 18;
  lua_close(state);
  if (tracker.active_tokens != 0 || tracker.live_bytes != 0 ||
      tracker.issued_tokens != tracker.refunded_tokens ||
      tracker.invalid_pairs != 0 || tracker.duplicate_refunds != 0) return 13;
  printf("P16_STRESS seed=%u iterations=%d callback=%d gc=%d coroutine=%d debug_ref=%d warmup=%d stable_samples=%d warm_active=%zu warm_bytes=%zu peak_bytes=%zu active_tokens=%zu live_bytes=%zu issued=%zu refunded=%zu invalid_pairs=%zu duplicate_refunds=%zu\n",
         stress_seed, STRESS_ITERATIONS, callback_count, gc_count, coroutine_count,
         debug_ref_count, STRESS_WARMUP, stable_samples, warm_active,
         warm_bytes, tracker.peak_bytes, tracker.active_tokens, tracker.live_bytes,
         tracker.issued_tokens,
         tracker.refunded_tokens, tracker.invalid_pairs, tracker.duplicate_refunds);
  puts("P16_ASSERT ABI-STRESS callback_longrun=PASS");
  puts("P16_ASSERT ABI-STRESS gc=PASS");
  puts("P16_ASSERT ABI-STRESS coroutine=PASS");
  puts("P16_ASSERT ABI-STRESS debug_ref=PASS");
  puts("P16_ASSERT ABI-STRESS no_leak=PASS");
  puts("P16_C_BODY ABI-STRESS PASS");
  stress_record *record = tracker.records;
  while (record != NULL) {
    stress_record *next = record->next;
    free(record);
    record = next;
  }
  return 0;
}
