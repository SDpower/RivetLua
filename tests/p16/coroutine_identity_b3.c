/* P16-2 B3：固定 Lua headers 下驗證 thread 身分與受保護配置錯誤。 */
#include "lua.h"
#include "lauxlib.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  int fail_next;
  size_t live;
  size_t failed;
} allocator_b3;

static void *allocate_b3(void *ud, void *pointer, size_t old_size,
                         size_t new_size) {
  allocator_b3 *state = (allocator_b3 *)ud;
  (void)old_size;
  if (new_size != 0 && state->fail_next) {
    state->fail_next = 0;
    state->failed++;
    return NULL;
  }
  if (new_size == 0) {
    if (pointer != NULL) {
      state->live--;
      free(pointer);
    }
    return NULL;
  }
  void *resized = realloc(pointer, new_size);
  if (resized != NULL && pointer == NULL) state->live++;
  return resized;
}

static lua_State *newstate_b3(allocator_b3 *allocator) {
#if LUA_VERSION_NUM >= 505
  return lua_newstate(allocate_b3, allocator, 0U);
#else
  return lua_newstate(allocate_b3, allocator);
#endif
}

typedef struct { int32_t kind; int32_t value; } action_b3;
typedef action_b3 (*action_fn_b3)(void *, uint64_t, uint64_t, void *);
typedef struct { int32_t kind; int32_t value; } outcome_b3;
extern outcome_b3 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_b3, void *);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);

typedef struct { allocator_b3 *allocator; int reached; } context_b3;

static action_b3 fail_newthread_b3(void *raw_state, uint64_t generation,
                                   uint64_t token, void *raw_context) {
  context_b3 *context = (context_b3 *)raw_context;
  (void)generation;
  (void)token;
  context->allocator->fail_next = 1;
  (void)lua_newthread((lua_State *)raw_state);
  context->reached = 1;
  return (action_b3){0, 99};
}

int main(void) {
  allocator_b3 allocator = {0};
  lua_State *main_state = newstate_b3(&allocator);
  if (main_state == NULL) return 1;
  int result = 0;
  int32_t error_class = 0;
  context_b3 context = {&allocator, 0};
  unsigned char expected[LUA_EXTRASPACE];

#define CHECK_B3(code, condition) do { if (!(condition)) { result = code; goto done; } } while (0)

  CHECK_B3(2, lua_rawgeti(main_state, LUA_REGISTRYINDEX,
                        LUA_RIDX_MAINTHREAD) == LUA_TTHREAD);
  CHECK_B3(3, lua_tothread(main_state, -1) == main_state);
  lua_pop(main_state, 1);
#if LUA_VERSION_NUM >= 505
  CHECK_B3(4, lua_rawgeti(main_state, LUA_REGISTRYINDEX, 1) == LUA_TBOOLEAN &&
              lua_toboolean(main_state, -1) == 0);
  lua_pop(main_state, 1);
#endif
  CHECK_B3(5, lua_pushthread(main_state) == 1 &&
              lua_tothread(main_state, -1) == main_state);
  lua_pop(main_state, 1);
  for (size_t index = 0; index < LUA_EXTRASPACE; ++index)
    expected[index] = ((unsigned char *)lua_getextraspace(main_state))[index] =
        (unsigned char)(0x31 + index);

  lua_State *child = lua_newthread(main_state);
  CHECK_B3(6, child != NULL && child != main_state &&
              lua_type(main_state, -1) == LUA_TTHREAD &&
              lua_tothread(main_state, -1) == child);
  CHECK_B3(7, memcmp(lua_getextraspace(child), expected, LUA_EXTRASPACE) == 0);
  memset(lua_getextraspace(child), 0x7f, LUA_EXTRASPACE);
  lua_State *grandchild = lua_newthread(child);
  CHECK_B3(8, grandchild != NULL &&
              memcmp(lua_getextraspace(grandchild), expected, LUA_EXTRASPACE) == 0);
  CHECK_B3(9, lua_pushthread(child) == 0 &&
              lua_tothread(child, -1) == child);
  lua_pushinteger(main_state, 12);
  CHECK_B3(10, lua_tothread(main_state, -1) == NULL &&
               lua_tothread(main_state, 0) == NULL);
  lua_settop(main_state, 0);

  size_t failures_before = allocator.failed;
  outcome_b3 outcome = rivetlua_capi_trampoline_protect_a1(
      main_state, fail_newthread_b3, &context);
  CHECK_B3(11, outcome.kind == 1 && outcome.value == 5 &&
               context.reached == 0 && allocator.failed == failures_before + 1);
  CHECK_B3(12, rivetlua_capi_error_consume_a1(main_state, &error_class) == 0 &&
               error_class == 5 && lua_gettop(main_state) == 1);
  lua_settop(main_state, 0);
  CHECK_B3(13, lua_newthread(main_state) != NULL &&
               lua_tothread(main_state, -1) != NULL);
  lua_settop(main_state, 0);

done:
  lua_close(main_state);
  if (result == 0 && allocator.live != 0) result = 14;
  return result;
}
