/* P16-2 B9：固定 Lua 5.5 header 的 external string ABI 與 ownership。 */
#include "lua.h"
#include "lauxlib.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  int fail_next;
  int rejected;
} allocator_b9;

static void *allocate_b9(void *ud, void *pointer, size_t old_size,
                         size_t new_size) {
  allocator_b9 *allocator = (allocator_b9 *)ud;
  (void)old_size;
  if (new_size == 0) { free(pointer); return NULL; }
  if (allocator->fail_next) {
    allocator->fail_next = 0;
    allocator->rejected++;
    return NULL;
  }
  return realloc(pointer, new_size);
}

typedef struct {
  int calls;
  void *pointer;
  size_t old_size;
  size_t new_size;
} release_b9;

static void *release_external_b9(void *ud, void *pointer,
                                 size_t old_size, size_t new_size) {
  release_b9 *release = (release_b9 *)ud;
  release->calls++;
  release->pointer = pointer;
  release->old_size = old_size;
  release->new_size = new_size;
  if (new_size == 0) free(pointer);
  return NULL;
}

static char *new_external_b9(const char *bytes, size_t len) {
  char *source = (char *)malloc(len + 1);
  if (source == NULL) return NULL;
  memcpy(source, bytes, len);
  source[len] = '\0';
  return source;
}

typedef struct { int32_t kind; int32_t value; } action_b9;
typedef action_b9 (*action_fn_b9)(void *, uint64_t, uint64_t, void *);
typedef struct { int32_t kind; int32_t value; } outcome_b9;
extern outcome_b9 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_b9, void *);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);

typedef struct {
  allocator_b9 *allocator;
  release_b9 *release;
  char *source;
  int reached;
} failure_b9;

static action_b9 fail_external_b9(void *state, uint64_t generation,
                                 uint64_t token, void *context) {
  failure_b9 *failure = (failure_b9 *)context;
  (void)generation;
  (void)token;
  failure->allocator->fail_next = 1;  /* checkpoint admission 已完成。 */
  (void)lua_pushexternalstring((lua_State *)state, failure->source, 7,
                               release_external_b9, failure->release);
  failure->reached = 1;
  return (action_b9){0, 91};
}

#define CHECK_B9(code, expression) do { if (!(expression)) { result = code; goto done; } } while (0)

int main(void) {
  allocator_b9 allocator = {0};
  allocator_b9 replacement = {0};
  release_b9 release = {0};
  lua_State *state = lua_newstate(allocate_b9, &allocator, 0U);
  if (state == NULL) return 1;
  int result = 0;
  const char key[] = {'a', '\0', 'b'};
  char *source = new_external_b9(key, sizeof(key));
  CHECK_B9(2, source != NULL);
  lua_createtable(state, 0, 1);
  CHECK_B9(3, lua_pushexternalstring(state, source, sizeof(key),
                                     release_external_b9, &release) == source);
  CHECK_B9(4, lua_rawlen(state, -1) == sizeof(key) &&
              lua_tolstring(state, -1, NULL) == source);
  lua_pushvalue(state, -1);
  CHECK_B9(5, lua_tolstring(state, -1, NULL) == source);
  lua_pop(state, 1);
  lua_pushinteger(state, 7);
  lua_rawset(state, 1);  /* table 的長短 key 均需維持 source edge。 */
  CHECK_B9(6, lua_gc(state, LUA_GCCOLLECT) == 0 && release.calls == 0);
  (void)lua_pushlstring(state, key, sizeof(key));
  CHECK_B9(7, lua_rawget(state, 1) == LUA_TNUMBER &&
              lua_tointeger(state, -1) == 7);
  lua_settop(state, 0);
  CHECK_B9(8, lua_gc(state, LUA_GCCOLLECT) == 0 && release.calls == 1 &&
              release.pointer == source && release.old_size == sizeof(key) + 1 &&
              release.new_size == 0);

  static const char fixed[] = {'\0', 'f', 'i', 'x', 'e', 'd', '\0'};
  CHECK_B9(9, lua_pushexternalstring(state, fixed, 6, NULL, NULL) == fixed &&
              lua_rawlen(state, -1) == 6);
  (void)lua_pushlstring(state, "+", 1);
  lua_concat(state, 2);
  size_t joined_len = 0;
  const char *joined = lua_tolstring(state, -1, &joined_len);
  static const char joined_expected[] = {'\0', 'f', 'i', 'x', 'e', 'd', '+'};
  CHECK_B9(18, joined != NULL && joined_len == sizeof(joined_expected) &&
               memcmp(joined, joined_expected, joined_len) == 0);
  lua_settop(state, 0);
  CHECK_B9(10, lua_gc(state, LUA_GCCOLLECT) == 0 && release.calls == 1);

  /* falloc/ud 在建立時擷取；後續替換 state allocator 不得改釋放目標。 */
  char *captured = new_external_b9("captured", 8);
  CHECK_B9(11, captured != NULL &&
               lua_pushexternalstring(state, captured, 8,
                                      release_external_b9, &release) == captured);
  lua_setallocf(state, allocate_b9, &replacement);
  lua_settop(state, 0);
  CHECK_B9(12, lua_gc(state, LUA_GCCOLLECT) == 0 && release.calls == 2 &&
               release.pointer == captured && release.old_size == 9);

  /* 在已建立的 C checkpoint 內拒絕 header admission，先釋放再 raise。 */
  failure_b9 failure = {&replacement, &release,
                        new_external_b9("failure", 7), 0};
  CHECK_B9(13, failure.source != NULL);
  outcome_b9 outcome = rivetlua_capi_trampoline_protect_a1(
      state, fail_external_b9, &failure);
  CHECK_B9(14, outcome.kind == 1 && outcome.value == 5 &&
               failure.reached == 0 && replacement.rejected == 1 &&
               release.calls == 3 && release.pointer == failure.source &&
               release.old_size == 8 && release.new_size == 0);
  int32_t error_class = 0;
  CHECK_B9(15, rivetlua_capi_error_consume_a1(state, &error_class) == 0 &&
               error_class == 5 && lua_gettop(state) == 1);
  lua_settop(state, 0);
  char *retry = new_external_b9("retry", 5);
  CHECK_B9(16, retry != NULL &&
               lua_pushexternalstring(state, retry, 5,
                                      release_external_b9, &release) == retry);
  lua_settop(state, 0);
  CHECK_B9(17, lua_gc(state, LUA_GCCOLLECT) == 0 && release.calls == 4 &&
               release.pointer == retry && lua_gettop(state) == 0);

done:
  lua_close(state);
  return result;
}
