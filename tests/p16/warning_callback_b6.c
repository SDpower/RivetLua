/* P16-2 B6：固定 header 下驗證 warning binding、預設輸出與純 C 錯誤跳轉。 */
#define _POSIX_C_SOURCE 200809L
#include "lua.h"
#include "lauxlib.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct { int32_t kind; int32_t value; } action_b6;
typedef action_b6 (*action_fn_b6)(void *, uint64_t, uint64_t, void *);
typedef struct { int32_t kind; int32_t value; } outcome_b6;
extern outcome_b6 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_b6, void *);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);

static void *allocator_b6(void *ud, void *ptr, size_t osize, size_t nsize) {
  (void)ud;
  (void)osize;
  if (nsize == 0) { free(ptr); return NULL; }
  return realloc(ptr, nsize);
}

static lua_State *direct_state_b6(void) {
#if LUA_VERSION_NUM >= 505
  return lua_newstate(allocator_b6, NULL, 0);
#else
  return lua_newstate(allocator_b6, NULL);
#endif
}

typedef struct {
  lua_State *state;
  const char *message;
  int tocont;
  int calls;
} binding_b6;

static void record_b6(void *ud, const char *message, int tocont) {
  binding_b6 *binding = (binding_b6 *)ud;
  binding->calls++;
  binding->message = message;
  binding->tocont = tocont;
}

static int marker_b6;
static void raising_b6(void *ud, const char *message, int tocont) {
  lua_State *state = (lua_State *)ud;
  (void)message;
  (void)tocont;
  luaL_checktype(state, 1, LUA_TNUMBER);
  marker_b6++;
}

static action_b6 protected_warning_b6(void *raw_state, uint64_t generation,
                                      uint64_t token, void *context) {
  (void)generation;
  (void)token;
  (void)context;
  lua_warning((lua_State *)raw_state, "raise", 0);
  marker_b6++;
  return (action_b6){0, 42};
}

static int default_output_b6(void) {
  FILE *capture = tmpfile();
  if (capture == NULL) return 1;
  int original = dup(STDERR_FILENO);
  if (original < 0 || dup2(fileno(capture), STDERR_FILENO) < 0) {
    fclose(capture);
    if (original >= 0) close(original);
    return 2;
  }
  lua_State *state = luaL_newstate();
  if (state != NULL) {
    lua_warning(state, "initial", 0);
    lua_warning(state, "@off", 0);
    lua_warning(state, "muted", 0);
    lua_warning(state, "@on", 0);
    lua_warning(state, "part ", 1);
    lua_warning(state, "end", 0);
    lua_warning(state, "again", 0);
    lua_close(state);
  }
  fflush(stderr);
  dup2(original, STDERR_FILENO);
  close(original);
  char output[256] = {0};
  rewind(capture);
  size_t length = fread(output, 1, sizeof(output) - 1, capture);
  fclose(capture);
  if (state == NULL) return 3;
#if LUA_VERSION_NUM >= 505
  const char *expected = "Lua warning: initial\nLua warning: part end\nLua warning: again\n";
#else
  const char *expected = "Lua warning: part end\nLua warning: again\n";
#endif
  return length == strlen(expected) && memcmp(output, expected, length) == 0
      ? 0 : 4;
}

int main(void) {
  lua_State *state = direct_state_b6();
  if (state == NULL) return 1;
  binding_b6 first = {state, NULL, 0, 0};
  binding_b6 second = {state, NULL, 0, 0};
  static const char exact[] = "exact";
  lua_warning(state, exact, -11);
  if (first.calls != 0) return 2;
  lua_setwarnf(state, record_b6, &first);
  lua_warning(state, exact, -11);
  if (first.calls != 1 || first.message != exact || first.tocont != -11)
    return 3;
  lua_setwarnf(state, record_b6, &second);
  lua_warning(state, exact, 17);
  if (first.calls != 1 || second.calls != 1 || second.message != exact ||
      second.tocont != 17) return 4;
  lua_setwarnf(state, NULL, NULL);
  lua_warning(state, exact, 1);
  if (second.calls != 1) return 5;
  lua_setwarnf(state, raising_b6, state);
  outcome_b6 outcome = rivetlua_capi_trampoline_protect_a1(
      state, protected_warning_b6, NULL);
  if (outcome.kind != 1 || marker_b6 != 0) return 6;
  int32_t error_class = 0;
  if (rivetlua_capi_error_consume_a1(state, &error_class) != 0 ||
      error_class == 0) return 7;
  lua_setwarnf(state, record_b6, &second);
  lua_warning(state, exact, 2);
  if (second.calls != 2 || second.tocont != 2) return 8;
  lua_close(state);
  int output_result = default_output_b6();
  return output_result == 0 ? 0 : 20 + output_result;
}
