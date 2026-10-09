/* P16-2A48：固定 header macro 與 C-only error jump 的實際連結／呼叫驗證。 */
#include "lua.h"
#include "lauxlib.h"
#include <stdint.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct {
  int32_t kind;
  int32_t value;
} action_a1;
typedef struct {
  int32_t kind;
  int32_t value;
} outcome_a1;
typedef action_a1 (*action_fn_a1)(void *, uint64_t, uint64_t, void *);

extern outcome_a1 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_a1, void *);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);

typedef struct {
  lua_Number version;
  size_t sizes;
  int use_macro;
  int after;
} check_case;

static action_a1 check_version(void *raw_state, uint64_t generation,
                               uint64_t token, void *raw_case) {
  (void)generation;
  (void)token;
  lua_State *state = (lua_State *)raw_state;
  check_case *test = (check_case *)raw_case;
  if (test->use_macro)
    luaL_checkversion(state);
  else
    luaL_checkversion_(state, test->version, test->sizes);
  test->after += 1;
  return (action_a1){0, 73};
}

static int check_error(lua_State *state, check_case *test,
                       const char *expected) {
  outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, check_version, test);
  if (outcome.kind != 1 || outcome.value != 2 || test->after != 0 ||
      lua_gettop(state) != 0) return 1;
  int32_t class = 0;
  if (rivetlua_capi_error_consume_a1(state, &class) != 0 || class != 2 ||
      lua_gettop(state) != 1) return 2;
  size_t len = 0;
  const char *bytes = lua_tolstring(state, -1, &len);
  size_t expected_len = strlen(expected);
  if (bytes == NULL || len != expected_len ||
      memcmp(bytes, expected, len) != 0 || bytes[len] != '\0') return 3;
  lua_settop(state, 0);
  return 0;
}

static action_a1 nested(void *raw_state, uint64_t generation,
                        uint64_t token, void *raw_case) {
  (void)generation;
  (void)token;
  lua_State *state = (lua_State *)raw_state;
  check_case *inner = (check_case *)raw_case;
  const char *expected = "core and library have incompatible numeric types";
  if (check_error(state, inner, expected) != 0) return (action_a1){2, -31};
  return (action_a1){0, 83};
}

static int check_unprotected_fatal(int numeric) {
  pid_t pid = fork();
  if (pid < 0) return 1;
  if (pid == 0) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) _exit(2);
    lua_State *state = luaL_newstate();
    if (state == NULL) _exit(3);
    if (numeric)
      luaL_checkversion_(state, LUA_VERSION_NUM, LUAL_NUMSIZES + 1);
    else
      luaL_checkversion_(state, 0.0, LUAL_NUMSIZES);
    _exit(99);
  }
  int status = 0;
  if (waitpid(pid, &status, 0) != pid || !WIFSIGNALED(status) ||
      WTERMSIG(status) != SIGABRT) return 2;
  return 0;
}

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  luaL_checkversion_(state, LUA_VERSION_NUM, LUAL_NUMSIZES);
  luaL_checkversion(state);
  if (lua_gettop(state) != 0) return 2;

  check_case normal = {LUA_VERSION_NUM, LUAL_NUMSIZES, 0, 0};
  outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, check_version, &normal);
  if (outcome.kind != 0 || outcome.value != 73 || normal.after != 1 ||
      lua_gettop(state) != 0) return 3;
  normal.use_macro = 1;
  normal.after = 0;
  outcome = rivetlua_capi_trampoline_protect_a1(
      state, check_version, &normal);
  if (outcome.kind != 0 || outcome.value != 73 || normal.after != 1 ||
      lua_gettop(state) != 0) return 4;

  check_case numeric = {LUA_VERSION_NUM, LUAL_NUMSIZES + 1, 0, 0};
  const char *numeric_error = "core and library have incompatible numeric types";
  if (check_error(state, &numeric, numeric_error) != 0) return 5;

  char version_error[128];
  int written = snprintf(version_error, sizeof(version_error),
      "version mismatch: app. needs %.1f, Lua core provides %.1f",
      (double)0.0, (double)LUA_VERSION_NUM);
  if (written < 0 || (size_t)written >= sizeof(version_error)) return 6;
  check_case version = {0.0, LUAL_NUMSIZES, 0, 0};
  if (check_error(state, &version, version_error) != 0) return 7;

  check_case both = {0.0, LUAL_NUMSIZES + 1, 0, 0};
  if (check_error(state, &both, numeric_error) != 0) return 8;

  check_case inner = {LUA_VERSION_NUM, LUAL_NUMSIZES + 1, 0, 0};
  outcome = rivetlua_capi_trampoline_protect_a1(state, nested, &inner);
  if (outcome.kind != 0 || outcome.value != 83 || inner.after != 0 ||
      lua_gettop(state) != 0) return 9;

  lua_close(state);
  if (check_unprotected_fatal(0) != 0) return 10;
  if (check_unprotected_fatal(1) != 0) return 11;
  return 0;
}
