/* P16-2 B10：固定 header 的真 C debug／hook 與 longjmp 驗收。 */
#include "lua.h"
#include "lauxlib.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

extern int rivetlua_capi_test_push_lua_b4(lua_State *state, int selector);
extern int rivetlua_capi_call_b4(lua_State *state, int nargs, int nresults);
extern int32_t rivetlua_capi_error_consume_a1(void *state, int32_t *class_code);

static int hook_error_b10;
static unsigned events_b10;
static int local_written_b10;
static int where_checked_b10;
static int replaced_b10;
static int disabled_b10;
static int raised_b10;
static int after_raise_b10;
static int original_nil_calls_b10;
static int replacement_nil_calls_b10;

static void fail_b10(int code) {
  if (hook_error_b10 == 0) hook_error_b10 = code;
}

static int plus_one_b10(lua_State *state) {
  if (lua_gettop(state) != 1 || !lua_isinteger(state, 1)) fail_b10(101);
  lua_pushinteger(state, lua_tointeger(state, 1) + 1);
  return 1;
}

static int original_nil_b10(lua_State *state) {
  if (lua_gettop(state) != 1) fail_b10(102);
  original_nil_calls_b10++;
  return 0;
}

static int replacement_nil_b10(lua_State *state) {
  if (lua_gettop(state) != 1) fail_b10(118);
  replacement_nil_calls_b10++;
  return 0;
}

static void observe_b10(lua_State *state, lua_Debug *ar) {
  if (ar == NULL || ar->i_ci == NULL || ar->event < LUA_HOOKCALL ||
      ar->event > LUA_HOOKTAILCALL) {
    fail_b10(103);
    return;
  }
  int event = ar->event;
  if (lua_gettop(state) != 0 ||
      (event == LUA_HOOKLINE ? ar->currentline != 3 : ar->currentline != -1))
    fail_b10(104);
  events_b10 |= 1U << event;
  if (!lua_getinfo(state, "nSlutr", ar) || ar->source == NULL ||
      ar->what == NULL || strcmp(ar->what, "Lua") != 0) {
    fail_b10(105);
    return;
  }
  lua_Debug frame;
  if (!lua_getstack(state, 0, &frame) || !lua_getinfo(state, "S", &frame) ||
      frame.what == NULL || strcmp(frame.what, "Lua") != 0)
    fail_b10(106);
  if (strcmp(ar->source, "@debug_api_b10.lua") == 0) {
    if (ar->nparams != 2 || ar->isvararg ||
        (event == LUA_HOOKTAILCALL && !ar->istailcall))
      fail_b10(107);
    if ((event == LUA_HOOKCALL || event == LUA_HOOKTAILCALL) &&
        (ar->ftransfer != 1 || ar->ntransfer != 2))
      fail_b10(108);
    if (event == LUA_HOOKCALL && !local_written_b10) {
      const char *name = lua_getlocal(state, ar, 2);
      if (name == NULL || strcmp(name, "second") != 0 ||
          lua_type(state, -1) != LUA_TFUNCTION)
        fail_b10(109);
      lua_pushcfunction(state, replacement_nil_b10);
      name = lua_setlocal(state, ar, 2);
      if (name == NULL || strcmp(name, "second") != 0 || lua_gettop(state) != 1)
        fail_b10(110);
      name = lua_getlocal(state, ar, 2);
      if (name == NULL || strcmp(name, "second") != 0 ||
          lua_tocfunction(state, -1) != replacement_nil_b10)
        fail_b10(119);
      lua_pop(state, 2);
      local_written_b10 = 1;
      luaL_where(state, 0);
      size_t length = 0;
      const char *where = lua_tolstring(state, -1, &length);
      static const char expected[] = "debug_api_b10.lua:3: ";
      if (where == NULL || length != sizeof(expected) - 1 ||
          memcmp(where, expected, sizeof(expected) - 1) != 0)
        fail_b10(111);
      else
        where_checked_b10 = 1;
      lua_pop(state, 1);
    }
  }
  if (lua_gethook(state) != observe_b10 ||
      lua_gethookmask(state) != (LUA_MASKCALL | LUA_MASKRET |
                                 LUA_MASKLINE | LUA_MASKCOUNT) ||
      lua_gethookcount(state) != 1)
    fail_b10(112);
  lua_pushinteger(state, 99); /* hook 專用 overlay 不得污染外層 call。 */
}

static void disable_b10(lua_State *state, lua_Debug *ar) {
  (void)ar;
  disabled_b10++;
  lua_sethook(state, NULL, 0, 17);
  if (lua_gethook(state) != NULL || lua_gethookmask(state) != 0 ||
      lua_gethookcount(state) != 17)
    fail_b10(113);
}

static void replace_b10(lua_State *state, lua_Debug *ar) {
  if (ar == NULL || ar->event != LUA_HOOKCALL || replaced_b10++ != 0)
    fail_b10(114);
  lua_sethook(state, disable_b10, LUA_MASKCALL | LUA_MASKRET |
                                   LUA_MASKLINE | LUA_MASKCOUNT, 1);
  if (lua_gethook(state) != disable_b10) fail_b10(115);
}

static void raise_b10(lua_State *state, lua_Debug *ar) {
  if (ar == NULL || ar->event != LUA_HOOKCALL || raised_b10++ != 0)
    fail_b10(116);
  if (lua_gettop(state) != 0) fail_b10(117);
  luaL_checktype(state, 1, LUA_TTABLE); /* 必須 longjmp 回純 C checkpoint。 */
  after_raise_b10++;
}

#define CHECK_B10(code, condition) do { \
  if (!(condition)) { result = (code); goto done; } \
} while (0)

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  int result = 0;
  int mask = LUA_MASKCALL | LUA_MASKRET | LUA_MASKLINE | LUA_MASKCOUNT;

  /* 既有 B4 正常 Return；新 selector 2 提供帶 native line 的 tail-call。 */
  CHECK_B10(2, rivetlua_capi_test_push_lua_b4(state, 1) == 1);
  lua_pushcfunction(state, plus_one_b10);
  lua_pushinteger(state, 41);
  lua_sethook(state, observe_b10, mask, 1);
  CHECK_B10(3, lua_gethook(state) == observe_b10 &&
      lua_gethookmask(state) == mask && lua_gethookcount(state) == 1);
  CHECK_B10(4, rivetlua_capi_call_b4(state, 2, 1) == 0 &&
      lua_gettop(state) == 1 && lua_tointeger(state, -1) == 42);
  lua_settop(state, 0);
  lua_sethook(state, NULL, 0, 0);
  CHECK_B10(5, rivetlua_capi_test_push_lua_b4(state, 2) == 1);
  lua_pushvalue(state, 1);
  lua_pushcfunction(state, original_nil_b10);
  lua_sethook(state, observe_b10, mask, 1);
  CHECK_B10(6, rivetlua_capi_call_b4(state, 2, 1) == 0 &&
      lua_gettop(state) == 1 && lua_type(state, -1) == LUA_TNIL);
  CHECK_B10(7, hook_error_b10 == 0 && local_written_b10 == 1 &&
      where_checked_b10 == 1 && (events_b10 & 0x1fU) == 0x1fU &&
      original_nil_calls_b10 == 0 && replacement_nil_calls_b10 > 0);
  lua_settop(state, 0);

  /* 目前事件用已取樣 pointer，後續事件採替換／停用後的 binding。 */
  lua_sethook(state, NULL, 0, 0);
  CHECK_B10(8, rivetlua_capi_test_push_lua_b4(state, 1) == 1);
  lua_pushcfunction(state, plus_one_b10);
  lua_pushinteger(state, 41);
  lua_sethook(state, replace_b10, mask, 1);
  CHECK_B10(9, rivetlua_capi_call_b4(state, 2, 1) == 0 &&
      lua_gettop(state) == 1 && lua_tointeger(state, -1) == 42);
  CHECK_B10(10, replaced_b10 == 1 && disabled_b10 == 1 &&
      lua_gethook(state) == NULL && lua_gethookmask(state) == 0 &&
      lua_gethookcount(state) == 17 && hook_error_b10 == 0);
  lua_settop(state, 0);

  /* strict auxiliary 在 hook 中真 longjmp；驗證不執行後續碼與同 state 重試。 */
  CHECK_B10(11, rivetlua_capi_test_push_lua_b4(state, 1) == 1);
  lua_pushcfunction(state, plus_one_b10);
  lua_pushinteger(state, 41);
  lua_sethook(state, raise_b10, LUA_MASKCALL, 0);
  CHECK_B10(12, rivetlua_capi_call_b4(state, 2, 1) == -1 &&
      raised_b10 == 1 && after_raise_b10 == 0);
  int32_t error_class = 0;
  CHECK_B10(13, rivetlua_capi_error_consume_a1(state, &error_class) == 0 &&
      error_class == 2 && lua_gettop(state) == 4);
  CHECK_B10(14, lua_type(state, -1) == LUA_TSTRING);
  lua_settop(state, 3);
  lua_sethook(state, observe_b10, mask, 1);
  CHECK_B10(15, rivetlua_capi_call_b4(state, 2, 1) == 0 &&
      lua_gettop(state) == 1 && lua_tointeger(state, -1) == 42 &&
      hook_error_b10 == 0);

done:
  if (result != 0)
    fprintf(stderr, "B10 C fixture result=%d hook_error=%d top=%d events=%#x "
                    "replaced=%d disabled=%d raised=%d after=%d\n",
            result, hook_error_b10, lua_gettop(state), events_b10,
            replaced_b10, disabled_b10, raised_b10, after_raise_b10);
  lua_close(state);
  return result;
}
