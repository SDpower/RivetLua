/* P16-2 B5：固定 Lua header 的運算、metamethod、stack 與 C-only error。 */
#include "lua.h"
#include "lauxlib.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct { int32_t kind; int32_t value; } action_b5;
typedef action_b5 (*action_fn_b5)(void *, uint64_t, uint64_t, void *);
extern action_b5 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_b5, void *);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);
extern int rivetlua_capi_call_b4(lua_State *, int, int);

static int number_37(lua_State *state) {
  lua_pushinteger(state, 37);
  return 1;
}
static int number_42(lua_State *state) {
  lua_pushinteger(state, 42);
  return 1;
}
static int numeric_string_37(lua_State *state) {
  lua_pushliteral(state, "37");
  return 1;
}
static int integral_float_37(lua_State *state) {
  lua_pushnumber(state, 37.0);
  return 1;
}
static int boolean_true(lua_State *state) {
  lua_pushboolean(state, 1);
  return 1;
}
static int invalid_tostring(lua_State *state) {
  lua_createtable(state, 0, 0);
  return 1;
}
static int nested_add(lua_State *state) {
  lua_pushvalue(state, 1);
  lua_pushvalue(state, 2);
  lua_arith(state, LUA_OPADD);
  return 1;
}
static void metafield(lua_State *state, int target, const char *name,
                      lua_CFunction function) {
  lua_createtable(state, 0, 1);
  lua_pushstring(state, name);
  lua_pushcclosure(state, function, 0);
  lua_rawset(state, -3);
  if (lua_setmetatable(state, target) != 1) __builtin_trap();
}

static int arithmetic(lua_State *state) {
  static const struct { int op; lua_Integer answer; } integer_cases[] = {
    {LUA_OPADD, 9}, {LUA_OPSUB, 3}, {LUA_OPMUL, 18},
    {LUA_OPMOD, 0}, {LUA_OPIDIV, 2}, {LUA_OPBAND, 2},
    {LUA_OPBOR, 7}, {LUA_OPBXOR, 5}, {LUA_OPSHL, 48},
    {LUA_OPSHR, 0},
  };
  for (size_t i = 0; i < sizeof(integer_cases) / sizeof(integer_cases[0]); ++i) {
    lua_settop(state, 0);
    lua_pushinteger(state, 6);
    lua_pushinteger(state, 3);
    lua_arith(state, integer_cases[i].op);
    if (lua_gettop(state) != 1 ||
        lua_tointeger(state, -1) != integer_cases[i].answer) return 10 + (int)i;
  }
  lua_settop(state, 0);
  lua_pushinteger(state, 6);
  lua_pushinteger(state, 3);
  lua_arith(state, LUA_OPDIV);
  if (lua_gettop(state) != 1 || lua_tonumber(state, -1) != 2.0) return 21;
  lua_settop(state, 0);
  lua_pushinteger(state, 6);
  lua_pushinteger(state, 3);
  lua_arith(state, LUA_OPPOW);
  if (lua_gettop(state) != 1 || lua_tonumber(state, -1) != 216.0) return 22;
  lua_settop(state, 0);
  lua_pushinteger(state, 6);
  lua_arith(state, LUA_OPUNM);
  if (lua_gettop(state) != 1 || lua_tointeger(state, -1) != -6) return 23;
  lua_settop(state, 0);
  lua_pushinteger(state, 6);
  lua_arith(state, LUA_OPBNOT);
  if (lua_gettop(state) != 1 || lua_tointeger(state, -1) != ~((lua_Integer)6)) return 24;
  lua_settop(state, 0);
  lua_pushinteger(state, LUA_MAXINTEGER);
  lua_pushinteger(state, 1);
  lua_arith(state, LUA_OPADD);
  if (lua_gettop(state) != 1 || lua_tointeger(state, -1) != LUA_MININTEGER) return 25;
  lua_settop(state, 0);
  lua_pushinteger(state, LUA_MININTEGER);
  lua_arith(state, LUA_OPUNM);
  if (lua_gettop(state) != 1 || lua_tointeger(state, -1) != LUA_MININTEGER) return 26;
  return 0;
}

static int concat_len_compare(lua_State *state) {
  lua_settop(state, 0);
  lua_concat(state, 0);
  size_t length = 99;
  const char *text = lua_tolstring(state, -1, &length);
  if (lua_gettop(state) != 1 || text == NULL || length != 0) return 30;
  lua_settop(state, 0);
  lua_pushinteger(state, 42);
  lua_concat(state, 1);
  if (lua_gettop(state) != 1 || !lua_isinteger(state, 1) ||
      lua_tointeger(state, 1) != 42) return 31;
  lua_settop(state, 0);
  lua_pushliteral(state, "a");
  lua_pushinteger(state, 4);
  lua_pushliteral(state, "b");
  lua_concat(state, 3);
  text = lua_tolstring(state, -1, &length);
  if (lua_gettop(state) != 1 || text == NULL || length != 3 ||
      memcmp(text, "a4b", 3) != 0) return 32;
  lua_len(state, -1);
  if (lua_gettop(state) != 2 || lua_tointeger(state, -1) != 3) return 33;
  lua_settop(state, 0);
  lua_pushlstring(state, "a\0b", 3);
  lua_pushlstring(state, "a\0c", 3);
  if (lua_compare(state, 1, 2, LUA_OPEQ) ||
      !lua_compare(state, 1, 2, LUA_OPLT) ||
      !lua_compare(state, 1, 2, LUA_OPLE) ||
      lua_compare(state, 1, 99, LUA_OPEQ) || lua_gettop(state) != 2)
    return 34;
  lua_settop(state, 0);
  lua_createtable(state, 0, 0);
  metafield(state, 1, "__len", number_37);
  if (luaL_len(state, 1) != 37 || lua_gettop(state) != 1) return 35;
  lua_settop(state, 0);
  lua_createtable(state, 0, 0);
  metafield(state, 1, "__len", numeric_string_37);
  if (luaL_len(state, 1) != 37 || lua_gettop(state) != 1) return 38;
  lua_settop(state, 0);
  lua_createtable(state, 0, 0);
  metafield(state, 1, "__len", integral_float_37);
  if (luaL_len(state, 1) != 37 || lua_gettop(state) != 1) return 39;
  lua_settop(state, 0);
  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 0);
  metafield(state, 1, "__eq", boolean_true);
  if (!lua_compare(state, 1, 2, LUA_OPEQ) || lua_gettop(state) != 2) return 36;
  lua_settop(state, 0);
  lua_pushcfunction(state, nested_add);
  lua_createtable(state, 0, 0);
  metafield(state, 2, "__add", number_42);
  lua_pushinteger(state, 2);
  if (rivetlua_capi_call_b4(state, 2, 1) != 0 || lua_gettop(state) != 1 ||
      lua_tointeger(state, 1) != 42) return 37;
  return 0;
}

static int tostring_cases(lua_State *state) {
  lua_settop(state, 0);
  lua_pushinteger(state, 42);
  size_t length = 0;
  const char *text = luaL_tolstring(state, -1, &length);
  if (text == NULL || text != lua_tolstring(state, -1, NULL) ||
      length != 2 || memcmp(text, "42", 2) != 0 || lua_gettop(state) != 2) return 40;
  lua_settop(state, 0);
  lua_pushnumber(state, 1.5);
  text = luaL_tolstring(state, -1, &length);
  if (text == NULL || text != lua_tolstring(state, -1, NULL) ||
      length != 3 || memcmp(text, "1.5", 3) != 0 || lua_gettop(state) != 2) return 49;
  lua_settop(state, 0);
  lua_pushboolean(state, 1);
  text = luaL_tolstring(state, -1, &length);
  if (text == NULL || length != 4 || memcmp(text, "true", 4) != 0) return 41;
  lua_settop(state, 0);
  lua_pushnil(state);
  text = luaL_tolstring(state, -1, &length);
  if (text == NULL || length != 3 || memcmp(text, "nil", 3) != 0) return 42;
  lua_settop(state, 0);
  lua_createtable(state, 0, 0);
  metafield(state, 1, "__tostring", number_42);
  text = luaL_tolstring(state, -1, &length);
  if (text == NULL || length != 2 || memcmp(text, "42", 2) != 0 ||
      text != lua_tolstring(state, -1, NULL)) return 43;
  lua_settop(state, 0);
  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushliteral(state, "__name");
  lua_pushliteral(state, "Widget");
  lua_rawset(state, -3);
  if (!lua_setmetatable(state, -2)) return 44;
  text = luaL_tolstring(state, -1, &length);
  if (text == NULL || length < 9 || memcmp(text, "Widget: ", 8) != 0) return 45;
  lua_settop(state, 0);
  lua_pushcfunction(state, number_42);
  const void *identity = lua_topointer(state, -1);
  if (identity == NULL) return 46;
  char expected[96];
  int expected_length = snprintf(expected, sizeof(expected), "function: %p", identity);
  if (expected_length < 0 || (size_t)expected_length >= sizeof(expected)) return 47;
  text = luaL_tolstring(state, -1, &length);
  if (text == NULL || length != (size_t)expected_length ||
      memcmp(text, expected, length) != 0) return 48;
  return 0;
}

typedef struct { int operation; int after; } error_case;
static action_b5 error_action(void *raw, uint64_t generation,
                              uint64_t token, void *context) {
  (void)generation;
  (void)token;
  lua_State *state = (lua_State *)raw;
  error_case *test = (error_case *)context;
  switch (test->operation) {
    case 1: (void)luaL_len(state, -1); break;
    case 2: (void)luaL_tolstring(state, -1, NULL); break;
    case 3: lua_arith(state, LUA_OPADD); break;
  }
  test->after++;
  return (action_b5){0, 91};
}
static int errors_and_retry(lua_State *state) {
  static const char *messages[] = {
    NULL, "object length is not an integer",
    "'__tostring' must return a string", "value operation failed"
  };
  for (int operation = 1; operation <= 3; ++operation) {
    lua_settop(state, 0);
    if (operation == 1) {
      lua_createtable(state, 0, 0);
      metafield(state, 1, "__len", invalid_tostring);
    } else if (operation == 2) {
      lua_createtable(state, 0, 0);
      metafield(state, 1, "__tostring", invalid_tostring);
    } else {
      lua_pushboolean(state, 1);
      lua_pushboolean(state, 0);
    }
    int original_top = lua_gettop(state);
    error_case test = {operation, 0};
    action_b5 outcome = rivetlua_capi_trampoline_protect_a1(
        state, error_action, &test);
    if (outcome.kind != 1 || outcome.value != 2 || test.after != 0 ||
        lua_gettop(state) != original_top) return 50 + operation;
    int32_t kind = 0;
    if (rivetlua_capi_error_consume_a1(state, &kind) != 0 || kind != 2 ||
        lua_gettop(state) != original_top + 1) return 60 + operation;
    size_t length = 0;
    const char *text = lua_tolstring(state, -1, &length);
    if (text == NULL || length != strlen(messages[operation]) ||
        memcmp(text, messages[operation], length) != 0) return 70 + operation;
  }
  lua_settop(state, 0);
  lua_pushinteger(state, 20);
  lua_pushinteger(state, 22);
  lua_arith(state, LUA_OPADD);
  return lua_gettop(state) == 1 && lua_tointeger(state, -1) == 42 ? 0 : 80;
}

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  int status = arithmetic(state);
  if (status == 0) status = concat_len_compare(state);
  if (status == 0) status = tostring_cases(state);
  if (status == 0) status = errors_and_retry(state);
  lua_close(state);
  return status;
}
