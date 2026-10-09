#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <unistd.h>

#define LUA_COMPAT_APIINTCASTS 1
#include "lua.h"
#include "lauxlib.h"

extern int rivetlua_capi_test_push_lua_b4(lua_State *state, int selector);
extern int rivetlua_capi_test_inject_next_allocation_a2(lua_State *state);
typedef struct { int32_t kind; int32_t value; } action_a3;
typedef action_a3 (*action_fn_a3)(void *, uint64_t, uint64_t, void *);
extern action_a3 rivetlua_capi_trampoline_protect_a1(
    void *state, action_fn_a3 action, void *context);
extern int32_t rivetlua_capi_error_consume_a1(void *state, int32_t *class_code);

static int frame_depth_seen;
static int stale_rejected;
static lua_Debug old_frame;
static int panic_pipe = -1;
static int deep_trace_depth;
static int deep_trace_ellipsis;
static int tail_trace_seen;

static int generic_panic_probe(lua_State *state) {
  const char marker = lua_gettop(state) >= 1 &&
      lua_type(state, -1) == LUA_TSTRING ? 'm' : 'x';
  if (panic_pipe >= 0) (void)write(panic_pipe, &marker, 1);
  return 0;
}

static int frame_probe(lua_State *state) {
  lua_Debug frames[3];
  int depth = 0;
  while (depth < 3 && lua_getstack(state, depth, &frames[depth])) {
    if (!lua_getinfo(state, "nSlut", &frames[depth])) return 0;
    depth++;
  }
  frame_depth_seen = depth;
  if (depth != 3 || strcmp(frames[0].what, "C") != 0 ||
      strcmp(frames[1].what, "Lua") != 0 ||
      strcmp(frames[2].what, "C") != 0) return 0;
  old_frame = frames[0];
  int top = lua_gettop(state);
  const char *local = lua_getlocal(state, &frames[0], 1);
  if (local == NULL || lua_gettop(state) != top + 1 ||
      lua_tointeger(state, -1) != 41) return 0;
  lua_pop(state, 1);
  lua_pushinteger(state, 42);
  if (lua_setlocal(state, &frames[0], 1) == NULL ||
      lua_tointeger(state, 1) != 42) return 0;
  luaL_where(state, 0);
  if (lua_type(state, -1) != LUA_TSTRING) return 0;
  lua_pop(state, 1);
  luaL_where(state, 1);
  size_t where_len = 0;
  const char *where = lua_tolstring(state, -1, &where_len);
  if (where == NULL || where_len != 21 ||
      memcmp(where, "debug_api_b10.lua:3: ", 21) != 0) return 0;
  lua_pop(state, 1);
  luaL_traceback(state, state, "nested", 0);
  size_t trace_len = 0;
  const char *trace = lua_tolstring(state, -1, &trace_len);
  if (trace == NULL || strstr(trace, "debug_api_b10.lua:3: in ") == NULL)
    return 0;
  lua_pop(state, 1);
  lua_pushinteger(state, 43);
  return 1;
}

static int nested_public(lua_State *state) {
  lua_pushvalue(state, lua_upvalueindex(1));
  lua_pushcfunction(state, frame_probe);
  lua_pushinteger(state, 41);
  lua_call(state, 2, 1);
  return 1;
}

static int deep_trace_probe(lua_State *state) {
  deep_trace_depth++;
  if (deep_trace_depth < 14) {
    lua_pushvalue(state, 1);
    lua_pushcfunction(state, deep_trace_probe);
    lua_pushvalue(state, 1);
    lua_call(state, 2, 1);
    lua_pop(state, 1);
  } else {
    luaL_traceback(state, state, "deep", 0);
    const char *trace = lua_tostring(state, -1);
    deep_trace_ellipsis = trace != NULL &&
        strstr(trace, "...\t(skipping ") != NULL;
    lua_pop(state, 1);
  }
  deep_trace_depth--;
  lua_pushinteger(state, 43);
  return 1;
}

static int tail_trace_probe(lua_State *state) {
  luaL_traceback(state, state, NULL, 0);
  const char *trace = lua_tostring(state, -1);
  tail_trace_seen = trace != NULL &&
      strstr(trace, "(...tail calls...)") != NULL;
  lua_pop(state, 1);
  lua_pushinteger(state, 43);
  return 1;
}

static int nested_tail_public(lua_State *state) {
  lua_pushvalue(state, lua_upvalueindex(1));
  lua_pushcfunction(state, tail_trace_probe);
  lua_pushinteger(state, 41);
  lua_call(state, 2, 1);
  return 1;
}

static int push_nil_failure(lua_State *state) {
  lua_settop(state, 20);
  if (rivetlua_capi_test_inject_next_allocation_a2(state) != 1) return 0;
  lua_pushnil(state);
  return 0;
}

static int generic_case;
static int inject_generic;

static int generic_probe(lua_State *state) {
  switch (generic_case) {
    case 1: case 2: case 3: case 4: case 5: case 6: case 7:
      lua_settop(state, 20);
      break;
    case 8:
      lua_settop(state, 20);
      break;
    case 9:
      lua_createtable(state, 0, 0);
      break;
    case 10:
      lua_createtable(state, 0, 0);
      break;
    case 11:
      lua_createtable(state, 0, 1);
      lua_pushinteger(state, 9);
      lua_rawseti(state, 1, 1);
      lua_settop(state, 20);
      break;
    case 13:
      break;
    case 14:
      lua_settop(state, 20);
      break;
    default:
      return 0;
  }
  if (inject_generic &&
      rivetlua_capi_test_inject_next_allocation_a2(state) != 1) return 0;
  switch (generic_case) {
    case 1: lua_pushnil(state); break;
    case 2: lua_pushboolean(state, 1); break;
    case 3: lua_pushinteger(state, 9); break;
    case 4: lua_pushnumber(state, 9.5); break;
    case 5: lua_pushlightuserdata(state, state); break;
    case 6: luaL_pushfail(state); break;
#if LUA_VERSION_NUM < 505
    case 7: lua_pushunsigned(state, 9); break;
#else
    case 7: lua_pushinteger(state, 9); break;
#endif
    case 8: luaL_checkstack(state, 1, "room"); break;
    case 9: (void)luaL_gsub(state, "aba", "a", "z"); break;
    case 10: luaL_setmetatable(state, "a3.named"); break;
    case 11: (void)lua_next(state, 1); break;
    case 13: (void)luaL_newmetatable(state, "a3.generated"); break;
    case 14: (void)lua_newuserdatauv(state, 8, 0); break;
    default: return 0;
  }
  return 0;
}

static action_a3 xmove_failure_action(void *raw, uint64_t generation,
                                       uint64_t token, void *context) {
  (void)generation;
  (void)token;
  lua_State *state = (lua_State *)raw;
  lua_State *child = (lua_State *)context;
  if (rivetlua_capi_test_inject_next_allocation_a2(state) != 1)
    return (action_a3){0, -1};
  lua_xmove(state, child, 1);
  return (action_a3){0, 0};
}

static int formatted_error(lua_State *state) {
  return luaL_error(state, "bad%c%s", 0, "tail");
}

static int long_formatted_error(lua_State *state) {
  char text[1201];
  memset(text, 'x', 1200);
  text[1200] = '\0';
  return luaL_error(state, "%s", text);
}

static int nested_formatted_public(lua_State *state) {
  lua_pushvalue(state, lua_upvalueindex(1));
  lua_pushcfunction(state, formatted_error);
  lua_pushinteger(state, 41);
  lua_call(state, 2, 1);
  return 1;
}

static int argument_error(lua_State *state) {
  luaL_argcheck(state, lua_isnumber(state, 1), 1, "number expected");
  return 0;
}

static int method_arg;
static int method_name_seen;

static int method_argument_error(lua_State *state) {
  lua_Debug ar;
  if (lua_getstack(state, 0, &ar) && lua_getinfo(state, "n", &ar) &&
      ar.name != NULL && strcmp(ar.name, "m") == 0 &&
      strcmp(ar.namewhat, "method") == 0)
    method_name_seen++;
  return luaL_argerror(state, method_arg,
                       method_arg == 1 ? "bad self" : "bad arg");
}

static int expected_type(lua_State *state) {
  luaL_argexpected(state, lua_type(state, 1) == LUA_TNUMBER, 1, "number");
  return 0;
}

static int strict_type(lua_State *state) {
  luaL_checktype(state, 1, LUA_TSTRING);
  return 0;
}

static int strict_any(lua_State *state) {
  luaL_checkany(state, 2);
  return 0;
}

static int strict_userdata(lua_State *state) {
  (void)luaL_checkudata(state, 1, "a3.values");
  return 0;
}

static int strict_option(lua_State *state) {
  static const char *const choices[] = {"red", "blue", NULL};
  (void)luaL_checkoption(state, 1, NULL, choices);
  return 0;
}

static int nested_strict_public(lua_State *state) {
  lua_pushvalue(state, lua_upvalueindex(1));
  lua_pushcfunction(state, strict_type);
  lua_pushinteger(state, 41);
  lua_call(state, 2, 1);
  return 1;
}

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  lua_pushcfunction(state, formatted_error);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 2;
  size_t length = 0;
  const char *message = lua_tolstring(state, -1, &length);
  if (message == NULL || length != 8 || memcmp(message, "bad\0tail", 8) != 0)
    return 3;
  lua_pop(state, 1);

  if (rivetlua_capi_test_push_lua_b4(state, 2) != 1) return 89;
  lua_pushcclosure(state, nested_tail_public, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK ||
      lua_tointeger(state, -1) != 43 || !tail_trace_seen) return 90;
  lua_pop(state, 1);

  lua_pushcfunction(state, long_formatted_error);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 73;
  message = lua_tolstring(state, -1, &length);
  if (message == NULL || length != 1200 || message[0] != 'x' ||
      message[1199] != 'x') return 74;
  lua_pop(state, 1);

  lua_pushcfunction(state, argument_error);
  lua_pushnil(state);
  if (lua_pcall(state, 1, 0, 0) != LUA_ERRRUN) return 4;
  message = lua_tolstring(state, -1, &length);
  const char *argument_text = "bad argument #1 to '?' (number expected)";
  if (message == NULL || length != strlen(argument_text) ||
      memcmp(message, argument_text, length) != 0) return 12;
  lua_pop(state, 1);
  char binary_message[] = {'a', '\0', 'b', '\0'};
  luaL_traceback(state, state, binary_message, 1000);
  message = lua_tolstring(state, -1, &length);
  if (message == NULL || length != 18 ||
      memcmp(message, "a\nstack traceback:", 18) != 0) return 75;
  lua_pop(state, 1);

  lua_pushcfunction(state, expected_type);
  lua_pushnil(state);
  if (lua_pcall(state, 1, 0, 0) != LUA_ERRRUN) return 5;
  message = lua_tolstring(state, -1, &length);
  const char *type_text = "bad argument #1 to '?' (number expected, got nil)";
  if (message == NULL || length != strlen(type_text) ||
      memcmp(message, type_text, length) != 0) return 13;
  lua_pop(state, 1);

  luaL_traceback(state, state, "trace", 0);
  message = lua_tolstring(state, -1, &length);
  if (message == NULL || length < 22 ||
      memcmp(message, "trace\nstack traceback:", 22) != 0) return 6;
  lua_pop(state, 1);

  lua_State *child = lua_newthread(state);
  if (child == NULL) return 7;
  int child_top = lua_gettop(child);
  int parent_top = lua_gettop(state);
  luaL_traceback(state, child, NULL, 0);
  message = lua_tolstring(state, -1, &length);
  if (message == NULL || length != 16 ||
      memcmp(message, "stack traceback:", 16) != 0 ||
      lua_gettop(child) != child_top || lua_gettop(state) != parent_top + 1)
    return 8;
  lua_pop(state, 1);

  if (rivetlua_capi_test_push_lua_b4(state, 4) != 1) return 9;
  lua_pushcclosure(state, nested_public, 1);
  if (lua_pcall(state, 0, 1, 0) != LUA_OK ||
      lua_gettop(state) != 2 || lua_tointeger(state, -1) != 43 ||
      frame_depth_seen != 3) return 10;
  lua_pop(state, 1);
  stale_rejected = lua_getinfo(state, "nSl", &old_frame) == 0 &&
      lua_getlocal(state, &old_frame, 1) == NULL;
  if (!stale_rejected) return 11;

  lua_pushcfunction(state, deep_trace_probe);
  if (rivetlua_capi_test_push_lua_b4(state, 4) != 1) return 87;
  if (lua_pcall(state, 1, 1, 0) != LUA_OK ||
      lua_tointeger(state, -1) != 43 || deep_trace_depth != 0 ||
      !deep_trace_ellipsis) return 88;
  lua_pop(state, 1);

  if (rivetlua_capi_test_push_lua_b4(state, 4) != 1) return 76;
  lua_pushcclosure(state, nested_formatted_public, 1);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 77;
  message = lua_tolstring(state, -1, &length);
  if (message == NULL || length < 29 ||
      memcmp(message, "debug_api_b10.lua:3: bad\0tail", 29) != 0)
    return 78;
  lua_pop(state, 1);

  lua_pushcfunction(state, strict_type);
  lua_pushnil(state);
  if (lua_pcall(state, 1, 0, 0) != LUA_ERRRUN) return 62;
  message = lua_tostring(state, -1);
  if (message == NULL || strcmp(message,
      "bad argument #1 (string expected, got nil)") != 0) return 63;
  lua_pop(state, 1);
  lua_pushcfunction(state, strict_any);
  lua_pushinteger(state, 1);
  if (lua_pcall(state, 1, 0, 0) != LUA_ERRRUN) return 64;
  message = lua_tostring(state, -1);
  if (message == NULL || strcmp(message,
      "bad argument #2 (value expected)") != 0) return 65;
  lua_pop(state, 1);
  lua_pushcfunction(state, strict_userdata);
  lua_pushnil(state);
  if (lua_pcall(state, 1, 0, 0) != LUA_ERRRUN) return 66;
  message = lua_tostring(state, -1);
  if (message == NULL || strcmp(message,
      "bad argument #1 (a3.values expected, got nil)") != 0)
    return 67;
  lua_pop(state, 1);
  lua_pushcfunction(state, strict_option);
  lua_pushliteral(state, "green");
  if (lua_pcall(state, 1, 0, 0) != LUA_ERRRUN) return 68;
  message = lua_tostring(state, -1);
  if (message == NULL || strcmp(message,
      "bad argument #1 (invalid option 'green')") != 0) return 69;
  lua_pop(state, 1);
  if (rivetlua_capi_test_push_lua_b4(state, 4) != 1) return 70;
  lua_pushcclosure(state, nested_strict_public, 1);
  if (lua_pcall(state, 0, 0, 0) != LUA_ERRRUN) return 71;
  message = lua_tostring(state, -1);
  if (message == NULL || strstr(message, "debug_api_b10.lua:3:") == NULL ||
      strstr(message, "string expected, got number") == NULL) return 72;
  lua_pop(state, 1);

  lua_createtable(state, 0, 1);
  lua_pushcfunction(state, method_argument_error);
  lua_setfield(state, -2, "m");
  for (method_arg = 1; method_arg <= 2; method_arg++) {
    if (rivetlua_capi_test_push_lua_b4(state, 5) != 1) return 91;
    lua_pushvalue(state, -2);
    lua_pushinteger(state, 41);
    if (lua_pcall(state, 2, 0, 0) != LUA_ERRRUN) return 92;
    message = lua_tostring(state, -1);
    const char *expected = method_arg == 1
        ? "debug_api_b10.lua:3: calling 'm' on bad self (bad self)"
        : "debug_api_b10.lua:3: bad argument #1 to 'm' (bad arg)";
    if (message == NULL || strcmp(message, expected) != 0) return 93;
    lua_pop(state, 1);
  }
  if (method_name_seen != 2) return 94;
  lua_pop(state, 1);

  lua_State *allocation_state = luaL_newstate();
  if (allocation_state == NULL) return 14;
  lua_pushcfunction(allocation_state, push_nil_failure);
  if (lua_pcall(allocation_state, 0, 0, 0) != LUA_ERRMEM ||
      lua_gettop(allocation_state) != 1 ||
      lua_type(allocation_state, -1) != LUA_TSTRING) return 15;
  lua_close(allocation_state);

  for (generic_case = 1; generic_case <= 14; generic_case++) {
    if (generic_case == 12) continue;
    lua_State *probe = luaL_newstate();
    if (probe == NULL) return 16;
    if (generic_case == 10) {
      if (luaL_newmetatable(probe, "a3.named") != 1) return 17;
      lua_pop(probe, 1);
    }
    inject_generic = 1;
    lua_pushcfunction(probe, generic_probe);
    if (lua_pcall(probe, 0, 0, 0) != LUA_ERRMEM ||
        lua_gettop(probe) != 1 || lua_type(probe, -1) != LUA_TSTRING)
      return 18 + generic_case;
    lua_pop(probe, 1);
    inject_generic = 0;
    lua_pushcfunction(probe, generic_probe);
    if (lua_pcall(probe, 0, 0, 0) != LUA_OK || lua_gettop(probe) != 0)
      return 32 + generic_case;
    lua_close(probe);
  }

  lua_State *move_state = luaL_newstate();
  if (move_state == NULL) return 46;
  lua_State *move_child = lua_newthread(move_state);
  if (move_child == NULL) return 47;
  lua_settop(move_child, 20);
  lua_pushinteger(move_state, 9);
  action_a3 move_result = rivetlua_capi_trampoline_protect_a1(
      move_state, xmove_failure_action, move_child);
  int32_t move_class = 0;
  if (move_result.kind != 1 || move_result.value != 5 ||
      rivetlua_capi_error_consume_a1(move_state, &move_class) != 0 ||
      move_class != 5 || lua_gettop(move_state) != 3 ||
      lua_gettop(move_child) != 20) return 48;
  lua_pop(move_state, 1);
  lua_xmove(move_state, move_child, 1);
  if (lua_gettop(move_state) != 1 || lua_gettop(move_child) != 21 ||
      lua_tointeger(move_child, -1) != 9) return 49;
  lua_close(move_state);

  lua_State *values = luaL_newstate();
  if (values == NULL) return 50;
  lua_pushnil(values);
  lua_pushboolean(values, 1);
  lua_pushinteger(values, 17);
  lua_pushnumber(values, 2.5);
  lua_pushlightuserdata(values, values);
  luaL_pushfail(values);
#if LUA_VERSION_NUM >= 505 && defined(LUA_FAILISFALSE)
  int fail_value_ok = lua_type(values, 6) == LUA_TBOOLEAN &&
      lua_toboolean(values, 6) == 0;
#else
  int fail_value_ok = lua_type(values, 6) == LUA_TNIL;
#endif
  if (lua_gettop(values) != 6 || lua_type(values, 1) != LUA_TNIL ||
      lua_toboolean(values, 2) != 1 || lua_tointeger(values, 3) != 17 ||
      lua_tonumber(values, 4) != 2.5 ||
      lua_touserdata(values, 5) != values ||
      !fail_value_ok ||
      lua_touserdata(values, 3) != NULL) return 51;
  lua_pop(values, 6);
  lua_pushinteger(values, 1);
  lua_pushinteger(values, 2);
  lua_pushinteger(values, 3);
  lua_insert(values, 1);
  if (lua_tointeger(values, 1) != 3 || lua_tointeger(values, 2) != 1 ||
      lua_tointeger(values, 3) != 2) return 52;
  lua_remove(values, 2);
  lua_rotate(values, 1, 1);
  if (lua_gettop(values) != 2 || lua_tointeger(values, 1) != 2 ||
      lua_tointeger(values, 2) != 3) return 53;
  lua_pop(values, 2);
#if LUA_VERSION_NUM < 505
  lua_pushunsigned(values, 23);
#else
  lua_pushinteger(values, 23);
#endif
  if (lua_tointeger(values, -1) != 23) return 54;
  lua_pop(values, 1);
  const char *sub = luaL_gsub(values, "aba", "a", "z");
  if (sub == NULL || strcmp(sub, "zbz") != 0 ||
      lua_gettop(values) != 1) return 55;
  lua_pop(values, 1);
  if (luaL_newmetatable(values, "a3.values") != 1 ||
      lua_type(values, -1) != LUA_TTABLE) return 56;
  lua_pop(values, 1);
  if (luaL_newmetatable(values, "a3.values") != 0 ||
      lua_type(values, -1) != LUA_TTABLE) return 57;
  lua_pop(values, 1);
  void *userdata = lua_newuserdatauv(values, 8, 0);
  if (userdata == NULL || lua_touserdata(values, -1) != userdata ||
      lua_touserdata(values, -2) != NULL) return 58;
  luaL_setmetatable(values, "a3.values");
  if (lua_getmetatable(values, -1) != 1 ||
      lua_type(values, -1) != LUA_TTABLE) return 59;
  lua_pop(values, 2);
  void *macro_userdata = lua_newuserdata(values, 4);
  if (macro_userdata == NULL ||
      lua_touserdata(values, -1) != macro_userdata) return 83;
  lua_pop(values, 1);
  lua_createtable(values, 0, 1);
  lua_pushinteger(values, 31);
  lua_rawseti(values, -2, 1);
  lua_pushnil(values);
  if (lua_next(values, 1) != 1 || lua_tointeger(values, -1) != 31 ||
      lua_tointeger(values, -2) != 1) return 60;
  lua_pop(values, 1);
  if (lua_next(values, 1) != 0 || lua_gettop(values) != 1) return 61;
  lua_pop(values, 1);
  lua_close(values);

  lua_State *panic_state = luaL_newstate();
  if (panic_state == NULL) return 79;
  int panic_fds[2];
  if (pipe(panic_fds) != 0) return 80;
  pid_t panic_child = fork();
  if (panic_child < 0) return 81;
  if (panic_child == 0) {
    close(panic_fds[0]);
    panic_pipe = panic_fds[1];
    (void)lua_atpanic(panic_state, generic_panic_probe);
    lua_settop(panic_state, 20);
    if (rivetlua_capi_test_inject_next_allocation_a2(panic_state) != 1)
      _exit(98);
    lua_pushnil(panic_state);
    _exit(99);
  }
  close(panic_fds[1]);
  char panic_marker = 0;
  ssize_t panic_seen = read(panic_fds[0], &panic_marker, 1);
  close(panic_fds[0]);
  int panic_status = 0;
  pid_t reaped = waitpid(panic_child, &panic_status, 0);
  if (reaped != panic_child ||
      panic_seen != 1 || panic_marker != 'm' ||
      !WIFSIGNALED(panic_status) || WTERMSIG(panic_status) != SIGABRT)
    return 82;
  int strict_fds[2];
  if (pipe(strict_fds) != 0) return 84;
  pid_t strict_child = fork();
  if (strict_child < 0) return 85;
  if (strict_child == 0) {
    close(strict_fds[0]);
    panic_pipe = strict_fds[1];
    (void)lua_atpanic(panic_state, generic_panic_probe);
    lua_pushinteger(panic_state, 1);
    luaL_checktype(panic_state, 1, LUA_TSTRING);
    _exit(99);
  }
  close(strict_fds[1]);
  char strict_marker = 0;
  ssize_t strict_seen = read(strict_fds[0], &strict_marker, 1);
  close(strict_fds[0]);
  int strict_status = 0;
  if (waitpid(strict_child, &strict_status, 0) != strict_child ||
      strict_seen != 1 || strict_marker != 'm' ||
      !WIFSIGNALED(strict_status) || WTERMSIG(strict_status) != SIGABRT)
    return 86;
  lua_close(panic_state);
  lua_close(state);
  return 0;
}
