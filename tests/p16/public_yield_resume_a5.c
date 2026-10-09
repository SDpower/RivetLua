#include "lua.h"
#include "lauxlib.h"
#include <string.h>

static int continuation_count = 0;
static int callback_yieldable = 0;
static int outer_count = 0;
static int outer_status = -1;
static int error_count = 0;
static int multiple_count = 0;
static int no_yield_count = 0;
static int close_count = 0;
static int handler_count = 0;
static int mixed_order[8];
static int mixed_count = 0;
static const void *mixed_values[4];
static int mixed_error_mode = 0;
static int mixed_outer_saw_error = 0;
static int mixed_fault_armed = 0;
static int mixed_capture_refs[3] = {LUA_NOREF, LUA_NOREF, LUA_NOREF};
static lua_State *nested_fault_child = NULL;
static int parent_close_status = -1;
static int parent_depth_before = -1;
static int parent_depth_after = -1;
static int parent_top_before = -1;
static int parent_top_after = -1;
static int parent_api_alive = 0;

extern int rivetlua_capi_test_push_lua_b4(lua_State *state, int selector);
extern int rivetlua_capi_test_fail_next_close_boundary_root_a5(lua_State *state);

static int plain_yield(lua_State *state) {
  callback_yieldable = lua_isyieldable(state);
  lua_pushinteger(state, 17);
  return lua_yield(state, 1);
}

static int finish_yield(lua_State *state, int status, lua_KContext context) {
  if (status != LUA_YIELD || context != 91) return 0;
  continuation_count++;
  lua_pushinteger(state, lua_tointeger(state, -1) + context);
  return 1;
}

static int yield_with_continuation(lua_State *state) {
  callback_yieldable = lua_isyieldable(state);
  lua_pushinteger(state, 23);
  return lua_yieldk(state, 1, 91, finish_yield);
}

static int finish_outer_call(lua_State *state, int status, lua_KContext context) {
  outer_count++;
  outer_status = status;
  if (status != LUA_YIELD || context != 31) return 0;
  lua_pushinteger(state, lua_tointeger(state, -1) + 1);
  return 1;
}

static int outer_callk(lua_State *state) {
  lua_pushcfunction(state, yield_with_continuation);
  lua_callk(state, 0, 1, 31, finish_outer_call);
  return 1; /* 沒有 yield 時才返回此處。 */
}

static int finish_outer_pcall(lua_State *state, int status, lua_KContext context) {
  outer_count++;
  outer_status = status;
  if (status != LUA_YIELD || context != 37) return 0;
  lua_pushinteger(state, lua_tointeger(state, -1) + 2);
  return 1;
}

static int outer_pcallk(lua_State *state) {
  lua_pushcfunction(state, yield_with_continuation);
  if (lua_pcallk(state, 0, 1, 0, 37, finish_outer_pcall) != LUA_OK) return 0;
  return 1; /* 沒有 yield 時才返回此處。 */
}

static int error_after_resume(lua_State *state, int status, lua_KContext context) {
  if (status != LUA_YIELD || context != 47) return 0;
  return luaL_error(state, "resumed failure");
}

static int yield_then_error(lua_State *state) {
  lua_pushinteger(state, 5);
  return lua_yieldk(state, 1, 47, error_after_resume);
}

static int finish_error_pcall(lua_State *state, int status, lua_KContext context) {
  error_count++;
  if (status != LUA_ERRRUN || context != 41 ||
      lua_type(state, -1) != LUA_TSTRING) return 0;
  lua_pushinteger(state, 77);
  return 1;
}

static int outer_pcall_error(lua_State *state) {
  lua_pushcfunction(state, yield_then_error);
  if (lua_pcallk(state, 0, 1, 0, 41, finish_error_pcall) != LUA_OK) return 0;
  return 1;
}

static int error_handler(lua_State *state) {
  if (lua_type(state, 1) != LUA_TSTRING) return 0;
  handler_count++;
  lua_pushstring(state, "handled error");
  return 1;
}

static int finish_handled_pcall(lua_State *state, int status,
                                lua_KContext context) {
  if (status != LUA_ERRRUN || context != 51 ||
      lua_type(state, -1) != LUA_TSTRING) return 0;
  lua_pushinteger(state, 88);
  return 1;
}

static int outer_pcall_error_handler(lua_State *state) {
  lua_pushcfunction(state, error_handler);
  int handler_index = lua_gettop(state);
  lua_pushcfunction(state, yield_then_error);
  if (lua_pcallk(state, 0, 1, handler_index, 51,
                 finish_handled_pcall) != LUA_OK) return 0;
  return 1;
}

static int continue_multiple(lua_State *state, int status, lua_KContext context) {
  if (status != LUA_YIELD || context != 57) return 0;
  multiple_count++;
  if (multiple_count == 1) {
    lua_pushinteger(state, 31);
    return lua_yieldk(state, 1, 57, continue_multiple);
  }
  lua_pushinteger(state, 32);
  return 1;
}

static int multiple_yield(lua_State *state) {
  lua_pushinteger(state, 30);
  return lua_yieldk(state, 1, 57, continue_multiple);
}

static int finish_nested(lua_State *state, int status, lua_KContext context) {
  outer_count++;
  if (status != LUA_YIELD || context != 43) return 0;
  lua_pushinteger(state, lua_tointeger(state, -1) + 1);
  return 1;
}

static int nested_lua_call(lua_State *state) {
  lua_pushvalue(state, lua_upvalueindex(1));
  lua_pushcfunction(state, plain_yield);
  lua_pushcfunction(state, plain_yield);
  lua_callk(state, 2, 1, 43, finish_nested);
  return 1;
}

static int no_yield_inner(lua_State *state) {
  lua_pushinteger(state, 5);
  return 1;
}

static int unexpected_k(lua_State *state, int status, lua_KContext context) {
  (void)state;
  (void)status;
  (void)context;
  no_yield_count++;
  return 0;
}

static int no_yield_outer(lua_State *state) {
  lua_pushcfunction(state, no_yield_inner);
  lua_callk(state, 0, 1, 67, unexpected_k);
  return 1;
}

static int count_close(lua_State *state) {
  (void)state;
  close_count++;
  return 0;
}

static int count_close_error(lua_State *state) {
  close_count++;
  return luaL_error(state, "close failure");
}

static int close_then_yield(lua_State *state) {
  lua_newtable(state);
  lua_newtable(state);
  lua_pushcfunction(state, count_close);
  lua_setfield(state, -2, "__close");
  lua_setmetatable(state, -2);
  lua_toclose(state, -1);
  lua_pushinteger(state, 73);
  return lua_yield(state, 1);
}

static int outer_close_then_callk(lua_State *state) {
  lua_newtable(state);
  lua_newtable(state);
  lua_pushcfunction(state, count_close);
  lua_setfield(state, -2, "__close");
  lua_setmetatable(state, -2);
  lua_toclose(state, -1);
  lua_pushcfunction(state, plain_yield);
  lua_callk(state, 0, 0, 69, unexpected_k);
  return 0;
}

static int close_error_then_yield(lua_State *state) {
  lua_newtable(state);
  lua_newtable(state);
  lua_pushcfunction(state, count_close_error);
  lua_setfield(state, -2, "__close");
  lua_setmetatable(state, -2);
  lua_toclose(state, -1);
  lua_pushinteger(state, 74);
  return lua_yield(state, 1);
}

static int ordered_close(lua_State *state) {
  const void *value = lua_topointer(state, 1);
  int tag = 0;
  for (int candidate = 1; candidate <= 3; candidate++) {
    if (mixed_values[candidate] == value) tag = candidate;
  }
  if (mixed_count < 8) mixed_order[mixed_count++] = tag;
  if (tag == 1 && mixed_error_mode) {
    lua_gc(state, LUA_GCCOLLECT, 0);
    if (lua_type(state, 2) == LUA_TSTRING &&
        strcmp(lua_tostring(state, 2), "mixed close failure") == 0)
      mixed_outer_saw_error = 1;
    if (mixed_error_mode == 2) {
      mixed_fault_armed =
          rivetlua_capi_test_fail_next_close_boundary_root_a5(state);
      if (mixed_fault_armed) {
        lua_pushstring(state, "outer close failure");
        return lua_error(state);
      }
    }
  }
  if (tag == 2 && mixed_error_mode) {
    lua_pushstring(state, "mixed close failure");
    return lua_error(state);
  }
  return 0;
}

static void push_ordered_close(lua_State *state, int tag) {
  lua_newtable(state);
  lua_pushinteger(state, tag);
  lua_setfield(state, -2, "tag");
  mixed_values[tag] = lua_topointer(state, -1);
  lua_newtable(state);
  lua_pushcfunction(state, ordered_close);
  lua_setfield(state, -2, "__close");
  lua_setmetatable(state, -2);
}

static int mixed_inner_yield(lua_State *state) {
  if (lua_type(state, 1) != LUA_TFUNCTION) return 0;
  if (lua_getupvalue(state, 1, 1) == NULL) return 0;
  lua_getfield(state, -1, "tag");
  if (lua_tointeger(state, -1) != 2) return 0;
  lua_pop(state, 2);
  lua_pushvalue(state, 1);
  mixed_capture_refs[mixed_error_mode] = luaL_ref(state, LUA_REGISTRYINDEX);
  if (mixed_capture_refs[mixed_error_mode] < 0) return 0;
  push_ordered_close(state, 3);
  lua_toclose(state, -1);
  lua_pushinteger(state, 83);
  return lua_yield(state, 1);
}

static int mixed_outer_call(lua_State *state) {
  push_ordered_close(state, 1);
  lua_toclose(state, -1);
  lua_pushvalue(state, lua_upvalueindex(1));
  lua_pushcfunction(state, mixed_inner_yield);
  push_ordered_close(state, 2);
  lua_callk(state, 2, 0, 79, unexpected_k);
  return 0;
}

static int check_mixed_capture(lua_State *state, int ref) {
  if (ref < 0) return 0;
  lua_rawgeti(state, LUA_REGISTRYINDEX, ref);
  if (lua_type(state, -1) != LUA_TFUNCTION ||
      lua_getupvalue(state, -1, 1) == NULL) return 0;
  lua_getfield(state, -1, "tag");
  int correct = lua_tointeger(state, -1) == 2;
  lua_pop(state, 3);
  luaL_unref(state, LUA_REGISTRYINDEX, ref);
  return correct;
}

static int active_depth(lua_State *state) {
  lua_Debug frame;
  int depth = 0;
  while (depth < 8 && lua_getstack(state, depth, &frame)) depth++;
  return depth;
}

static int parent_closes_fault_child(lua_State *state) {
  lua_pushinteger(state, 314);
  lua_newtable(state);
  lua_pushinteger(state, 316);
  lua_setfield(state, -2, "keep");
  const void *parent_root = lua_topointer(state, -1);
  parent_top_before = lua_gettop(state);
  parent_depth_before = active_depth(state);
  parent_close_status = lua_closethread(nested_fault_child, state);
  parent_top_after = lua_gettop(state);
  parent_depth_after = active_depth(state);
  lua_gc(state, LUA_GCCOLLECT, 0);
  parent_api_alive = lua_tointeger(state, -2) == 314 &&
                     lua_topointer(state, -1) == parent_root;
  lua_getfield(state, -1, "keep");
  parent_api_alive = parent_api_alive && lua_tointeger(state, -1) == 316;
  lua_pop(state, 1);
  lua_pushinteger(state, 315);
  return 1;
}

int main(void) {
  lua_State *main_state = luaL_newstate();
  if (main_state == NULL) return 1;
  if (lua_status(main_state) != LUA_OK || lua_isyieldable(main_state) != 0)
    return 2;

  lua_State *child = lua_newthread(main_state);
  if (child == NULL || lua_status(child) != LUA_OK || lua_isyieldable(child) != 1)
    return 3;
  lua_pushcfunction(child, plain_yield);
  int results = -7;
  int status = lua_resume(child, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || callback_yieldable != 1 ||
      lua_status(child) != LUA_YIELD || lua_isyieldable(child) != 1 ||
      lua_gettop(child) != 1 ||
      lua_tointeger(child, -1) != 17)
    return 4;
  lua_pop(child, 1);
  lua_pushinteger(child, 19);
  status = lua_resume(child, main_state, 1, &results);
  if (status != LUA_OK || results != 1 || lua_gettop(child) != 1 ||
      lua_tointeger(child, -1) != 19 || lua_status(child) != LUA_OK ||
      lua_isyieldable(child) != 1)
    return 5;

  lua_State *with_k = lua_newthread(main_state);
  if (with_k == NULL) return 6;
  lua_pushcfunction(with_k, yield_with_continuation);
  results = -7;
  status = lua_resume(with_k, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || callback_yieldable != 1 ||
      lua_tointeger(with_k, -1) != 23 || continuation_count != 0)
    return 7;
  lua_pop(with_k, 1);
  lua_pushinteger(with_k, 24);
  status = lua_resume(with_k, main_state, 1, &results);
  if (status != LUA_OK || results != 1 || continuation_count != 1 ||
      lua_tointeger(with_k, -1) != 115)
    return 8;

  lua_State *first = lua_newthread(main_state);
  lua_State *second = lua_newthread(main_state);
  if (first == NULL || second == NULL) return 34;
  lua_pushcfunction(first, yield_with_continuation);
  lua_pushcfunction(second, yield_with_continuation);
  continuation_count = 0;
  results = -7;
  if (lua_resume(first, main_state, 0, &results) != LUA_YIELD ||
      results != 1 || lua_tointeger(first, -1) != 23)
    return 35;
  results = -7;
  if (lua_resume(second, main_state, 0, &results) != LUA_YIELD ||
      results != 1 || lua_tointeger(second, -1) != 23 || continuation_count != 0)
    return 36;
  lua_pop(first, 1);
  lua_pushinteger(first, 24);
  if (lua_resume(first, main_state, 1, &results) != LUA_OK ||
      results != 1 || lua_tointeger(first, -1) != 115 ||
      lua_status(second) != LUA_YIELD || continuation_count != 1)
    return 37;
  lua_pop(second, 1);
  lua_pushinteger(second, 34);
  if (lua_resume(second, main_state, 1, &results) != LUA_OK ||
      results != 1 || lua_tointeger(second, -1) != 125 || continuation_count != 2)
    return 38;

  lua_State *callk_child = lua_newthread(main_state);
  if (callk_child == NULL) return 9;
  lua_pushcfunction(callk_child, outer_callk);
  continuation_count = outer_count = 0;
  results = -7;
  status = lua_resume(callk_child, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 ||
      lua_tointeger(callk_child, -1) != 23 || outer_count != 0)
    return 10;
  lua_pop(callk_child, 1);
  lua_pushinteger(callk_child, 24);
  status = lua_resume(callk_child, main_state, 1, &results);
  if (status != LUA_OK || results != 1 ||
      lua_tointeger(callk_child, -1) != 116 || continuation_count != 1 ||
      outer_count != 1 || outer_status != LUA_YIELD)
    return 11;

  lua_State *pcall_child = lua_newthread(main_state);
  if (pcall_child == NULL) return 12;
  lua_pushcfunction(pcall_child, outer_pcallk);
  continuation_count = outer_count = 0;
  results = -7;
  status = lua_resume(pcall_child, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || outer_count != 0) return 13;
  lua_pop(pcall_child, 1);
  lua_pushinteger(pcall_child, 24);
  status = lua_resume(pcall_child, main_state, 1, &results);
  if (status != LUA_OK || results != 1 ||
      lua_tointeger(pcall_child, -1) != 117 || continuation_count != 1 ||
      outer_count != 1 || outer_status != LUA_YIELD)
    return 14;

  lua_State *error_child = lua_newthread(main_state);
  if (error_child == NULL) return 15;
  lua_pushcfunction(error_child, outer_pcall_error);
  error_count = 0;
  results = -7;
  status = lua_resume(error_child, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || error_count != 0) return 16;
  lua_pop(error_child, 1);
  status = lua_resume(error_child, main_state, 0, &results);
  if (status != LUA_OK || results != 1 ||
      lua_tointeger(error_child, -1) != 77 || error_count != 1)
    return 17;

  lua_State *handled_error = lua_newthread(main_state);
  if (handled_error == NULL) return 42;
  lua_pushcfunction(handled_error, outer_pcall_error_handler);
  handler_count = 0;
  results = -7;
  status = lua_resume(handled_error, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || handler_count != 0)
    return 43;
  lua_pop(handled_error, 1);
  status = lua_resume(handled_error, main_state, 0, &results);
  if (status != LUA_OK || results != 1 ||
      lua_tointeger(handled_error, -1) != 88 || handler_count != 1)
    return 44;

  lua_State *unprotected_error = lua_newthread(main_state);
  if (unprotected_error == NULL) return 30;
  lua_pushcfunction(unprotected_error, yield_then_error);
  results = -7;
  status = lua_resume(unprotected_error, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 ||
      lua_status(unprotected_error) != LUA_YIELD)
    return 31;
  lua_pop(unprotected_error, 1);
  status = lua_resume(unprotected_error, main_state, 0, &results);
  if (status != LUA_ERRRUN || lua_status(unprotected_error) != LUA_ERRRUN ||
      lua_gettop(unprotected_error) != 2 ||
      lua_type(unprotected_error, -1) != LUA_TSTRING)
    return 32;
  lua_settop(unprotected_error, 0);
  results = -7;
  status = lua_resume(unprotected_error, main_state, 0, &results);
  if (status != LUA_ERRRUN || results != -7 ||
      lua_status(unprotected_error) != LUA_ERRRUN ||
      lua_gettop(unprotected_error) != 1)
    return 33;

  lua_State *multiple = lua_newthread(main_state);
  if (multiple == NULL) return 18;
  lua_pushcfunction(multiple, multiple_yield);
  multiple_count = 0;
  results = -7;
  status = lua_resume(multiple, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 ||
      lua_tointeger(multiple, -1) != 30 || multiple_count != 0)
    return 19;
  lua_pop(multiple, 1);
  status = lua_resume(multiple, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 ||
      lua_tointeger(multiple, -1) != 31 || multiple_count != 1)
    return 20;
  lua_pop(multiple, 1);
  status = lua_resume(multiple, main_state, 0, &results);
  if (status != LUA_OK || results != 1 ||
      lua_tointeger(multiple, -1) != 32 || multiple_count != 2)
    return 21;

  lua_State *nested = lua_newthread(main_state);
  if (nested == NULL) return 22;
  if (rivetlua_capi_test_push_lua_b4(nested, 1) != 1) return 22;
  lua_pushcclosure(nested, nested_lua_call, 1);
  outer_count = 0;
  results = -7;
  status = lua_resume(nested, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 ||
      lua_tointeger(nested, -1) != 17 || outer_count != 0)
    return 23;
  lua_pop(nested, 1);
  lua_pushinteger(nested, 19);
  status = lua_resume(nested, main_state, 1, &results);
  if (status != LUA_OK || results != 1 ||
      lua_tointeger(nested, -1) != 20 || outer_count != 1)
    return 24;

  lua_State *normal = lua_newthread(main_state);
  if (normal == NULL) return 25;
  lua_pushcfunction(normal, no_yield_outer);
  no_yield_count = 0;
  results = -7;
  status = lua_resume(normal, main_state, 0, &results);
  if (status != LUA_OK || results != 1 ||
      lua_tointeger(normal, -1) != 5 || no_yield_count != 0)
    return 26;

  lua_settop(child, 0);
  results = -7;
  status = lua_resume(child, main_state, 0, &results);
  if (status != LUA_ERRRUN || results != -7 || lua_gettop(child) != 1 ||
      lua_type(child, -1) != LUA_TSTRING || lua_status(child) != LUA_OK)
    return 27;

  int main_top = lua_gettop(main_state);
  lua_pushcfunction(main_state, plain_yield);
  status = lua_pcall(main_state, 0, 1, 0);
  if (status != LUA_ERRRUN || lua_gettop(main_state) != main_top + 1 ||
      lua_type(main_state, -1) != LUA_TSTRING)
    return 28;
  lua_pop(main_state, 1);
  lua_pushcfunction(main_state, no_yield_inner);
  status = lua_pcall(main_state, 0, 1, 0);
  if (status != LUA_OK || lua_tointeger(main_state, -1) != 5) return 29;

  lua_State *closable = lua_newthread(main_state);
  if (closable == NULL) return 39;
  lua_pushcfunction(closable, close_then_yield);
  close_count = 0;
  results = -7;
  status = lua_resume(closable, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || close_count != 0 ||
      lua_tointeger(closable, -1) != 73)
    return 40;
  status = lua_closethread(closable, main_state);
  if (status != LUA_OK || close_count != 1 ||
      lua_status(closable) != LUA_OK || lua_gettop(closable) != 0)
    return 41;

  lua_State *outer_closable = lua_newthread(main_state);
  if (outer_closable == NULL) return 45;
  lua_pushcfunction(outer_closable, outer_close_then_callk);
  close_count = 0;
  results = -7;
  status = lua_resume(outer_closable, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || close_count != 0)
    return 46;
  status = lua_closethread(outer_closable, main_state);
  if (status != LUA_OK || close_count != 1 ||
      no_yield_count != 0 ||
      lua_status(outer_closable) != LUA_OK ||
      lua_gettop(outer_closable) != 0)
    return 47;

  lua_State *closing_error = lua_newthread(main_state);
  if (closing_error == NULL) return 48;
  lua_pushcfunction(closing_error, close_error_then_yield);
  close_count = 0;
  results = -7;
  status = lua_resume(closing_error, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || close_count != 0)
    return 49;
  status = lua_closethread(closing_error, main_state);
  if (status != LUA_ERRRUN || close_count != 1 ||
      lua_status(closing_error) != LUA_OK ||
      lua_gettop(closing_error) != 1 ||
      lua_type(closing_error, -1) != LUA_TSTRING)
    return 50;

  lua_State *mixed = lua_newthread(main_state);
  if (mixed == NULL) return 51;
  if (rivetlua_capi_test_push_lua_b4(mixed, 9) != 1) return 51;
  lua_pushcclosure(mixed, mixed_outer_call, 1);
  mixed_count = 0;
  results = -7;
  status = lua_resume(mixed, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 ||
      lua_tointeger(mixed, -1) != 83 || mixed_count != 0)
    return 52;
  lua_gc(mixed, LUA_GCCOLLECT, 0);
  status = lua_closethread(mixed, main_state);
  if (status != LUA_OK || mixed_count != 3 ||
      mixed_order[0] != 3 || mixed_order[1] != 2 || mixed_order[2] != 1 ||
      no_yield_count != 0 || lua_gettop(mixed) != 0 ||
      lua_status(mixed) != LUA_OK ||
      !check_mixed_capture(main_state, mixed_capture_refs[0]))
    return 53;

  lua_State *mixed_error = lua_newthread(main_state);
  if (mixed_error == NULL) return 54;
  if (rivetlua_capi_test_push_lua_b4(mixed_error, 9) != 1) return 54;
  lua_pushcclosure(mixed_error, mixed_outer_call, 1);
  mixed_error_mode = 1;
  mixed_outer_saw_error = 0;
  mixed_count = 0;
  results = -7;
  status = lua_resume(mixed_error, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || mixed_count != 0 ||
      lua_tointeger(mixed_error, -1) != 83)
    return 55;
  lua_gc(mixed_error, LUA_GCCOLLECT, 0);
  status = lua_closethread(mixed_error, main_state);
  if (status != LUA_ERRRUN || mixed_count != 3 || !mixed_outer_saw_error ||
      mixed_order[0] != 3 || mixed_order[1] != 2 || mixed_order[2] != 1 ||
      no_yield_count != 0 || lua_status(mixed_error) != LUA_OK ||
      lua_gettop(mixed_error) != 1 ||
      lua_type(mixed_error, -1) != LUA_TSTRING ||
      strcmp(lua_tostring(mixed_error, -1), "mixed close failure") != 0 ||
      !check_mixed_capture(main_state, mixed_capture_refs[1]))
    return 56;
  mixed_error_mode = 0;
  status = lua_closethread(mixed_error, main_state);
  if (status != LUA_OK || mixed_count != 3 || lua_gettop(mixed_error) != 0)
    return 57;
  lua_pushcfunction(mixed_error, no_yield_inner);
  status = lua_resume(mixed_error, main_state, 0, &results);
  if (status != LUA_OK || results != 1 ||
      lua_tointeger(mixed_error, -1) != 5 || mixed_count != 3)
    return 58;

  lua_State *mixed_fault = lua_newthread(main_state);
  if (mixed_fault == NULL) return 59;
  if (rivetlua_capi_test_push_lua_b4(mixed_fault, 9) != 1) return 59;
  lua_pushcclosure(mixed_fault, mixed_outer_call, 1);
  mixed_error_mode = 2;
  mixed_outer_saw_error = 0;
  mixed_fault_armed = 0;
  mixed_count = 0;
  status = lua_resume(mixed_fault, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || mixed_count != 0 ||
      lua_tointeger(mixed_fault, -1) != 83)
    return 60;
  status = lua_closethread(mixed_fault, main_state);
  lua_gc(mixed_fault, LUA_GCCOLLECT, 0);
  if (mixed_count != 3 || mixed_order[0] != 3 || mixed_order[1] != 2 ||
      mixed_order[2] != 1 || !mixed_outer_saw_error || no_yield_count != 0 ||
      lua_status(mixed_fault) != LUA_OK || lua_gettop(mixed_fault) != 1 ||
      lua_type(mixed_fault, -1) != LUA_TSTRING ||
      !check_mixed_capture(main_state, mixed_capture_refs[2]))
    return 61;
  if (mixed_fault_armed) {
    if (status != LUA_ERRMEM ||
        strcmp(lua_tostring(mixed_fault, -1), "not enough memory") != 0)
      return 62;
  } else if (status != LUA_ERRRUN ||
             strcmp(lua_tostring(mixed_fault, -1), "mixed close failure") != 0) {
    return 63;
  }
  mixed_error_mode = 0;
  status = lua_closethread(mixed_fault, main_state);
  if (status != LUA_OK || mixed_count != 3 || lua_gettop(mixed_fault) != 0)
    return 64;
  lua_pushcfunction(mixed_fault, no_yield_inner);
  status = lua_resume(mixed_fault, main_state, 0, &results);
  if (status != LUA_OK || results != 1 ||
      lua_tointeger(mixed_fault, -1) != 5 || mixed_count != 3)
    return 65;

  nested_fault_child = lua_newthread(main_state);
  if (nested_fault_child == NULL) return 66;
  if (rivetlua_capi_test_push_lua_b4(nested_fault_child, 9) != 1)
    return 66;
  lua_pushcclosure(nested_fault_child, mixed_outer_call, 1);
  mixed_error_mode = 2;
  mixed_outer_saw_error = 0;
  mixed_fault_armed = 0;
  mixed_count = 0;
  status = lua_resume(nested_fault_child, main_state, 0, &results);
  if (status != LUA_YIELD || results != 1 || mixed_count != 0 ||
      lua_tointeger(nested_fault_child, -1) != 83)
    return 67;
  lua_pushcfunction(main_state, parent_closes_fault_child);
  status = lua_pcall(main_state, 0, 1, 0);
  if (status != LUA_OK || lua_tointeger(main_state, -1) != 315)
    return 68;
  if (parent_top_before != 2 || parent_top_after != 2 ||
      parent_depth_before < 1 || parent_depth_after != parent_depth_before ||
      !parent_api_alive)
    return 72;
  if (parent_close_status != LUA_ERRMEM && parent_close_status != LUA_ERRRUN)
    return 80 + parent_close_status;
  if (mixed_count != 3) return 73;
  if (mixed_order[0] != 3 || mixed_order[1] != 2 ||
      mixed_order[2] != 1 || !mixed_outer_saw_error || no_yield_count != 0)
    return 77;
  if (lua_status(nested_fault_child) != LUA_OK ||
      lua_gettop(nested_fault_child) != 1 ||
      lua_type(nested_fault_child, -1) != LUA_TSTRING ||
      !check_mixed_capture(main_state, mixed_capture_refs[2]))
    return 74;
  if (mixed_fault_armed) {
    if (parent_close_status != LUA_ERRMEM ||
        strcmp(lua_tostring(nested_fault_child, -1), "not enough memory") != 0)
      return 69;
  } else if (parent_close_status != LUA_ERRRUN ||
             strcmp(lua_tostring(nested_fault_child, -1),
                    "mixed close failure") != 0) {
    return 70;
  }
  mixed_error_mode = 0;
  status = lua_closethread(nested_fault_child, main_state);
  if (status != LUA_OK || mixed_count != 3 ||
      lua_gettop(nested_fault_child) != 0)
    return 71;
  lua_close(main_state);
  return 0;
}
