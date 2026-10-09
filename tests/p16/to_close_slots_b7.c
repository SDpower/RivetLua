/* P16-2 B7：固定 header 的位置標記、C close、error unwind 與 C-only jump。 */
#include "lua.h"
#include "lauxlib.h"
#include <stdint.h>
#include <string.h>

typedef struct { int32_t kind; int32_t value; } action_b7;
typedef action_b7 (*action_fn_b7)(void *, uint64_t, uint64_t, void *);
extern action_b7 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_b7, void *);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);
extern int rivetlua_capi_call_b4(lua_State *, int, int);

typedef struct {
  int id;
  int argc;
  int second_type;
  char error[128];
} close_event_b7;
static close_event_b7 events_b7[16];
static int event_count_b7;
static int unreachable_b7;

static void reset_events_b7(void) {
  event_count_b7 = 0;
  memset(events_b7, 0, sizeof(events_b7));
}

static void record_b7(lua_State *state, int id) {
  if (event_count_b7 >= 16) __builtin_trap();
  close_event_b7 *event = &events_b7[event_count_b7++];
  event->id = id;
  event->argc = lua_gettop(state);
  event->second_type = lua_type(state, 2);
  if (event->second_type == LUA_TSTRING) {
    size_t length = 0;
    const char *text = lua_tolstring(state, 2, &length);
    if (text != NULL) {
      size_t copied = length < sizeof(event->error) - 1
          ? length : sizeof(event->error) - 1;
      memcpy(event->error, text, copied);
      event->error[copied] = '\0';
    }
  }
}

static int close_low_b7(lua_State *state) {
  record_b7(state, 1);
  return 0;
}

static int close_high_b7(lua_State *state) {
  record_b7(state, 2);
  return 0;
}

static int close_raises_b7(lua_State *state) {
  record_b7(state, 3);
  luaL_checktype(state, 1, LUA_TNUMBER);
  unreachable_b7++;
  return 0;
}

static void push_marked_b7(lua_State *state, lua_CFunction closer) {
  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushliteral(state, "__close");
  lua_pushcclosure(state, closer, 0);
  lua_rawset(state, -3);
  if (lua_setmetatable(state, -2) != 1) __builtin_trap();
  lua_toclose(state, -1);
}

static int normal_arg_shape_b7(const close_event_b7 *event) {
#if LUA_VERSION_NUM < 505
  return event->argc == 2 && event->second_type == LUA_TNIL;
#else
  return event->argc == 1 && event->second_type == LUA_TNONE;
#endif
}

static int normal_marks_b7(lua_State *state) {
  reset_events_b7();
  lua_settop(state, 0);
  lua_pushnil(state);
  lua_toclose(state, 1);
  lua_pushboolean(state, 0);
  lua_toclose(state, 2);
  push_marked_b7(state, close_low_b7);
  push_marked_b7(state, close_high_b7);
  lua_closeslot(state, 4);
  if (event_count_b7 != 1 || events_b7[0].id != 2 ||
      !normal_arg_shape_b7(&events_b7[0]) || lua_type(state, 4) != LUA_TNIL)
    return 10;
  lua_settop(state, 2);
  if (event_count_b7 != 2 || events_b7[1].id != 1 ||
      !normal_arg_shape_b7(&events_b7[1]) || lua_gettop(state) != 2)
    return 11;
  lua_settop(state, 0);
  if (event_count_b7 != 2) return 12;
  reset_events_b7();
  push_marked_b7(state, close_low_b7);
  push_marked_b7(state, close_high_b7);
  lua_pop(state, 2);
  return lua_gettop(state) == 0 && event_count_b7 == 2 &&
      events_b7[0].id == 2 && events_b7[1].id == 1 ? 0 : 13;
}

typedef struct { int index; int after; } invalid_b7;
static action_b7 try_toclose_b7(void *raw, uint64_t generation,
                               uint64_t token, void *context) {
  (void)generation;
  (void)token;
  invalid_b7 *test = (invalid_b7 *)context;
  lua_toclose((lua_State *)raw, test->index);
  test->after++;
  return (action_b7){0, 91};
}

static action_b7 try_closeslot_b7(void *raw, uint64_t generation,
                                 uint64_t token, void *context) {
  (void)generation;
  (void)token;
  invalid_b7 *test = (invalid_b7 *)context;
  lua_closeslot((lua_State *)raw, test->index);
  test->after++;
  return (action_b7){0, 92};
}

static action_b7 try_pop_b7(void *raw, uint64_t generation,
                           uint64_t token, void *context) {
  (void)generation;
  (void)token;
  invalid_b7 *test = (invalid_b7 *)context;
  lua_pop((lua_State *)raw, 2);
  test->after++;
  return (action_b7){0, 93};
}

static int invalid_marks_b7(lua_State *state) {
  reset_events_b7();
  lua_settop(state, 0);
  lua_pushinteger(state, 7);
  invalid_b7 bad = {1, 0};
  action_b7 result = rivetlua_capi_trampoline_protect_a1(
      state, try_toclose_b7, &bad);
  if (result.kind != 1 || bad.after != 0 || lua_gettop(state) != 1) return 20;
  int32_t error_class = 0;
  if (rivetlua_capi_error_consume_a1(state, &error_class) != 0 ||
      error_class != 2 || lua_gettop(state) != 2) return 21;
  lua_settop(state, 0);
  if (event_count_b7 != 0) return 22;

  push_marked_b7(state, close_low_b7);
  push_marked_b7(state, close_high_b7);
  bad.index = 1;
  bad.after = 0;
  result = rivetlua_capi_trampoline_protect_a1(
      state, try_closeslot_b7, &bad);
  if (event_count_b7 != 0 || lua_gettop(state) != 2) return 23;
  if (result.kind == 1) {
    if (bad.after != 0 ||
        rivetlua_capi_error_consume_a1(state, &error_class) != 0 ||
        error_class != 2) return 24;
    lua_settop(state, 2);
  } else if (result.kind != 0 || bad.after != 1) {
    return 25;
  }
  lua_closeslot(state, 2);
  lua_closeslot(state, 1);
  if (event_count_b7 != 2 || events_b7[0].id != 2 ||
      events_b7[1].id != 1) return 26;
  lua_settop(state, 0);
  return 0;
}

static int callback_return_b7(lua_State *state) {
  push_marked_b7(state, close_low_b7);
  lua_pushinteger(state, 42);
  return 1;
}

static int callback_error_b7(lua_State *state) {
  push_marked_b7(state, close_low_b7);
  push_marked_b7(state, close_raises_b7);
  luaL_checktype(state, 1, LUA_TSTRING);
  unreachable_b7++;
  return 0;
}

static int callback_paths_b7(lua_State *state) {
  reset_events_b7();
  lua_settop(state, 0);
  lua_pushcfunction(state, callback_return_b7);
  if (rivetlua_capi_call_b4(state, 0, 1) != 0 ||
      event_count_b7 != 1 || events_b7[0].id != 1 ||
      !normal_arg_shape_b7(&events_b7[0]) || lua_gettop(state) != 1 ||
      lua_tointeger(state, 1) != 42) return 30;

  reset_events_b7();
  lua_settop(state, 0);
  lua_pushcfunction(state, callback_error_b7);
  if (rivetlua_capi_call_b4(state, 0, 0) == 0 || unreachable_b7 != 0 ||
      event_count_b7 != 2 || events_b7[0].id != 3 ||
      events_b7[1].id != 1 ||
      events_b7[0].second_type != LUA_TSTRING ||
      events_b7[1].second_type != LUA_TSTRING ||
      strstr(events_b7[0].error, "string") == NULL ||
      strstr(events_b7[1].error, "number") == NULL) return 31;
  int32_t error_class = 0;
  if (rivetlua_capi_error_consume_a1(state, &error_class) != 0 ||
      error_class != 2) return 32;
  size_t length = 0;
  const char *message = lua_tolstring(state, -1, &length);
  if (message == NULL || strstr(message, "number") == NULL) return 33;
  lua_settop(state, 0);
  reset_events_b7();
  lua_pushcfunction(state, callback_return_b7);
  if (rivetlua_capi_call_b4(state, 0, 1) != 0 ||
      event_count_b7 != 1 || lua_tointeger(state, -1) != 42) return 34;
  lua_settop(state, 0);
  return 0;
}

static int pop_close_error_b7(lua_State *state) {
  reset_events_b7();
  lua_settop(state, 0);
  push_marked_b7(state, close_low_b7);
  push_marked_b7(state, close_raises_b7);
  invalid_b7 test = {0, 0};
  action_b7 outcome = rivetlua_capi_trampoline_protect_a1(
      state, try_pop_b7, &test);
  if (outcome.kind != 1 || test.after != 0 || unreachable_b7 != 0 ||
      event_count_b7 != 2 || events_b7[0].id != 3 ||
      events_b7[1].id != 1 ||
      !normal_arg_shape_b7(&events_b7[0]) ||
      events_b7[1].second_type != LUA_TSTRING ||
      strstr(events_b7[1].error, "number") == NULL) return 40;
  int32_t error_class = 0;
  if (rivetlua_capi_error_consume_a1(state, &error_class) != 0 ||
      error_class != 2) return 41;
  lua_settop(state, 0);
  return event_count_b7 == 2 ? 0 : 42;
}

int main(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 1;
  int status = normal_marks_b7(state);
  if (status == 0) status = invalid_marks_b7(state);
  if (status == 0) status = callback_paths_b7(state);
  if (status == 0) status = pop_close_error_b7(state);
  lua_close(state);
  return status;
}
