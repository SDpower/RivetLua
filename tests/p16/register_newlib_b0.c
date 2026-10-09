/* P16-2 B0 宏片：真實固定 header 巨集展開與 C ABI 執行。 */
#include "lua.h"
#include "lauxlib.h"
#include "rivetlua_abi.h"

static lua_State *state;

typedef struct {
  int state_calls;
  int function_calls;
  int name_calls;
  int events[2];
  int event_count;
} register_trace;

static register_trace registration;
static int newlib_state_calls;
static int newlib_order_error;

static int registered_callback(lua_State *L) {
  (void)L;
  return 0;
}

static int first_library_callback(lua_State *L) {
  (void)L;
  return 0;
}

static int second_library_callback(lua_State *L) {
  (void)L;
  return 0;
}

static int after_sentinel_callback(lua_State *L) {
  (void)L;
  return 0;
}

static lua_State *registration_state(void) {
  registration.state_calls += 1;
  return state;
}

static lua_CFunction registration_function(void) {
  registration.function_calls += 1;
  registration.events[registration.event_count++] = 1;
  return registered_callback;
}

static const char *registration_name(void) {
  registration.name_calls += 1;
  registration.events[registration.event_count++] = 2;
  return "b0_registered";
}

static luaL_Reg library[] = {
    {"first", first_library_callback},
    {"second", second_library_callback},
    {NULL, NULL},
    {"after_sentinel", after_sentinel_callback},
    {NULL, NULL},
};

static lua_State *newlib_state(void) {
  newlib_state_calls += 1;
  if (newlib_state_calls == 3 &&
      (lua_gettop(state) != 1 || lua_type(state, -1) != LUA_TTABLE))
    newlib_order_error = 1;
  return state;
}

#define CHECK(code, condition) \
  do { \
    if (!(condition)) { \
      lua_close(state); \
      return (code); \
    } \
  } while (0)

int main(void) {
  state = luaL_newstate();
  if (state == NULL)
    return 1;
  CHECK(2, RIVETLUA_PROFILE_ID == 54 || RIVETLUA_PROFILE_ID == 55);
  CHECK(3, lua_gettop(state) == 0);

  lua_register(registration_state(), registration_name(), registration_function());
  CHECK(4, registration.state_calls == 2);
  CHECK(5, registration.function_calls == 1);
  CHECK(6, registration.name_calls == 1);
  CHECK(7, registration.event_count == 2);
  CHECK(8, registration.events[0] == 1 && registration.events[1] == 2);
  CHECK(9, lua_gettop(state) == 0);
  CHECK(10, lua_getglobal(state, "b0_registered") == LUA_TFUNCTION);
  CHECK(11, lua_tocfunction(state, -1) == registered_callback);
  lua_settop(state, 0);

  luaL_newlib(newlib_state(), library);
  CHECK(12, newlib_state_calls == 3);
  CHECK(13, newlib_order_error == 0);
  CHECK(14, lua_gettop(state) == 1);
  CHECK(15, lua_type(state, 1) == LUA_TTABLE);

  CHECK(16, lua_getfield(state, 1, "first") == LUA_TFUNCTION);
  CHECK(17, lua_tocfunction(state, -1) == first_library_callback);
  lua_settop(state, 1);

  CHECK(18, lua_getfield(state, 1, "second") == LUA_TFUNCTION);
  CHECK(19, lua_tocfunction(state, -1) == second_library_callback);
  lua_settop(state, 1);

  CHECK(20, lua_getfield(state, 1, "after_sentinel") == LUA_TNIL);
  lua_settop(state, 0);
  lua_close(state);
  return 0;
}
