#if defined(P24_LUA54)
#include <rivetlua/lua54/lua.h>
#include <rivetlua/lua54/lauxlib.h>
#else
#include <rivetlua/lua55/lua.h>
#include <rivetlua/lua55/lauxlib.h>
#endif
#include <rivetlua/rivetlua_abi.h>
#include <string.h>

#if defined(P24_LUA54)
#define P24_GLOBAL_DECLARATION ""
#else
#define P24_GLOBAL_DECLARATION "global record_once; "
#endif

static unsigned callback_calls;

static int record_once(lua_State *state) {
  callback_calls++;
  lua_pushinteger(state, 41);
  return 1;
}

static int same_identity(const rivetlua_abi_identity *actual,
                         const rivetlua_abi_identity *expected) {
  return actual->revision == expected->revision &&
         actual->profile == expected->profile &&
         actual->numeric_config == expected->numeric_config &&
         actual->pointer_width_bits == expected->pointer_width_bits &&
         actual->endianness == expected->endianness &&
         actual->reserved_zero == expected->reserved_zero &&
         memcmp(actual->target, expected->target, sizeof(actual->target)) == 0 &&
         memcmp(actual->header_set_sha256, expected->header_set_sha256,
                sizeof(actual->header_set_sha256)) == 0 &&
         memcmp(actual->lua_h_sha256, expected->lua_h_sha256,
                sizeof(actual->lua_h_sha256)) == 0 &&
         memcmp(actual->lauxlib_h_sha256, expected->lauxlib_h_sha256,
                sizeof(actual->lauxlib_h_sha256)) == 0 &&
         memcmp(actual->luaconf_h_sha256, expected->luaconf_h_sha256,
                sizeof(actual->luaconf_h_sha256)) == 0 &&
         memcmp(actual->layout, expected->layout, sizeof(actual->layout)) == 0;
}

int main(void) {
  rivetlua_abi_identity expected = rivetlua_expected_abi_identity();
  rivetlua_abi_identity actual = rivetlua_abi_identity_v1();
  if (!same_identity(&actual, &expected)) return 1;

  lua_State *state = luaL_newstate();
  if (state == NULL) return 2;
  lua_pushcfunction(state, record_once);
  lua_setglobal(state, "record_once");
  if (luaL_loadstring(state,
                      P24_GLOBAL_DECLARATION "record_once(); return 1 + 'bad'") != LUA_OK) {
    lua_close(state);
    return 3;
  }
  if (lua_pcall(state, 0, 0, 0) == LUA_OK || callback_calls != 1 ||
      lua_gettop(state) != 1) {
    lua_close(state);
    return 4;
  }
  lua_settop(state, 0);
  if (lua_gettop(state) != 0) {
    lua_close(state);
    return 5;
  }
  lua_close(state);
  return 0;
}
