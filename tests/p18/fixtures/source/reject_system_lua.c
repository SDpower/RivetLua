#include <lua.h>

int luaopen_rivetlua_example_reject_system_lua(lua_State *state) {
   lua_pushstring(state, "system Lua linkage example");
   return 1;
}
