#include <lua.h>

int luaopen_rivetlua_example_native(lua_State *state) {
   lua_pushstring(state, "RivetLua example native module");
   return 1;
}
