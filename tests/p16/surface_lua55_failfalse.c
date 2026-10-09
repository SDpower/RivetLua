/* 由 tests/p16/generate_manifest.py 產生；只編譯，不連結或執行。 */
/* P16 A10：明確啟用 Lua 5.5 LUA_FAILISFALSE 條件分支。 */
#define LUA_FAILISFALSE
#include "lua.h"
#include "lauxlib.h"
void rivetlua_p16_surface_lua55_failfalse_probe(void) {
  /* P16 macro expansion: luaL_pushfail */
  (void)luaL_pushfail((lua_State *)0);
}
