/* 由 tests/p16/generate_manifest.py 產生；只測試固定 lua.h 巨集。 */
#include "lua.h"
#include <assert.h>

int main(void) {
  const int registry_index = LUA_REGISTRYINDEX;
  const int upvalue_1 = lua_upvalueindex(1);
  const int upvalue_2 = lua_upvalueindex(2);
  const int upvalue_255 = lua_upvalueindex(255);
  assert(upvalue_1 == registry_index - 1);
  assert(upvalue_2 == registry_index - 2);
  assert(upvalue_255 == registry_index - 255);
  assert(upvalue_1 > upvalue_2);
  assert(upvalue_2 > upvalue_255);
  assert(LUA_REGISTRYINDEX == registry_index);
  return 0;
}
