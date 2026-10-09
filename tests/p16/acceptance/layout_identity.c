#include "lua.h"
#include "lauxlib.h"
#include "rivetlua_abi.h"
#include <stdio.h>
#include <string.h>

int main(void) {
  rivetlua_abi_identity expected = rivetlua_expected_abi_identity();
  rivetlua_abi_identity actual = rivetlua_abi_identity_v1();
  if (actual.revision != expected.revision || actual.profile != expected.profile ||
      actual.numeric_config != expected.numeric_config ||
      actual.pointer_width_bits != expected.pointer_width_bits ||
      actual.endianness != expected.endianness ||
      actual.reserved_zero != expected.reserved_zero ||
      memcmp(actual.target, expected.target, sizeof(actual.target)) != 0 ||
      memcmp(actual.header_set_sha256, expected.header_set_sha256, 32) != 0 ||
      memcmp(actual.lua_h_sha256, expected.lua_h_sha256, 32) != 0 ||
      memcmp(actual.lauxlib_h_sha256, expected.lauxlib_h_sha256, 32) != 0 ||
      memcmp(actual.luaconf_h_sha256, expected.luaconf_h_sha256, 32) != 0) {
    fputs("P16_LAYOUT identity mismatch\n", stderr);
    return 1;
  }
  for (int i = 0; i < RIVETLUA_LAYOUT_COUNT; ++i) {
    if (actual.layout[i] != expected.layout[i]) return 2;
    printf("P16_LAYOUT %d %u\n", i, (unsigned)actual.layout[i]);
  }
  puts("P16_LAYOUT 37 PASS");
  return 0;
}
