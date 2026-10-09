#include "lua.h"
#include "lauxlib.h"
#include "rivetlua_abi.h"

#include <float.h>
#include <locale.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failure(const char *name) {
  fprintf(stderr, "P16_MACRO_FAIL %s\n", name);
  return 1;
}

#define CHECK(name, condition) do { \
  if (!(condition)) return failure(name); \
  printf("P16_MACRO %s PASS\n", name); \
} while (0)

#if LUA_VERSION_NUM == 504
LUAI_DDEC(int macro_declaration_probe(void));
int macro_declaration_probe(void) { return 17; }
#endif

int main(void) {
  char buffer[128];
  char *end;
  int length;
  lua_Integer integer = 0;
  int side_effect = 0;

  CHECK("luaL_intop", luaL_intop(+, 7, 9) == 16);
#if LUA_VERSION_NUM == 504
  lua_assert(++side_effect);
  CHECK("lua_assert", side_effect == 0);
  lua_writestring("P16_WRITE_STRING\n", strlen("P16_WRITE_STRING\n"));
  CHECK("lua_writestring", 1);
  lua_writeline();
  CHECK("lua_writeline", 1);
  lua_writestringerror("P16_WRITE_ERROR:%d\n", 42);
  CHECK("lua_writestringerror", 1);
  CHECK("LUAI_DDEC", macro_declaration_probe() == 17);
  length = lua_number2str(buffer, sizeof(buffer), (lua_Number)3.5);
  CHECK("lua_number2str", length > 0 && strcmp(buffer, "3.5") == 0);
  CHECK("lua_numbertointeger", lua_numbertointeger((lua_Number)42, &integer) && integer == 42);
#else
  CHECK("LUAI_TOSTRAUX", strcmp(LUAI_TOSTRAUX(foo), "foo") == 0);
#define RV_MACRO_EXPANSION 19
  CHECK("LUAI_TOSTR", strcmp(LUAI_TOSTR(RV_MACRO_EXPANSION), "19") == 0);
#endif
  CHECK("l_floor", l_floor(3.75) == 3.0);
  CHECK("l_floatatt", l_floatatt(MAX) == DBL_MAX);
  CHECK("l_mathop", l_mathop(floor)(2.75) == 2.0);
  CHECK("lua_str2number", lua_str2number("4.25", &end) == 4.25 && *end == '\0');
  length = lua_integer2str(buffer, sizeof(buffer), (lua_Integer)42);
  CHECK("lua_integer2str", length > 0 && strcmp(buffer, "42") == 0);
  length = l_sprintf(buffer, sizeof(buffer), "%d", 23);
  CHECK("l_sprintf", length == 2 && strcmp(buffer, "23") == 0);
  CHECK("lua_strx2number", lua_strx2number("5.5", &end) == 5.5 && *end == '\0');
  length = lua_pointer2str(buffer, sizeof(buffer), (void *)&integer);
  CHECK("lua_pointer2str", length > 0 && buffer[0] != '\0');
  length = lua_number2strx(NULL, buffer, sizeof(buffer), "%.2f", (lua_Number)2.5);
  CHECK("lua_number2strx", length == 4 && strcmp(buffer, "2.50") == 0);
  CHECK("lua_getlocaledecpoint", lua_getlocaledecpoint() == localeconv()->decimal_point[0]);
  CHECK("luai_likely", luai_likely(++side_effect == 1) && side_effect == 1);
  CHECK("luai_unlikely", !luai_unlikely(++side_effect == 1) && side_effect == 2);
  return 0;
}
