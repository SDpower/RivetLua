#include "lua.h"
#include "lauxlib.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int append_line(const char *variable, const char *line) {
  const char *path = getenv(variable);
  FILE *file;
  if (path == NULL) return 0;
  file = fopen(path, "ab");
  if (file == NULL) return 0;
  if (fprintf(file, "%s\n", line) < 0) {
    fclose(file);
    return 0;
  }
  return fclose(file) == 0;
}

static void p17_constructor(void) __attribute__((constructor));
static void p17_constructor(void) {
  const char *token = getenv("RIVETLUA_P17_PROBE_TOKEN");
  char line[256];
  if (token == NULL) token = "missing-token";
  (void)snprintf(line, sizeof(line), "constructor|%s", token);
  (void)append_line("RIVETLUA_P17_CONSTRUCTOR_MARKER", line);
}

static int p17_echo(lua_State *L) {
  if (lua_gettop(L) != 2) return luaL_error(L, "P17_HOST_PROBE_ECHO_ARITY");
  lua_pushvalue(L, 1);
  lua_pushvalue(L, 2);
  return 2;
}

static int p17_finalizer(lua_State *L) {
  const char *token = getenv("RIVETLUA_P17_PROBE_TOKEN");
  char line[256];
  (void)L;
  if (token == NULL) token = "missing-token";
  (void)snprintf(line, sizeof(line), "finalizer|%s", token);
  if (!append_line("RIVETLUA_P17_PROBE_EVENTS", line))
    return luaL_error(L, "P17_HOST_PROBE_FINALIZER_MARKER");
  return 0;
}

static int p17_finalizable(lua_State *L) {
  lua_createtable(L, 0, 0);
  lua_createtable(L, 0, 1);
  lua_pushcfunction(L, p17_finalizer);
  lua_setfield(L, -2, "__gc");
  lua_setmetatable(L, -2);
  return 1;
}

static const luaL_Reg p17_functions[] = {
  {"echo", p17_echo},
  {"finalizable", p17_finalizable},
  {NULL, NULL}
};

LUAMOD_API int luaopen_p17probe(lua_State *L) {
  const char *module = lua_tostring(L, 1);
  const char *filename = lua_tostring(L, 2);
  const char *token = getenv("RIVETLUA_P17_PROBE_TOKEN");
  char line[8192];
  if (lua_gettop(L) != 2 || module == NULL || filename == NULL)
    return luaL_error(L, "P17_HOST_PROBE_TWO_ARGUMENTS");
  if (token == NULL) token = "missing-token";
  if (snprintf(line, sizeof(line), "open|%s|%s|%s", token, module, filename) < 0 ||
      !append_line("RIVETLUA_P17_PROBE_EVENTS", line))
    return luaL_error(L, "P17_HOST_PROBE_OPEN_MARKER");
  if (strcmp(module, "p17probe-error") == 0)
    return luaL_error(L, "P17_HOST_PROBE_EXPECTED_ERROR");
  lua_pushstring(L, token);
  lua_setglobal(L, "P17_NATIVE_TOKEN");
  luaL_newlib(L, p17_functions);
  return 1;
}
