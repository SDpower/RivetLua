#include "lua.h"
#include "lauxlib.h"

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int rivetlua_capi_configure_load_limits_b3(lua_State *L, size_t source,
    size_t encoded, size_t module, size_t temporary, size_t work,
    size_t chunks, size_t paths);

typedef struct Allocation {
  void *ptr;
  struct Allocation *next;
} Allocation;

static Allocation *allocations;
static size_t outstanding;

static void *tracked_alloc(void *ud, void *ptr, size_t old_size, size_t new_size) {
  Allocation **slot = &allocations;
  (void)ud;
  (void)old_size;
  while (*slot != NULL && (*slot)->ptr != ptr) slot = &(*slot)->next;
  if (new_size == 0) {
    if (ptr != NULL) {
      Allocation *record;
      if (*slot == NULL) abort();
      record = *slot;
      *slot = record->next;
      free(record);
      --outstanding;
      free(ptr);
    }
    return NULL;
  }
  if (ptr != NULL && *slot == NULL) abort();
  void *resized = realloc(ptr, new_size);
  if (resized == NULL) return NULL;
  if (ptr == NULL) {
    Allocation *record = (Allocation *)malloc(sizeof(*record));
    if (record == NULL) abort();
    record->next = allocations;
    allocations = record;
    ++outstanding;
  } else {
    (*slot)->ptr = resized;
    return resized;
  }
  allocations->ptr = resized;
  return resized;
}

static int fail(const char *what) {
  fprintf(stderr, "P16_SDK_FAIL %s\n", what);
  return 1;
}

static int check_global_string(lua_State *L, const char *name, const char *expected) {
  size_t len = 0;
  const char *actual;
  lua_getglobal(L, name);
  actual = lua_tolstring(L, -1, &len);
  int ok = actual != NULL && strlen(expected) == len && memcmp(actual, expected, len) == 0;
  lua_pop(L, 1);
  return ok;
}

static int load_module(lua_State *L, void *handle, const char *label, const char *symbol,
                       const char *modname, const char *filename, int version_two) {
  lua_CFunction opener = (lua_CFunction)dlsym(handle, symbol);
  if (opener == NULL) return fail("dlsym");
  lua_pushcclosure(L, opener, 0);
  lua_pushstring(L, modname);
  lua_pushstring(L, filename);
  if (lua_pcall(L, 2, 1, 0) != LUA_OK) return fail("opener_pcall");
  if (!lua_istable(L, -1)) return fail("opener_table");
  if (!check_global_string(L, "x", modname) ||
      !check_global_string(L, "y", filename)) return fail("opener_two_args");
  lua_getfield(L, -1, "id");
  if (!lua_isfunction(L, -1)) return fail("id_field");
  lua_pushinteger(L, 7);
  if (lua_pcall(L, 1, LUA_MULTRET, 0) != LUA_OK) return fail("id_pcall");
  if (version_two) {
    if (lua_gettop(L) != 3 || !lua_toboolean(L, -2) ||
        lua_tointeger(L, -1) != 7) return fail("id_v2_result");
    lua_pop(L, 2);
  } else {
    if (lua_gettop(L) != 2 || lua_tointeger(L, -1) != 7)
      return fail("id_original_result");
    lua_pop(L, 1);
  }
  lua_pop(L, 1);
  printf("P16_SDK_MODULE %s %s TWO_ARG_ID PASS\n", label, symbol);
  return 0;
}

static int check_p1(lua_State *L, const char *path, int expected) {
  FILE *file = fopen(path, "rb");
  char source[96];
  size_t count;
  if (file == NULL) return fail("p1_open");
  count = fread(source, 1, sizeof(source) - 1, file);
  if (ferror(file) || !feof(file)) { fclose(file); return fail("p1_read"); }
  fclose(file);
  source[count] = '\0';
  if (luaL_loadstring(L, source) != LUA_OK) return fail("p1_load");
  if (lua_pcall(L, 0, 1, 0) != LUA_OK) return fail("p1_execute");
  if (!lua_istable(L, -1)) return fail("p1_table");
  lua_getfield(L, -1, "AA");
  if (lua_tointeger(L, -1) != expected) return fail("p1_value");
  lua_pop(L, 2);
  lua_getglobal(L, "AA");
  if (lua_tointeger(L, -1) != 0) return fail("p1_global_isolation");
  lua_pop(L, 1);
  printf("P16_SDK_P1 %s AA=%d GLOBAL=0 PASS\n", path, expected);
  return 0;
}

int main(int argc, char **argv) {
  void *handles[5] = {NULL, NULL, NULL, NULL, NULL};
  lua_State *L;
  int status = 1;
  if (argc != 8) return fail("arguments");
#if LUA_VERSION_NUM >= 505
  L = lua_newstate(tracked_alloc, NULL, 0);
#else
  L = lua_newstate(tracked_alloc, NULL);
#endif
  if (L == NULL) return fail("newstate");
  if (rivetlua_capi_configure_load_limits_b3(L, 65536, 4194304, 8388608,
      1048576, 2000000, 256, 256) != 1) {
    fail("host_load_limits");
    goto close;
  }
  printf("P16_SDK_HOST_LIMITS source=65536 encoded=4194304 module=8388608 temporary=1048576 work=2000000 chunks=256 paths=256 PASS\n");
  lua_pushinteger(L, 0);
  lua_setglobal(L, "AA");
  for (int i = 0; i < 5; ++i) {
    int flags = RTLD_NOW | ((i == 0 || i == 2) ? RTLD_GLOBAL : RTLD_LOCAL);
    handles[i] = dlopen(argv[i + 1], flags);
    if (handles[i] == NULL) { fprintf(stderr, "%s\n", dlerror()); goto close; }
    printf("P16_SDK_DLOPEN %s PASS\n", argv[i + 1]);
  }
  if (load_module(L, handles[0], "lib1.so", "luaopen_lib1_sub", "lib1.sub", argv[1], 0)) goto close;
  if (load_module(L, handles[2], "lib2.so", "luaopen_lib2", "lib2", argv[3], 0)) goto close;
  if (load_module(L, handles[3], "lib21.so", "luaopen_lib21", "lib21", argv[4], 0)) goto close;
  if (load_module(L, handles[4], "lib2-v2.so", "luaopen_lib2", "lib2.v2", argv[5], 1)) goto close;
  {
    lua_CFunction exported = (lua_CFunction)dlsym(handles[0], "lib1_export");
    lua_CFunction linked = (lua_CFunction)dlsym(handles[1], "luaopen_lib11");
    if (exported == NULL || linked == NULL) { fail("lib11_resolve"); goto close; }
    lua_pushcclosure(L, linked, 0);
    if (lua_pcall(L, 0, 1, 0) != LUA_OK || lua_tostring(L, -1) == NULL ||
        strcmp(lua_tostring(L, -1), "exported") != 0) { fail("lib11_call"); goto close; }
    lua_pop(L, 1);
    printf("P16_SDK_LIB11 lib11.so GLOBAL_LINK PASS\n");
    lua_CFunction one = (lua_CFunction)dlsym(handles[0], "onefunction");
    lua_CFunction another = (lua_CFunction)dlsym(handles[0], "anotherfunc");
    if (one == NULL || another == NULL) { fail("lib1_functions_resolve"); goto close; }
    lua_pushcclosure(L, one, 0);
    lua_pushinteger(L, 15);
    lua_pushinteger(L, 25);
    if (lua_pcall(L, 2, 2, 0) != LUA_OK ||
        lua_tointeger(L, -2) != 25 || lua_tointeger(L, -1) != 15)
      { fail("onefunction"); goto close; }
    lua_pop(L, 2);
    lua_pushcclosure(L, another, 0);
    lua_pushinteger(L, 10);
    lua_pushinteger(L, 20);
    if (lua_pcall(L, 2, 1, 0) != LUA_OK || lua_tostring(L, -1) == NULL ||
        strcmp(lua_tostring(L, -1), "10%20\n") != 0)
      { fail("anotherfunc"); goto close; }
    lua_pop(L, 1);
    printf("P16_SDK_LIB1 FUNCTIONS PASS\n");
  }
  if (check_p1(L, argv[6], 10) || check_p1(L, argv[7], 20)) goto close;
  status = 0;
close:
  lua_close(L);
  if (outstanding != 0) status = fail("allocator_close_release");
  else printf("P16_SDK_CLOSE ALLOCATOR_RELEASE PASS\n");
  for (int i = 4; i >= 0; --i) if (handles[i] != NULL) dlclose(handles[i]);
  printf("P16_SDK_DLCLOSE AFTER_LUA_CLOSE PASS\n");
  if (status == 0) printf("P16_SDK_RESULT PASS\n");
  return status;
}
