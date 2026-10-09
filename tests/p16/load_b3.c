#include <lauxlib.h>
#include <lua.h>
#include <stdio.h>
#include <string.h>

#define CHECK(condition) do { if (!(condition)) return __LINE__; } while (0)

extern int rivetlua_capi_configure_load_limits_b3(
    lua_State *state, size_t source, size_t encoded, size_t module,
    size_t temporary, size_t work, size_t chunks, size_t paths);

struct reader_data {
  const char *chunks[4];
  size_t sizes[4];
  int next;
  int touch_stack;
  int configure_calls;
  int configure_result;
};

static const char *read_chunk(lua_State *state, void *opaque, size_t *size) {
  struct reader_data *data = (struct reader_data *)opaque;
  if (data->touch_stack) {
    data->configure_calls++;
    data->configure_result = rivetlua_capi_configure_load_limits_b3(
        state, 64 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
        1024 * 1024, 2 * 1000 * 1000, 256, 256);
    lua_pushinteger(state, 88);
#if LUA_VERSION_NUM < 505
    lua_pop(state, 1);
#endif
  }
  if (data->next == 4 || data->chunks[data->next] == NULL) {
    *size = 0;
    return NULL;
  }
  *size = data->sizes[data->next];
  return data->chunks[data->next++];
}

static const char *read_error(lua_State *state, void *opaque, size_t *size) {
  (void)opaque;
  (void)size;
  lua_pushinteger(state, 88);
  lua_gc(state, LUA_GCCOLLECT);
#if LUA_VERSION_NUM < 505
  lua_pop(state, 1);
#endif
  luaL_error(state, "reader error from C");
  return NULL;
}

static const char *read_table_error(lua_State *state, void *opaque,
                                    size_t *size) {
  (void)opaque;
  (void)size;
  lua_pushinteger(state, 88);
#if LUA_VERSION_NUM < 505
  lua_pop(state, 1);
#endif
  lua_newtable(state);
  lua_pushinteger(state, 29);
  lua_setfield(state, -2, "marker");
  lua_gc(state, LUA_GCCOLLECT);
  lua_error(state);
  return NULL;
}

#if LUA_VERSION_NUM >= 505
static int close_count;
static int close_error_seen;
static int close_replacement;

static int close_reader_value(lua_State *state) {
  close_count++;
  const char *message = lua_tostring(state, 2);
  if (message != NULL && strstr(message, "reader tbc original") != NULL)
    close_error_seen++;
  if (close_replacement)
    return luaL_error(state, "reader tbc replacement");
  return 0;
}

static const char *read_tbc_error(lua_State *state, void *opaque,
                                  size_t *size) {
  (void)opaque;
  (void)size;
  lua_newuserdatauv(state, 0, 0);
  lua_newtable(state);
  lua_pushcfunction(state, close_reader_value);
  lua_setfield(state, -2, "__close");
  lua_setmetatable(state, -2);
  lua_toclose(state, -1);
  lua_gc(state, LUA_GCCOLLECT);
  luaL_error(state, "reader tbc original");
  return NULL;
}

static const char *read_tbc_success(lua_State *state, void *opaque,
                                    size_t *size) {
  int *calls = (int *)opaque;
  if ((*calls)++ != 0) {
    *size = 0;
    return NULL;
  }
  lua_newuserdatauv(state, 0, 0);
  lua_newtable(state);
  lua_pushcfunction(state, close_reader_value);
  lua_setfield(state, -2, "__close");
  lua_setmetatable(state, -2);
  lua_toclose(state, -1);
  *size = 8;
  return "return 1";
}
#endif

struct writer_data {
  unsigned char bytes[1024 * 1024];
  size_t len;
  int calls;
  int stop;
  int stop_eof;
  int eof_calls;
  int reenter;
};

static int write_chunk(lua_State *state, const void *bytes, size_t len,
                       void *opaque) {
  struct writer_data *data = (struct writer_data *)opaque;
  data->calls++;
  if (bytes == NULL && len == 0) {
    data->eof_calls++;
    return data->stop_eof;
  }
  if (data->reenter) {
    int top = lua_gettop(state);
    lua_pushinteger(state, 91);
    lua_gc(state, LUA_GCCOLLECT);
    lua_settop(state, top);
  }
  if (data->stop != 0) return data->stop;
  if (len > sizeof(data->bytes) - data->len) return 87;
  memcpy(data->bytes + data->len, bytes, len);
  data->len += len;
  return 0;
}

static int write_error(lua_State *state, const void *bytes, size_t len,
                       void *opaque) {
  (void)bytes;
  (void)len;
  (void)opaque;
  return luaL_error(state, "writer error from C");
}

static int call_writer_error(lua_State *state) {
  return lua_dump(state, write_error, NULL, 0);
}

static int run_stdin(void) {
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);
  CHECK(lua_checkstack(state, 1) == 1);
  CHECK(luaL_loadfilex(state, NULL, "t") == LUA_OK);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 37);
  lua_close(state);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "stdin") == 0) return run_stdin();
  CHECK(argc == 2);
  const char *path = argv[1];
  lua_State *state = luaL_newstate();
  CHECK(state != NULL);
  CHECK(lua_checkstack(state, 1) == 1);
  CHECK(rivetlua_capi_configure_load_limits_b3(
      state, 64 * 1024, 4 * 1024 * 1024, 8 * 1024 * 1024,
      1024 * 1024, 2 * 1000 * 1000, 256, 256) == 1);
  lua_pushinteger(state, 73);

  CHECK(luaL_loadstring(state, "return 41") == LUA_OK);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TFUNCTION);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 41);
  lua_pop(state, 1);

  CHECK(luaL_loadbufferx(state, "return 9", 8, "=mode", "b") == LUA_ERRSYNTAX);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  CHECK(lua_tointeger(state, 1) == 73);
  lua_pop(state, 1);
  CHECK(luaL_loadbuffer(state, "return 8", 8, "=macro") == LUA_OK);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 8);
  lua_pop(state, 1);
  CHECK(luaL_dostring(state, "return 12") == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 12);
  lua_pop(state, 1);
  CHECK(luaL_dostring(state, "return )") != LUA_OK);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  lua_pop(state, 1);

  struct reader_data fragments = {
    .chunks = {"ret", "urn ", "17", NULL},
    .sizes = {3, 4, 2, 0},
    .next = 0,
  };
  CHECK(lua_load(state, read_chunk, &fragments, NULL, "t") == LUA_OK);
  CHECK(fragments.next == 3 && lua_gettop(state) == 2);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 17);
  lua_pop(state, 1);

  struct reader_data stack_reader = {
    .chunks = {"return ", "19", NULL, NULL},
    .sizes = {7, 2, 0, 0}, .next = 0, .touch_stack = 1,
  };
  CHECK(lua_load(state, read_chunk, &stack_reader,
                 "=reader-stack", "t") == LUA_OK);
  CHECK(stack_reader.configure_calls > 0 && stack_reader.configure_result == 0);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TFUNCTION);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 19);
  lua_pop(state, 1);

  CHECK(luaL_loadstring(state,
      "local first, second = 11, 22; return function() return first, second end")
      == LUA_OK);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_type(state, -1) == LUA_TFUNCTION);
  int function_top = lua_gettop(state);
  struct writer_data plain = { .len = 0, .calls = 0, .stop = 0, .reenter = 1 };
  struct writer_data stripped = { .len = 0, .calls = 0, .stop = 0, .reenter = 1 };
  CHECK(lua_dump(state, write_chunk, &plain, 0) == 0);
  CHECK(lua_gettop(state) == function_top);
  CHECK(lua_dump(state, write_chunk, &stripped, 1) == 0);
  CHECK(lua_gettop(state) == function_top);
  CHECK(plain.calls > 0 && stripped.calls > 0);
  CHECK(plain.len > 4 && stripped.len > 4);
  CHECK(memcmp(plain.bytes, "\x1bLua", 4) == 0);
  CHECK(stripped.len <= plain.len);
#if LUA_VERSION_NUM >= 505
  CHECK(plain.eof_calls == 1 && stripped.eof_calls == 1);
#else
  CHECK(plain.eof_calls == 0 && stripped.eof_calls == 0);
#endif

  struct writer_data eof_stopped = {
    .len = 0, .calls = 0, .stop = 0, .stop_eof = 72,
    .eof_calls = 0, .reenter = 0,
  };
#if LUA_VERSION_NUM >= 505
  CHECK(lua_dump(state, write_chunk, &eof_stopped, 0) == 72);
  CHECK(eof_stopped.eof_calls == 1);
#else
  CHECK(lua_dump(state, write_chunk, &eof_stopped, 0) == 0);
  CHECK(eof_stopped.eof_calls == 0);
#endif
  CHECK(lua_gettop(state) == function_top);

  struct writer_data stopped = { .len = 0, .calls = 0, .stop = 71, .reenter = 0 };
  CHECK(lua_dump(state, write_chunk, &stopped, 0) == 71);
  CHECK(stopped.calls == 1 && stopped.len == 0);
  CHECK(lua_gettop(state) == function_top);

  CHECK(luaL_loadbufferx(state, (const char *)stripped.bytes, stripped.len,
                         "=reloaded", "b") == LUA_OK);
  CHECK(lua_gettop(state) == function_top + 1);
  CHECK(lua_getupvalue(state, -1, 1) != NULL);
  CHECK(lua_type(state, -1) == LUA_TTABLE);
  lua_pop(state, 1);

#if LUA_VERSION_NUM >= 505
  CHECK(luaL_loadbufferx(state, (const char *)stripped.bytes, stripped.len,
                         "=reloaded-B", "B") == LUA_OK);
  CHECK(lua_type(state, -1) == LUA_TFUNCTION);
  lua_pop(state, 1);
#else
  CHECK(luaL_loadbufferx(state, (const char *)stripped.bytes, stripped.len,
                         "=reloaded-B", "B") == LUA_ERRSYNTAX);
  CHECK(lua_type(state, -1) == LUA_TSTRING);
  lua_pop(state, 1);
#endif
  CHECK(lua_getupvalue(state, -1, 2) != NULL);
  CHECK(lua_type(state, -1) == LUA_TNIL);
  lua_pop(state, 1);
  lua_pop(state, 1);

  unsigned char wrong[1024 * 1024];
  CHECK(stripped.len <= sizeof(wrong));
  memcpy(wrong, stripped.bytes, stripped.len);
  wrong[4] = (unsigned char)(wrong[4] == 0x54 ? 0x55 : 0x54);
  CHECK(luaL_loadbufferx(state, (const char *)wrong, stripped.len,
                         "=wrong-profile", "b") == LUA_ERRSYNTAX);
  CHECK(lua_gettop(state) == function_top + 1 && lua_type(state, -1) == LUA_TSTRING);
  lua_pop(state, 1);
  CHECK(luaL_loadbufferx(state, (const char *)stripped.bytes, 6,
                         "=truncated", "b") == LUA_ERRSYNTAX);
  lua_pop(state, 1);

  lua_pop(state, 1);
  CHECK(lua_load(state, read_error, NULL,
                 "=reader-error", "t") == LUA_ERRRUN);
  CHECK(lua_gettop(state) == 2);
  CHECK(lua_type(state, -1) == LUA_TSTRING);
  CHECK(strstr(lua_tostring(state, -1), "reader error from C") != NULL);
  lua_pop(state, 1);
  CHECK(lua_load(state, read_table_error, NULL,
                 "=reader-table-error", "t") == LUA_ERRRUN);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TTABLE);
  lua_getfield(state, -1, "marker");
  CHECK(lua_tointeger(state, -1) == 29);
  lua_pop(state, 2);
#if LUA_VERSION_NUM >= 505
  close_count = 0;
  close_error_seen = 0;
  close_replacement = 0;
  CHECK(lua_load(state, read_tbc_error, NULL,
                 "=reader-tbc", "t") == LUA_ERRRUN);
  CHECK(close_count == 1 && close_error_seen == 1);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  CHECK(strstr(lua_tostring(state, -1), "reader tbc original") != NULL);
  CHECK(lua_tointeger(state, 1) == 73);
  lua_gc(state, LUA_GCCOLLECT);
  lua_pop(state, 1);

  close_count = 0;
  close_error_seen = 0;
  close_replacement = 1;
  CHECK(lua_load(state, read_tbc_error, NULL,
                 "=reader-tbc-replacement", "t") == LUA_ERRRUN);
  CHECK(close_count == 1 && close_error_seen == 1);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  CHECK(strstr(lua_tostring(state, -1), "reader tbc replacement") != NULL);
  CHECK(lua_tointeger(state, 1) == 73);
  lua_gc(state, LUA_GCCOLLECT);
  lua_pop(state, 1);

  close_count = 0;
  close_error_seen = 0;
  close_replacement = 0;
  int success_calls = 0;
  CHECK(lua_load(state, read_tbc_success, &success_calls,
                 "=reader-unclosed-tbc", "t") == LUA_ERRRUN);
  CHECK(success_calls == 2 && close_count == 1);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  CHECK(lua_tointeger(state, 1) == 73);
  lua_pop(state, 1);
#endif
  CHECK(luaL_loadstring(state, "return 23") == LUA_OK);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 23);
  lua_pop(state, 1);
  CHECK(luaL_loadstring(state, "return 1") == LUA_OK);
  lua_pushcfunction(state, call_writer_error);
  lua_pushvalue(state, -2);
  CHECK(lua_pcall(state, 1, 1, 0) == LUA_ERRRUN);
  CHECK(lua_type(state, -1) == LUA_TSTRING);
  CHECK(strstr(lua_tostring(state, -1), "writer error from C") != NULL);
  lua_pop(state, 2);

  FILE *file = fopen(path, "wb");
  CHECK(file != NULL);
  const unsigned char file_source[] = "\xef\xbb\xbf#!/bin/sh\nreturn 31\n";
  CHECK(fwrite(file_source, 1, sizeof(file_source) - 1, file)
        == sizeof(file_source) - 1);
  CHECK(fclose(file) == 0);
  CHECK(luaL_loadfilex(state, path, "t") == LUA_OK);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 31);
  lua_pop(state, 1);
  CHECK(luaL_loadfile(state, path) == LUA_OK);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TFUNCTION);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 31);
  lua_pop(state, 1);
  CHECK(luaL_dofile(state, path) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 31);
  lua_pop(state, 1);
  CHECK(remove(path) == 0);
  CHECK(luaL_loadfilex(state, path, "t") == LUA_ERRFILE);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  lua_pop(state, 1);
  CHECK(luaL_loadfile(state, path) == LUA_ERRFILE);
  CHECK(lua_gettop(state) == 2 && lua_type(state, -1) == LUA_TSTRING);
  lua_pop(state, 1);
  CHECK(lua_gettop(state) == 1 && lua_tointeger(state, 1) == 73);
  CHECK(luaL_loadstring(state, "return 24") == LUA_OK);
  CHECK(lua_pcall(state, 0, 1, 0) == LUA_OK);
  CHECK(lua_tointeger(state, -1) == 24);
  lua_pop(state, 1);

  lua_close(state);
  return 0;
}
