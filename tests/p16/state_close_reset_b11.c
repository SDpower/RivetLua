/* P16-2 B11：固定 Lua header 的 thread reset、main shutdown 與 child pointer。 */
#include "lua.h"
#include "lauxlib.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int closed_b11;
static int finalized_b11;
static int finalizer_error_seen_b11;
static int finalizer_continued_b11;
static int requeued_self_b11;
static int new_finalizer_b11;
static char shutdown_order_b11[4];
static int shutdown_order_len_b11;
static lua_Alloc original_alloc_b11;
static void *original_alloc_ud_b11;
static int reject_large_b11;

extern int rivetlua_capi_test_install_runtime_close_b11(lua_State *state);
static void push_mark_with_b11(lua_State *state, lua_CFunction closer);
#if LUA_VERSION_NUM >= 505
static int external_freed_b11;
static int external_bad_size_b11;

static void *external_free_b11(void *ud, void *ptr, size_t osize,
                               size_t nsize) {
  (void)ud;
  (void)osize;
  if (nsize != 0) external_bad_size_b11 = 1;
  if (ptr != NULL) {
    external_freed_b11++;
    free(ptr);
  }
  return NULL;
}
#endif

static int close_mark_b11(lua_State *state) {
  (void)state;
  closed_b11++;
  return 0;
}

static int close_error_b11(lua_State *state) {
  closed_b11++;
  luaL_checktype(state, 1, LUA_TNUMBER);
  return 0;
}

static int finalizer_b11(lua_State *state) {
  (void)state;
  finalized_b11++;
  finalizer_continued_b11 = finalizer_error_seen_b11;
  return 0;
}

static int finalizer_error_b11(lua_State *state) {
  finalized_b11++;
  finalizer_error_seen_b11 = 1;
  luaL_checktype(state, 1, LUA_TNUMBER);
  return 0;
}

static int new_finalizer_callback_b11(lua_State *state) {
  (void)state;
  new_finalizer_b11++;
  shutdown_order_b11[shutdown_order_len_b11++] = 'N';
  return 0;
}

static int requeue_finalizer_b11(lua_State *state) {
  requeued_self_b11++;
  shutdown_order_b11[shutdown_order_len_b11++] = 'S';
  if (requeued_self_b11 == 1) {
    /* Running 物件只重新註冊一次，並建立另一個待終結物件。 */
    lua_createtable(state, 0, 1);
    lua_pushliteral(state, "__gc");
    lua_pushcfunction(state, requeue_finalizer_b11);
    lua_rawset(state, -3);
    if (lua_setmetatable(state, 1) != 1) abort();
    lua_createtable(state, 0, 0);
    lua_createtable(state, 0, 1);
    lua_pushliteral(state, "__gc");
    lua_pushcfunction(state, new_finalizer_callback_b11);
    lua_rawset(state, -3);
    if (lua_setmetatable(state, -2) != 1) abort();
  }
  return 0;
}

static void push_gc_object_b11(lua_State *state, lua_CFunction callback) {
  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushliteral(state, "__gc");
  lua_pushcfunction(state, callback);
  lua_rawset(state, -3);
  if (lua_setmetatable(state, -2) != 1) abort();
}

static void *reject_large_alloc_b11(void *ud, void *ptr, size_t osize,
                                    size_t nsize) {
  (void)ud;
  if (reject_large_b11 && nsize >= 65536) return NULL;
  return original_alloc_b11(original_alloc_ud_b11, ptr, osize, nsize);
}

static int allocation_close_error_b11(lua_State *state) {
  reject_large_b11 = 1;
  (void)lua_newuserdatauv(state, 1024 * 1024, 0);
  abort();
}

static void push_close_value_b11(lua_State *state, lua_CFunction closer) {
  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushliteral(state, "__close");
  lua_pushcfunction(state, closer);
  lua_rawset(state, -3);
  if (lua_setmetatable(state, -2) != 1) abort();
}

static int verify_shutdown_requeue_b11(void) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 15;
  requeued_self_b11 = 0;
  new_finalizer_b11 = 0;
  shutdown_order_len_b11 = 0;
  push_gc_object_b11(state, requeue_finalizer_b11);
  lua_close(state);
  if (requeued_self_b11 != 2 || new_finalizer_b11 != 1 ||
      shutdown_order_len_b11 != 3 ||
      memcmp(shutdown_order_b11, "SNS", 3) != 0) {
    fprintf(stderr, "requeue: self=%d new=%d order=%.*s\n",
            requeued_self_b11, new_finalizer_b11, shutdown_order_len_b11,
            shutdown_order_b11);
    return 15;
  }
  return 0;
}

static int verify_reset_error_class_b11(int overlay_allocation) {
  lua_State *state = luaL_newstate();
  if (state == NULL) return 16;
  lua_State *child = lua_newthread(state);
  if (child == NULL) return 16;
  original_alloc_b11 = lua_getallocf(state, &original_alloc_ud_b11);
  if (original_alloc_b11 == NULL) return 16;
  lua_setallocf(state, reject_large_alloc_b11, NULL);
  reject_large_b11 = 0;
  push_close_value_b11(child, overlay_allocation ? close_error_b11
                                                : allocation_close_error_b11);
  if (rivetlua_capi_test_install_runtime_close_b11(child) != 1) return 16;
  lua_settop(child, 0);
  push_mark_with_b11(child, overlay_allocation ? allocation_close_error_b11
                                               : close_error_b11);
  int status = lua_closethread(child, state);
  int expected = overlay_allocation ? LUA_ERRRUN : LUA_ERRMEM;
  if (status != expected || lua_gettop(child) != 1 ||
      lua_type(child, -1) != LUA_TSTRING) {
    fprintf(stderr, "reset class: overlay_mem=%d status=%d expected=%d top=%d\n",
            overlay_allocation, status, expected, lua_gettop(child));
    return 16;
  }
  const char *error = lua_tostring(child, -1);
  if (error == NULL ||
      (overlay_allocation && strstr(error, "number expected") == NULL) ||
      (!overlay_allocation && strcmp(error, "not enough memory") != 0)) {
    fprintf(stderr, "reset value: overlay_mem=%d text=%s\n",
            overlay_allocation, error == NULL ? "<null>" : error);
    return 16;
  }
  reject_large_b11 = 0;
  if (lua_closethread(child, state) != LUA_OK || lua_gettop(child) != 0)
    return 16;
  lua_close(state);
  return 0;
}

static void push_mark_with_b11(lua_State *state, lua_CFunction closer) {
  lua_createtable(state, 0, 0);
  lua_createtable(state, 0, 1);
  lua_pushliteral(state, "__close");
  lua_pushcfunction(state, closer);
  lua_rawset(state, -3);
  if (lua_setmetatable(state, -2) != 1) __builtin_trap();
  lua_toclose(state, -1);
}

static void push_close_mark_b11(lua_State *state) {
  push_mark_with_b11(state, close_mark_b11);
}

int main(void) {
  lua_State *main_state = luaL_newstate();
  if (main_state == NULL) return 1;
  lua_State *child = lua_newthread(main_state);
  if (child == NULL) return 2;
  push_close_mark_b11(child);
  if (lua_closethread(child, NULL) != LUA_OK ||
      lua_gettop(child) != 0 || closed_b11 != 1) return 5;
  push_close_mark_b11(child);
  if (lua_resetthread(child) != LUA_OK ||
      lua_gettop(child) != 0 || closed_b11 != 2) return 6;
  push_mark_with_b11(child, close_error_b11);
  int error_status = lua_closethread(child, main_state);
  if (error_status != LUA_ERRRUN || lua_gettop(child) != 1 ||
      lua_type(child, -1) != LUA_TSTRING || closed_b11 != 3) {
    fprintf(stderr, "reset error: status=%d top=%d type=%d closed=%d\n",
            error_status, lua_gettop(child), lua_type(child, -1), closed_b11);
    return 8;
  }
  if (lua_resetthread(child) != LUA_OK || lua_gettop(child) != 0)
    return 9;
  lua_createtable(main_state, 0, 0);
  lua_createtable(main_state, 0, 1);
  lua_pushliteral(main_state, "__gc");
  lua_pushcfunction(main_state, finalizer_b11);
  lua_rawset(main_state, -3);
  if (lua_setmetatable(main_state, -2) != 1) return 10;
  lua_createtable(main_state, 0, 0);
  lua_createtable(main_state, 0, 1);
  lua_pushliteral(main_state, "__gc");
  lua_pushcfunction(main_state, finalizer_error_b11);
  lua_rawset(main_state, -3);
  if (lua_setmetatable(main_state, -2) != 1) return 11;
#if LUA_VERSION_NUM >= 505
  char *external = (char *)malloc(4);
  if (external == NULL) return 12;
  memcpy(external, "b11", 4);
  if (lua_pushexternalstring(main_state, external, 3, external_free_b11, NULL)
      != external) return 13;
#endif
  push_close_mark_b11(main_state);
  lua_close(child);
  if (closed_b11 != 4 || finalized_b11 != 2 ||
      !finalizer_error_seen_b11 || !finalizer_continued_b11) {
    fprintf(stderr, "shutdown: closed=%d finalized=%d error=%d continue=%d\n",
            closed_b11, finalized_b11,
            finalizer_error_seen_b11, finalizer_continued_b11);
    return 7;
  }
#if LUA_VERSION_NUM >= 505
  if (external_freed_b11 != 1 || external_bad_size_b11) return 14;
#endif
  if (verify_reset_error_class_b11(1) != 0) return 17;
  if (verify_reset_error_class_b11(0) != 0) return 16;
  if (verify_shutdown_requeue_b11() != 0) return 15;
  return 0;
}
