#include <stdio.h>

#define main p16_original_allocator_main
#include "../allocator_state_a50.c"
#undef main

extern uint64_t rivetlua_capi_test_current_ordinal_a4a(lua_State *state);
extern uint64_t rivetlua_capi_test_inject_offset_a4a(lua_State *state,
                                                     uint64_t offset);

typedef struct p16_userdata_context {
  int inject_offset;
  uint64_t start;
  uint64_t end;
  void *pointer;
  int returned;
} p16_userdata_context;

static _Thread_local p16_userdata_context *p16_active_userdata_context;

static int p16_userdata_callback(lua_State *state) {
  p16_userdata_context *context = p16_active_userdata_context;
  if (context == NULL) return luaL_error(state, "missing P16 userdata context");
  context->start = context->inject_offset < 0
                       ? rivetlua_capi_test_current_ordinal_a4a(state)
                       : rivetlua_capi_test_inject_offset_a4a(
                             state, (uint64_t)context->inject_offset);
  if (context->start == 0) return luaL_error(state, "P16 ordinal helper failed");
  context->pointer = lua_newuserdatauv(state, 17, 3);
  context->end = rivetlua_capi_test_current_ordinal_a4a(state);
  context->returned = 1;
  return 1;
}

static int p16_protected_userdata(lua_State *state,
                                  p16_userdata_context *context) {
  lua_pushcfunction(state, p16_userdata_callback);
  p16_active_userdata_context = context;
  int status = lua_pcall(state, 0, 1, 0);
  p16_active_userdata_context = NULL;
  return status;
}

static int p16_ordinal_trial(int offset, int *attempts) {
  tracker_a50 tracker = {0};
  allocator_binding_a50 binding = {&tracker, 1, 0, 0, 0, 0};
  lua_State *state = newstate_a50(tracking_allocator_a50, &binding);
  p16_userdata_context context = {offset, 0, 0, NULL, 0};
  int status;
  int result = 0;

  if (state == NULL) {
    result = 30;
    goto done;
  }
  if (lua_gettop(state) != 0) {
    result = 31;
    goto done;
  }
  status = p16_protected_userdata(state, &context);
  if (offset < 0) {
    if (status != LUA_OK || context.returned != 1 ||
        context.pointer == NULL || context.end <= context.start ||
        lua_gettop(state) != 1) {
      result = 32;
      goto done;
    }
    *attempts = (int)(context.end - context.start);
    lua_settop(state, 0);
  } else {
    if (status != LUA_ERRMEM || context.returned != 0 ||
        lua_gettop(state) != 1 || lua_type(state, -1) != LUA_TSTRING) {
      result = 33;
      goto done;
    }
    lua_settop(state, 0);
    if (lua_gettop(state) != 0) {
      result = 34;
      goto done;
    }
    /* 注入為單次失敗；同一 state 不再注入，經 C checkpoint 重試。 */
    context = (p16_userdata_context){-1, 0, 0, NULL, 0};
    status = p16_protected_userdata(state, &context);
    if (status != LUA_OK || context.returned != 1 ||
        context.pointer == NULL || lua_gettop(state) != 1) {
      result = 35;
      goto done;
    }
    lua_settop(state, 0);
  }
  if (lua_gettop(state) != 0) result = 36;

done:
  if (state != NULL) lua_close(state);
  if (tracker.active_tokens != 0 ||
      tracker.issued_tokens != tracker.refunded_tokens ||
      tracker.invalid_pairs != 0 || tracker.duplicate_refunds != 0)
    result = result == 0 ? 37 : result;
  free_records_a50(&tracker);
  return result;
}

int main(void) {
  int result = p16_original_allocator_main();
  int attempts = 0;
  if (result != 0) return result;
  result = p16_ordinal_trial(-1, &attempts);
  if (result != 0) return result;
  if (attempts != 6) return 38;
  for (int offset = 0; offset < attempts; ++offset) {
    result = p16_ordinal_trial(offset, &attempts);
    if (result != 0) return result;
  }
  puts("P16_C_BODY ABI-004 PASS");
  puts("P16_ASSERT ABI-004 allocation_ordinals=PASS");
  puts("P16_ASSERT ABI-004 structured_failure=PASS");
  puts("P16_ASSERT ABI-004 no_fallback=PASS");
  puts("P16_ASSERT ABI-004 cleanup=PASS");
  return 0;
}
