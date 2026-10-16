#include "lua.h"
#include "lauxlib.h"
#include "luaconf.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern int rivetlua_capi_configure_load_limits_b3(lua_State *state, size_t source,
    size_t encoded, size_t module, size_t temporary, size_t work,
    size_t chunks, size_t paths);

#define P17_SEED 0x173003u
#define P17_ITERATIONS 128u

typedef struct AllocationRecord {
  void *pointer;
  struct AllocationRecord *next;
} AllocationRecord;

typedef struct AllocationContext {
  AllocationRecord *records;
  size_t attempts;
  size_t fail_at;
  size_t failures;
  size_t outstanding_blocks;
  size_t tracking_errors;
  size_t callback_entries;
  size_t inner_successes;
  size_t inner_errors;
  uint64_t random_state;
} AllocationContext;

static uint64_t next_word(uint64_t *state) {
  *state ^= *state << 13;
  *state ^= *state >> 7;
  *state ^= *state << 17;
  return *state;
}

static void *tracked_allocator(void *user_data, void *pointer, size_t old_size,
                               size_t new_size) {
  AllocationContext *context = (AllocationContext *)user_data;
  AllocationRecord **slot = &context->records;
  AllocationRecord *new_record = NULL;
  void *resized;
  (void)old_size;
  while (*slot != NULL && (*slot)->pointer != pointer) slot = &(*slot)->next;
  if (new_size == 0) {
    if (pointer != NULL) {
      AllocationRecord *record;
      if (*slot == NULL) {
        ++context->tracking_errors;
        return NULL;
      }
      record = *slot;
      *slot = record->next;
      free(record);
      free(pointer);
      --context->outstanding_blocks;
    }
    return NULL;
  }
  if (pointer != NULL && *slot == NULL) {
    ++context->tracking_errors;
    return NULL;
  }
  ++context->attempts;
  if (context->attempts == context->fail_at) {
    ++context->failures;
    return NULL;
  }
  if (pointer == NULL) {
    new_record = (AllocationRecord *)malloc(sizeof(*new_record));
    if (new_record == NULL) return NULL;
  }
  resized = realloc(pointer, new_size);
  if (resized == NULL) {
    free(new_record);
    return NULL;
  }
  if (new_record != NULL) {
    new_record->pointer = resized;
    new_record->next = context->records;
    context->records = new_record;
    ++context->outstanding_blocks;
  } else {
    (*slot)->pointer = resized;
  }
  return resized;
}

static lua_State *new_tracked_state(AllocationContext *context) {
#if LUA_VERSION_NUM >= 505
  return lua_newstate(tracked_allocator, context, P17_SEED);
#else
  return lua_newstate(tracked_allocator, context);
#endif
}

static int failure(const char *case_id, const char *step) {
  fprintf(stderr, "P17_B03_FAIL %s %s\n", case_id, step);
  return 1;
}

static int allocation_fault_callback(lua_State *state) {
  void *user_data = NULL;
  AllocationContext *context;
  (void)lua_getallocf(state, &user_data);
  context = (AllocationContext *)user_data;
  if (context == NULL) return luaL_error(state, "P17_ALLOCATOR_CONTEXT_MISSING");
  ++context->callback_entries;
  context->fail_at = context->attempts + 1;
  (void)lua_newuserdatauv(state,
                          4096 + (size_t)(next_word(&context->random_state) % 256), 0);
  return 1;
}

static int allocation_ok_callback(lua_State *state) {
  (void)lua_newuserdatauv(state, 64, 0);
  return 1;
}

static int allocator_case(const char *profile) {
  const char *case_id = "p17_allocator_failure";
  AllocationContext context = {0};
  lua_State *state;
  size_t completed = 0;
  size_t error_checks = 0;
  size_t recovery_checks = 0;
  size_t gc_checks = 0;
  int status = 1;

  context.random_state = P17_SEED;
  context.fail_at = 1;
  state = new_tracked_state(&context);
  if (state != NULL) {
    lua_close(state);
    return failure(case_id, "newstate_failure_was_accepted");
  }
  if (context.failures != 1 || context.outstanding_blocks != 0 ||
      context.tracking_errors != 0)
    return failure(case_id, "newstate_failure_accounting");
  context.fail_at = 0;
  state = new_tracked_state(&context);
  if (state == NULL) return failure(case_id, "newstate_recovery");

  for (size_t iteration = 0; iteration < P17_ITERATIONS; ++iteration) {
    const size_t failures_before = context.failures;
    const size_t callbacks_before = context.callback_entries;
    const char *message;
    size_t message_length = 0;
    int call_status;
    lua_pushcfunction(state, allocation_fault_callback);
    call_status = lua_pcall(state, 0, 1, 0);
    context.fail_at = 0;
    if (call_status != LUA_ERRMEM || context.failures != failures_before + 1 ||
        context.callback_entries != callbacks_before + 1 || lua_gettop(state) != 1) {
      failure(case_id, "protected_allocation_failure");
      goto close;
    }
    message = lua_tolstring(state, -1, &message_length);
    if (message == NULL || message_length == 0) {
      failure(case_id, "protected_error_object");
      goto close;
    }
    ++error_checks;
    lua_pop(state, 1);
    if (lua_gettop(state) != 0) {
      failure(case_id, "error_stack_cleanup");
      goto close;
    }
    lua_pushcfunction(state, allocation_ok_callback);
    if (lua_pcall(state, 0, 1, 0) != LUA_OK || !lua_isuserdata(state, -1) ||
        lua_gettop(state) != 1) {
      failure(case_id, "protected_recovery");
      goto close;
    }
    ++recovery_checks;
    lua_pop(state, 1);
    if (lua_gc(state, LUA_GCCOLLECT) != 0 || lua_gettop(state) != 0) {
      failure(case_id, "gc_stack_cleanup");
      goto close;
    }
    ++gc_checks;
    ++completed;
  }
  if (context.failures != P17_ITERATIONS + 1 ||
      error_checks != P17_ITERATIONS || recovery_checks != P17_ITERATIONS ||
      gc_checks != P17_ITERATIONS) {
    failure(case_id, "coverage_counts");
    goto close;
  }
  status = 0;
close:
  lua_close(state);
  if (context.outstanding_blocks != 0 || context.records != NULL ||
      context.tracking_errors != 0)
    return failure(case_id, "allocator_close_release");
  if (status != 0) return status;
  printf("P17_B03_CASE {\"case_id\":\"%s\",\"profile\":\"%s\","
         "\"seed\":%u,\"iterations\":%zu,\"outcome\":\"PASS\","
         "\"failure_injections\":%zu,\"error_checks\":%zu,"
         "\"recovery_checks\":%zu,\"gc_checks\":%zu,"
         "\"outstanding_blocks\":%zu}\n",
         case_id, profile, P17_SEED, completed, context.failures, error_checks,
         recovery_checks, gc_checks, context.outstanding_blocks);
  return ferror(stdout) ? failure(case_id, "record_write") : 0;
}

static int nested_leaf(lua_State *state) {
  lua_Integer value = lua_tointeger(state, 1);
  if (value < 0) return luaL_error(state, "P17_NESTED_CALLBACK_ERROR");
  lua_pushinteger(state, value * 2);
  return 1;
}

static int nested_outer(lua_State *state) {
  void *user_data = NULL;
  AllocationContext *context;
  int call_status;
  (void)lua_getallocf(state, &user_data);
  context = (AllocationContext *)user_data;
  if (context == NULL || lua_gettop(state) != 2 || !lua_isfunction(state, 1))
    return luaL_error(state, "P17_NESTED_BAD_FRAME");
  lua_pushvalue(state, 1);
  lua_pushvalue(state, 2);
  call_status = lua_pcall(state, 1, 1, 0);
  if (call_status == LUA_OK) {
    ++context->inner_successes;
    return 1;
  }
  if (call_status == LUA_ERRRUN) ++context->inner_errors;
  return lua_error(state);
}

static int nested_case(const char *profile) {
  const char *case_id = "p17_nested_callback";
  const char *callback_source = "return function(n) return p17_leaf(n) + 1 end";
  AllocationContext context = {0};
  lua_State *state = new_tracked_state(&context);
  size_t completed = 0;
  size_t error_checks = 0;
  size_t normal_checks = 0;
  size_t gc_checks = 0;
  int load_status;
  int setup_status = LUA_OK;
  int status = 1;
  context.random_state = P17_SEED;
  if (state == NULL) return failure(case_id, "newstate");
  /* 僅測試宿主調整既有載入預算；此入口不屬於 Lua 公開 SDK。 */
  if (rivetlua_capi_configure_load_limits_b3(state, 65536, 4194304, 8388608,
      1048576, 2000000, 256, 256) != 1) {
    failure(case_id, "host_load_limits");
    goto close;
  }
  fprintf(stderr,
          "P17_B03_HOST_CONFIG 測試宿主專用，非公開 SDK："
          "source=65536 encoded=4194304 module=8388608 temporary=1048576 "
          "work=2000000 chunks=256 paths=256\n");
  lua_pushcfunction(state, nested_leaf);
  lua_setglobal(state, "p17_leaf");
  load_status = luaL_loadstring(state, callback_source);
  if (load_status == LUA_OK) setup_status = lua_pcall(state, 0, 1, 0);
  if (load_status != LUA_OK || setup_status != LUA_OK ||
      !lua_isfunction(state, -1)) {
    const char *error_text = lua_gettop(state) > 0 ? lua_tostring(state, -1) : NULL;
    fprintf(stderr,
            "P17_B03_DIAG %s load_status=%d setup_status=%d top=%d "
            "error=%s source=%s outstanding_blocks=%zu\n",
            case_id, load_status, setup_status, lua_gettop(state),
            error_text == NULL ? "<none>" : error_text, callback_source,
            context.outstanding_blocks);
    failure(case_id, "callback_setup");
    goto close;
  }
  lua_setglobal(state, "p17_callback");
  if (lua_gettop(state) != 0) {
    failure(case_id, "setup_stack");
    goto close;
  }

  for (size_t iteration = 0; iteration < P17_ITERATIONS; ++iteration) {
    lua_Integer value = (lua_Integer)(1 + (next_word(&context.random_state) % 97));
    int call_status;
    const char *message;
    lua_pushcfunction(state, nested_outer);
    lua_getglobal(state, "p17_callback");
    lua_pushinteger(state, value);
    call_status = lua_pcall(state, 2, 1, 0);
    if (call_status != LUA_OK || lua_gettop(state) != 1 ||
        !lua_isinteger(state, -1) || lua_tointeger(state, -1) != value * 2 + 1) {
      failure(case_id, "nested_normal_result");
      goto close;
    }
    ++normal_checks;
    lua_pop(state, 1);

    lua_pushcfunction(state, nested_outer);
    lua_getglobal(state, "p17_callback");
    lua_pushinteger(state, -value);
    call_status = lua_pcall(state, 2, 1, 0);
    if (call_status != LUA_ERRRUN || lua_gettop(state) != 1) {
      failure(case_id, "nested_error_status");
      goto close;
    }
    message = lua_tostring(state, -1);
    if (message == NULL || strstr(message, "P17_NESTED_CALLBACK_ERROR") == NULL) {
      failure(case_id, "nested_error_object");
      goto close;
    }
    ++error_checks;
    lua_pop(state, 1);
    if (lua_gettop(state) != 0) {
      failure(case_id, "nested_error_cleanup");
      goto close;
    }
    if ((iteration + 1) % 8 == 0) {
      if (lua_gc(state, LUA_GCCOLLECT) != 0 || lua_gettop(state) != 0) {
        failure(case_id, "nested_gc_cleanup");
        goto close;
      }
      ++gc_checks;
    }
    ++completed;
  }
  if (context.inner_successes != P17_ITERATIONS ||
      context.inner_errors != P17_ITERATIONS ||
      normal_checks != P17_ITERATIONS || error_checks != P17_ITERATIONS ||
      gc_checks != P17_ITERATIONS / 8) {
    failure(case_id, "coverage_counts");
    goto close;
  }
  status = 0;
close:
  lua_close(state);
  if (context.outstanding_blocks != 0 || context.records != NULL ||
      context.tracking_errors != 0)
    return failure(case_id, "allocator_close_release");
  if (status != 0) return status;
  printf("P17_B03_CASE {\"case_id\":\"%s\",\"profile\":\"%s\","
         "\"seed\":%u,\"iterations\":%zu,\"outcome\":\"PASS\","
         "\"normal_checks\":%zu,\"error_checks\":%zu,"
         "\"inner_successes\":%zu,\"inner_errors\":%zu,"
         "\"gc_checks\":%zu,\"outstanding_blocks\":%zu}\n",
         case_id, profile, P17_SEED, completed, normal_checks, error_checks,
         context.inner_successes, context.inner_errors, gc_checks,
         context.outstanding_blocks);
  return ferror(stdout) ? failure(case_id, "record_write") : 0;
}

int main(int argc, char **argv) {
#if LUA_VERSION_NUM >= 505
  const char *expected_profile = "lua55-i64f64";
#else
  const char *expected_profile = "lua54-i64f64";
#endif
  if (argc != 2 || strcmp(argv[1], expected_profile) != 0)
    return failure("p17_lifecycle", "profile_argument");
  if (allocator_case(expected_profile) != 0) return 1;
  if (nested_case(expected_profile) != 0) return 1;
  return ferror(stdout) ? failure("p17_lifecycle", "stdout") : 0;
}
