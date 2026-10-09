/* P16-2 B1：以固定 Lua C ABI 驗證 state allocator 綁定與生命週期。 */
#include "lua.h"
#include "lauxlib.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct allocation_header_a50 {
  max_align_t alignment;
  uint64_t magic;
  uint64_t token;
  size_t size;
} allocation_header_a50;

typedef struct allocation_record_a50 {
  void *pointer;
  size_t size;
  uint64_t token;
  int binding_id;
  int active;
  struct allocation_record_a50 *next;
} allocation_record_a50;

typedef struct tracker_a50 {
  allocation_record_a50 *records;
  uint64_t next_token;
  size_t issued_tokens;
  size_t refunded_tokens;
  size_t active_tokens;
  size_t failed_admissions;
  size_t invalid_pairs;
  size_t duplicate_refunds;
  size_t cross_binding_refunds;
} tracker_a50;

typedef struct allocator_binding_a50 {
  tracker_a50 *tracker;
  int binding_id;
  int fail_next;
  size_t calls;
  size_t nonzero_calls;
  size_t successful_allocations;
} allocator_binding_a50;

static const uint64_t allocation_magic_a50 = UINT64_C(0xA550A110CA7E5AFE);

static allocation_record_a50 *find_record_a50(tracker_a50 *tracker,
                                                void *pointer,
                                                int *was_refunded) {
  allocation_record_a50 *record;
  *was_refunded = 0;
  for (record = tracker->records; record != NULL; record = record->next) {
    if (record->pointer == pointer) {
      if (record->active)
        return record;
      *was_refunded = 1;
    }
  }
  return NULL;
}

static allocation_record_a50 *new_record_a50(void) {
  return (allocation_record_a50 *)malloc(sizeof(allocation_record_a50));
}

static void issue_token_a50(tracker_a50 *tracker,
                            allocation_record_a50 *record,
                            void *pointer,
                            size_t size,
                            int binding_id) {
  tracker->next_token += 1;
  record->pointer = pointer;
  record->size = size;
  record->token = tracker->next_token;
  record->binding_id = binding_id;
  record->active = 1;
  record->next = tracker->records;
  tracker->records = record;
  tracker->issued_tokens += 1;
  tracker->active_tokens += 1;
}

static void refund_token_a50(tracker_a50 *tracker,
                             allocation_record_a50 *record,
                             int current_binding_id) {
  record->active = 0;
  tracker->refunded_tokens += 1;
  tracker->active_tokens -= 1;
  if (record->binding_id != current_binding_id)
    tracker->cross_binding_refunds += 1;
}

/* 此 callback 僅使用系統配置函式與本地記錄，不呼叫 Lua 或做非區域跳轉。 */
static void *tracking_allocator_a50(void *raw_binding,
                                    void *pointer,
                                    size_t old_size,
                                    size_t new_size) {
  allocator_binding_a50 *binding = (allocator_binding_a50 *)raw_binding;
  tracker_a50 *tracker = binding->tracker;
  allocation_record_a50 *record = NULL;
  allocation_header_a50 *header = NULL;
  int was_refunded = 0;

  binding->calls += 1;
  if (new_size != 0)
    binding->nonzero_calls += 1;

  if (new_size != 0 && binding->fail_next) {
    binding->fail_next = 0;
    tracker->failed_admissions += 1;
    return NULL;
  }

  if (pointer != NULL) {
    record = find_record_a50(tracker, pointer, &was_refunded);
    if (record == NULL) {
      if (was_refunded)
        tracker->duplicate_refunds += 1;
      else
        tracker->invalid_pairs += 1;
      return NULL;
    }
    header = ((allocation_header_a50 *)pointer) - 1;
    if (old_size != record->size ||
        header->magic != allocation_magic_a50 ||
        header->size != record->size || header->token != record->token) {
      tracker->invalid_pairs += 1;
      return NULL;
    }
  }

  if (new_size == 0) {
    if (pointer == NULL)
      return NULL;
    refund_token_a50(tracker, record, binding->binding_id);
    header->magic = 0;
    free(header);
    return NULL;
  }

  if (new_size > SIZE_MAX - sizeof(allocation_header_a50)) {
    tracker->failed_admissions += 1;
    return NULL;
  }

  if (pointer == NULL) {
    allocation_record_a50 *new_record = new_record_a50();
    if (new_record == NULL) {
      tracker->failed_admissions += 1;
      return NULL;
    }
    header = (allocation_header_a50 *)malloc(
        sizeof(allocation_header_a50) + new_size);
    if (header == NULL) {
      free(new_record);
      tracker->failed_admissions += 1;
      return NULL;
    }
    header->magic = allocation_magic_a50;
    header->size = new_size;
    header->token = tracker->next_token + 1;
    issue_token_a50(tracker, new_record, header + 1, new_size,
                    binding->binding_id);
    binding->successful_allocations += 1;
    return header + 1;
  }

  {
    allocation_record_a50 *new_record = new_record_a50();
    allocation_header_a50 *resized_header;
    if (new_record == NULL) {
      tracker->failed_admissions += 1;
      return NULL;
    }
    resized_header = (allocation_header_a50 *)realloc(
        header, sizeof(allocation_header_a50) + new_size);
    if (resized_header == NULL) {
      free(new_record);
      tracker->failed_admissions += 1;
      return NULL;
    }
    refund_token_a50(tracker, record, binding->binding_id);
    resized_header->magic = allocation_magic_a50;
    resized_header->size = new_size;
    resized_header->token = tracker->next_token + 1;
    issue_token_a50(tracker, new_record, resized_header + 1, new_size,
                    binding->binding_id);
    binding->successful_allocations += 1;
    return resized_header + 1;
  }
}

static lua_State *newstate_a50(lua_Alloc allocator, void *ud) {
#if LUA_VERSION_NUM >= 505
  return lua_newstate(allocator, ud, 0U);
#else
  return lua_newstate(allocator, ud);
#endif
}

static void free_records_a50(tracker_a50 *tracker) {
  allocation_record_a50 *record = tracker->records;
  while (record != NULL) {
    allocation_record_a50 *next = record->next;
    free(record);
    record = next;
  }
  tracker->records = NULL;
}

static size_t active_tokens_for_binding_a50(const tracker_a50 *tracker,
                                            int binding_id) {
  const allocation_record_a50 *record;
  size_t active = 0;
  for (record = tracker->records; record != NULL; record = record->next) {
    if (record->active && record->binding_id == binding_id)
      active += 1;
  }
  return active;
}

static int make_public_allocations_a50(lua_State *state,
                                      size_t *successful_before,
                                      tracker_a50 *tracker) {
  char string_data[4096];
  char buffer_data[LUAL_BUFFERSIZE + 128];
  luaL_Buffer buffer;

  for (size_t index = 0; index < sizeof(string_data); ++index)
    string_data[index] = (char)('A' + (index % 23));
  for (size_t index = 0; index < sizeof(buffer_data); ++index)
    buffer_data[index] = (char)('a' + (index % 19));

  *successful_before = tracker->issued_tokens;
  if (lua_pushlstring(state, string_data, sizeof(string_data)) == NULL)
    return 1;
  lua_pop(state, 1);

  lua_createtable(state, 24, 12);
  lua_pop(state, 1);

  if (lua_newuserdatauv(state, 4096, 0) == NULL)
    return 2;
  lua_pop(state, 1);

  luaL_buffinit(state, &buffer);
  luaL_addlstring(&buffer, buffer_data, sizeof(buffer_data));
  luaL_pushresult(&buffer);
  lua_pop(state, 1);

  return tracker->issued_tokens > *successful_before ? 0 : 3;
}

typedef struct failed_action_context_a50 {
  allocator_binding_a50 *binding;
  int marker;
} failed_action_context_a50;

typedef struct action_a50 {
  int32_t kind;
  int32_t value;
} action_a50;

typedef action_a50 (*action_fn_a50)(void *, uint64_t, uint64_t, void *);

typedef struct outcome_a50 {
  int32_t kind;
  int32_t value;
} outcome_a50;

extern outcome_a50 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_a50, void *);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);

static action_a50 fail_next_growth_action_a50(void *raw_state,
                                              uint64_t generation,
                                              uint64_t token,
                                              void *raw_context) {
  lua_State *state = (lua_State *)raw_state;
  failed_action_context_a50 *context =
      (failed_action_context_a50 *)raw_context;
  (void)generation;
  (void)token;

  context->binding->fail_next = 1;
  (void)lua_newuserdatauv(state, 32768, 0);
  context->marker += 1;
  return (action_a50){0, 50};
}

int main(void) {
  tracker_a50 tracker = {0};
  allocator_binding_a50 first = {&tracker, 1, 0, 0, 0, 0};
  allocator_binding_a50 second = {&tracker, 2, 0, 0, 0, 0};
  lua_State *state = NULL;
  lua_State *default_state = NULL;
  void *actual_ud = NULL;
  lua_Alloc actual_allocator;
  size_t successful_before = 0;
  size_t failures_before = 0;
  size_t second_before = 0;
  size_t cross_refunds_before_close = 0;
  failed_action_context_a50 action_context = {&first, 0};
  outcome_a50 outcome;
  int32_t error_class = 0;
  int result = 0;

#define CHECK_A50(code, condition) \
  do { \
    if (!(condition)) { \
      result = (code); \
      goto done; \
    } \
  } while (0)

  state = newstate_a50(NULL, NULL);
  if (state != NULL) {
    lua_close(state);
    state = NULL;
    result = 1;
    goto done;
  }

  state = newstate_a50(tracking_allocator_a50, &first);
  CHECK_A50(2, state != NULL);
  actual_allocator = lua_getallocf(state, &actual_ud);
  CHECK_A50(3, actual_allocator == tracking_allocator_a50 &&
                   actual_ud == &first);

  CHECK_A50(4, make_public_allocations_a50(
                   state, &successful_before, &tracker) == 0);
  CHECK_A50(5, first.nonzero_calls != 0 &&
                   first.successful_allocations != 0);

  failures_before = tracker.failed_admissions;
  action_context.marker = 0;
  outcome = rivetlua_capi_trampoline_protect_a1(
      state, fail_next_growth_action_a50, &action_context);
  CHECK_A50(6, outcome.kind == 1 && outcome.value == 5);
  CHECK_A50(7, action_context.marker == 0);
  CHECK_A50(8, !first.fail_next &&
                   tracker.failed_admissions == failures_before + 1);
  CHECK_A50(9, rivetlua_capi_error_consume_a1(state, &error_class) == 0 &&
                   error_class == 5);
  CHECK_A50(10, lua_gettop(state) == 1);
  lua_settop(state, 0);
  CHECK_A50(11, lua_gettop(state) == 0);
  CHECK_A50(12, lua_newuserdatauv(state, 32768, 0) != NULL);
  lua_pop(state, 1);

  CHECK_A50(13, tracker.active_tokens != 0);
  lua_setallocf(state, tracking_allocator_a50, &second);
  actual_ud = NULL;
  actual_allocator = lua_getallocf(state, &actual_ud);
  CHECK_A50(14, actual_allocator == tracking_allocator_a50 &&
                    actual_ud == &second);
  second_before = second.successful_allocations;
  CHECK_A50(15, lua_newuserdatauv(state, 8192, 0) != NULL);
  lua_pop(state, 1);
  CHECK_A50(16, second.nonzero_calls != 0 &&
                    second.successful_allocations > second_before);
  CHECK_A50(17, active_tokens_for_binding_a50(&tracker, first.binding_id) != 0);

  cross_refunds_before_close = tracker.cross_binding_refunds;
  lua_close(state);
  state = NULL;
  CHECK_A50(18, tracker.active_tokens == 0 &&
                    tracker.issued_tokens == tracker.refunded_tokens);
  CHECK_A50(19, tracker.invalid_pairs == 0 &&
                    tracker.duplicate_refunds == 0);
  CHECK_A50(20, tracker.cross_binding_refunds > cross_refunds_before_close);

  default_state = luaL_newstate();
  CHECK_A50(21, default_state != NULL);
  lua_close(default_state);
  default_state = NULL;

done:
  if (state != NULL)
    lua_close(state);
  if (default_state != NULL)
    lua_close(default_state);
  free_records_a50(&tracker);
  return result;

#undef CHECK_A50
}
