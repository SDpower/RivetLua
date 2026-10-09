/* P16-2 B2：固定 header 的嚴格 auxiliary 與真 C variadic ABI。 */
#include "lua.h"
#include "lauxlib.h"

#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

typedef struct { int32_t kind; int32_t value; } action_b2;
typedef action_b2 (*action_fn_b2)(void *, uint64_t, uint64_t, void *);
extern action_b2 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_b2, void *);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);

typedef struct {
  int operation;
  int argument;
  int tag;
  const char *name;
  const char *const *choices;
  int reached;
} case_b2;

static int *format_failure_flag_b2;

static const char *call_vf_b2(lua_State *state, const char *format, ...) {
  va_list args;
  va_start(args, format);
  const char *result = lua_pushvfstring(state, format, args);
  va_end(args);
  return result;
}

static const char *call_vf_tracked_b2(lua_State *state, int *ended,
                                      const char *format, ...) {
  va_list args;
  va_start(args, format);
  const char *result = lua_pushvfstring(state, format, args);
  va_end(args);
  *ended = 1;
  return result;
}

static int check_top_b2(lua_State *state, const char *expected,
                        size_t expected_len, int top) {
  size_t length = SIZE_MAX;
  const char *value = lua_tolstring(state, -1, &length);
  return lua_gettop(state) == top && value != NULL &&
      length == expected_len && memcmp(value, expected, length) == 0;
}

static action_b2 strict_action_b2(void *opaque, uint64_t generation,
                                 uint64_t token, void *context) {
  (void)generation;
  (void)token;
  lua_State *state = (lua_State *)opaque;
  case_b2 *test = (case_b2 *)context;
  switch (test->operation) {
    case 1: luaL_checktype(state, test->argument, test->tag); break;
    case 2: luaL_checkany(state, test->argument); break;
    case 3: (void)luaL_checkudata(state, test->argument, test->name); break;
    case 4: (void)luaL_checkoption(state, test->argument,
                                 test->name, test->choices); break;
    case 5: (void)lua_pushfstring(state, "before %q after"); break;
    case 6: (void)call_vf_b2(state, "bad %q"); break;
    case 7:
      if (format_failure_flag_b2 != NULL) *format_failure_flag_b2 = 1;
      (void)lua_pushfstring(state, "%s", test->name);
      break;
    default: abort();
  }
  test->reached += 1;
  return (action_b2){0, 16};
}

static int check_error_b2(lua_State *state, case_b2 *test,
                          int expected_class, const char *expected,
                          size_t expected_len, int original_top) {
  action_b2 result = rivetlua_capi_trampoline_protect_a1(
      state, strict_action_b2, test);
  if (result.kind != 1 || result.value != expected_class ||
      test->reached != 0 || lua_gettop(state) != original_top) {
    fprintf(stderr, "B2 checkpoint kind=%d value=%d reached=%d top=%d expected=%d\n",
            result.kind, result.value, test->reached,
            lua_gettop(state), expected_class);
    return 1;
  }
  int32_t class_code = 0;
  if (rivetlua_capi_error_consume_a1(state, &class_code) != 0 ||
      class_code != expected_class ||
      !check_top_b2(state, expected, expected_len, original_top + 1)) {
    fprintf(stderr, "B2 consume class=%d top=%d expected=%d\n",
            class_code, lua_gettop(state), expected_class);
    return 2;
  }
  lua_settop(state, original_top);
  return lua_gettop(state) == original_top ? 0 : 3;
}

static action_b2 nested_action_b2(void *opaque, uint64_t generation,
                                 uint64_t token, void *context) {
  (void)generation;
  (void)token;
  (void)context;
  lua_State *state = (lua_State *)opaque;
  case_b2 missing = {2, 1, 0, NULL, NULL, 0};
  const char message[] = "bad argument #1 (value expected)";
  if (check_error_b2(state, &missing, 2,
                     message, sizeof(message) - 1, 0) != 0)
    return (action_b2){2, -9};
  return (action_b2){0, 17};
}

typedef struct { int fail_next; int rejects; } allocator_b2;

static void *allocate_b2(void *context, void *pointer,
                         size_t old_size, size_t new_size) {
  allocator_b2 *allocator = (allocator_b2 *)context;
  (void)old_size;
  if (new_size == 0) {
    free(pointer);
    return NULL;
  }
  if (allocator->fail_next) {
    allocator->fail_next = 0;
    allocator->rejects += 1;
    return NULL;
  }
  return realloc(pointer, new_size);
}

typedef struct {
  const char *text;
  allocator_b2 *allocator;
  const char *result;
  int after_va_end;
  int resumed;
} vf_failure_b2;

static action_b2 vf_failure_action_b2(void *opaque, uint64_t generation,
                                      uint64_t token, void *context) {
  (void)generation;
  (void)token;
  lua_State *state = (lua_State *)opaque;
  vf_failure_b2 *test = (vf_failure_b2 *)context;
  test->allocator->fail_next = 1; /* 外層 checkpoint admission 已完成。 */
  test->result = call_vf_tracked_b2(state, &test->after_va_end,
                                     "%s", test->text);
  test->resumed = 1;
  return (action_b2){0, 18};
}

static int fail_stop_b2(lua_State *state) {
  pid_t child = fork();
  if (child < 0) return 1;
  if (child == 0) {
    struct rlimit limit = {0, 0};
    (void)setrlimit(RLIMIT_CORE, &limit);
    luaL_checkany(state, 999);
    _Exit(91);
  }
  int status = 0;
  if (waitpid(child, &status, 0) != child) return 2;
  return WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT ? 0 : 3;
}

#define CHECK_B2(code, condition) do { if (!(condition)) return (code); } while (0)

static int run_b2(lua_State *state, allocator_b2 *allocator) {
  CHECK_B2(2, lua_gettop(state) == 0);
  CHECK_B2(3, fail_stop_b2(state) == 0);
  action_b2 nested = rivetlua_capi_trampoline_protect_a1(
      state, nested_action_b2, NULL);
  CHECK_B2(30, nested.kind == 0 && nested.value == 17 && lua_gettop(state) == 0);

  const char *result = lua_pushfstring(state, "");
  CHECK_B2(4, result != NULL && check_top_b2(state, "", 0, 1));
  lua_settop(state, 0);
#if LUA_VERSION_NUM == 504
  result = call_vf_b2(state, "%s|%c|%d|%I|%f|%p|%U|%%",
                      (char *)NULL, 0, INT_MIN, (long long)LLONG_MIN,
                      1.0, (void *)state, (long)0x10FFFF);
#else
  result = call_vf_b2(state, "%s|%c|%d|%I|%f|%p|%U|%%",
                      (char *)NULL, 0, INT_MIN, (long long)LLONG_MIN,
                      1.0, (void *)state, (unsigned long)0x10FFFF);
#endif
  CHECK_B2(5, result != NULL && lua_gettop(state) == 1);
  char pointer_bytes[64];
  int pointer_len = snprintf(pointer_bytes, sizeof(pointer_bytes), "%p", (void *)state);
  CHECK_B2(6, pointer_len > 0 && (size_t)pointer_len < sizeof(pointer_bytes));
  char expected[256];
  int prefix = snprintf(expected, sizeof(expected),
                        "(null)|x|%d|%lld|1.0|%s|", INT_MIN,
                        (long long)LLONG_MIN, pointer_bytes);
  CHECK_B2(7, prefix > 0 && (size_t)prefix + 6 < sizeof(expected));
  expected[7] = '\0'; /* `%c` 真正插入 NUL；下方逐 byte 比對。 */
  expected[prefix + 0] = (char)0xF4;
  expected[prefix + 1] = (char)0x8F;
  expected[prefix + 2] = (char)0xBF;
  expected[prefix + 3] = (char)0xBF;
  expected[prefix + 4] = '|';
  expected[prefix + 5] = '%';
  CHECK_B2(8, check_top_b2(state, expected, (size_t)prefix + 6, 1));
  CHECK_B2(9, result == lua_tolstring(state, -1, NULL));
  lua_settop(state, 0);

  result = lua_pushfstring(state, "%f|%f", -0.0, 1.2345678901234567);
#if LUA_VERSION_NUM == 504
  const char float_edges[] = "-0.0|1.2345678901235";
#else
  const char float_edges[] = "-0.0|1.2345678901234567";
#endif
  CHECK_B2(31, result != NULL &&
      check_top_b2(state, float_edges, sizeof(float_edges) - 1, 1));
  lua_settop(state, 0);
#if LUA_VERSION_NUM == 504
  result = call_vf_b2(state, "%U|%U|%U", (long)0, (long)0x80,
                      (long)0x7FFFFFFF);
#else
  result = call_vf_b2(state, "%U|%U|%U", (unsigned long)0,
                      (unsigned long)0x80, (unsigned long)0x7FFFFFFF);
#endif
  const char utf8_edges[] = "\0|\xC2\x80|\xFD\xBF\xBF\xBF\xBF\xBF";
  CHECK_B2(32, result != NULL &&
      check_top_b2(state, utf8_edges, sizeof(utf8_edges) - 1, 1));
  lua_settop(state, 0);

  char long_text[4097];
  memset(long_text, 'x', sizeof(long_text) - 1);
  long_text[sizeof(long_text) - 1] = '\0';
  result = lua_pushfstring(state, "%s", long_text);
  CHECK_B2(10, result != NULL &&
           check_top_b2(state, long_text, sizeof(long_text) - 1, 1));
  lua_settop(state, 0);

#if LUA_VERSION_NUM == 504
  case_b2 unknown = {5, 0, 0, NULL, NULL, 0};
  const char unknown_message[] = "invalid option '%q' to 'lua_pushfstring'";
  CHECK_B2(11, check_error_b2(state, &unknown, 2,
                            unknown_message, sizeof(unknown_message) - 1, 0) == 0);
  unknown.operation = 6;
  CHECK_B2(12, check_error_b2(state, &unknown, 2,
                            unknown_message, sizeof(unknown_message) - 1, 0) == 0);
#else
  result = lua_pushfstring(state, "before %q after");
  CHECK_B2(11, result != NULL &&
           check_top_b2(state, "before %q after", 15, 1));
  lua_settop(state, 0);
  result = call_vf_b2(state, "bad %q");
  CHECK_B2(12, result != NULL && check_top_b2(state, "bad %q", 6, 1));
  lua_settop(state, 0);
#endif

  case_b2 missing = {2, 1, 0, NULL, NULL, 0};
  CHECK_B2(13, check_error_b2(state, &missing, 2,
      "bad argument #1 (value expected)",
      sizeof("bad argument #1 (value expected)") - 1, 0) == 0);
  lua_pushnil(state);
  luaL_checkany(state, 1);
  luaL_checktype(state, -1, LUA_TNIL);
  CHECK_B2(14, lua_gettop(state) == 1);
  case_b2 wrong = {1, 1, LUA_TNUMBER, NULL, NULL, 0};
  CHECK_B2(15, check_error_b2(state, &wrong, 2,
      "bad argument #1 (number expected, got nil)",
      sizeof("bad argument #1 (number expected, got nil)") - 1, 1) == 0);
  lua_settop(state, 0);

  const char *const choices[] = {"alpha", "beta", NULL};
  case_b2 required_option = {4, 1, 0, NULL, choices, 0};
  const char required_message[] =
      "bad argument #1 (string expected, got no value)";
  CHECK_B2(33, check_error_b2(state, &required_option, 2,
      required_message, sizeof(required_message) - 1, 0) == 0);
  CHECK_B2(16, luaL_checkoption(state, 1, "beta", choices) == 1);
  lua_pushinteger(state, 42);
  const char *const numbers[] = {"42", NULL};
  CHECK_B2(17, luaL_checkoption(state, -1, NULL, numbers) == 0 &&
      lua_type(state, -1) == LUA_TSTRING &&
      check_top_b2(state, "42", 2, 1));
  case_b2 invalid = {4, 1, 0, NULL, choices, 0};
  CHECK_B2(18, check_error_b2(state, &invalid, 2,
      "bad argument #1 (invalid option '42')",
      sizeof("bad argument #1 (invalid option '42')") - 1, 1) == 0);
  lua_settop(state, 0);

  void *memory = lua_newuserdatauv(state, 8, 0);
  CHECK_B2(19, memory != NULL);
  case_b2 no_metatable = {3, 1, 0, "B2Thing", NULL, 0};
  const char missing_metatable_message[] =
      "bad argument #1 (B2Thing expected, got userdata)";
  CHECK_B2(34, check_error_b2(state, &no_metatable, 2,
      missing_metatable_message, sizeof(missing_metatable_message) - 1, 1) == 0);
  CHECK_B2(20, luaL_newmetatable(state, "B2Thing") == 1);
  lua_pushstring(state, "NamedThing");
  lua_setfield(state, -2, "__name");
  CHECK_B2(21, lua_setmetatable(state, 1) == 1);
  CHECK_B2(22, luaL_checkudata(state, 1, "B2Thing") == memory);
  CHECK_B2(23, luaL_checkudata(state, -1, "B2Thing") == memory);
  case_b2 named = {1, 1, LUA_TNUMBER, NULL, NULL, 0};
  CHECK_B2(24, check_error_b2(state, &named, 2,
      "bad argument #1 (number expected, got NamedThing)",
      sizeof("bad argument #1 (number expected, got NamedThing)") - 1, 1) == 0);
  CHECK_B2(35, luaL_newmetatable(state, "OtherThing") == 1);
  lua_settop(state, 1);
  case_b2 wrong_name = {3, 1, 0, "OtherThing", NULL, 0};
  CHECK_B2(25, check_error_b2(state, &wrong_name, 2,
      "bad argument #1 (OtherThing expected, got NamedThing)",
      sizeof("bad argument #1 (OtherThing expected, got NamedThing)") - 1, 1) == 0);
  lua_settop(state, 0);

  if (allocator != NULL) {
    vf_failure_b2 vf_failure = {long_text, allocator, NULL, 0, 0};
    int rejected_before = allocator->rejects;
    action_b2 vf_outcome = rivetlua_capi_trampoline_protect_a1(
        state, vf_failure_action_b2, &vf_failure);
#if LUA_VERSION_NUM == 505
    CHECK_B2(36, vf_outcome.kind == 0 && vf_outcome.value == 18 &&
        vf_failure.result == NULL && vf_failure.after_va_end == 1 &&
        vf_failure.resumed == 1 &&
        check_top_b2(state, "not enough memory", 17, 1));
    int32_t no_pending_class = 0;
    CHECK_B2(37, rivetlua_capi_error_consume_a1(state, &no_pending_class) == -11);
#else
    CHECK_B2(36, vf_outcome.kind == 1 && vf_outcome.value == 5 &&
        vf_failure.after_va_end == 0 && vf_failure.resumed == 0 &&
        lua_gettop(state) == 0);
    int32_t vf_class = 0;
    CHECK_B2(37, rivetlua_capi_error_consume_a1(state, &vf_class) == 0 &&
        vf_class == 5 && check_top_b2(state, "not enough memory", 17, 1));
#endif
    CHECK_B2(38, allocator->rejects == rejected_before + 1);
    lua_settop(state, 0);
    result = call_vf_b2(state, "%s", long_text);
    CHECK_B2(39, result != NULL &&
        check_top_b2(state, long_text, sizeof(long_text) - 1, 1));
    lua_settop(state, 0);

    format_failure_flag_b2 = &allocator->fail_next;
    int before_fstring = allocator->rejects;
    case_b2 allocation = {7, 0, 0, long_text, NULL, 0};
    CHECK_B2(26, check_error_b2(state, &allocation, 5,
        "not enough memory", 17, 0) == 0);
    format_failure_flag_b2 = NULL;
    CHECK_B2(27, allocator->rejects == before_fstring + 1);
    result = lua_pushfstring(state, "%s", long_text);
    CHECK_B2(28, result != NULL &&
        check_top_b2(state, long_text, sizeof(long_text) - 1, 1));
    lua_settop(state, 0);
  }
  return 0;
}

int main(void) {
  lua_State *normal = luaL_newstate();
  if (normal == NULL) return 1;
  int code = run_b2(normal, NULL);
  lua_close(normal);
  if (code != 0) return code;
  allocator_b2 allocator = {0, 0};
#if LUA_VERSION_NUM == 504
  lua_State *custom = lua_newstate(allocate_b2, &allocator);
#else
  lua_State *custom = lua_newstate(allocate_b2, &allocator, 0);
#endif
  if (custom == NULL) return 29;
  code = run_b2(custom, &allocator);
  lua_close(custom);
  return code;
}
