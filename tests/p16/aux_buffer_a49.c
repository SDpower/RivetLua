/* P16-2A49：固定公開 buffer API 的 C ABI 與執行語意驗證。 */
#include "lua.h"
#include "lauxlib.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

typedef struct {
  int32_t kind;
  int32_t value;
} action_a1;
typedef action_a1 (*action_fn_a1)(void *, uint64_t, uint64_t, void *);
typedef action_a1 outcome_a1;
extern outcome_a1 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_a1, void *);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);

typedef struct {
  int grow;
  int after;
} overflow_case;

static action_a1 overflow_buffer(void *raw_state, uint64_t generation,
                                 uint64_t token, void *raw_case) {
  (void)generation;
  (void)token;
  lua_State *state = (lua_State *)raw_state;
  overflow_case *test = (overflow_case *)raw_case;
  luaL_Buffer buffer;
  luaL_buffinit(state, &buffer);
  if (test->grow) {
    char bytes[LUAL_BUFFERSIZE + 1];
    memset(bytes, 'x', sizeof(bytes));
    luaL_addlstring(&buffer, bytes, sizeof(bytes));
  }
  (void)luaL_prepbuffsize(&buffer, SIZE_MAX);
  test->after += 1;
  return (action_a1){0, 49};
}

static int check_overflow(lua_State *state, int grow) {
  overflow_case test = {grow, 0};
  outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, overflow_buffer, &test);
  if (outcome.kind != 1 || outcome.value != 2 || test.after != 0 ||
      lua_gettop(state) != 0) return 1;
  int32_t error_class = 0;
  if (rivetlua_capi_error_consume_a1(state, &error_class) != 0 ||
      error_class != 2 || lua_gettop(state) != 1) return 2;
  const char expected[] = "resulting string too large";
  size_t length = 0;
  const char *actual = lua_tolstring(state, -1, &length);
  if (actual == NULL || length != sizeof(expected) - 1 ||
      memcmp(actual, expected, length) != 0 || actual[length] != '\0')
    return 3;
  lua_settop(state, 0);
  if (lua_gettop(state) != 0) return 4;
  return 0;
}

_Static_assert(offsetof(luaL_Buffer, b) == 0,
               "luaL_Buffer.b 必須位於結構開頭");
_Static_assert(offsetof(luaL_Buffer, size) >= sizeof(char *),
               "luaL_Buffer.size 必須位於 b 之後");
_Static_assert(offsetof(luaL_Buffer, n) >=
                   offsetof(luaL_Buffer, size) + sizeof(size_t),
               "luaL_Buffer.n 必須位於 size 之後");
_Static_assert(offsetof(luaL_Buffer, L) >=
                   offsetof(luaL_Buffer, n) + sizeof(size_t),
               "luaL_Buffer.L 必須位於 n 之後");
_Static_assert(offsetof(luaL_Buffer, init) >=
                   offsetof(luaL_Buffer, L) + sizeof(lua_State *),
               "luaL_Buffer.init 必須位於 L 之後");
_Static_assert(sizeof(((luaL_Buffer *)0)->init.b) == LUAL_BUFFERSIZE,
               "luaL_Buffer.init.b 必須符合固定緩衝區大小");
_Static_assert(offsetof(luaL_Buffer, init) + LUAL_BUFFERSIZE <=
                   sizeof(luaL_Buffer),
               "luaL_Buffer 必須完整包含初始緩衝區");

static int check_string(lua_State *L, const char *expected,
                        size_t expected_len, int expected_top) {
  if (lua_gettop(L) != expected_top)
    return 1;

  size_t actual_len = 0;
  const char *actual = lua_tolstring(L, -1, &actual_len);
  if (actual == NULL || actual_len != expected_len)
    return 2;
  if (memcmp(actual, expected, expected_len) != 0)
    return 3;
  return 0;
}

#define CHECK(code, condition) \
  do { \
    if (!(condition)) { \
      lua_close(L); \
      return (code); \
    } \
  } while (0)

int main(void) {
  lua_State *L = luaL_newstate();
  if (L == NULL)
    return 1;
  CHECK(2, lua_gettop(L) == 0);

  luaL_Buffer buffer;
  luaL_buffinit(L, &buffer);
  CHECK(29, lua_gettop(L) == 1);
  CHECK(3, buffer.b == buffer.init.b);
  CHECK(4, buffer.size == LUAL_BUFFERSIZE);
  CHECK(5, buffer.n == 0);
  CHECK(6, buffer.L == L);

  luaL_addchar(&buffer, 'A');
  luaL_addstring(&buffer, "BC");
  const char with_nul[] = {'D', '\0', 'E'};
  luaL_addlstring(&buffer, with_nul, sizeof(with_nul));
  const char combined[] = {'A', 'B', 'C', 'D', '\0', 'E'};
  CHECK(7, luaL_bufflen(&buffer) == sizeof(combined));
  CHECK(8, lua_gettop(L) == 1);
  luaL_pushresult(&buffer);
  CHECK(9, check_string(L, combined, sizeof(combined), 1) == 0);
  lua_settop(L, 0);

  const char sized[] = "sized!";
  char *area = luaL_buffinitsize(L, &buffer, 12);
  CHECK(30, lua_gettop(L) == 1);
  CHECK(10, area != NULL);
  CHECK(11, area == luaL_buffaddr(&buffer));
  memcpy(area, sized, sizeof(sized) - 1);
  CHECK(31, lua_gettop(L) == 1);
  luaL_pushresultsize(&buffer, sizeof(sized) - 1);
  CHECK(12, check_string(L, sized, sizeof(sized) - 1, 1) == 0);
  lua_settop(L, 0);

  luaL_buffinit(L, &buffer);
  CHECK(32, lua_gettop(L) == 1);
  area = luaL_prepbuffsize(&buffer, 12);
  CHECK(33, lua_gettop(L) == 1);
  CHECK(13, area != NULL);
  CHECK(14, area == luaL_buffaddr(&buffer));
  memcpy(area, sized, sizeof(sized) - 1);
  CHECK(34, lua_gettop(L) == 1);
  luaL_pushresultsize(&buffer, sizeof(sized) - 1);
  CHECK(15, check_string(L, sized, sizeof(sized) - 1, 1) == 0);
  lua_settop(L, 0);

  luaL_buffinit(L, &buffer);
  CHECK(35, lua_gettop(L) == 1);
  area = luaL_prepbuffer(&buffer);
  CHECK(36, lua_gettop(L) == 1);
  CHECK(16, area != NULL);
  CHECK(17, area == luaL_buffaddr(&buffer));
  memcpy(area, sized, sizeof(sized) - 1);
  CHECK(37, lua_gettop(L) == 1);
  luaL_pushresultsize(&buffer, sizeof(sized) - 1);
  CHECK(18, check_string(L, sized, sizeof(sized) - 1, 1) == 0);
  lua_settop(L, 0);

  char grown[LUAL_BUFFERSIZE + 37];
  for (size_t i = 0; i < sizeof(grown); ++i)
    grown[i] = (char)('a' + (i % 26));
  luaL_buffinit(L, &buffer);
  CHECK(38, lua_gettop(L) == 1);
  luaL_addlstring(&buffer, grown, sizeof(grown));
  CHECK(19, luaL_bufflen(&buffer) == sizeof(grown));
  CHECK(20, buffer.size >= sizeof(grown));
  CHECK(21, buffer.b != buffer.init.b);
  CHECK(22, lua_gettop(L) == 1);
  luaL_pushresult(&buffer);
  CHECK(23, check_string(L, grown, sizeof(grown), 1) == 0);
  lua_settop(L, 0);

  luaL_buffinit(L, &buffer);
  luaL_addstring(&buffer, "abcde");
  luaL_addlstring(&buffer, buffer.b + 1, 3);
  luaL_pushresult(&buffer);
  CHECK(47, check_string(L, "abcdebcd", 8, 1) == 0);
  lua_settop(L, 0);

  luaL_buffinit(L, &buffer);
  luaL_addlstring(&buffer, grown, sizeof(grown));
  CHECK(48, buffer.b != buffer.init.b);
  luaL_addlstring(&buffer, buffer.b, sizeof(grown));
  luaL_pushresult(&buffer);
  CHECK(49, lua_gettop(L) == 1);
  size_t alias_len = 0;
  const char *alias_result = lua_tolstring(L, -1, &alias_len);
  CHECK(50, alias_result != NULL && alias_len == 2 * sizeof(grown));
  CHECK(51, memcmp(alias_result, grown, sizeof(grown)) == 0);
  CHECK(52, memcmp(alias_result + sizeof(grown), grown, sizeof(grown)) == 0);
  lua_settop(L, 0);

  luaL_buffinit(L, &buffer);
  CHECK(39, lua_gettop(L) == 1);
  luaL_addchar(&buffer, '[');
  lua_pushlstring(L, "part", 4);
  CHECK(24, lua_gettop(L) == 2);
  luaL_addvalue(&buffer);
  CHECK(25, lua_gettop(L) == 1);
  luaL_addchar(&buffer, ']');
  luaL_pushresult(&buffer);
  CHECK(26, check_string(L, "[part]", 6, 1) == 0);
  lua_settop(L, 0);

  luaL_buffinit(L, &buffer);
  lua_pushinteger(L, 42);
  luaL_addvalue(&buffer);
  CHECK(53, lua_gettop(L) == 1);
  luaL_pushresult(&buffer);
  CHECK(54, check_string(L, "42", 2, 1) == 0);
  lua_settop(L, 0);

  luaL_buffinit(L, &buffer);
  CHECK(40, lua_gettop(L) == 1);
  luaL_addgsub(&buffer, "red--red-red", "red", "X");
  CHECK(41, lua_gettop(L) == 1);
  luaL_pushresult(&buffer);
  CHECK(27, check_string(L, "X--X-X", 6, 1) == 0);
  lua_settop(L, 0);

  luaL_buffinit(L, &buffer);
  CHECK(42, lua_gettop(L) == 1);
  luaL_addgsub(&buffer, "unchanged", "missing", "X");
  CHECK(43, lua_gettop(L) == 1);
  luaL_pushresult(&buffer);
  CHECK(28, check_string(L, "unchanged", 9, 1) == 0);
  lua_settop(L, 0);

  CHECK(44, check_overflow(L, 0) == 0);
  CHECK(45, check_overflow(L, 1) == 0);
  luaL_buffinit(L, &buffer);
  luaL_addstring(&buffer, "retry");
  luaL_pushresult(&buffer);
  CHECK(46, check_string(L, "retry", 5, 1) == 0);

  lua_close(L);
  return 0;
}
