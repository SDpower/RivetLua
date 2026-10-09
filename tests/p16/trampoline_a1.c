/* P16-3A1 私有 C-only checkpoint 實際連結／呼叫測試。 */
#include <stdint.h>
#include <stddef.h>

typedef struct {
  int32_t kind;
  int32_t value;
} action_a1;
typedef struct {
  int32_t kind;
  int32_t value;
} outcome_a1;
typedef action_a1 (*action_fn_a1)(void *, uint64_t, uint64_t, void *);

extern outcome_a1 rivetlua_capi_trampoline_protect_a1(
    void *, action_fn_a1, void *);
extern int32_t rivetlua_capi_trampoline_probe_a1(void *, uint64_t, uint64_t);
extern int32_t rivetlua_capi_error_prepare_a1(
    void *, uint64_t, uint64_t, int32_t);
extern int32_t rivetlua_capi_error_consume_a1(void *, int32_t *);
extern void *luaL_newstate(void);
extern void lua_close(void *);
extern void lua_pushinteger(void *, int64_t);
extern int32_t lua_gettop(void *);

static action_a1 normal(void *state, uint64_t generation, uint64_t token,
                        void *context) {
  if (rivetlua_capi_trampoline_probe_a1(state, generation, token) != 0)
    return (action_a1){2, -9};
  int32_t *called = (int32_t *)context;
  *called += 1;
  return (action_a1){0, 17};
}

static action_a1 raising(void *state, uint64_t generation, uint64_t token,
                         void *context) {
  int32_t *called = (int32_t *)context;
  *called += 1;
  int32_t status = rivetlua_capi_error_prepare_a1(state, generation, token, 2);
  if (status != 0) return (action_a1){2, status};
  return (action_a1){1, 2};
}

static action_a1 close_while_active(void *state, uint64_t generation,
                                     uint64_t token, void *context) {
  (void)generation;
  (void)token;
  (void)context;
  lua_close(state);
  return (action_a1){0, lua_gettop(state)};
}

int main(void) {
  void *state = luaL_newstate();
  if (state == NULL) return 1;
  lua_pushinteger(state, 83);
  if (lua_gettop(state) != 1) return 2;
  int32_t called = 0;
  outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, normal, &called);
  if (outcome.kind != 0 || outcome.value != 17 || called != 1 ||
      lua_gettop(state) != 1) return 3;
  outcome = rivetlua_capi_trampoline_protect_a1(
      state, close_while_active, NULL);
  if (outcome.kind != 0 || outcome.value != 1) return 4;
  outcome = rivetlua_capi_trampoline_protect_a1(
      state, raising, &called);
  if (outcome.kind != 1 || outcome.value != 2 || called != 2 ||
      lua_gettop(state) != 0) return 5;
  lua_close(state); /* pending 期間必須拒絕釋放。 */
  int32_t class = 0;
  if (rivetlua_capi_error_consume_a1(state, &class) != 0 ||
      class != 2 || lua_gettop(state) != 1) return 6;
  lua_close(state);
  return 0;
}
