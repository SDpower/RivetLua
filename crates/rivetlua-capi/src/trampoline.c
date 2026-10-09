#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>

#include "lua.h"
#include "lauxlib.h"

#include "trampoline_codes.h"

typedef struct {
  char *b;
  size_t size;
  size_t n;
  lua_State *state;
} rivetlua_buffer_prefix_a49;

typedef struct {
  int32_t kind;
  int32_t value;
} rivetlua_capi_action_a1;

typedef struct {
  int32_t kind;
  int32_t value;
} rivetlua_capi_outcome_a1;

typedef struct {
  int32_t kind;
  int32_t value;
  char *pointer;
} rivetlua_capi_buffer_result_a49;

typedef struct {
  int32_t kind;
  int32_t value;
  void *pointer;
} rivetlua_capi_userdata_result_a50;

#if LUA_VERSION_NUM >= 505
typedef struct {
  int32_t kind;
  int32_t value;
  const char *pointer;
} rivetlua_capi_external_string_result_b9;
#endif

typedef struct {
  int32_t kind;
  int32_t value;
  lua_State *pointer;
} rivetlua_capi_newthread_result_b3;

typedef struct {
  int32_t kind;
  int32_t value;
  int32_t answer;
} rivetlua_capi_pushthread_result_b3;

typedef struct {
  int32_t kind;
  int32_t value;
  lua_CFunction function;
  lua_Hook hook;
  int32_t event;
  int32_t currentline;
  void *token;
} rivetlua_capi_callback_step_b4;

typedef struct {
  int32_t kind;
  size_t base;
  void *handler;
} rivetlua_capi_public_call_setup_a2;

typedef struct {
  int32_t kind;
  int32_t status;
  int32_t nresults;
  int32_t resume_args;
  size_t base;
  rivetlua_capi_callback_step_b4 step;
  lua_KFunction continuation;
  lua_KContext context;
} rivetlua_capi_resume_setup_a5;

typedef struct {
  int32_t status;
  int32_t nresults;
} rivetlua_capi_resume_finish_result_a5;

typedef struct {
  int32_t kind;
  int32_t protected_call;
  int32_t nresults;
  size_t base;
  lua_KFunction continuation;
  lua_KContext context;
  void *handler;
} rivetlua_capi_continuation_record_a5;

typedef struct {
  int32_t kind;
  int32_t value;
} rivetlua_capi_close_step_b7;

typedef struct {
  int32_t kind;
  int32_t value;
  void *pointer;
} rivetlua_capi_strict_result_b2;

typedef struct {
  int32_t kind;
  int32_t value;
  lua_Number number;
  lua_Integer integer;
  const char *pointer;
  size_t length;
} rivetlua_capi_aux_value_a4b;

typedef struct {
  int32_t kind;
  const char *pointer;
  size_t length;
} rivetlua_capi_tolstring_result_b5;

typedef struct {
  lua_WarnFunction callback;
  void *ud;
} rivetlua_capi_warning_binding_b6;

typedef rivetlua_capi_action_a1 (*rivetlua_capi_action_fn_a1)(
    void *state, uint64_t generation, uint64_t token, void *context);

typedef struct rivetlua_capi_checkpoint_a1 {
  jmp_buf jump;
  struct rivetlua_capi_checkpoint_a1 *previous;
  void *state;
  uint64_t generation;
  uint64_t token;
  uint64_t previous_state_token;
  volatile int32_t *raised_status;
  unsigned rust_action_active;
  unsigned yieldable_a5;
} rivetlua_capi_checkpoint_a1;

static _Thread_local rivetlua_capi_checkpoint_a1 *rivetlua_capi_top_a1;
static _Thread_local rivetlua_capi_checkpoint_a1 *rivetlua_capi_resume_top_a5;
#if LUA_VERSION_NUM >= 505
static _Thread_local rivetlua_capi_checkpoint_a1 *rivetlua_capi_selfclose_resume_b11;
static _Thread_local volatile int *rivetlua_capi_selfclose_status_b11;
#endif

extern int32_t rivetlua_capi_checkpoint_enter_a1(
    void *state, uint64_t *generation, uint64_t *token,
    uint64_t *previous_state_token);
extern int32_t rivetlua_capi_checkpoint_exit_a1(
    void *state, uint64_t generation, uint64_t token,
    uint64_t previous_state_token);
extern int32_t rivetlua_capi_checkpoint_rewind_a5(
    void *state, uint64_t generation, uint64_t token, unsigned skipped);
extern int rivetlua_capi_yield_prepare_a5(
    lua_State *state, int nresults, lua_KContext context,
    lua_KFunction continuation);
extern rivetlua_capi_resume_setup_a5 rivetlua_capi_resume_prepare_a5(
    lua_State *state, lua_State *from, int nargs);
extern rivetlua_capi_resume_finish_result_a5 rivetlua_capi_resume_finish_a5(
    lua_State *state, size_t base, size_t frame_depth, int error_class);
extern int rivetlua_capi_continuation_push_a5(
    lua_State *state, lua_KFunction continuation, lua_KContext context,
    int protected_call, int nresults, size_t base, void *handler);
extern rivetlua_capi_continuation_record_a5 rivetlua_capi_continuation_step_a5(
    lua_State *state, size_t depth, int consume);
extern int rivetlua_capi_continuation_results_a5(lua_State *state);
extern int32_t rivetlua_capi_pending_matches_a1(
    void *state, uint64_t generation, uint64_t token, int32_t status);
extern int32_t rivetlua_capi_pending_cancel_a1(
    void *state, uint64_t generation, uint64_t token);
extern rivetlua_capi_action_a1 rivetlua_capi_checkversion_prepare_a48(
    void *state, uint64_t generation, uint64_t token,
    double version, size_t sizes);
extern rivetlua_capi_buffer_result_a49 rivetlua_capi_buffer_dispatch_a49(
    lua_State *state, uint64_t generation, uint64_t token,
    luaL_Buffer *buffer, int32_t operation, const char *source,
    const char *pattern, const char *replacement, size_t size);
extern rivetlua_capi_userdata_result_a50 rivetlua_capi_newuserdata_dispatch_a50(
    lua_State *state, uint64_t generation, uint64_t token,
    size_t size, int nuvalue);
#if LUA_VERSION_NUM >= 505
extern rivetlua_capi_external_string_result_b9
rivetlua_capi_pushexternalstring_dispatch_b9(
    lua_State *state, uint64_t generation, uint64_t token,
    const char *source, size_t len, lua_Alloc falloc, void *ud);
#endif
extern rivetlua_capi_newthread_result_b3 rivetlua_capi_newthread_dispatch_b3(
    lua_State *state, uint64_t generation, uint64_t token);
extern rivetlua_capi_pushthread_result_b3 rivetlua_capi_pushthread_dispatch_b3(
    lua_State *state, uint64_t generation, uint64_t token);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_prepare_b4(
    lua_State *state, int nargs, int nresults);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_gc_prepare_b8(
    lua_State *state, int what, size_t bytes, int first, int second, int third);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_gc_resume_error_b8(
    lua_State *state);
extern int rivetlua_capi_reset_preflight_b11(
    lua_State *state, lua_State *from);
extern int rivetlua_capi_reset_start_a5(lua_State *state);
extern int32_t rivetlua_capi_reset_checkpoint_exit_a5(
    lua_State *state, uint64_t generation, uint64_t token, uint64_t previous);
extern int rivetlua_capi_reset_cancel_b11(lua_State *state);
#if LUA_VERSION_NUM >= 505
extern int rivetlua_capi_selfclose_preflight_b11(lua_State *state);
extern int rivetlua_capi_selfclose_restore_b11(
    lua_State *state, int overlay_status);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_selfclose_prepare_b11(
    lua_State *state, int overlay_status);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_test_resume_prepare_b11(
    lua_State *state);
#endif
extern rivetlua_capi_callback_step_b4 rivetlua_capi_reset_prepare_b11(
    lua_State *state, int overlay_status);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_reset_resume_error_b11(
    lua_State *state);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_reset_resume_boundary_a5(
    lua_State *state, int overlay_status);
extern int rivetlua_capi_reset_finish_b11(
    lua_State *state, int overlay_status);
extern lua_State *rivetlua_capi_close_main_b11(lua_State *state);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_shutdown_prepare_b11(
    lua_State *state);
extern int rivetlua_capi_close_drop_b11(lua_State *state);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_resume_b4(
    lua_State *state, int count, int nresults);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_prepare_a2(
    lua_State *state, int nargs, int nresults);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_resume_a2(
    lua_State *state, int count, int nresults);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_resume_error_a2(
    lua_State *state, int nresults);
extern rivetlua_capi_public_call_setup_a2 rivetlua_capi_public_preflight_a2(
    lua_State *state, int nargs, int nresults, int errfunc);
extern int rivetlua_capi_public_settle_preflight_allocation_a2(
    lua_State *state, size_t base);
extern int rivetlua_capi_traceback_preflight_a3(
    lua_State *destination, lua_State *source);
extern rivetlua_capi_strict_result_b2 rivetlua_capi_generic_dispatch_a3(
    lua_State *state, lua_State *other, uint64_t generation, uint64_t token,
    int operation, int first, int second, lua_Integer integer, lua_Number number,
    void *opaque, const char *text1, const char *text2, const char *text3);
extern rivetlua_capi_strict_result_b2 rivetlua_capi_upvalue_dispatch_a4b(
    lua_State *state, uint64_t generation, uint64_t token, int operation,
    int first, int first_n, int second, int second_n);
extern rivetlua_capi_aux_value_a4b rivetlua_capi_aux_value_dispatch_a4b(
    lua_State *state, uint64_t generation, uint64_t token,
    int operation, int arg, lua_Number default_number,
    lua_Integer default_integer, const char *default_string);
extern rivetlua_capi_strict_result_b2 rivetlua_capi_pushcclosure_dispatch_a4b(
    lua_State *state, uint64_t generation, uint64_t token,
    lua_CFunction function, int n);
extern rivetlua_capi_strict_result_b2 rivetlua_capi_aux_push_a4a(
    lua_State *state, uint64_t generation, uint64_t token, int operation,
    int index, lua_CFunction function, int nup);
extern int rivetlua_capi_generic_panic_error_a3(lua_State *state);
extern int rivetlua_capi_public_settle_error_a2(lua_State *state, size_t base);
extern int rivetlua_capi_public_push_handler_a2(
    lua_State *state, void *handler, size_t base);
extern void rivetlua_capi_public_drop_handler_a2(void *handler);
extern lua_CFunction rivetlua_capi_panic_snapshot_a2(lua_State *state);
extern int rivetlua_capi_call_abort_b4(lua_State *state);
extern int rivetlua_capi_call_depth_b7(lua_State *state);
extern int rivetlua_capi_call_abort_to_b7(lua_State *state, int depth);
extern int rivetlua_capi_toclose_prepare_b7(lua_State *state, int index);
extern rivetlua_capi_close_step_b7 rivetlua_capi_close_next_b7(
    lua_State *state, size_t target, size_t error_position, int nil_slot);
extern int rivetlua_capi_close_capture_error_b7(
    lua_State *state, size_t trim_top);
extern int rivetlua_capi_close_finalize_error_b7(
    lua_State *state, size_t trim_top, uint64_t token, int error_class);
extern int rivetlua_capi_settop_direct_b7(lua_State *state, int index);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_operation_prepare_b5(
    lua_State *state, int kind, int operation, int left, int right, int count);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_operation_resume_b5(
    lua_State *state, int count);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_table_prepare_a4a(
    lua_State *state, int index, int setter);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_table_resume_a4a(
    lua_State *state, int count, int setter);
extern int rivetlua_capi_operation_depth_b5(lua_State *state);
extern int rivetlua_capi_operation_abort_to_b5(lua_State *state, int depth);
extern rivetlua_capi_strict_result_b2 rivetlua_capi_operation_error_b5(
    lua_State *state, uint64_t generation, uint64_t token, int class_code,
    int message);
extern rivetlua_capi_tolstring_result_b5 rivetlua_capi_tolstring_fallback_b5(
    lua_State *state, int index, const unsigned char *pointer, size_t length);
static rivetlua_capi_strict_result_b2 rivetlua_b2_finish(
    lua_State *state, uint64_t generation, uint64_t token,
    rivetlua_capi_strict_result_b2 result);
extern rivetlua_capi_strict_result_b2 rivetlua_capi_aux_dispatch_b2(
    lua_State *state, uint64_t generation, uint64_t token,
    int32_t operation, int arg, int tag, const char *name,
    const char *const *choices);
extern rivetlua_capi_strict_result_b2 rivetlua_capi_aux_dispatch_public_a3(
    lua_State *state, uint64_t generation, uint64_t token,
    int32_t operation, int arg, int tag, const char *name,
    const char *const *choices);
extern rivetlua_capi_strict_result_b2 rivetlua_capi_format_error_b2(
    lua_State *state, uint64_t generation, uint64_t token,
    luaL_Buffer *buffer, const char *message, size_t length);
extern int32_t rivetlua_capi_error_prepare_a1(
    void *state, uint64_t generation, uint64_t token, int32_t class_code);
extern int32_t rivetlua_capi_error_consume_a1(
    void *state, int32_t *class_code);
extern rivetlua_capi_warning_binding_b6 rivetlua_capi_warning_snapshot_b6(
    lua_State *state);
rivetlua_capi_outcome_a1 rivetlua_capi_trampoline_protect_a1(
    void *state, rivetlua_capi_action_fn_a1 action_fn, void *context);

_Static_assert(sizeof(rivetlua_capi_action_a1) == 2 * sizeof(int32_t),
               "C/Rust action layout");
_Static_assert(sizeof(rivetlua_capi_outcome_a1) == 2 * sizeof(int32_t),
               "C/Rust outcome layout");
_Static_assert(offsetof(rivetlua_buffer_prefix_a49, state) == 3 * sizeof(void *),
               "luaL_Buffer public prefix layout");
_Static_assert(offsetof(rivetlua_capi_buffer_result_a49, pointer) == 2 * sizeof(int32_t),
               "C/Rust buffer result layout");
_Static_assert(offsetof(rivetlua_capi_userdata_result_a50, pointer) == 2 * sizeof(int32_t),
               "C/Rust userdata result layout");
_Static_assert(offsetof(rivetlua_capi_newthread_result_b3, pointer) == 2 * sizeof(int32_t),
               "C/Rust newthread result layout");
_Static_assert(sizeof(rivetlua_capi_pushthread_result_b3) == 3 * sizeof(int32_t),
               "C/Rust pushthread result layout");
_Static_assert(offsetof(rivetlua_capi_callback_step_b4, function) == 2 * sizeof(int32_t),
               "C/Rust callback step layout");
_Static_assert(offsetof(rivetlua_capi_callback_step_b4, hook) ==
                   2 * sizeof(int32_t) + sizeof(lua_CFunction),
               "C/Rust hook step layout");
_Static_assert(offsetof(rivetlua_capi_callback_step_b4, event) ==
                   offsetof(rivetlua_capi_callback_step_b4, hook) + sizeof(lua_Hook),
               "C/Rust hook event layout");
_Static_assert(offsetof(rivetlua_capi_callback_step_b4, token) ==
                   offsetof(rivetlua_capi_callback_step_b4, event) + 2 * sizeof(int32_t),
               "C/Rust hook token layout");
_Static_assert(offsetof(rivetlua_capi_public_call_setup_a2, base) ==
                   sizeof(void *),
               "C/Rust public call setup layout");
_Static_assert(offsetof(rivetlua_capi_public_call_setup_a2, handler) ==
                   2 * sizeof(void *),
               "C/Rust public handler layout");
_Static_assert(sizeof(rivetlua_capi_close_step_b7) == 2 * sizeof(int32_t),
               "C/Rust close step layout");
_Static_assert(offsetof(rivetlua_capi_strict_result_b2, pointer) == 2 * sizeof(int32_t),
               "C/Rust strict result layout");
_Static_assert(offsetof(rivetlua_capi_aux_value_a4b, pointer) ==
                   2 * sizeof(int32_t) + sizeof(lua_Number) + sizeof(lua_Integer),
               "C/Rust auxiliary value layout");
_Static_assert(offsetof(rivetlua_capi_tolstring_result_b5, pointer) == 2 * sizeof(int32_t),
               "C/Rust tolstring fallback layout");
_Static_assert(sizeof(rivetlua_capi_warning_binding_b6) == 2 * sizeof(void *),
               "C/Rust warning binding layout");

void lua_warning(lua_State *state, const char *message, int tocont) {
  rivetlua_capi_warning_binding_b6 binding =
      rivetlua_capi_warning_snapshot_b6(state);
  if (binding.callback != NULL)
    binding.callback(binding.ud, message, tocont);
}

static void rivetlua_warnfoff_b6(void *ud, const char *message, int tocont);
static void rivetlua_warnfon_b6(void *ud, const char *message, int tocont);
static void rivetlua_warnfcont_b6(void *ud, const char *message, int tocont);

static int rivetlua_warncontrol_b6(lua_State *state, const char *message,
                                    int tocont) {
  if (tocont || *message != '@') return 0;
  message++;
  if (strcmp(message, "off") == 0)
    lua_setwarnf(state, rivetlua_warnfoff_b6, state);
  else if (strcmp(message, "on") == 0)
    lua_setwarnf(state, rivetlua_warnfon_b6, state);
  return 1;
}

static void rivetlua_warnfoff_b6(void *ud, const char *message, int tocont) {
  (void)rivetlua_warncontrol_b6((lua_State *)ud, message, tocont);
}

static void rivetlua_warnfcont_b6(void *ud, const char *message, int tocont) {
  lua_State *state = (lua_State *)ud;
  fputs(message, stderr);
  if (tocont)
    lua_setwarnf(state, rivetlua_warnfcont_b6, state);
  else {
    fputc('\n', stderr);
    lua_setwarnf(state, rivetlua_warnfon_b6, state);
  }
}

static void rivetlua_warnfon_b6(void *ud, const char *message, int tocont) {
  if (rivetlua_warncontrol_b6((lua_State *)ud, message, tocont)) return;
  fputs("Lua warning: ", stderr);
  rivetlua_warnfcont_b6(ud, message, tocont);
}

void rivetlua_capi_default_warning_install_b6(lua_State *state) {
#ifdef RV_LUA55_B2
  lua_setwarnf(state, rivetlua_warnfon_b6, state);
#else
  lua_setwarnf(state, rivetlua_warnfoff_b6, state);
#endif
}

/* 兩版官方 lauxlib.c 的預設 panic：只在純 C frame 讀取 error 並輸出。 */
static int rivetlua_a2_default_panic(lua_State *state) {
  const char *message = lua_type(state, -1) == LUA_TSTRING
      ? lua_tostring(state, -1) : "error object is not a string";
  if (message == NULL) message = "error object is not a string";
  fprintf(stderr, "PANIC: unprotected error in call to Lua API (%s)\n", message);
  return 0;
}

void rivetlua_capi_default_panic_install_a2(lua_State *state) {
  (void)lua_atpanic(state, rivetlua_a2_default_panic);
}
_Static_assert(RV_A1_ACTION_RETURN != RV_A1_ACTION_RAISE &&
                   RV_A1_ACTION_RAISE != RV_A1_ACTION_REJECT &&
                   RV_A1_OUT_NORMAL != RV_A1_OUT_RAISED &&
                   RV_A1_OUT_RAISED != RV_A1_OUT_REJECTED,
               "action/outcome tags must be distinct");

int32_t rivetlua_capi_trampoline_probe_a1(
    void *state, uint64_t generation, uint64_t token) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (state == NULL) return RV_A1_REJECT_NULL;
  if (top == NULL) return RV_A1_REJECT_NO_CHECKPOINT;
  if (top->state != state) return RV_A1_REJECT_WRONG_STATE;
  if (top->generation != generation) return RV_A1_REJECT_WRONG_GENERATION;
  if (top->token != token) return RV_A1_REJECT_STALE;
  return RV_A1_OK;
}

int32_t rivetlua_capi_rust_action_enter_a1(
    void *state, uint64_t generation, uint64_t token) {
  int32_t probe = rivetlua_capi_trampoline_probe_a1(state, generation, token);
  if (probe != RV_A1_OK) return probe;
  if (rivetlua_capi_top_a1->rust_action_active != 0) return RV_A1_REJECT_BUSY;
  rivetlua_capi_top_a1->rust_action_active = 1;
  return RV_A1_OK;
}

int32_t rivetlua_capi_rust_action_exit_a1(
    void *state, uint64_t generation, uint64_t token) {
  int32_t probe = rivetlua_capi_trampoline_probe_a1(state, generation, token);
  if (probe != RV_A1_OK) return probe;
  if (rivetlua_capi_top_a1->rust_action_active != 1) return RV_A1_REJECT_STALE;
  rivetlua_capi_top_a1->rust_action_active = 0;
  return RV_A1_OK;
}

/* B4 私有同步 driver；所有 Rust step 均先返回，C 才呼叫 C callback。 */
static int rivetlua_b7_close_drive(lua_State *state, size_t target,
                                   size_t trim_top, int initial_class,
                                   int nil_slot);
static int rivetlua_b10_invoke_step(
    lua_State *state, const rivetlua_capi_callback_step_b4 *step, int *count) {
  if (step->kind == 1 && step->function != NULL) {
    *count = step->function(state);
    return 1;
  }
  if (step->kind == 2 && step->hook != NULL) {
    lua_Debug ar = {0};
    ar.event = step->event;
    ar.currentline = step->currentline;
    ar.i_ci = step->token;
    step->hook(state, &ar);
    *count = 0;
    return 1;
  }
  return 0;
}
static int rivetlua_b4_call_drive(lua_State *state, int nargs,
                                 int nresults, int public_call,
                                 int yieldable_a5) {
  if (state == NULL) return -1;
  int frame_depth = rivetlua_capi_call_depth_b7(state);
  if (frame_depth < 0) return -1;
  rivetlua_capi_checkpoint_a1 checkpoint;
  int32_t entered = rivetlua_capi_checkpoint_enter_a1(
      state, &checkpoint.generation, &checkpoint.token,
      &checkpoint.previous_state_token);
  if (entered != RV_A1_OK) return -1;
  checkpoint.state = state;
  checkpoint.previous = rivetlua_capi_top_a1;
  volatile int32_t raised_status = 0;
  checkpoint.raised_status = &raised_status;
  checkpoint.rust_action_active = 0;
  checkpoint.yieldable_a5 = yieldable_a5 != 0;
  rivetlua_capi_top_a1 = &checkpoint;
  int result = -1;
  volatile int first = 1;
  /* A1 checkpoint 的跳轉目標仍在此純 C frame，絕不跨越 Rust frame。 */
  for (;;) {
    rivetlua_capi_callback_step_b4 step;
    if (setjmp(checkpoint.jump) == 0) {
      if (!first) break;
      first = 0;
      checkpoint.rust_action_active = 1;
      step = public_call
          ? rivetlua_capi_call_prepare_a2(state, nargs, nresults)
          : rivetlua_capi_call_prepare_b4(state, nargs, nresults);
      checkpoint.rust_action_active = 0;
    } else {
      checkpoint.rust_action_active = 0;
      if (rivetlua_capi_call_depth_b7(state) <= frame_depth) break;
      size_t trim_top = (size_t)lua_gettop(state);
      int error_class = rivetlua_capi_close_capture_error_b7(state, trim_top);
      if (error_class <= 0) break;
      (void)rivetlua_b7_close_drive(state, 0, trim_top, error_class, 0);
      if (!public_call) break;
      checkpoint.rust_action_active = 1;
      step = rivetlua_capi_call_resume_error_a2(state, nresults);
      checkpoint.rust_action_active = 0;
    }
    while (step.kind == 1 || step.kind == 2) {
      int count = 0;
      if (!rivetlua_b10_invoke_step(state, &step, &count)) break;
      int close_status = rivetlua_b7_close_drive(
          state, 0, (size_t)lua_gettop(state), 0, 0);
      if (close_status != 0 && !public_call) break;
      checkpoint.rust_action_active = 1;
      step = close_status == 0
          ? (public_call
                ? rivetlua_capi_call_resume_a2(state, count, nresults)
                : rivetlua_capi_call_resume_b4(state, count, nresults))
          : rivetlua_capi_call_resume_error_a2(state, nresults);
      checkpoint.rust_action_active = 0;
    }
    if (step.kind == 0) result = 0;
    break;
  }
  if (result != 0) {
    checkpoint.rust_action_active = 1;
    (void)rivetlua_capi_call_abort_to_b7(state, frame_depth);
  }
  checkpoint.rust_action_active = 0;
  rivetlua_capi_top_a1 = checkpoint.previous;
  int32_t exited = rivetlua_capi_checkpoint_exit_a1(
      state, checkpoint.generation, checkpoint.token,
      checkpoint.previous_state_token);
  if (exited != RV_A1_OK) return -1;
  return result;
}

int rivetlua_capi_call_b4(lua_State *state, int nargs, int nresults) {
  return rivetlua_b4_call_drive(state, nargs, nresults, 0, 0);
}

static int rivetlua_a2_call_drive(lua_State *state, int nargs, int nresults,
                                 int yieldable_a5) {
  return rivetlua_b4_call_drive(state, nargs, nresults, 1, yieldable_a5);
}

/* B5：同一 operation 的 callback、pending 與 stack 發布都留在純 C checkpoint。 */
static int rivetlua_b5_operation_drive(
    lua_State *state, int kind, int operation, int left, int right, int count,
    int *published) {
  if (state == NULL || published == NULL) return -RV_A1_ERROR_LUA;
  int depth = rivetlua_capi_operation_depth_b5(state);
  if (depth < 0) return -RV_A1_ERROR_LUA;
  rivetlua_capi_checkpoint_a1 checkpoint;
  int32_t entered = rivetlua_capi_checkpoint_enter_a1(
      state, &checkpoint.generation, &checkpoint.token,
      &checkpoint.previous_state_token);
  if (entered != RV_A1_OK) return -RV_A1_ERROR_ALLOCATION;
  checkpoint.state = state;
  checkpoint.previous = rivetlua_capi_top_a1;
  volatile int32_t raised_status = 0;
  checkpoint.raised_status = &raised_status;
  checkpoint.rust_action_active = 0;
  checkpoint.yieldable_a5 = 0;
  rivetlua_capi_top_a1 = &checkpoint;
  int status = -RV_A1_ERROR_LUA;
  *published = 0;
  /* callback 只在 Rust step 完整返回且 guard 清零後呼叫。 */
  if (setjmp(checkpoint.jump) == 0) {
    checkpoint.rust_action_active = 1;
    rivetlua_capi_callback_step_b4 step =
        rivetlua_capi_operation_prepare_b5(
            state, kind, operation, left, right, count);
    checkpoint.rust_action_active = 0;
    while (step.kind == 1 || step.kind == 2) {
      int returned = 0;
      if (!rivetlua_b10_invoke_step(state, &step, &returned)) break;
      int close_status = rivetlua_b7_close_drive(
          state, 0, (size_t)lua_gettop(state), 0, 0);
      if (close_status != 0) {
        status = close_status;
        break;
      }
      checkpoint.rust_action_active = 1;
      step = rivetlua_capi_operation_resume_b5(state, returned);
      checkpoint.rust_action_active = 0;
    }
    if (step.kind == 0) {
      *published = step.value;
      status = 0;
    } else if (step.kind < 0 && step.value > 0) {
      status = -step.value;
    }
  } else if (raised_status != 0) {
    status = -raised_status;
    if (rivetlua_capi_operation_depth_b5(state) > depth) {
      size_t trim_top = (size_t)lua_gettop(state);
      int error_class = rivetlua_capi_close_capture_error_b7(state, trim_top);
      if (error_class > 0)
        status = rivetlua_b7_close_drive(
            state, 0, trim_top, error_class, 0);
    }
  }
  if (status != 0) {
    checkpoint.rust_action_active = 1;
    (void)rivetlua_capi_pending_cancel_a1(
        state, checkpoint.generation, checkpoint.token);
    (void)rivetlua_capi_operation_abort_to_b5(state, depth);
    checkpoint.rust_action_active = 0;
  }
  rivetlua_capi_top_a1 = checkpoint.previous;
  int32_t exited = rivetlua_capi_checkpoint_exit_a1(
      state, checkpoint.generation, checkpoint.token,
      checkpoint.previous_state_token);
  if (exited != RV_A1_OK) return -RV_A1_ERROR_LUA;
  return status;
}

static void rivetlua_b5_operation_raise_message(
    lua_State *state, int status, int message) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (top == NULL || top->state != state || top->rust_action_active != 0)
    abort();
  int class_code = status < 0 ? -status : RV_A1_ERROR_LUA;
  rivetlua_capi_strict_result_b2 action = rivetlua_capi_operation_error_b5(
      state, top->generation, top->token, class_code, message);
  (void)rivetlua_b2_finish(state, top->generation, top->token, action);
  abort();
}

static void rivetlua_b5_operation_raise(lua_State *state, int status) {
  rivetlua_b5_operation_raise_message(state, status, 0);
}

/* B7：錯誤值先暫存為 overlay root；每次 close handler 返回後才換成新的錯誤。 */
static int rivetlua_b7_capture_or_synthesize(lua_State *state,
                                             size_t trim_top, int error_class,
                                             int message) {
  int captured = rivetlua_capi_close_capture_error_b7(state, trim_top);
  if (captured > 0) return captured;
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (top == NULL || top->state != state || top->rust_action_active != 0)
    abort();
  rivetlua_capi_strict_result_b2 prepared = rivetlua_capi_operation_error_b5(
      state, top->generation, top->token, error_class, message);
  if (prepared.kind != RV_A1_ACTION_RAISE) abort();
  captured = rivetlua_capi_close_capture_error_b7(state, trim_top);
  if (captured <= 0) abort();
  return captured;
}

static int rivetlua_b7_close_drive(lua_State *state, size_t target,
                                   size_t trim_top, int initial_class,
                                   int nil_slot) {
  int error_class = initial_class;
  size_t error_position = initial_class > 0 ? (size_t)lua_gettop(state) : 0;
  int closed = 0;
  for (;;) {
    rivetlua_capi_close_step_b7 step = rivetlua_capi_close_next_b7(
        state, target, error_position, nil_slot);
    if (step.kind == 0) break;
    if (step.kind < 0) {
      error_class = rivetlua_b7_capture_or_synthesize(
          state, (size_t)lua_gettop(state), step.value, 3);
      error_position = (size_t)lua_gettop(state);
      if (nil_slot) break;
      continue;
    }
    closed++;
    if (step.kind == 2) {
      size_t call_top = (size_t)lua_gettop(state) - (size_t)step.value - 1;
      if (rivetlua_capi_call_b4(state, step.value, 0) != 0) {
        error_class = rivetlua_b7_capture_or_synthesize(
            state, call_top, RV_A1_ERROR_LUA, 3);
        error_position = (size_t)lua_gettop(state);
      }
    }
    if (nil_slot) break;
  }
  if (nil_slot && closed == 0 && error_class == 0) {
    error_class = rivetlua_b7_capture_or_synthesize(
        state, (size_t)lua_gettop(state), RV_A1_ERROR_LUA, 3);
    error_position = (size_t)lua_gettop(state);
  }
  if (error_class > 0) {
    rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
    if (top == NULL || top->state != state || error_position == 0 ||
        rivetlua_capi_close_finalize_error_b7(
            state, trim_top, top->token, error_class) != 1)
      abort();
    return -error_class;
  }
  return 0;
}

static int rivetlua_b11_public_status(int internal) {
  int code = internal < 0 ? -internal : internal;
  return code == RV_A1_ERROR_ALLOCATION ? LUA_ERRMEM : LUA_ERRRUN;
}

#if LUA_VERSION_NUM >= 505
/* B11 固定 C fixture 的私有 resume driver；self-close 只跳回此純 C frame。 */
int rivetlua_capi_test_resume_b11(lua_State *state) {
  if (state == NULL || rivetlua_capi_selfclose_resume_b11 != NULL) return LUA_ERRRUN;
  int frame_depth = rivetlua_capi_call_depth_b7(state);
  if (frame_depth < 0) return LUA_ERRRUN;
  rivetlua_capi_checkpoint_a1 checkpoint;
  if (rivetlua_capi_checkpoint_enter_a1(
          state, &checkpoint.generation, &checkpoint.token,
          &checkpoint.previous_state_token) != RV_A1_OK)
    return LUA_ERRMEM;
  checkpoint.state = state;
  checkpoint.previous = rivetlua_capi_top_a1;
  volatile int32_t raised_status = 0;
  volatile int selfclose_status = -1;
  checkpoint.raised_status = &raised_status;
  checkpoint.rust_action_active = 0;
  checkpoint.yieldable_a5 = 0;
  rivetlua_capi_top_a1 = &checkpoint;
  rivetlua_capi_selfclose_resume_b11 = &checkpoint;
  rivetlua_capi_selfclose_status_b11 = &selfclose_status;
  int result = LUA_ERRRUN;
  if (setjmp(checkpoint.jump) == 0) {
    checkpoint.rust_action_active = 1;
    rivetlua_capi_callback_step_b4 step =
        rivetlua_capi_test_resume_prepare_b11(state);
    checkpoint.rust_action_active = 0;
    while (step.kind == 1 || step.kind == 2) {
      int count = 0;
      if (!rivetlua_b10_invoke_step(state, &step, &count)) break;
      if (rivetlua_b7_close_drive(state, 0, (size_t)lua_gettop(state), 0, 0)
          != 0) break;
      checkpoint.rust_action_active = 1;
      step = rivetlua_capi_call_resume_b4(state, count, LUA_MULTRET);
      checkpoint.rust_action_active = 0;
    }
    if (step.kind == 0) result = LUA_OK;
    else if (step.kind < 0) result = rivetlua_b11_public_status(step.value);
  } else if (selfclose_status >= 0) {
    result = selfclose_status;
  } else if (raised_status != 0) {
    result = rivetlua_b11_public_status(raised_status);
  }
  if (result != LUA_OK) {
    checkpoint.rust_action_active = 1;
    (void)rivetlua_capi_call_abort_to_b7(state, frame_depth);
    checkpoint.rust_action_active = 0;
  }
  rivetlua_capi_selfclose_resume_b11 = NULL;
  rivetlua_capi_selfclose_status_b11 = NULL;
  rivetlua_capi_top_a1 = checkpoint.previous;
  if (rivetlua_capi_checkpoint_exit_a1(
          state, checkpoint.generation, checkpoint.token,
          checkpoint.previous_state_token) != RV_A1_OK)
    return LUA_ERRRUN;
  return result;
}

static void rivetlua_b11_selfclose_throw(lua_State *state, int status) {
  rivetlua_capi_checkpoint_a1 *target = rivetlua_capi_selfclose_resume_b11;
  if (target == NULL || target->state != state ||
      rivetlua_capi_selfclose_status_b11 == NULL) abort();
  *rivetlua_capi_selfclose_status_b11 = status;
  longjmp(target->jump, 1);
}
#endif

/* 公開 reset 的 callback 與 longjmp 都在此純 C checkpoint 內完成。 */
int lua_closethread(lua_State *state, lua_State *from) {
  int admission = rivetlua_capi_reset_preflight_b11(state, from);
#if LUA_VERSION_NUM >= 505
  int selfclose = state == from && rivetlua_capi_selfclose_resume_b11 != NULL &&
      rivetlua_capi_top_a1 == rivetlua_capi_selfclose_resume_b11;
  if (selfclose) admission = rivetlua_capi_selfclose_preflight_b11(state);
#endif
  if (admission != LUA_OK) {
#if LUA_VERSION_NUM >= 505
    if (selfclose) rivetlua_b11_selfclose_throw(state, admission);
#endif
    return admission;
  }
  rivetlua_capi_checkpoint_a1 checkpoint;
  if (rivetlua_capi_checkpoint_enter_a1(
          state, &checkpoint.generation, &checkpoint.token,
          &checkpoint.previous_state_token) != RV_A1_OK)
#if LUA_VERSION_NUM >= 505
  {
    (void)rivetlua_capi_reset_cancel_b11(state);
    if (selfclose) rivetlua_b11_selfclose_throw(state, LUA_ERRMEM);
    return LUA_ERRMEM;
  }
#else
  {
    (void)rivetlua_capi_reset_cancel_b11(state);
    return LUA_ERRMEM;
  }
#endif
  checkpoint.state = state;
  checkpoint.previous = rivetlua_capi_top_a1;
  volatile int32_t raised_status = 0;
  checkpoint.raised_status = &raised_status;
  checkpoint.rust_action_active = 0;
  checkpoint.yieldable_a5 = 0;
  rivetlua_capi_top_a1 = &checkpoint;
  int frame_depth = rivetlua_capi_call_depth_b7(state);
  int overlay_status = LUA_OK;
  volatile int latest_error_status = LUA_OK;
  int status = LUA_ERRRUN;
  checkpoint.rust_action_active = 1;
  int start_status = rivetlua_capi_reset_start_a5(state);
  checkpoint.rust_action_active = 0;
  if (start_status != LUA_OK) {
    status = start_status;
    goto reset_exit_b11;
  }
  int close_result = rivetlua_b7_close_drive(
      state, 0, 0, 0, 0);
  if (close_result != 0) {
    int32_t error_class = 0;
    if (rivetlua_capi_error_consume_a1(state, &error_class) != RV_A1_OK)
      goto reset_exit_b11;
    overlay_status = rivetlua_b11_public_status(error_class);
  }
#if LUA_VERSION_NUM >= 505
  if (selfclose) {
    checkpoint.rust_action_active = 1;
    int restored = rivetlua_capi_selfclose_restore_b11(state, overlay_status);
    checkpoint.rust_action_active = 0;
    if (restored != LUA_OK) {
      status = restored;
      goto reset_exit_b11;
    }
    frame_depth = rivetlua_capi_call_depth_b7(state);
    int original_class = overlay_status == LUA_OK ? 0 :
        (overlay_status == LUA_ERRMEM ? RV_A1_ERROR_ALLOCATION : RV_A1_ERROR_LUA);
    close_result = rivetlua_b7_close_drive(state, 0, 0, original_class, 0);
    if (close_result != 0) {
      int32_t error_class = 0;
      if (rivetlua_capi_error_consume_a1(state, &error_class) != RV_A1_OK)
        goto reset_exit_b11;
      overlay_status = rivetlua_b11_public_status(error_class);
    }
  }
#endif
  latest_error_status = overlay_status;
  checkpoint.rust_action_active = 1;
  rivetlua_capi_callback_step_b4 step =
#if LUA_VERSION_NUM >= 505
      selfclose ? rivetlua_capi_selfclose_prepare_b11(state, overlay_status) :
#endif
      rivetlua_capi_reset_prepare_b11(state, overlay_status);
  checkpoint.rust_action_active = 0;
  while (step.kind == 1 || step.kind == 2 || step.kind == 3) {
    if (step.kind == 3) {
      int prior_status = latest_error_status != LUA_OK ? latest_error_status : step.value;
      int original_class = prior_status == LUA_OK ? 0 :
          (prior_status == LUA_ERRMEM ? RV_A1_ERROR_ALLOCATION : RV_A1_ERROR_LUA);
      close_result = rivetlua_b7_close_drive(state, 0, 0, original_class, 0);
      int boundary_status = LUA_OK;
      if (close_result != 0) {
        int32_t error_class = 0;
        if (rivetlua_capi_error_consume_a1(state, &error_class) != RV_A1_OK)
          goto reset_exit_b11;
        boundary_status = rivetlua_b11_public_status(error_class);
      }
      latest_error_status = boundary_status;
      checkpoint.rust_action_active = 1;
      step = rivetlua_capi_reset_resume_boundary_a5(state, boundary_status);
      checkpoint.rust_action_active = 0;
      continue;
    }
    volatile int callback_failed = 0;
    volatile int count = 0;
    if (setjmp(checkpoint.jump) == 0) {
      int invoked_count = 0;
      if (!rivetlua_b10_invoke_step(state, &step, &invoked_count)) {
        callback_failed = 1;
        latest_error_status = LUA_ERRRUN;
      }
      count = invoked_count;
      int close_status = rivetlua_b7_close_drive(
          state, 0, (size_t)lua_gettop(state), 0, 0);
      if (close_status != 0) {
        callback_failed = 1;
        latest_error_status = rivetlua_b11_public_status(close_status);
      }
    } else {
      size_t trim_top = (size_t)lua_gettop(state);
      int error_class = rivetlua_capi_close_capture_error_b7(state, trim_top);
      if (error_class > 0) {
        int close_status = rivetlua_b7_close_drive(
            state, 0, trim_top, error_class, 0);
        latest_error_status = rivetlua_b11_public_status(
            close_status != 0 ? close_status : error_class);
      } else {
        latest_error_status = LUA_ERRRUN;
      }
      callback_failed = 1;
    }
    checkpoint.rust_action_active = 1;
    step = callback_failed
        ? rivetlua_capi_reset_resume_error_b11(state)
        : rivetlua_capi_call_resume_b4(state, (int)count, LUA_MULTRET);
    checkpoint.rust_action_active = 0;
  }
  if (step.kind == 0) {
    checkpoint.rust_action_active = 1;
    status = rivetlua_capi_reset_finish_b11(state, latest_error_status);
    checkpoint.rust_action_active = 0;
  } else {
    status = rivetlua_b11_public_status(step.value);
  }
reset_exit_b11:
  if (status != LUA_OK && frame_depth >= 0) {
    checkpoint.rust_action_active = 1;
    (void)rivetlua_capi_pending_cancel_a1(
        state, checkpoint.generation, checkpoint.token);
    (void)rivetlua_capi_call_abort_to_b7(state, frame_depth);
    checkpoint.rust_action_active = 0;
  }
  checkpoint.rust_action_active = 1;
  (void)rivetlua_capi_reset_cancel_b11(state);
  checkpoint.rust_action_active = 0;
  rivetlua_capi_top_a1 = checkpoint.previous;
  if (rivetlua_capi_reset_checkpoint_exit_a5(
          state, checkpoint.generation, checkpoint.token,
          checkpoint.previous_state_token) != RV_A1_OK)
    status = LUA_ERRRUN;
#if LUA_VERSION_NUM >= 505
  if (selfclose) rivetlua_b11_selfclose_throw(state, status);
#endif
  return status;
}

#if LUA_VERSION_NUM < 505
int lua_resetthread(lua_State *state) {
  return lua_closethread(state, NULL);
}
#endif

/* C-owned child pointer 一律解析到 main；finalizer 可重入前 state 保持 live。 */
static int rivetlua_b11_close_drive(lua_State *state) {
  lua_State *main_state = rivetlua_capi_close_main_b11(state);
  if (main_state == NULL) return 0;
  rivetlua_capi_checkpoint_a1 checkpoint;
  if (rivetlua_capi_checkpoint_enter_a1(
          main_state, &checkpoint.generation, &checkpoint.token,
          &checkpoint.previous_state_token) != RV_A1_OK)
    return 0;
  checkpoint.state = main_state;
  checkpoint.previous = rivetlua_capi_top_a1;
  volatile int32_t raised_status = 0;
  checkpoint.raised_status = &raised_status;
  checkpoint.rust_action_active = 0;
  checkpoint.yieldable_a5 = 0;
  rivetlua_capi_top_a1 = &checkpoint;
  int frame_depth = rivetlua_capi_call_depth_b7(main_state);
  int complete = 1;
  if (rivetlua_b7_close_drive(main_state, 0, 0, 0, 0) != 0) {
    int32_t error_class = 0;
    if (rivetlua_capi_error_consume_a1(main_state, &error_class) != RV_A1_OK ||
        rivetlua_capi_settop_direct_b7(main_state, 0) != 1)
      complete = 0;
  }
  while (complete) {
    checkpoint.rust_action_active = 1;
    rivetlua_capi_callback_step_b4 step =
        rivetlua_capi_shutdown_prepare_b11(main_state);
    checkpoint.rust_action_active = 0;
    int external_callback_seen = 0;
    while (step.kind == 1 || step.kind == 2) {
      external_callback_seen = 1;
      volatile int callback_failed = 0;
      volatile int count = 0;
      if (setjmp(checkpoint.jump) == 0) {
        int invoked_count = 0;
        if (!rivetlua_b10_invoke_step(main_state, &step, &invoked_count))
          callback_failed = 1;
        count = invoked_count;
        if (rivetlua_b7_close_drive(main_state, 0,
                                   (size_t)lua_gettop(main_state), 0, 0) != 0)
          callback_failed = 1;
      } else {
        size_t trim_top = (size_t)lua_gettop(main_state);
        int error_class = rivetlua_capi_close_capture_error_b7(main_state, trim_top);
        if (error_class > 0)
          (void)rivetlua_b7_close_drive(
              main_state, 0, trim_top, error_class, 0);
        callback_failed = 1;
      }
      checkpoint.rust_action_active = 1;
      step = callback_failed
          ? rivetlua_capi_gc_resume_error_b8(main_state)
          : rivetlua_capi_call_resume_b4(main_state, (int)count, 0);
      checkpoint.rust_action_active = 0;
    }
    if (step.kind < 0) complete = 0;
    else if (step.kind == 0) {
      /* callback 或同步 drain 有進展時再掃描；只有無工作的一輪才可 drop。 */
      if (external_callback_seen || step.value != 0) continue;
      break;
    } else complete = 0;
  }
  if (!complete && frame_depth >= 0) {
    checkpoint.rust_action_active = 1;
    (void)rivetlua_capi_pending_cancel_a1(
        main_state, checkpoint.generation, checkpoint.token);
    (void)rivetlua_capi_call_abort_to_b7(main_state, frame_depth);
    checkpoint.rust_action_active = 0;
  }
  rivetlua_capi_top_a1 = checkpoint.previous;
  if (rivetlua_capi_checkpoint_exit_a1(
          main_state, checkpoint.generation, checkpoint.token,
          checkpoint.previous_state_token) != RV_A1_OK)
    return 0;
  if (complete) return rivetlua_capi_close_drop_b11(main_state) == 1;
  return 0;
}

void lua_close(lua_State *state) {
  (void)rivetlua_b11_close_drive(state);
}

/* Rust-owned close 只多取完成狀態；public void ABI 與同一 coordinator 不變。 */
int rivetlua_capi_close_status_b2(lua_State *state) {
  return rivetlua_b11_close_drive(state);
}

static void rivetlua_b7_raise_existing(lua_State *state, int status) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  int error_class = status < 0 ? -status : RV_A1_ERROR_LUA;
  if (top != NULL && top->state == state && top->rust_action_active == 0 &&
      rivetlua_capi_pending_matches_a1(
          state, top->generation, top->token, error_class) == RV_A1_OK) {
    *top->raised_status = error_class;
    longjmp(top->jump, 1);
  }
  abort();
}

/* A4a：沿現有 parked operation step 驅動表存取；所有 C callback 前 Rust 借用已釋放。 */
static void rivetlua_a4_raise(lua_State *state, int status) {
  int error_class = status < 0 ? -status : RV_A1_ERROR_LUA;
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (top != NULL && top->state == state && top->rust_action_active == 0) {
    if (rivetlua_capi_pending_matches_a1(
            state, top->generation, top->token, error_class) == RV_A1_OK)
      rivetlua_b7_raise_existing(state, -error_class);
    rivetlua_b5_operation_raise(state, -error_class);
  }
  (void)rivetlua_capi_generic_panic_error_a3(state);
  lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
  if (panicf != NULL) (void)panicf(state);
  abort();
}

static void rivetlua_a4_table_drive(lua_State *state, int index, int setter) {
  int depth = rivetlua_capi_operation_depth_b5(state);
  if (depth < 0) rivetlua_a4_raise(state, -RV_A1_ERROR_LUA);
  rivetlua_capi_callback_step_b4 step =
      rivetlua_capi_table_prepare_a4a(state, index, setter);
  while (step.kind == 1 || step.kind == 2) {
    int returned = 0;
    if (!rivetlua_b10_invoke_step(state, &step, &returned)) break;
    int close_status = rivetlua_b7_close_drive(
        state, 0, (size_t)lua_gettop(state), 0, 0);
    if (close_status != 0) {
      if (rivetlua_capi_operation_abort_to_b5(state, depth) != 0) abort();
      rivetlua_a4_raise(state, close_status);
    }
    step = rivetlua_capi_table_resume_a4a(state, returned, setter);
  }
  if (step.kind == 0 && step.value == 1) return;
  if (rivetlua_capi_operation_abort_to_b5(state, depth) != 0) abort();
  rivetlua_a4_raise(state,
      -(step.kind < 0 && step.value > 0 ? step.value : RV_A1_ERROR_LUA));
}

static void rivetlua_a4_push_name(lua_State *state, const char *name) {
  if (name == NULL) rivetlua_a4_raise(state, -RV_A1_ERROR_LUA);
  if (lua_pushstring(state, name) == NULL)
    rivetlua_a4_raise(state, -RV_A1_ERROR_ALLOCATION);
}

/* auxiliary 組合需要可回報配置失敗的 push；獨立 public push 符號維持原契約。 */
static void rivetlua_a4_aux_push(lua_State *state, int operation, int index,
                                lua_CFunction function, int nup) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  rivetlua_capi_strict_result_b2 result = rivetlua_capi_aux_push_a4a(
      state, generation, token, operation, index, function, nup);
  if (result.kind == RV_A1_ACTION_RETURN) return;
  if (result.kind == RV_A1_ACTION_RAISE)
    (void)rivetlua_b2_finish(state, generation, token, result);
  if (top == NULL) {
    (void)rivetlua_capi_generic_panic_error_a3(state);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
  }
  abort();
}

int lua_gettable(lua_State *state, int index) {
  rivetlua_a4_table_drive(state, index, 0);
  return lua_type(state, -1);
}

int lua_getfield(lua_State *state, int index, const char *name) {
  index = lua_absindex(state, index);
  rivetlua_a4_push_name(state, name);
  return lua_gettable(state, index);
}

int lua_geti(lua_State *state, int index, lua_Integer key) {
  index = lua_absindex(state, index);
  lua_pushinteger(state, key);
  return lua_gettable(state, index);
}

int lua_getglobal(lua_State *state, const char *name) {
  int globals_tag = lua_rawgeti(state, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
  if (globals_tag != LUA_TTABLE) {
    if (globals_tag >= LUA_TNIL) {
      lua_pop(state, 1);
      rivetlua_a4_raise(state, -RV_A1_ERROR_LUA);
    }
    rivetlua_a4_raise(state, -RV_A1_ERROR_ALLOCATION);
  }
  int tag = lua_getfield(state, -1, name);
  lua_remove(state, -2);
  return tag;
}

void lua_settable(lua_State *state, int index) {
  rivetlua_a4_table_drive(state, index, 1);
}

void lua_setfield(lua_State *state, int index, const char *name) {
  index = lua_absindex(state, index);
  rivetlua_a4_push_name(state, name);
  lua_insert(state, -2);
  lua_settable(state, index);
}

void lua_seti(lua_State *state, int index, lua_Integer key) {
  index = lua_absindex(state, index);
  lua_pushinteger(state, key);
  lua_insert(state, -2);
  lua_settable(state, index);
}

void lua_setglobal(lua_State *state, const char *name) {
  int globals_tag = lua_rawgeti(state, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS);
  if (globals_tag != LUA_TTABLE) {
    if (globals_tag >= LUA_TNIL) {
      lua_pop(state, 1);
      rivetlua_a4_raise(state, -RV_A1_ERROR_LUA);
    }
    rivetlua_a4_raise(state, -RV_A1_ERROR_ALLOCATION);
  }
  lua_insert(state, -2);
  lua_setfield(state, -2, name);
  lua_pop(state, 1);
}

int luaL_callmeta(lua_State *state, int index, const char *event) {
  index = lua_absindex(state, index);
  if (luaL_getmetafield(state, index, event) == LUA_TNIL) return 0;
  rivetlua_a4_aux_push(state, 1, index, NULL, 0);
  lua_call(state, 1, 1);
  return 1;
}

int luaL_getsubtable(lua_State *state, int index, const char *name) {
  index = lua_absindex(state, index);
  int tag = lua_getfield(state, index, name);
  if (tag == LUA_TTABLE) return 1;
  lua_pop(state, 1);
  rivetlua_a4_aux_push(state, 3, 0, NULL, 0);
  rivetlua_a4_aux_push(state, 1, -1, NULL, 0);
  lua_setfield(state, index, name);
  return 0;
}

void luaL_requiref(lua_State *state, const char *modname,
                   lua_CFunction openf, int glb) {
  luaL_getsubtable(state, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  lua_getfield(state, -1, modname);
  if (!lua_toboolean(state, -1)) {
    lua_pop(state, 1);
    lua_pushcfunction(state, openf);
    lua_pushstring(state, modname);
    lua_call(state, 1, 1);
    lua_pushvalue(state, -1);
    lua_setfield(state, -3, modname);
  }
  lua_remove(state, -2);
  if (glb) {
    lua_pushvalue(state, -1);
    lua_setglobal(state, modname);
  }
}

typedef struct rivetlua_b2_requiref_context {
  const char *name;
  lua_CFunction opener;
  int global;
  int status;
  struct rivetlua_b2_requiref_context *previous;
} rivetlua_b2_requiref_context;

static _Thread_local rivetlua_b2_requiref_context *rivetlua_b2_requiref_top;

static int rivetlua_b2_requiref_body(lua_State *state) {
  rivetlua_b2_requiref_context *context = rivetlua_b2_requiref_top;
  if (context == NULL) return luaL_error(state, "requiref context unavailable");
  luaL_requiref(state, context->name, context->opener, context->global);
  return 1;
}

static rivetlua_capi_action_a1 rivetlua_b2_requiref_action(
    void *opaque, uint64_t generation, uint64_t token, void *context) {
  (void)generation;
  (void)token;
  lua_State *state = (lua_State *)opaque;
  rivetlua_b2_requiref_context *request = (rivetlua_b2_requiref_context *)context;
  lua_pushcfunction(state, rivetlua_b2_requiref_body);
  request->status = lua_pcall(state, 0, 1, 0);
  return (rivetlua_capi_action_a1){RV_A1_ACTION_RETURN, 0};
}

/* Rust 宿主入口只讀取 status；opener 的所有跳轉均止於純 C checkpoint。 */
int rivetlua_capi_requiref_protected_b2(lua_State *state, const char *name,
                                         lua_CFunction opener, int global) {
  if (state == NULL || name == NULL || opener == NULL) return -1;
  rivetlua_b2_requiref_context request = {
      name, opener, global, LUA_ERRRUN, rivetlua_b2_requiref_top};
  rivetlua_b2_requiref_top = &request;
  rivetlua_capi_outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, rivetlua_b2_requiref_action, &request);
  rivetlua_b2_requiref_top = request.previous;
  if (outcome.kind == RV_A1_OUT_NORMAL) return request.status;
  if (outcome.kind != RV_A1_OUT_RAISED) return -1;
  int32_t error_class = 0;
  if (rivetlua_capi_error_consume_a1(state, &error_class) != RV_A1_OK) return -1;
  return error_class == RV_A1_ERROR_ALLOCATION ? LUA_ERRMEM : LUA_ERRRUN;
}

void luaL_setfuncs(lua_State *state, const luaL_Reg *entries, int nup) {
  luaL_checkstack(state, nup, "too many upvalues");
  if (entries == NULL || nup < 0) rivetlua_a4_raise(state, -RV_A1_ERROR_LUA);
  for (; entries->name != NULL; entries++) {
    if (entries->func == NULL) {
      lua_pushboolean(state, 0);
    } else {
      for (int i = 0; i < nup; i++)
        rivetlua_a4_aux_push(state, 1, -nup, NULL, 0);
      rivetlua_a4_aux_push(state, 2, 0, entries->func, nup);
    }
    lua_setfield(state, -(nup + 2), entries->name);
  }
  lua_pop(state, nup);
}

/* 測試專用 C checkpoint：複製 caller stack 後於 C callback 執行公開同步 API。 */
extern uint64_t rivetlua_capi_test_inject_offset_a4a(lua_State *state,
                                                     uint64_t offset);
extern uint64_t rivetlua_capi_test_current_ordinal_a4a(lua_State *state);
extern int rivetlua_capi_test_inject_point_a4a(lua_State *state, int code);
typedef struct {
  int operation;
  int index;
  const char *name;
  lua_Integer key;
  const luaL_Reg *entries;
  int nup;
  int inject_offset;
  uint64_t injection_start;
  int result;
} rivetlua_a4_test_context;

static _Thread_local rivetlua_a4_test_context *rivetlua_a4_test_active;

static int rivetlua_a4_test_attempts(lua_State *state,
                                    rivetlua_a4_test_context *ctx) {
  if (ctx->inject_offset != -1000) return 1;
  uint64_t end = rivetlua_capi_test_current_ordinal_a4a(state);
  if (end < ctx->injection_start || end - ctx->injection_start > INT32_MAX)
    return 0;
  ctx->result = (int)(end - ctx->injection_start);
  return 1;
}

static int rivetlua_a4_test_public_callback(lua_State *state) {
  rivetlua_a4_test_context *ctx = rivetlua_a4_test_active;
  if (ctx == NULL) return luaL_error(state, "missing A4a test context");
  if (ctx->inject_offset >= 0) {
    ctx->injection_start = rivetlua_capi_test_inject_offset_a4a(
        state, (uint64_t)ctx->inject_offset);
    if (ctx->injection_start == 0)
      return luaL_error(state, "A4a test injection failed");
  } else if (ctx->inject_offset == -1000) {
    ctx->injection_start = rivetlua_capi_test_current_ordinal_a4a(state);
    if (ctx->injection_start == 0)
      return luaL_error(state, "A4a test ordinal snapshot failed");
  } else if (ctx->inject_offset <= -2) {
    int injected = rivetlua_capi_test_inject_point_a4a(state, -ctx->inject_offset - 2);
    if (!injected)
      return luaL_error(state, "A4a test point injection failed");
  }
  switch (ctx->operation) {
    case 0: ctx->result = lua_gettable(state, ctx->index);
            return rivetlua_a4_test_attempts(state, ctx) ? 1 : luaL_error(state, "A4a test ordinal range failed");
    case 1: ctx->result = lua_getfield(state, ctx->index, ctx->name);
            return rivetlua_a4_test_attempts(state, ctx) ? 1 : luaL_error(state, "A4a test ordinal range failed");
    case 2: ctx->result = lua_geti(state, ctx->index, ctx->key);
            return rivetlua_a4_test_attempts(state, ctx) ? 1 : luaL_error(state, "A4a test ordinal range failed");
    case 3: ctx->result = lua_getglobal(state, ctx->name);
            return rivetlua_a4_test_attempts(state, ctx) ? 1 : luaL_error(state, "A4a test ordinal range failed");
    case 4: lua_settable(state, ctx->index);
            return rivetlua_a4_test_attempts(state, ctx) ? 0 : luaL_error(state, "A4a test ordinal range failed");
    case 5: lua_setfield(state, ctx->index, ctx->name);
            return rivetlua_a4_test_attempts(state, ctx) ? 0 : luaL_error(state, "A4a test ordinal range failed");
    case 6: lua_seti(state, ctx->index, ctx->key);
            return rivetlua_a4_test_attempts(state, ctx) ? 0 : luaL_error(state, "A4a test ordinal range failed");
    case 7: lua_setglobal(state, ctx->name);
            return rivetlua_a4_test_attempts(state, ctx) ? 0 : luaL_error(state, "A4a test ordinal range failed");
    case 8:
      ctx->result = luaL_getsubtable(state, ctx->index, ctx->name);
      return rivetlua_a4_test_attempts(state, ctx) ? 1 : luaL_error(state, "A4a test ordinal range failed");
    case 9:
      luaL_setfuncs(state, ctx->entries, ctx->nup);
      return rivetlua_a4_test_attempts(state, ctx) ? 0 : luaL_error(state, "A4a test ordinal range failed");
    default: return luaL_error(state, "invalid A4a test operation");
  }
}

/* 測試夾具先註冊其 callback，讓 failpoint ledger 僅量測待測操作。 */
void rivetlua_capi_test_prime_a4a(lua_State *state) {
  lua_pushcfunction(state, rivetlua_a4_test_public_callback);
  lua_pop(state, 1);
}

int rivetlua_capi_test_public_protected_a4a(
    lua_State *state, int operation, int index, const char *name,
    lua_Integer key, const luaL_Reg *entries, int nup, int inject_offset,
    uint64_t *injection_start) {
  rivetlua_a4_test_context ctx = {
      operation, index, name, key, entries, nup, inject_offset, 0, 0};
  rivetlua_a4_test_context *previous = rivetlua_a4_test_active;
  int original_top = lua_gettop(state);
  rivetlua_a4_test_active = &ctx;
  lua_pushcfunction(state, rivetlua_a4_test_public_callback);
  for (int index = 1; index <= original_top; index++) lua_pushvalue(state, index);
  int status = lua_pcall(state, original_top,
                         operation <= 3 || operation == 8 ? 1 : 0, 0);
  rivetlua_a4_test_active = previous;
  if (injection_start != NULL) *injection_start = ctx.injection_start;
  if (status != LUA_OK) {
    lua_pop(state, 1);
    return -status;
  }
  if (operation == 0) lua_remove(state, original_top);
  if (operation == 4) lua_settop(state, original_top - 2);
  if (operation >= 5 && operation <= 7)
    lua_settop(state, original_top - 1);
  if (operation == 9) lua_settop(state, original_top - nup);
  return ctx.result;
}

/* A4b 舊回歸測試的純 C 錯誤邊界；保留 caller 原本的 stack 與 root。 */
typedef struct {
  int operation;
  int index;
  int argument;
  lua_CFunction function;
  const char *name;
  int answer;
  int original_top;
} rivetlua_a4b_error_probe;

static rivetlua_capi_action_a1 rivetlua_a4b_error_action(
    void *opaque, uint64_t generation, uint64_t token, void *context) {
  (void)generation;
  (void)token;
  lua_State *state = (lua_State *)opaque;
  rivetlua_a4b_error_probe *probe = (rivetlua_a4b_error_probe *)context;
  probe->original_top = lua_gettop(state);
  switch (probe->operation) {
    case -1: break;
    case 0: lua_pushcclosure(state, probe->function, probe->argument); break;
    case 1: (void)lua_setupvalue(state, probe->index, probe->argument); break;
    case 2: lua_upvaluejoin(state, 1, 1, 3, 1); break;
    case 3: probe->answer = luaL_getmetafield(state, probe->index, probe->name); break;
    case 4: probe->answer = lua_getmetatable(state, probe->index); break;
    case 5: probe->answer = lua_setmetatable(state, probe->index); break;
    case 6: probe->answer = lua_getiuservalue(state, probe->index, probe->argument); break;
    case 7: probe->answer = lua_setiuservalue(state, probe->index, probe->argument); break;
    case 8: probe->answer = luaL_testudata(state, probe->index, probe->name) != NULL; break;
    case 9: probe->answer = luaL_ref(state, probe->index); break;
    case 10: luaL_unref(state, probe->index, probe->argument); break;
    case 11: lua_pushvalue(state, probe->index); break;
    case 12: lua_copy(state, probe->index, probe->argument); break;
    case 13: (void)luaL_checknumber(state, probe->index); break;
    case 14: (void)luaL_optnumber(state, probe->index, 9.0); break;
    case 15: (void)luaL_checkinteger(state, probe->index); break;
    case 16: (void)luaL_optinteger(state, probe->index, 9); break;
    case 17: (void)luaL_checklstring(state, probe->index, NULL); break;
    case 18: (void)luaL_optlstring(state, probe->index, "fallback", NULL); break;
    case 19: probe->answer = lua_getglobal(state, probe->name); break;
    case 20: lua_setglobal(state, probe->name); break;
    default: return (rivetlua_capi_action_a1){RV_A1_ACTION_REJECT, -1};
  }
  return (rivetlua_capi_action_a1){RV_A1_ACTION_RETURN, 0};
}

int rivetlua_capi_test_protected_error_a4b(lua_State *state, int operation,
                                          int index, int argument,
                                          lua_CFunction function) {
  rivetlua_a4b_error_probe probe = {operation, index, argument, function, NULL, 0, 0};
  rivetlua_capi_outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, rivetlua_a4b_error_action, &probe);
  if (outcome.kind == RV_A1_OUT_RAISED) {
    int32_t error_class = 0;
    if (rivetlua_capi_error_consume_a1(state, &error_class) != RV_A1_OK)
      return -2;
    lua_pop(state, 1);
    lua_settop(state, probe.original_top);
    return outcome.value;
  }
  if (outcome.kind == RV_A1_OUT_NORMAL) return 0;
  return -1;
}

int rivetlua_capi_test_protected_index_a4b(lua_State *state, int operation,
                                           int index, int argument,
                                           const char *name, int *answer) {
  rivetlua_a4b_error_probe probe = {operation, index, argument, NULL, name, 0, 0};
  rivetlua_capi_outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, rivetlua_a4b_error_action, &probe);
  if (outcome.kind == RV_A1_OUT_RAISED) {
    int32_t error_class = 0;
    if (rivetlua_capi_error_consume_a1(state, &error_class) != RV_A1_OK)
      return -2;
    lua_pop(state, 1);
    lua_settop(state, probe.original_top);
    return outcome.value;
  }
  if (outcome.kind == RV_A1_OUT_NORMAL) {
    if (answer != NULL) *answer = probe.answer;
    return 0;
  }
  return -1;
}

/* 邊界容量測試：在 stack 填滿之前先建立真正的 public pcall frame。 */
static int rivetlua_a4b_full_stack_getiuservalue(lua_State *state) {
  lua_settop(state, 1000000);
  (void)lua_getiuservalue(state, 1, 1);
  return 0;
}

static int rivetlua_a4b_full_stack_pushnil(lua_State *state) {
  lua_settop(state, 1000000);
  lua_pushnil(state);
  return 0;
}

static int rivetlua_a4b_full_stack_settop(lua_State *state) {
  lua_settop(state, 1000000);
  lua_settop(state, 1000001);
  return 0;
}

static int rivetlua_a4b_full_stack_checkstack(lua_State *state) {
  lua_settop(state, 1000000);
  return lua_checkstack(state, 1) == 0 ? 0 : luaL_error(state, "checkstack crossed limit");
}

static int rivetlua_a4b_full_stack_nested(lua_State *state) {
  lua_settop(state, 1000000);
  if (rivetlua_capi_test_protected_index_a4b(state, -1, 0, 0, NULL, NULL) != 0)
    return luaL_error(state, "nested checkpoint unavailable");
  (void)lua_getiuservalue(state, 1, 1);
  return 0;
}

int rivetlua_capi_test_full_stack_boundary_a4b(lua_State *state, int mode) {
  if (state == NULL || lua_type(state, 1) != LUA_TUSERDATA) return -1;
  lua_CFunction function;
  switch (mode) {
    case 0: function = rivetlua_a4b_full_stack_getiuservalue; break;
    case 1: function = rivetlua_a4b_full_stack_pushnil; break;
    case 2: function = rivetlua_a4b_full_stack_settop; break;
    case 3: function = rivetlua_a4b_full_stack_checkstack; break;
    case 4: function = rivetlua_a4b_full_stack_nested; break;
    default: return -1;
  }
  int original_top = lua_gettop(state);
  lua_pushcclosure(state, function, 0);
  lua_pushvalue(state, 1);
  int status = lua_pcall(state, 1, 0, 0);
  if (mode == 3) {
    if (status != LUA_OK || lua_gettop(state) != original_top) {
      lua_settop(state, original_top);
      return -2;
    }
  } else {
    if (status == LUA_OK) {
      lua_settop(state, original_top);
      return -2;
    }
    if (status != LUA_ERRMEM || lua_gettop(state) != original_top + 1 ||
        lua_type(state, -1) != LUA_TSTRING ||
        strcmp(lua_tostring(state, -1), "not enough memory") != 0) {
      lua_settop(state, original_top);
      return -3;
    }
    /* public pcall 已 consume pending Lua error；移除唯一錯誤物件。 */
    lua_pop(state, 1);
    lua_settop(state, original_top);
  }
  int tag = lua_getiuservalue(state, 1, 1);
  if (tag != LUA_TNIL || lua_gettop(state) != original_top + 1) {
    lua_settop(state, original_top);
    return -4;
  }
  lua_pop(state, 1);
  return lua_gettop(state) == original_top ? status : -5;
}

static int rivetlua_a4b_cache_return(lua_State *state) {
  const char *value = luaL_checklstring(state, lua_upvalueindex(1), NULL);
  return value != NULL && strcmp(value, "outer") == 0 ? 0 : luaL_error(state, "A4b cache return");
}

static int rivetlua_a4b_cache_error(lua_State *state) {
  (void)luaL_checklstring(state, lua_upvalueindex(1), NULL);
  return luaL_error(state, "A4b cache error");
}

static int rivetlua_a4b_cache_abort(lua_State *state) {
  (void)luaL_checklstring(state, lua_upvalueindex(1), NULL);
  lua_pushstring(state, "A4b cache abort");
  return lua_error(state);
}

static int rivetlua_a4b_cache_inner(lua_State *state) {
  const char *value = luaL_checklstring(state, lua_upvalueindex(1), NULL);
  return value != NULL && strcmp(value, "inner") == 0 ? 0 : luaL_error(state, "A4b cache inner");
}

static int rivetlua_a4b_cache_outer(lua_State *state) {
  const char *outer = luaL_checklstring(state, lua_upvalueindex(1), NULL);
  if (outer == NULL || strcmp(outer, "outer") != 0)
    return luaL_error(state, "A4b cache outer");
  lua_pushstring(state, "inner");
  lua_pushcclosure(state, rivetlua_a4b_cache_inner, 1);
  if (lua_pcall(state, 0, 0, 0) != LUA_OK)
    return luaL_error(state, "A4b cache nested");
  if (strcmp(outer, "outer") != 0 ||
      luaL_checklstring(state, lua_upvalueindex(1), NULL) != outer)
    return luaL_error(state, "A4b cache outer lifetime");
  return 0;
}

int rivetlua_capi_test_upvalue_cache_lifecycle_a4b(lua_State *state, int mode) {
  lua_CFunction function;
  switch (mode) {
    case 0: function = rivetlua_a4b_cache_return; break;
    case 1: function = rivetlua_a4b_cache_error; break;
    case 2: function = rivetlua_a4b_cache_abort; break;
    case 3: function = rivetlua_a4b_cache_outer; break;
    default: return -1;
  }
  lua_pushstring(state, "outer");
  lua_pushcclosure(state, function, 1);
  int status = lua_pcall(state, 0, 0, 0);
  if (status != LUA_OK) lua_pop(state, 1);
  return status;
}

/* A2 public 同步呼叫只以 B4 coordinator 驅動；handler root 由 Rust preflight 持有。 */
static int rivetlua_a2_status(int class_code) {
  return class_code == RV_A1_ERROR_ALLOCATION ? LUA_ERRMEM : LUA_ERRRUN;
}

static int rivetlua_a2_consume_settle(
    lua_State *state, size_t base, int *class_code) {
  if (rivetlua_capi_error_consume_a1(state, class_code) != RV_A1_OK)
    return 0;
  return rivetlua_capi_public_settle_error_a2(state, base);
}

/* 固定 C callback：內層 Lua bytecode 錯誤被 pcall 捕捉後，外層仍須可返回。 */
int rivetlua_capi_test_nested_lua_error_a2(lua_State *state) {
  if (lua_type(state, 1) != LUA_TFUNCTION) {
    lua_pushinteger(state, -1);
    return 1;
  }
  lua_pushvalue(state, 1);
  int status = lua_pcall(state, 0, 0, 0);
  if (status != LUA_ERRRUN || lua_gettop(state) != 2) {
    lua_settop(state, 0);
    lua_pushinteger(state, -2);
    return 1;
  }
  lua_pop(state, 1);
  lua_pushinteger(state, 73);
  return 1;
}

int lua_error(lua_State *state) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (top != NULL && top->state == state && top->rust_action_active == 0 &&
      rivetlua_capi_error_prepare_a1(
          state, top->generation, top->token, RV_A1_ERROR_LUA) == RV_A1_OK)
    rivetlua_b7_raise_existing(state, -RV_A1_ERROR_LUA);
  /* 無保護框架時，Rust 只提供 POD callback；真正呼叫與 fail-stop 都在純 C。 */
  lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
  if (panicf != NULL) (void)panicf(state);
  abort();
}

/* A2 固定 C fixture 只在純 C callback frame 測試 typed error 穿越同步 call。 */
int rivetlua_capi_test_raise_class_a2(lua_State *state, int class_code) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (class_code != RV_A1_ERROR_HOST &&
      class_code != RV_A1_ERROR_POLICY &&
      class_code != RV_A1_ERROR_ABORTED) return 0;
  if (top != NULL && top->state == state && top->rust_action_active == 0 &&
      rivetlua_capi_error_prepare_a1(
          state, top->generation, top->token, class_code) == RV_A1_OK)
    rivetlua_b7_raise_existing(state, -class_code);
  return 0;
}

int lua_yieldk(lua_State *state, int nresults, lua_KContext context,
               lua_KFunction continuation) {
  rivetlua_capi_checkpoint_a1 *target = rivetlua_capi_resume_top_a5;
  if (state == NULL || target == NULL || target->state != state)
    return luaL_error(state, "attempt to yield from outside a coroutine");
  unsigned skipped = 0;
  rivetlua_capi_checkpoint_a1 *cursor = rivetlua_capi_top_a1;
  while (cursor != NULL && cursor != target) {
    if (cursor->state != state || cursor->yieldable_a5 == 0 ||
        cursor->rust_action_active != 0)
      return luaL_error(state, "attempt to yield across a C-call boundary");
    skipped++;
    cursor = cursor->previous;
  }
  if (cursor != target || target->rust_action_active != 0 || nresults < 0)
    return luaL_error(state, "attempt to yield across a C-call boundary");
  int prepared = rivetlua_capi_yield_prepare_a5(
      state, nresults, context, continuation);
  if (prepared == -RV_A1_ERROR_ALLOCATION)
    rivetlua_b5_operation_raise_message(state, prepared, 0);
  if (prepared != 0)
    return luaL_error(state, "attempt to yield across a C-call boundary");
  if (rivetlua_capi_checkpoint_rewind_a5(
          state, target->generation, target->token, skipped) != RV_A1_OK)
    abort();
  rivetlua_capi_top_a1 = target;
  /* Rust yield step 已完整返回，目標仍是此 child 的純 C resume frame。 */
  longjmp(target->jump, 2);
}

int lua_resume(lua_State *state, lua_State *from, int nargs, int *nresults) {
  if (state == NULL || nresults == NULL) return LUA_ERRRUN;
  int frame_depth = rivetlua_capi_call_depth_b7(state);
  if (frame_depth < 0) return LUA_ERRRUN;
  rivetlua_capi_checkpoint_a1 checkpoint;
  if (rivetlua_capi_checkpoint_enter_a1(
          state, &checkpoint.generation, &checkpoint.token,
          &checkpoint.previous_state_token) != RV_A1_OK)
    return LUA_ERRMEM;
  checkpoint.state = state;
  checkpoint.previous = rivetlua_capi_top_a1;
  volatile int32_t raised_status = 0;
  checkpoint.raised_status = &raised_status;
  checkpoint.rust_action_active = 0;
  checkpoint.yieldable_a5 = 1;
  rivetlua_capi_checkpoint_a1 *previous_resume = rivetlua_capi_resume_top_a5;
  rivetlua_capi_top_a1 = &checkpoint;
  rivetlua_capi_resume_top_a5 = &checkpoint;
  volatile size_t resume_base = 0;
  volatile int error_class = 0;
  int result = LUA_ERRRUN;
  int result_count = 0;
  rivetlua_capi_callback_step_b4 step;
  int jumped = setjmp(checkpoint.jump);
  if (jumped == 2) {
    result = LUA_YIELD;
    result_count = lua_gettop(state);
    goto finish;
  }
  if (jumped == 1) {
    checkpoint.rust_action_active = 0;
    if (raised_status != 0) error_class = raised_status;
    if (rivetlua_capi_call_depth_b7(state) > frame_depth) {
      size_t trim_top = (size_t)lua_gettop(state);
      int captured = rivetlua_capi_close_capture_error_b7(state, trim_top);
      if (captured <= 0) goto finish;
      int closed = rivetlua_b7_close_drive(state, 0, trim_top, captured, 0);
      if (closed < 0) error_class = -closed;
      checkpoint.rust_action_active = 1;
      step = rivetlua_capi_call_resume_error_a2(state, LUA_MULTRET);
      checkpoint.rust_action_active = 0;
      goto drive;
    }
    result = error_class == RV_A1_ERROR_ALLOCATION ? LUA_ERRMEM : LUA_ERRRUN;
    goto finish;
  }
  checkpoint.rust_action_active = 1;
  rivetlua_capi_resume_setup_a5 setup =
      rivetlua_capi_resume_prepare_a5(state, from, nargs);
  checkpoint.rust_action_active = 0;
  if (setup.kind < 0) {
    result = setup.status;
    int top = lua_gettop(state);
    if (nargs >= 0 && nargs <= top) lua_settop(state, top - nargs);
    if (lua_pushstring(state, result == LUA_ERRMEM
            ? "not enough memory" : "cannot resume non-suspended coroutine") == NULL)
      result = LUA_ERRMEM;
    goto finish;
  }
  resume_base = setup.base;
  if (setup.kind == 0) {
    result = setup.status;
    result_count = setup.nresults;
    goto finish;
  }
  if (setup.kind == 2) {
    int count = setup.resume_args;
    if (setup.continuation != NULL)
      count = setup.continuation(state, LUA_YIELD, setup.context);
    int closed = rivetlua_b7_close_drive(
        state, 0, (size_t)lua_gettop(state), 0, 0);
    checkpoint.rust_action_active = 1;
    step = closed == 0
        ? rivetlua_capi_call_resume_a2(
              state, count, rivetlua_capi_continuation_results_a5(state))
        : rivetlua_capi_call_resume_error_a2(
              state, rivetlua_capi_continuation_results_a5(state));
    checkpoint.rust_action_active = 0;
  } else {
    step = setup.step;
  }
drive:
  while (step.kind == 1 || step.kind == 2) {
    int count = 0;
    if (!rivetlua_b10_invoke_step(state, &step, &count)) goto finish;
    int closed = rivetlua_b7_close_drive(
        state, 0, (size_t)lua_gettop(state), 0, 0);
    checkpoint.rust_action_active = 1;
    step = closed == 0
        ? rivetlua_capi_call_resume_a2(
              state, count, rivetlua_capi_continuation_results_a5(state))
        : rivetlua_capi_call_resume_error_a2(
              state, rivetlua_capi_continuation_results_a5(state));
    checkpoint.rust_action_active = 0;
  }
  if (rivetlua_capi_call_depth_b7(state) > frame_depth) {
    int depth = rivetlua_capi_call_depth_b7(state);
    rivetlua_capi_continuation_record_a5 continuation_step =
        rivetlua_capi_continuation_step_a5(state, (size_t)depth, 0);
    if (continuation_step.kind == 1 && step.kind == 0) {
      continuation_step = rivetlua_capi_continuation_step_a5(
          state, (size_t)depth, 1);
      int count = continuation_step.continuation(
          state, LUA_YIELD, continuation_step.context);
      int closed = rivetlua_b7_close_drive(
          state, 0, (size_t)lua_gettop(state), 0, 0);
      checkpoint.rust_action_active = 1;
      step = closed == 0
          ? rivetlua_capi_call_resume_a2(
                state, count, rivetlua_capi_continuation_results_a5(state))
          : rivetlua_capi_call_resume_error_a2(
                state, rivetlua_capi_continuation_results_a5(state));
      checkpoint.rust_action_active = 0;
      goto drive;
    }
    if (continuation_step.kind == 1 && step.kind < 0) {
      if (continuation_step.protected_call) {
        int class_code = RV_A1_ERROR_LUA;
        if (!rivetlua_a2_consume_settle(
                state, continuation_step.base, &class_code)) goto finish;
        int kstatus = rivetlua_a2_status(class_code);
        if (continuation_step.handler != NULL) {
          if (!rivetlua_capi_public_push_handler_a2(
                  state, continuation_step.handler, continuation_step.base))
            goto finish;
          if (rivetlua_a2_call_drive(state, 1, 1, 0) != 0) {
            int handler_class = RV_A1_ERROR_LUA;
            if (!rivetlua_a2_consume_settle(
                    state, continuation_step.base, &handler_class)) goto finish;
            kstatus = LUA_ERRERR;
          }
        }
        continuation_step = rivetlua_capi_continuation_step_a5(
            state, (size_t)depth, 1);
        int count = continuation_step.continuation(
            state, kstatus, continuation_step.context);
        int closed = rivetlua_b7_close_drive(
            state, 0, (size_t)lua_gettop(state), 0, 0);
        checkpoint.rust_action_active = 1;
        step = closed == 0
            ? rivetlua_capi_call_resume_a2(
                  state, count, rivetlua_capi_continuation_results_a5(state))
            : rivetlua_capi_call_resume_error_a2(
                  state, rivetlua_capi_continuation_results_a5(state));
        checkpoint.rust_action_active = 0;
        goto drive;
      }
      (void)rivetlua_capi_continuation_step_a5(state, (size_t)depth, 1);
    }
  }
  if (step.kind < 0 && rivetlua_capi_call_depth_b7(state) > frame_depth) {
    if (step.value > 0) error_class = step.value;
    checkpoint.rust_action_active = 1;
    step = rivetlua_capi_call_resume_error_a2(
        state, rivetlua_capi_continuation_results_a5(state));
    checkpoint.rust_action_active = 0;
    goto drive;
  }
  if (step.kind < 0 && rivetlua_capi_call_depth_b7(state) == frame_depth) {
    int class_code = RV_A1_ERROR_LUA;
    if (rivetlua_capi_error_consume_a1(state, &class_code) != RV_A1_OK)
      goto finish;
    checkpoint.rust_action_active = 1;
    rivetlua_capi_resume_finish_result_a5 finished = rivetlua_capi_resume_finish_a5(
        state, (size_t)resume_base, (size_t)frame_depth, class_code);
    checkpoint.rust_action_active = 0;
    if (finished.status >= 0) {
      result = finished.status;
      result_count = finished.nresults;
    }
    goto finish;
  }
  if (step.kind == 0 && rivetlua_capi_call_depth_b7(state) == frame_depth) {
    checkpoint.rust_action_active = 1;
    rivetlua_capi_resume_finish_result_a5 finished = rivetlua_capi_resume_finish_a5(
        state, (size_t)resume_base, (size_t)frame_depth, 0);
    checkpoint.rust_action_active = 0;
    if (finished.status >= 0) {
      result = finished.status;
      result_count = finished.nresults;
    }
  }
finish:
  if (result != LUA_YIELD && rivetlua_capi_call_depth_b7(state) > frame_depth) {
    checkpoint.rust_action_active = 1;
    (void)rivetlua_capi_call_abort_to_b7(state, frame_depth);
    checkpoint.rust_action_active = 0;
  }
  rivetlua_capi_resume_top_a5 = previous_resume;
  rivetlua_capi_top_a1 = checkpoint.previous;
  if (rivetlua_capi_checkpoint_exit_a1(
          state, checkpoint.generation, checkpoint.token,
          checkpoint.previous_state_token) != RV_A1_OK)
    return LUA_ERRRUN;
  if (result == LUA_OK || result == LUA_YIELD) *nresults = result_count;
  return result;
}

/* A5 C-only 測試入口：K 讀取跨暫停期由 C closure 持有的唯一字串 upvalue。 */
static int rivetlua_a5_gc_probe_continue(lua_State *state, int status,
                                        lua_KContext context) {
  if (status != LUA_YIELD || context != 91)
    return luaL_error(state, "A5 continuation context");
  lua_pushvalue(state, lua_upvalueindex(1));
  return 1;
}

static int rivetlua_a5_gc_probe_yield(lua_State *state) {
  lua_pushinteger(state, 7);
  return lua_yieldk(state, 1, 91, rivetlua_a5_gc_probe_continue);
}

int rivetlua_capi_test_prepare_gc_probe_a5(lua_State *state) {
  if (lua_pushstring(state, "A5 suspended upvalue") == NULL) return 0;
  lua_pushcclosure(state, rivetlua_a5_gc_probe_yield, 1);
  return 1;
}

extern int rivetlua_capi_test_inject_point_a4a(lua_State *state, int code);

static int rivetlua_a5_allocation_probe_yield(lua_State *state) {
  lua_pushinteger(state, 9);
  if (rivetlua_capi_test_inject_point_a4a(state, 11) != 1)
    return luaL_error(state, "A5 allocation probe setup");
  return lua_yield(state, 1);
}

int rivetlua_capi_test_prepare_allocation_probe_a5(lua_State *state) {
  lua_pushcfunction(state, rivetlua_a5_allocation_probe_yield);
  return 1;
}

int lua_pcallk(lua_State *state, int nargs, int nresults, int errfunc,
               lua_KContext context, lua_KFunction continuation) {
  rivetlua_capi_public_call_setup_a2 setup =
      rivetlua_capi_public_preflight_a2(state, nargs, nresults, errfunc);
  if (setup.kind == -RV_A1_ERROR_ALLOCATION) {
    if (!rivetlua_capi_public_settle_preflight_allocation_a2(
            state, setup.base)) return LUA_ERRRUN;
    return LUA_ERRMEM;
  }
  if (setup.kind != 1)
    return rivetlua_a2_status(-setup.kind);
  int registered = 0;
  if (continuation != NULL && rivetlua_capi_resume_top_a5 != NULL &&
      rivetlua_capi_resume_top_a5->state == state) {
    int pushed = rivetlua_capi_continuation_push_a5(
        state, continuation, context, 1, nresults, setup.base, setup.handler);
    if (pushed != 0) {
      rivetlua_capi_public_drop_handler_a2(setup.handler);
      if (pushed == -RV_A1_ERROR_ALLOCATION) {
        if (!rivetlua_capi_public_settle_preflight_allocation_a2(state, setup.base))
          return LUA_ERRRUN;
        return LUA_ERRMEM;
      }
      rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
      if (top != NULL && top->state == state && top->rust_action_active == 0) {
        rivetlua_capi_strict_result_b2 prepared = rivetlua_capi_operation_error_b5(
            state, top->generation, top->token, -pushed, 0);
        int class_code = RV_A1_ERROR_LUA;
        if (prepared.kind == RV_A1_ACTION_RAISE &&
            rivetlua_a2_consume_settle(state, setup.base, &class_code))
          return rivetlua_a2_status(class_code);
      }
      return LUA_ERRRUN;
    }
    registered = 1;
  }
  int status = LUA_OK;
  if (rivetlua_a2_call_drive(state, nargs, nresults, registered) != 0) {
    int class_code = RV_A1_ERROR_LUA;
    if (!rivetlua_a2_consume_settle(state, setup.base, &class_code)) {
      if (registered)
        (void)rivetlua_capi_continuation_step_a5(
            state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
      else
        rivetlua_capi_public_drop_handler_a2(setup.handler);
      return LUA_ERRRUN;
    }
    status = rivetlua_a2_status(class_code);
    if (setup.handler != NULL) {
      if (!rivetlua_capi_public_push_handler_a2(
              state, setup.handler, setup.base)) {
        if (registered)
          (void)rivetlua_capi_continuation_step_a5(
              state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
        else
          rivetlua_capi_public_drop_handler_a2(setup.handler);
        return LUA_ERRMEM;
      }
      if (rivetlua_a2_call_drive(state, 1, 1, 0) != 0) {
        int handler_class = RV_A1_ERROR_LUA;
        if (!rivetlua_a2_consume_settle(
                state, setup.base, &handler_class)) {
          if (registered)
            (void)rivetlua_capi_continuation_step_a5(
                state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
          else
            rivetlua_capi_public_drop_handler_a2(setup.handler);
          return LUA_ERRRUN;
        }
        status = LUA_ERRERR;
      }
    }
  }
  if (registered)
    (void)rivetlua_capi_continuation_step_a5(
        state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
  else
    rivetlua_capi_public_drop_handler_a2(setup.handler);
  return status;
}

void lua_callk(lua_State *state, int nargs, int nresults,
               lua_KContext context, lua_KFunction continuation) {
  rivetlua_capi_public_call_setup_a2 setup =
      rivetlua_capi_public_preflight_a2(state, nargs, nresults, 0);
  if (setup.kind == -RV_A1_ERROR_ALLOCATION) {
    if (!rivetlua_capi_public_settle_preflight_allocation_a2(
            state, setup.base)) abort();
    rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
    if (top != NULL && top->state == state && top->rust_action_active == 0 &&
        rivetlua_capi_error_prepare_a1(
            state, top->generation, top->token,
            RV_A1_ERROR_ALLOCATION) == RV_A1_OK)
      rivetlua_b7_raise_existing(state, -RV_A1_ERROR_ALLOCATION);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
    abort();
  }
  if (setup.kind != 1) abort();
  int registered = 0;
  if (continuation != NULL && rivetlua_capi_resume_top_a5 != NULL &&
      rivetlua_capi_resume_top_a5->state == state) {
    int pushed = rivetlua_capi_continuation_push_a5(
        state, continuation, context, 0, nresults, setup.base, NULL);
    if (pushed != 0) rivetlua_b5_operation_raise_message(state, pushed, 0);
    registered = 1;
  }
  if (rivetlua_a2_call_drive(state, nargs, nresults, registered) == 0) {
    if (registered)
      (void)rivetlua_capi_continuation_step_a5(
          state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
    return;
  }
  int class_code = RV_A1_ERROR_LUA;
  if (!rivetlua_a2_consume_settle(state, setup.base, &class_code)) abort();
  if (registered)
    (void)rivetlua_capi_continuation_step_a5(
        state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (top != NULL && top->state == state && top->rust_action_active == 0 &&
      rivetlua_capi_error_prepare_a1(
          state, top->generation, top->token, class_code) == RV_A1_OK)
    rivetlua_b7_raise_existing(state, -class_code);
  lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
  if (panicf != NULL) (void)panicf(state);
  abort();
}

/* B8：每一個 C callback 與 Rust step 間都沒有存活的 Rust 借用。 */
static int rivetlua_b8_gc_drive(lua_State *state, int what, size_t bytes,
                                int first, int second, int third) {
  if (state == NULL) return -1;
  int frame_depth = rivetlua_capi_call_depth_b7(state);
  if (frame_depth < 0) return -1;
  rivetlua_capi_checkpoint_a1 checkpoint;
  int32_t entered = rivetlua_capi_checkpoint_enter_a1(
      state, &checkpoint.generation, &checkpoint.token,
      &checkpoint.previous_state_token);
  if (entered != RV_A1_OK) return -1;
  checkpoint.state = state;
  checkpoint.previous = rivetlua_capi_top_a1;
  volatile int32_t raised_status = 0;
  checkpoint.raised_status = &raised_status;
  checkpoint.rust_action_active = 0;
  checkpoint.yieldable_a5 = 0;
  rivetlua_capi_top_a1 = &checkpoint;
  int answer = -1;
  int status = 0;
  checkpoint.rust_action_active = 1;
  rivetlua_capi_callback_step_b4 step = rivetlua_capi_gc_prepare_b8(
      state, what, bytes, first, second, third);
  checkpoint.rust_action_active = 0;
  if (step.kind >= 0) answer = step.value;
  for (; step.kind == 1 || step.kind == 2;) {
    volatile int callback_failed = 0;
    volatile int count = 0;
    /* C finalizer 的錯誤只回到此 C checkpoint，再交給 protected VM boundary。 */
    if (setjmp(checkpoint.jump) == 0) {
      int invoked_count = 0;
      if (!rivetlua_b10_invoke_step(state, &step, &invoked_count))
        callback_failed = 1;
      count = invoked_count;
      if (rivetlua_b7_close_drive(state, 0, (size_t)lua_gettop(state), 0, 0)
          != 0) callback_failed = 1;
    } else {
      size_t trim_top = (size_t)lua_gettop(state);
      int error_class = rivetlua_capi_close_capture_error_b7(state, trim_top);
      if (error_class > 0)
        (void)rivetlua_b7_close_drive(state, 0, trim_top, error_class, 0);
      callback_failed = 1;
    }
    checkpoint.rust_action_active = 1;
    step = callback_failed
        ? rivetlua_capi_gc_resume_error_b8(state)
        : rivetlua_capi_call_resume_b4(state, (int)count, 0);
    checkpoint.rust_action_active = 0;
  }
  if (step.kind < 0 || step.kind == 1 || step.kind == 2)
    status = -(step.value > 0 ? step.value : RV_A1_ERROR_LUA);
  if (status != 0) {
    checkpoint.rust_action_active = 1;
    (void)rivetlua_capi_pending_cancel_a1(
        state, checkpoint.generation, checkpoint.token);
    (void)rivetlua_capi_call_abort_to_b7(state, frame_depth);
    checkpoint.rust_action_active = 0;
  }
  rivetlua_capi_top_a1 = checkpoint.previous;
  int32_t exited = rivetlua_capi_checkpoint_exit_a1(
      state, checkpoint.generation, checkpoint.token,
      checkpoint.previous_state_token);
  if (exited != RV_A1_OK) return -RV_A1_ERROR_LUA;
  if (status != 0) return status;
  return answer;
}

int lua_gc(lua_State *state, int what, ...) {
  size_t bytes = 0;
  int first = 0, second = 0, third = 0;
  va_list args;
  va_start(args, what);
  switch (what) {
    case LUA_GCSTEP:
#if LUA_VERSION_NUM < 505
      first = va_arg(args, int);
      bytes = first <= 0 ? 0 :
          ((size_t)first > SIZE_MAX / 1024 ? SIZE_MAX : (size_t)first * 1024);
#else
      bytes = va_arg(args, size_t);
#endif
      break;
#if LUA_VERSION_NUM < 505
    case LUA_GCSETPAUSE:
    case LUA_GCSETSTEPMUL:
      first = va_arg(args, int);
      break;
    case LUA_GCGEN:
      first = va_arg(args, int);
      second = va_arg(args, int);
      break;
    case LUA_GCINC:
      first = va_arg(args, int);
      second = va_arg(args, int);
      third = va_arg(args, int);
      break;
#else
    case LUA_GCPARAM:
      first = va_arg(args, int);
      second = va_arg(args, int);
      break;
#endif
    default: break;
  }
  va_end(args);
  /* 查詢及純參數控制無須 checkpoint；COUNT 應觀察呼叫前的穩定帳本。 */
  if (what != LUA_GCCOLLECT && what != LUA_GCSTEP &&
      what != LUA_GCGEN && what != LUA_GCINC) {
    rivetlua_capi_callback_step_b4 step = rivetlua_capi_gc_prepare_b8(
        state, what, bytes, first, second, third);
    if (step.kind == 0) return step.value;
    rivetlua_b5_operation_raise(state,
        -(step.value > 0 ? step.value : RV_A1_ERROR_LUA));
  }
  int answer = rivetlua_b8_gc_drive(state, what, bytes, first, second, third);
  if (answer < -1) rivetlua_b5_operation_raise(state, answer);
  return answer;
}

void lua_toclose(lua_State *state, int index) {
  int result = rivetlua_capi_toclose_prepare_b7(state, index);
  if (result != 1)
    rivetlua_b5_operation_raise_message(state, result, 3);
}

void lua_closeslot(lua_State *state, int index) {
  int position = lua_absindex(state, index);
  if (position <= 0)
    rivetlua_b5_operation_raise_message(state, -RV_A1_ERROR_LUA, 3);
  int result = rivetlua_b7_close_drive(
      state, (size_t)position - 1, (size_t)lua_gettop(state), 0, 1);
  if (result != 0) rivetlua_b7_raise_existing(state, result);
}

void lua_settop(lua_State *state, int index) {
  int top = lua_gettop(state);
  int64_t target = index >= 0 ? (int64_t)index : (int64_t)top + index + 1;
  if (target < 0 || target > INT32_MAX) {
    if (rivetlua_capi_top_a1 == NULL) return;
    rivetlua_b5_operation_raise_message(state, -RV_A1_ERROR_LUA, 3);
  }
  if (target < top) {
    int result = rivetlua_b7_close_drive(state, (size_t)target,
                                         (size_t)target, 0, 0);
    if (result != 0) rivetlua_b7_raise_existing(state, result);
  }
  int result = rivetlua_capi_settop_direct_b7(state, index);
  if (result != 1) {
    if (rivetlua_capi_top_a1 == NULL) return;
    rivetlua_b5_operation_raise_message(state, result, 3);
  }
}

void lua_arith(lua_State *state, int operation) {
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 0, operation, 0, 0, 0, &published);
  if (status != 0 || published != 1)
    rivetlua_b5_operation_raise(state, status);
}

void lua_concat(lua_State *state, int count) {
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 1, 0, 0, 0, count, &published);
  if (status != 0 || published != 1)
    rivetlua_b5_operation_raise(state, status);
}

void lua_len(lua_State *state, int index) {
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 2, 0, index, 0, 0, &published);
  if (status != 0 || published != 1)
    rivetlua_b5_operation_raise(state, status);
}

int lua_compare(lua_State *state, int left, int right, int operation) {
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 3, operation, left, right, 0, &published);
  if (status != 0) rivetlua_b5_operation_raise(state, status);
  if (published == 0) return 0;
  int answer = lua_toboolean(state, -1);
  lua_settop(state, -2);
  return answer;
}

lua_Integer luaL_len(lua_State *state, int index) {
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 4, 0, index, 0, 0, &published);
  if (status != 0 || published != 1)
    rivetlua_b5_operation_raise(state, status);
  int isnum = 0;
  lua_Integer answer = lua_tointegerx(state, -1, &isnum);
  lua_settop(state, -2);
  if (!isnum)
    rivetlua_b5_operation_raise_message(state, -RV_A1_ERROR_LUA, 1);
  return answer;
}

void luaL_where(lua_State *state, int level) {
  lua_Debug ar;
  if (lua_getstack(state, level, &ar) && lua_getinfo(state, "Sl", &ar) &&
      ar.currentline > 0) {
    lua_pushfstring(state, "%s:%d: ", ar.short_src, ar.currentline);
    return;
  }
  lua_pushfstring(state, "");
}

/* A3：只透過公開 API 讀 debug frame；L1 上不建立跨 GC 存活的 C 指標。 */
static int rivetlua_a3_findfield(lua_State *state, int object, int depth) {
  if (depth == 0 || !lua_istable(state, -1)) return 0;
  lua_pushnil(state);
  while (lua_next(state, -2)) {
    if (lua_type(state, -2) == LUA_TSTRING) {
      if (lua_rawequal(state, object, -1)) {
        lua_pop(state, 1);
        return 1;
      }
      if (rivetlua_a3_findfield(state, object, depth - 1)) {
        lua_pushliteral(state, ".");
        lua_replace(state, -3);
        lua_concat(state, 3);
        return 1;
      }
    }
    lua_pop(state, 1);
  }
  return 0;
}

static int rivetlua_a3_global_name(lua_State *state, lua_Debug *ar) {
  int top = lua_gettop(state);
  if (!lua_getinfo(state, "f", ar)) return 0;
  lua_getfield(state, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  luaL_checkstack(state, 6, "not enough stack");
  if (rivetlua_a3_findfield(state, top + 1, 2)) {
    const char *name = lua_tostring(state, -1);
    if (strncmp(name, LUA_GNAME ".", 3) == 0) {
      lua_pushstring(state, name + 3);
      lua_remove(state, -2);
    }
    lua_copy(state, -1, top + 1);
    lua_settop(state, top + 1);
    return 1;
  }
  lua_settop(state, top);
  return 0;
}

static void rivetlua_a3_func_name(lua_State *state, lua_Debug *ar) {
#if LUA_VERSION_NUM < 505
  if (rivetlua_a3_global_name(state, ar)) {
    lua_pushfstring(state, "function '%s'", lua_tostring(state, -1));
    lua_remove(state, -2);
    return;
  }
#endif
  if (ar->namewhat != NULL && *ar->namewhat != '\0') {
    lua_pushfstring(state, "%s '%s'", ar->namewhat, ar->name);
  } else if (ar->what != NULL && *ar->what == 'm') {
    lua_pushliteral(state, "main chunk");
  }
#if LUA_VERSION_NUM >= 505
  else if (rivetlua_a3_global_name(state, ar)) {
    lua_pushfstring(state, "function '%s'", lua_tostring(state, -1));
    lua_remove(state, -2);
  }
#endif
  else if (ar->what != NULL && *ar->what != 'C') {
    lua_pushfstring(state, "function <%s:%d>", ar->short_src, ar->linedefined);
  } else {
    lua_pushliteral(state, "?");
  }
}

static int rivetlua_a3_lastlevel(lua_State *state) {
  lua_Debug ar;
  int low = 1, high = 1;
  while (lua_getstack(state, high, &ar)) { low = high; high *= 2; }
  while (low < high) {
    int middle = (low + high) / 2;
    if (lua_getstack(state, middle, &ar)) low = middle + 1;
    else high = middle;
  }
  return high - 1;
}

void luaL_traceback(lua_State *state, lua_State *source,
                    const char *message, int level) {
  if (!rivetlua_capi_traceback_preflight_a3(state, source)) return;
  luaL_Buffer buffer;
  lua_Debug ar;
  int last = rivetlua_a3_lastlevel(source);
  int limit = last - level > 21 ? 10 : -1;
  luaL_buffinit(state, &buffer);
  if (message != NULL) {
    luaL_addstring(&buffer, message);
    luaL_addchar(&buffer, '\n');
  }
  luaL_addstring(&buffer, "stack traceback:");
  while (lua_getstack(source, level++, &ar)) {
    if (limit-- == 0) {
      int skip = last - level - 11 + 1;
      lua_pushfstring(state, "\n\t...\t(skipping %d levels)", skip);
      luaL_addvalue(&buffer);
      level += skip;
    } else {
      lua_getinfo(source, "Slnt", &ar);
      if (ar.currentline <= 0)
        lua_pushfstring(state, "\n\t%s: in ", ar.short_src);
      else
        lua_pushfstring(state, "\n\t%s:%d: in ", ar.short_src, ar.currentline);
      luaL_addvalue(&buffer);
      rivetlua_a3_func_name(state, &ar);
      luaL_addvalue(&buffer);
      if (ar.istailcall)
        luaL_addstring(&buffer, "\n\t(...tail calls...)");
    }
  }
  luaL_pushresult(&buffer);
}

int luaL_argerror(lua_State *state, int arg, const char *extra) {
  lua_Debug ar;
  if (!lua_getstack(state, 0, &ar))
    return luaL_error(state, "bad argument #%d (%s)", arg, extra);
#if LUA_VERSION_NUM >= 505
  lua_getinfo(state, "nt", &ar);
  const char *word;
  if (arg <= ar.extraargs) word = "extra argument";
  else {
    arg -= ar.extraargs;
    if (strcmp(ar.namewhat, "method") == 0) {
      arg--;
      if (arg == 0)
        return luaL_error(state, "calling '%s' on bad self (%s)",
                          ar.name, extra);
    }
    word = "argument";
  }
#else
  lua_getinfo(state, "n", &ar);
  if (strcmp(ar.namewhat, "method") == 0) {
    arg--;
    if (arg == 0)
      return luaL_error(state, "calling '%s' on bad self (%s)", ar.name, extra);
  }
#endif
  if (ar.name == NULL)
    ar.name = rivetlua_a3_global_name(state, &ar) ? lua_tostring(state, -1) : "?";
#if LUA_VERSION_NUM >= 505
  return luaL_error(state, "bad %s #%d to '%s' (%s)",
                    word, arg, ar.name, extra);
#else
  return luaL_error(state, "bad argument #%d to '%s' (%s)",
                    arg, ar.name, extra);
#endif
}

int luaL_typeerror(lua_State *state, int arg, const char *type) {
  const char *actual;
  if (luaL_getmetafield(state, arg, "__name") == LUA_TSTRING)
    actual = lua_tostring(state, -1);
  else if (lua_type(state, arg) == LUA_TLIGHTUSERDATA)
    actual = "light userdata";
  else
    actual = luaL_typename(state, arg);
  const char *message = lua_pushfstring(state, "%s expected, got %s", type, actual);
  return luaL_argerror(state, arg, message);
}

int luaL_error(lua_State *state, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
  luaL_where(state, 1);
  const char *formatted = lua_pushvfstring(state, format, arguments);
  va_end(arguments);
#if LUA_VERSION_NUM >= 505
  if (formatted == NULL) {
    lua_remove(state, -2);  /* 移除 where，保留唯一 emergency error slot。 */
    rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
    if (top != NULL && top->state == state && top->rust_action_active == 0 &&
        rivetlua_capi_error_prepare_a1(state, top->generation, top->token,
                                       RV_A1_ERROR_ALLOCATION) == RV_A1_OK)
      rivetlua_b7_raise_existing(state, -RV_A1_ERROR_ALLOCATION);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
    abort();
  }
#else
  (void)formatted;
#endif
  lua_concat(state, 2);
  return lua_error(state);
}

enum {
  RV_A3_CHECKSTACK = 1, RV_A3_ROTATE, RV_A3_XMOVE, RV_A3_PUSHNIL,
  RV_A3_PUSHBOOLEAN, RV_A3_PUSHINTEGER, RV_A3_PUSHNUMBER,
  RV_A3_PUSHLIGHTUSERDATA, RV_A3_GSUB, RV_A3_NEWMETATABLE,
  RV_A3_SETMETATABLE, RV_A3_NEXT, RV_A4B_PUSHVALUE, RV_A4B_COPY,
  RV_A4B_REF, RV_A4B_UNREF, RV_A4B_GETMETATABLE, RV_A4B_SETMETATABLE,
  RV_A4B_GETUSERVALUE, RV_A4B_SETUSERVALUE,
  RV_A4B_GETMETAFIELD, RV_A4B_TESTUDATA
};

/* Rust dispatch 已返回 POD；所有非局部跳轉只在目前 C checkpoint。 */
static rivetlua_capi_strict_result_b2 rivetlua_a3_generic(
    lua_State *state, lua_State *other, int operation, int first, int second,
    lua_Integer integer, lua_Number number, void *opaque,
    const char *text1, const char *text2, const char *text3) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  rivetlua_capi_strict_result_b2 result = rivetlua_capi_generic_dispatch_a3(
      state, other, generation, token, operation, first, second, integer, number,
      opaque, text1, text2, text3);
  if (result.kind == RV_A1_ACTION_RETURN) return result;
  if (result.kind == RV_A1_ACTION_RAISE)
    return rivetlua_b2_finish(state, generation, token, result);
  if (top == NULL) {
    (void)rivetlua_capi_generic_panic_error_a3(state);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
  }
  abort();
}

void lua_pushvalue(lua_State *state, int index) {
  (void)rivetlua_a3_generic(state, NULL, RV_A4B_PUSHVALUE, index, 0,
                            0, 0, NULL, NULL, NULL, NULL);
}

void lua_copy(lua_State *state, int source, int destination) {
  (void)rivetlua_a3_generic(state, NULL, RV_A4B_COPY, source, destination,
                            0, 0, NULL, NULL, NULL, NULL);
}

static void *rivetlua_a4b_upvalue(lua_State *state, int operation,
                                  int first, int first_n, int second, int second_n) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  rivetlua_capi_strict_result_b2 result = rivetlua_capi_upvalue_dispatch_a4b(
      state, generation, token, operation, first, first_n, second, second_n);
  if (result.kind == RV_A1_ACTION_RETURN) return result.pointer;
  if (result.kind == RV_A1_ACTION_RAISE)
    (void)rivetlua_b2_finish(state, generation, token, result);
  if (top == NULL) {
    (void)rivetlua_capi_generic_panic_error_a3(state);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
  }
  abort();
}

const char *lua_getupvalue(lua_State *state, int index, int n) {
  return (const char *)rivetlua_a4b_upvalue(state, 1, index, n, 0, 0);
}

const char *lua_setupvalue(lua_State *state, int index, int n) {
  return (const char *)rivetlua_a4b_upvalue(state, 2, index, n, 0, 0);
}

void *lua_upvalueid(lua_State *state, int index, int n) {
  return rivetlua_a4b_upvalue(state, 3, index, n, 0, 0);
}

void lua_upvaluejoin(lua_State *state, int first, int first_n,
                     int second, int second_n) {
  (void)rivetlua_a4b_upvalue(state, 4, first, first_n, second, second_n);
}

void lua_pushcclosure(lua_State *state, lua_CFunction function, int n) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  rivetlua_capi_strict_result_b2 result = rivetlua_capi_pushcclosure_dispatch_a4b(
      state, generation, token, function, n);
  if (result.kind == RV_A1_ACTION_RETURN) return;
  if (result.kind == RV_A1_ACTION_RAISE)
    (void)rivetlua_b2_finish(state, generation, token, result);
  if (top == NULL) {
    (void)rivetlua_capi_generic_panic_error_a3(state);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
  }
  abort();
}

static rivetlua_capi_aux_value_a4b rivetlua_a4b_aux_value(
    lua_State *state, int operation, int arg, lua_Number default_number,
    lua_Integer default_integer, const char *default_string) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  rivetlua_capi_aux_value_a4b result = rivetlua_capi_aux_value_dispatch_a4b(
      state, generation, token, operation, arg,
      default_number, default_integer, default_string);
  if (result.kind == RV_A1_ACTION_RETURN) return result;
  if (result.kind == 40) {
    if ((operation == 3 || operation == 4) && result.value == 1)
      (void)luaL_argerror(state, arg, "number has no integer representation");
    else
      (void)luaL_typeerror(state, arg, operation >= 5 ? "string" : "number");
    abort();
  }
  if (result.kind == RV_A1_ACTION_RAISE) {
    rivetlua_capi_strict_result_b2 action = {
      result.kind, result.value, NULL
    };
    (void)rivetlua_b2_finish(state, generation, token, action);
  }
  if (top == NULL) {
    (void)rivetlua_capi_generic_panic_error_a3(state);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
  }
  abort();
}

lua_Number luaL_checknumber(lua_State *state, int arg) {
  return rivetlua_a4b_aux_value(state, 1, arg, 0, 0, NULL).number;
}

lua_Number luaL_optnumber(lua_State *state, int arg, lua_Number def) {
  return rivetlua_a4b_aux_value(state, 2, arg, def, 0, NULL).number;
}

lua_Integer luaL_checkinteger(lua_State *state, int arg) {
  return rivetlua_a4b_aux_value(state, 3, arg, 0, 0, NULL).integer;
}

lua_Integer luaL_optinteger(lua_State *state, int arg, lua_Integer def) {
  return rivetlua_a4b_aux_value(state, 4, arg, 0, def, NULL).integer;
}

const char *luaL_checklstring(lua_State *state, int arg, size_t *len) {
  rivetlua_capi_aux_value_a4b result =
      rivetlua_a4b_aux_value(state, 5, arg, 0, 0, NULL);
  if (len != NULL) *len = result.length;
  return result.pointer;
}

const char *luaL_optlstring(lua_State *state, int arg,
                            const char *def, size_t *len) {
  rivetlua_capi_aux_value_a4b result =
      rivetlua_a4b_aux_value(state, 6, arg, 0, 0, def);
  if (len != NULL) *len = result.length;
  return result.pointer;
}

int luaL_ref(lua_State *state, int index) {
  return rivetlua_a3_generic(state, NULL, RV_A4B_REF, index, 0,
      0, 0, NULL, NULL, NULL, NULL).value;
}

void luaL_unref(lua_State *state, int index, int reference) {
  (void)rivetlua_a3_generic(state, NULL, RV_A4B_UNREF, index, reference,
                            0, 0, NULL, NULL, NULL, NULL);
}

int lua_getmetatable(lua_State *state, int index) {
  return rivetlua_a3_generic(state, NULL, RV_A4B_GETMETATABLE, index, 0,
      0, 0, NULL, NULL, NULL, NULL).value;
}

int lua_setmetatable(lua_State *state, int index) {
  return rivetlua_a3_generic(state, NULL, RV_A4B_SETMETATABLE, index, 0,
      0, 0, NULL, NULL, NULL, NULL).value;
}

int lua_getiuservalue(lua_State *state, int index, int n) {
  return rivetlua_a3_generic(state, NULL, RV_A4B_GETUSERVALUE, index, n,
      0, 0, NULL, NULL, NULL, NULL).value;
}

int lua_setiuservalue(lua_State *state, int index, int n) {
  return rivetlua_a3_generic(state, NULL, RV_A4B_SETUSERVALUE, index, n,
      0, 0, NULL, NULL, NULL, NULL).value;
}

int luaL_getmetafield(lua_State *state, int index, const char *event) {
  return rivetlua_a3_generic(state, NULL, RV_A4B_GETMETAFIELD, index, 0,
      0, 0, NULL, event, NULL, NULL).value;
}

void *luaL_testudata(lua_State *state, int index, const char *name) {
  return rivetlua_a3_generic(state, NULL, RV_A4B_TESTUDATA, index, 0,
      0, 0, NULL, name, NULL, NULL).pointer;
}

void luaL_checkstack(lua_State *state, int space, const char *message) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_CHECKSTACK, space, 0,
                            0, 0, NULL, message, NULL, NULL);
}

void lua_rotate(lua_State *state, int index, int count) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_ROTATE, index, count,
                            0, 0, NULL, NULL, NULL, NULL);
}

void lua_xmove(lua_State *from, lua_State *to, int count) {
  (void)rivetlua_a3_generic(from, to, RV_A3_XMOVE, count, 0,
                            0, 0, NULL, NULL, NULL, NULL);
}

void lua_pushnil(lua_State *state) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_PUSHNIL, 0, 0,
                            0, 0, NULL, NULL, NULL, NULL);
}

void lua_pushboolean(lua_State *state, int value) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_PUSHBOOLEAN, value, 0,
                            0, 0, NULL, NULL, NULL, NULL);
}

void lua_pushinteger(lua_State *state, lua_Integer value) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_PUSHINTEGER, 0, 0,
                            value, 0, NULL, NULL, NULL, NULL);
}

void lua_pushnumber(lua_State *state, lua_Number value) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_PUSHNUMBER, 0, 0,
                            0, value, NULL, NULL, NULL, NULL);
}

void lua_pushlightuserdata(lua_State *state, void *value) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_PUSHLIGHTUSERDATA, 0, 0,
                            0, 0, value, NULL, NULL, NULL);
}

const char *luaL_gsub(lua_State *state, const char *source,
                      const char *pattern, const char *replacement) {
  return (const char *)rivetlua_a3_generic(state, NULL, RV_A3_GSUB, 0, 0,
      0, 0, NULL, source, pattern, replacement).pointer;
}

int luaL_newmetatable(lua_State *state, const char *name) {
  return rivetlua_a3_generic(state, NULL, RV_A3_NEWMETATABLE, 0, 0,
      0, 0, NULL, name, NULL, NULL).value;
}

void luaL_setmetatable(lua_State *state, const char *name) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_SETMETATABLE, 0, 0,
                            0, 0, NULL, name, NULL, NULL);
}

int lua_next(lua_State *state, int index) {
  return rivetlua_a3_generic(state, NULL, RV_A3_NEXT, index, 0,
      0, 0, NULL, NULL, NULL, NULL).value;
}

const char *luaL_tolstring(lua_State *state, int index, size_t *length) {
  index = lua_absindex(state, index);
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 5, 0, index, 0, 0, &published);
  if (status != 0) rivetlua_b5_operation_raise(state, status);
  if (published == 1) {
    if (!lua_isstring(state, -1)) {
      lua_settop(state, -2);
      rivetlua_b5_operation_raise_message(state, -RV_A1_ERROR_LUA, 2);
    }
    const char *result = lua_tolstring(state, -1, length);
    if (result == NULL) {
      lua_settop(state, -2);
      rivetlua_b5_operation_raise(state, -RV_A1_ERROR_ALLOCATION);
    }
    return result;
  }
  char pointer_text[64];
  int pointer_length = snprintf(
      pointer_text, sizeof(pointer_text), "%p", lua_topointer(state, index));
  if (pointer_length < 0 || (size_t)pointer_length >= sizeof(pointer_text))
    rivetlua_b5_operation_raise(state, -RV_A1_ERROR_LUA);
  rivetlua_capi_tolstring_result_b5 fallback =
      rivetlua_capi_tolstring_fallback_b5(
          state, index, (const unsigned char *)pointer_text,
          (size_t)pointer_length);
  if (fallback.kind != 1 || fallback.pointer == NULL)
    rivetlua_b5_operation_raise(state, fallback.kind < 0
        ? fallback.kind : -RV_A1_ERROR_LUA);
  if (length != NULL) *length = fallback.length;
  return fallback.pointer;
}

void luaL_checkversion_(lua_State *state, double version, size_t sizes) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  /* Rust 僅準備結果；此呼叫完整返回後才可能由 C 跳轉。 */
  rivetlua_capi_action_a1 action = rivetlua_capi_checkversion_prepare_a48(
      state, generation, token, version, sizes);
  if (action.kind == RV_A1_ACTION_RETURN && action.value == 0) return;
  if (action.kind == RV_A1_ACTION_RAISE && top != NULL &&
      top == rivetlua_capi_top_a1 && top->state == state &&
      top->rust_action_active == 0 &&
      rivetlua_capi_trampoline_probe_a1(
          state, generation, token) == RV_A1_OK &&
      rivetlua_capi_pending_matches_a1(
          state, generation, token, action.value) == RV_A1_OK) {
    *top->raised_status = action.value;
    longjmp(top->jump, 1);
  }
  /* 無 checkpoint、Rust action frame 或無法準備錯誤時絕不假裝相容成功。 */
  abort();
}

void *lua_newuserdatauv(lua_State *state, size_t size, int nuvalue) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  /* Rust 先完成 admission／pending 準備；longjmp 只發生在此 C frame。 */
  rivetlua_capi_userdata_result_a50 result =
      rivetlua_capi_newuserdata_dispatch_a50(
          state, generation, token, size, nuvalue);
  if (result.kind == RV_A1_ACTION_RETURN && result.value == 0)
    return result.pointer;
  if (result.kind == RV_A1_ACTION_RAISE && top != NULL &&
      top == rivetlua_capi_top_a1 && top->state == state &&
      top->rust_action_active == 0 &&
      rivetlua_capi_trampoline_probe_a1(
          state, generation, token) == RV_A1_OK &&
      rivetlua_capi_pending_matches_a1(
          state, generation, token, result.value) == RV_A1_OK) {
    *top->raised_status = result.value;
    longjmp(top->jump, 1);
  }
  if (top == NULL) {
    (void)rivetlua_capi_generic_panic_error_a3(state);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
  }
  abort();
}

#if LUA_VERSION_NUM >= 505
const char *lua_pushexternalstring(lua_State *state, const char *source,
                                   size_t len, lua_Alloc falloc, void *ud) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  /* Rust 完成 owner 接管與回滾，C frame 才能消費 pending 並跳轉。 */
  rivetlua_capi_external_string_result_b9 result =
      rivetlua_capi_pushexternalstring_dispatch_b9(
          state, generation, token, source, len, falloc, ud);
  if (result.kind == RV_A1_ACTION_RETURN && result.value == 0)
    return result.pointer;
  if (result.kind == RV_A1_ACTION_RAISE && top != NULL &&
      top == rivetlua_capi_top_a1 && top->state == state &&
      top->rust_action_active == 0 &&
      rivetlua_capi_trampoline_probe_a1(
          state, generation, token) == RV_A1_OK &&
      rivetlua_capi_pending_matches_a1(
          state, generation, token, result.value) == RV_A1_OK) {
    *top->raised_status = result.value;
    longjmp(top->jump, 1);
  }
  if (result.kind == RV_A1_ACTION_REJECT && top == NULL)
    return NULL;
  abort();
}
#endif

static int rivetlua_b3_raise(lua_State *state, uint64_t generation,
                            uint64_t token, int32_t kind, int32_t value) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (kind == RV_A1_ACTION_RAISE && top != NULL &&
      top->state == state && top->rust_action_active == 0 &&
      rivetlua_capi_trampoline_probe_a1(state, generation, token) == RV_A1_OK &&
      rivetlua_capi_pending_matches_a1(state, generation, token, value) == RV_A1_OK) {
    *top->raised_status = value;
    longjmp(top->jump, 1);
  }
  if (kind == RV_A1_ACTION_REJECT && top == NULL) return 0;
  abort();
}

lua_State *lua_newthread(lua_State *state) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  rivetlua_capi_newthread_result_b3 result =
      rivetlua_capi_newthread_dispatch_b3(state, generation, token);
  if (result.kind == RV_A1_ACTION_RETURN && result.value == 0)
    return result.pointer;
  (void)rivetlua_b3_raise(state, generation, token, result.kind, result.value);
  return NULL;
}

int lua_pushthread(lua_State *state) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  rivetlua_capi_pushthread_result_b3 result =
      rivetlua_capi_pushthread_dispatch_b3(state, generation, token);
  if (result.kind == RV_A1_ACTION_RETURN && result.value == 0)
    return result.answer;
  (void)rivetlua_b3_raise(state, generation, token, result.kind, result.value);
  return 0;
}

static char *rivetlua_buffer_call_a49(
    lua_State *state, luaL_Buffer *buffer, int32_t operation,
    const char *source, const char *pattern, const char *replacement,
    size_t size) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  /* Rust 完整返回後，才檢查 pending 並由純 C frame 跳轉。 */
  rivetlua_capi_buffer_result_a49 result = rivetlua_capi_buffer_dispatch_a49(
      state, generation, token, buffer, operation, source, pattern,
      replacement, size);
  if (result.kind == RV_A1_ACTION_RETURN && result.value == 0)
    return result.pointer;
  if (result.kind == RV_A1_ACTION_RAISE && top != NULL &&
      top == rivetlua_capi_top_a1 && top->state == state &&
      top->rust_action_active == 0 &&
      rivetlua_capi_trampoline_probe_a1(
          state, generation, token) == RV_A1_OK &&
      rivetlua_capi_pending_matches_a1(
          state, generation, token, result.value) == RV_A1_OK) {
    *top->raised_status = result.value;
    longjmp(top->jump, 1);
  }
  abort();
}

static lua_State *rivetlua_buffer_state_a49(luaL_Buffer *buffer) {
  if (buffer == NULL) abort();
  return ((rivetlua_buffer_prefix_a49 *)buffer)->state;
}

void luaL_buffinit(lua_State *state, luaL_Buffer *buffer) {
  (void)rivetlua_buffer_call_a49(
      state, buffer, RV_A1_BUFFER_INIT, NULL, NULL, NULL, 0);
}

char *luaL_prepbuffsize(luaL_Buffer *buffer, size_t size) {
  return rivetlua_buffer_call_a49(
      rivetlua_buffer_state_a49(buffer), buffer, RV_A1_BUFFER_PREP,
      NULL, NULL, NULL, size);
}

void luaL_addlstring(luaL_Buffer *buffer, const char *source, size_t len) {
  (void)rivetlua_buffer_call_a49(
      rivetlua_buffer_state_a49(buffer), buffer, RV_A1_BUFFER_ADDLSTRING,
      source, NULL, NULL, len);
}

void luaL_addstring(luaL_Buffer *buffer, const char *source) {
  (void)rivetlua_buffer_call_a49(
      rivetlua_buffer_state_a49(buffer), buffer, RV_A1_BUFFER_ADDSTRING,
      source, NULL, NULL, 0);
}

void luaL_addvalue(luaL_Buffer *buffer) {
  (void)rivetlua_buffer_call_a49(
      rivetlua_buffer_state_a49(buffer), buffer, RV_A1_BUFFER_ADDVALUE,
      NULL, NULL, NULL, 0);
}

void luaL_pushresult(luaL_Buffer *buffer) {
  (void)rivetlua_buffer_call_a49(
      rivetlua_buffer_state_a49(buffer), buffer, RV_A1_BUFFER_PUSHRESULT,
      NULL, NULL, NULL, 0);
}

void luaL_pushresultsize(luaL_Buffer *buffer, size_t size) {
  (void)rivetlua_buffer_call_a49(
      rivetlua_buffer_state_a49(buffer), buffer, RV_A1_BUFFER_PUSHRESULTSIZE,
      NULL, NULL, NULL, size);
}

char *luaL_buffinitsize(lua_State *state, luaL_Buffer *buffer, size_t size) {
  return rivetlua_buffer_call_a49(
      state, buffer, RV_A1_BUFFER_BUFFINITSIZE, NULL, NULL, NULL, size);
}

void luaL_addgsub(luaL_Buffer *buffer, const char *source,
                  const char *pattern, const char *replacement) {
  (void)rivetlua_buffer_call_a49(
      rivetlua_buffer_state_a49(buffer), buffer, RV_A1_BUFFER_ADDGSUB,
      source, pattern, replacement, 0);
}

/* 六個嚴格入口共用的錯誤邊界：Rust 已完整返回，且只跳到目前 C checkpoint。 */
static rivetlua_capi_strict_result_b2 rivetlua_b2_finish(
    lua_State *state, uint64_t generation, uint64_t token,
    rivetlua_capi_strict_result_b2 result) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (result.kind == RV_A1_ACTION_RETURN) return result;
  if (result.kind == RV_A1_ACTION_RAISE && top != NULL &&
      top == rivetlua_capi_top_a1 && top->state == state &&
      top->rust_action_active == 0 &&
      rivetlua_capi_trampoline_probe_a1(state, generation, token) == RV_A1_OK &&
      rivetlua_capi_pending_matches_a1(state, generation, token, result.value) == RV_A1_OK) {
    *top->raised_status = result.value;
    longjmp(top->jump, 1);
  }
  abort();
}

static rivetlua_capi_strict_result_b2 rivetlua_b2_aux(
    lua_State *state, int32_t operation, int arg, int tag,
    const char *name, const char *const *choices) {
  enum { RV_A3_AUX_SEMANTIC_ERROR = 40,
         RV_A3_OPTION_TYPE = 1, RV_A3_OPTION_INVALID = 2 };
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  lua_Debug caller;
  int lua_caller = lua_getstack(state, 1, &caller) &&
      lua_getinfo(state, "S", &caller) && caller.what != NULL &&
      (strcmp(caller.what, "Lua") == 0 || strcmp(caller.what, "main") == 0);
  rivetlua_capi_strict_result_b2 result = (lua_caller || top == NULL)
      ? rivetlua_capi_aux_dispatch_public_a3(
            state, generation, token, operation, arg, tag, name, choices)
      : rivetlua_capi_aux_dispatch_b2(
            state, generation, token, operation, arg, tag, name, choices);
  if (result.kind == RV_A3_AUX_SEMANTIC_ERROR) {
    /* Rust 已釋放所有 borrow；官方診斷及非局部跳轉只在此 C frame。 */
    if (operation == RV_A1_AUX_CHECKTYPE)
      (void)luaL_typeerror(state, arg, lua_typename(state, tag));
    else if (operation == RV_A1_AUX_CHECKANY)
      (void)luaL_argerror(state, arg, "value expected");
    else if (operation == RV_A1_AUX_CHECKUDATA)
      (void)luaL_typeerror(state, arg, name);
    else if (operation == RV_A1_AUX_CHECKOPTION &&
             result.value == RV_A3_OPTION_TYPE)
      (void)luaL_typeerror(state, arg, "string");
    else if (operation == RV_A1_AUX_CHECKOPTION &&
             result.value == RV_A3_OPTION_INVALID) {
      const char *selected = name != NULL && lua_isnoneornil(state, arg)
          ? name : lua_tostring(state, arg);
      const char *message = lua_pushfstring(state, "invalid option '%s'", selected);
      (void)luaL_argerror(state, arg, message);
    }
    abort();
  }
  if (top == NULL && result.kind != RV_A1_ACTION_RETURN) {
    (void)rivetlua_capi_generic_panic_error_a3(state);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
    abort();
  }
  return rivetlua_b2_finish(state, generation, token, result);
}

void luaL_checktype(lua_State *state, int arg, int tag) {
  (void)rivetlua_b2_aux(state, RV_A1_AUX_CHECKTYPE, arg, tag, NULL, NULL);
}

void luaL_checkany(lua_State *state, int arg) {
  (void)rivetlua_b2_aux(state, RV_A1_AUX_CHECKANY, arg, 0, NULL, NULL);
}

void *luaL_checkudata(lua_State *state, int arg, const char *name) {
  return rivetlua_b2_aux(state, RV_A1_AUX_CHECKUDATA,
                         arg, 0, name, NULL).pointer;
}

int luaL_checkoption(lua_State *state, int arg, const char *def,
                     const char *const choices[]) {
  return rivetlua_b2_aux(state, RV_A1_AUX_CHECKOPTION,
                         arg, 0, def, choices).value;
}

static void rivetlua_b2_append(luaL_Buffer *buffer, const char *part, size_t length) {
  luaL_addlstring(buffer, part, length);
}

static void rivetlua_b2_number(luaL_Buffer *buffer, double value) {
  char bytes[128];
#ifdef RV_LUA55_B2
  int length = snprintf(bytes, sizeof(bytes), "%.15g", value);
  if (length < 0 || (size_t)length >= sizeof(bytes)) abort();
  if (strtod(bytes, NULL) != value)
    length = snprintf(bytes, sizeof(bytes), "%.17g", value);
#else
  int length = snprintf(bytes, sizeof(bytes), "%.14g", value);
#endif
  if (length < 0 || (size_t)length >= sizeof(bytes)) abort();
  size_t index = strspn(bytes, "-0123456789");
  if (index == (size_t)length) {
    if ((size_t)length + 2 > sizeof(bytes)) abort();
    bytes[length++] = localeconv()->decimal_point[0];
    bytes[length++] = '0';
  }
  rivetlua_b2_append(buffer, bytes, (size_t)length);
}

static void rivetlua_b2_integer(luaL_Buffer *buffer, long long value) {
  char bytes[64];
  int length = snprintf(bytes, sizeof(bytes), "%lld", value);
  if (length < 0 || (size_t)length >= sizeof(bytes)) abort();
  rivetlua_b2_append(buffer, bytes, (size_t)length);
}

static void rivetlua_b2_utf8(luaL_Buffer *buffer, unsigned long value) {
  char bytes[8];
  int count = 1;
  if (value > 0x7FFFFFFFUL) abort();
  if (value < 0x80)
    bytes[7] = (char)value;
  else {
    unsigned int first = 0x3f;
    do {
      bytes[8 - (count++)] = (char)(0x80 | (value & 0x3f));
      value >>= 6;
      first >>= 1;
    } while (value > first);
    bytes[8 - count] = (char)((~first << 1) | value);
  }
  rivetlua_b2_append(buffer, bytes + 8 - count, (size_t)count);
}

static const char *rivetlua_b2_vformat(lua_State *state,
                                      const char *format, va_list arguments) {
  luaL_Buffer buffer;
  luaL_buffinit(state, &buffer);
  const char *cursor = format;
  const char *mark;
  while ((mark = strchr(cursor, '%')) != NULL) {
    rivetlua_b2_append(&buffer, cursor, (size_t)(mark - cursor));
    const char specifier = mark[1];
    char bytes[128];
    int length;
    switch (specifier) {
      case 's': {
        const char *source = va_arg(arguments, char *);
        if (source == NULL) source = "(null)";
        rivetlua_b2_append(&buffer, source, strlen(source));
        break;
      }
      case 'c': {
        char value = (char)(unsigned char)va_arg(arguments, int);
        rivetlua_b2_append(&buffer, &value, 1);
        break;
      }
      case 'd':
        rivetlua_b2_integer(&buffer, (long long)va_arg(arguments, int));
        break;
      case 'I':
        rivetlua_b2_integer(&buffer, va_arg(arguments, long long));
        break;
      case 'f':
        rivetlua_b2_number(&buffer, va_arg(arguments, double));
        break;
      case 'p': {
        void *pointer = va_arg(arguments, void *);
        length = snprintf(bytes, sizeof(bytes), "%p", pointer);
        if (length < 0 || (size_t)length >= sizeof(bytes)) abort();
        rivetlua_b2_append(&buffer, bytes, (size_t)length);
        break;
      }
      case 'U':
#ifdef RV_LUA55_B2
        rivetlua_b2_utf8(&buffer, (uint32_t)va_arg(arguments, unsigned long));
#else
        rivetlua_b2_utf8(&buffer, (unsigned long)va_arg(arguments, long));
#endif
        break;
      case '%':
        rivetlua_b2_append(&buffer, "%", 1);
        break;
      default:
#ifdef RV_LUA55_B2
        rivetlua_b2_append(&buffer, mark, specifier == '\0' ? 1 : 2);
#else
        {
          const char prefix[] = "invalid option '%";
          const char suffix[] = "' to 'lua_pushfstring'";
          char message[sizeof(prefix) + sizeof(suffix)];
          memcpy(message, prefix, sizeof(prefix) - 1);
          message[sizeof(prefix) - 1] = specifier;
          memcpy(message + sizeof(prefix), suffix, sizeof(suffix) - 1);
          rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
          uint64_t generation = top == NULL ? 0 : top->generation;
          uint64_t token = top == NULL ? 0 : top->token;
          (void)rivetlua_b2_finish(state, generation, token,
              rivetlua_capi_format_error_b2(state, generation, token,
                  &buffer, message, sizeof(prefix) + sizeof(suffix) - 1));
          abort();
        }
#endif
    }
    if (specifier == '\0') {
      cursor = mark + 1;
      break;
    }
    cursor = mark + 2;
  }
  rivetlua_b2_append(&buffer, cursor, strlen(cursor));
  luaL_pushresult(&buffer);
  const char *result = lua_tolstring(state, -1, NULL);
  if (result == NULL) abort();
  return result;
}

#ifdef RV_LUA55_B2
typedef struct {
  const char *format;
  va_list *arguments;
  const char *result;
} rivetlua_b2_format_context;

static rivetlua_capi_action_a1 rivetlua_b2_format_action(
    void *opaque, uint64_t generation, uint64_t token, void *context) {
  (void)generation;
  (void)token;
  rivetlua_b2_format_context *format = (rivetlua_b2_format_context *)context;
  format->result = rivetlua_b2_vformat(
      (lua_State *)opaque, format->format, *format->arguments);
  return (rivetlua_capi_action_a1){RV_A1_ACTION_RETURN, 0};
}

/* 5.5 先在純 C 內層 checkpoint 收斂 formatter 配置失敗，然後結束副本 va_list。 */
static const char *rivetlua_b2_vformat_protected(
    lua_State *state, const char *format, va_list arguments) {
  va_list copy;
  va_copy(copy, arguments);
  rivetlua_b2_format_context context = {format, &copy, NULL};
  rivetlua_capi_outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, rivetlua_b2_format_action, &context);
  va_end(copy);
  if (outcome.kind == RV_A1_OUT_NORMAL && context.result != NULL)
    return context.result;
  if (outcome.kind == RV_A1_OUT_RAISED &&
      outcome.value == RV_A1_ERROR_ALLOCATION) {
    int32_t class_code = 0;
    if (rivetlua_capi_error_consume_a1(state, &class_code) == RV_A1_OK &&
        class_code == RV_A1_ERROR_ALLOCATION)
      return NULL; /* 已恢復單一頂端 canonical memory error slot。 */
  }
  /* A1 admission 未預留 error slot 時屬既有 fail-stop 邊界，不能偽裝成 NULL。 */
  abort();
}
#endif

const char *lua_pushvfstring(lua_State *state, const char *format,
                            va_list arguments) {
#ifdef RV_LUA55_B2
  return rivetlua_b2_vformat_protected(state, format, arguments);
#else
  return rivetlua_b2_vformat(state, format, arguments);
#endif
}

const char *lua_pushfstring(lua_State *state, const char *format, ...) {
  va_list arguments;
  va_start(arguments, format);
#ifdef RV_LUA55_B2
  const char *result = lua_pushvfstring(state, format, arguments);
  va_end(arguments);
  if (result == NULL) {
    rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
    if (top == NULL || top->state != state || top->rust_action_active != 0 ||
        rivetlua_capi_error_prepare_a1(state, top->generation, top->token,
                                       RV_A1_ERROR_ALLOCATION) != RV_A1_OK)
      abort();
    rivetlua_capi_strict_result_b2 raised = {
        RV_A1_ACTION_RAISE, RV_A1_ERROR_ALLOCATION, NULL};
    (void)rivetlua_b2_finish(state, top->generation, top->token, raised);
    abort();
  }
#else
  const char *result = rivetlua_b2_vformat(state, format, arguments);
  va_end(arguments);
#endif
  return result;
}

typedef void (*rivetlua_capi_raised_hook_a1)(
    lua_State *state, void *context, rivetlua_capi_outcome_a1 *outcome);

static rivetlua_capi_outcome_a1 rivetlua_capi_trampoline_protect_impl_a1(
    void *state, rivetlua_capi_action_fn_a1 action_fn, void *context,
    rivetlua_capi_raised_hook_a1 raised_hook) {
  rivetlua_capi_outcome_a1 outcome = {RV_A1_OUT_REJECTED, RV_A1_REJECT_NULL};
  if (state == NULL) return outcome;
  if (action_fn == NULL) {
    outcome.value = RV_A1_REJECT_INVALID_ACTION;
    return outcome;
  }

  rivetlua_capi_checkpoint_a1 checkpoint;
  int32_t entered = rivetlua_capi_checkpoint_enter_a1(
      state, &checkpoint.generation, &checkpoint.token,
      &checkpoint.previous_state_token);
  if (entered != RV_A1_OK) {
    outcome.value = entered;
    return outcome;
  }
  checkpoint.state = state;
  checkpoint.previous = rivetlua_capi_top_a1;
  volatile int32_t raised_status = 0;
  checkpoint.raised_status = &raised_status;
  checkpoint.rust_action_active = 0;
  checkpoint.yieldable_a5 = 0;
  rivetlua_capi_top_a1 = &checkpoint;

  /* 跳轉目標與 jump 呼叫都在此 C frame；Rust action 已完整返回。 */
  if (setjmp(checkpoint.jump) == 0) {
    rivetlua_capi_action_a1 action = action_fn(
        state, checkpoint.generation, checkpoint.token, context);
    if (action.kind == RV_A1_ACTION_RETURN) {
      outcome.kind = RV_A1_OUT_NORMAL;
      outcome.value = action.value;
    } else if (action.kind == RV_A1_ACTION_REJECT) {
      outcome.kind = RV_A1_OUT_REJECTED;
      outcome.value = action.value;
    } else if (action.kind == RV_A1_ACTION_RAISE) {
      int32_t matched = rivetlua_capi_trampoline_probe_a1(
          state, checkpoint.generation, checkpoint.token);
      if (matched == RV_A1_OK) {
        matched = rivetlua_capi_pending_matches_a1(
            state, checkpoint.generation, checkpoint.token, action.value);
      }
      if (matched == RV_A1_OK) {
        raised_status = action.value;
        longjmp(checkpoint.jump, 1);
      }
      outcome.value = matched;
    } else {
      outcome.value = RV_A1_REJECT_INVALID_ACTION;
    }
    /* panic、拒絕及不合法 action 若已 prepare，將同一 slot 原封搬回。 */
    int32_t cancelled = rivetlua_capi_pending_cancel_a1(
        state, checkpoint.generation, checkpoint.token);
    if (cancelled < RV_A1_OK) {
      outcome.kind = RV_A1_OUT_REJECTED;
      outcome.value = cancelled;
    } else if (cancelled == RV_A1_CANCELLED &&
               outcome.kind == RV_A1_OUT_NORMAL) {
      outcome.kind = RV_A1_OUT_REJECTED;
      outcome.value = RV_A1_REJECT_INVALID_ACTION;
    }
  } else {
    outcome.kind = RV_A1_OUT_RAISED;
    outcome.value = raised_status;
    if (raised_hook != NULL)
      raised_hook((lua_State *)state, context, &outcome);
  }

  rivetlua_capi_top_a1 = checkpoint.previous;
  int32_t exited = rivetlua_capi_checkpoint_exit_a1(
      state, checkpoint.generation, checkpoint.token,
      checkpoint.previous_state_token);
  if (exited != RV_A1_OK) {
    outcome.kind = RV_A1_OUT_REJECTED;
    outcome.value = exited;
  }
  return outcome;
}

rivetlua_capi_outcome_a1 rivetlua_capi_trampoline_protect_a1(
    void *state, rivetlua_capi_action_fn_a1 action_fn, void *context) {
  return rivetlua_capi_trampoline_protect_impl_a1(
      state, action_fn, context, NULL);
}

/* B3：C reader／writer frame 是唯一 callback 與 longjmp 邊界。Rust session
   只在 callback 已返回時短借 VM，並由本 frame 在所有退出路徑釋放。 */
typedef struct { void *pointer; int32_t fault; } rivetlua_b3_load_start;
typedef struct {
  void *pointer;
  const void *data;
  size_t len;
  int32_t fault;
} rivetlua_b3_dump_start;

extern rivetlua_b3_load_start rivetlua_capi_load_begin_b3(
    lua_State *state, const char *name, int file_style);
extern int rivetlua_capi_load_append_b3(
    lua_State *state, void *session, const char *bytes, size_t len);
extern int rivetlua_capi_load_finish_b3(
    lua_State *state, void *session, const char *mode);
extern void rivetlua_capi_load_drop_b3(void *session);
extern int rivetlua_capi_load_error_b3(
    lua_State *state, uint64_t generation, uint64_t token, int fault);
extern int rivetlua_capi_restore_reader_stack_b3(
    lua_State *state, int original_top);
extern rivetlua_b3_dump_start rivetlua_capi_dump_begin_b3(
    lua_State *state, int strip);
extern void rivetlua_capi_dump_drop_b3(void *session);

enum { RV_B3_SYNTAX = 1, RV_B3_MEMORY = 2, RV_B3_BUDGET = 3,
       RV_B3_FILE = 4 };

typedef struct {
  lua_Reader reader;
  void *data;
  const char *chunkname;
  const char *mode;
  int file_style;
  FILE *file;
  int own_file;
  int initial_fault;
  int result_status;
  int original_top;
  void *session;
} rivetlua_b3_load_context;

static int rivetlua_b3_load_status(int fault) {
  if (fault == RV_B3_SYNTAX) return LUA_ERRSYNTAX;
  if (fault == RV_B3_MEMORY) return LUA_ERRMEM;
  if (fault == RV_B3_FILE) return LUA_ERRFILE;
  return LUA_ERRRUN;
}

static rivetlua_capi_action_a1 rivetlua_b3_load_action(
    void *opaque, uint64_t generation, uint64_t token, void *context) {
  lua_State *state = (lua_State *)opaque;
  rivetlua_b3_load_context *load = (rivetlua_b3_load_context *)context;
  int fault = load->initial_fault;
  if (fault == 0) {
    rivetlua_b3_load_start start = rivetlua_capi_load_begin_b3(
        state, load->chunkname, load->file_style);
    load->session = start.pointer;
    fault = start.fault;
  }
  while (fault == 0) {
    size_t size = 0;
    const char *part = load->reader(state, load->data, &size);
    if (part == NULL || size == 0) break;
    fault = rivetlua_capi_load_append_b3(state, load->session, part, size);
  }
  if (load->file != NULL && ferror(load->file)) fault = RV_B3_FILE;
  if (load->own_file && load->file != NULL) {
    if (fclose(load->file) != 0) fault = RV_B3_FILE;
    load->file = NULL;
  }
#if LUA_VERSION_NUM >= 505
  /* 5.5 reader 可變動 stack；片段已複製後才恢復原 top。 */
  int restore_fault = rivetlua_capi_restore_reader_stack_b3(
      state, load->original_top);
  if (restore_fault != 0) fault = restore_fault;
#endif
  if (fault == 0)
    fault = rivetlua_capi_load_finish_b3(state, load->session, load->mode);
  if (fault == 0) {
    rivetlua_capi_action_a1 done = {RV_A1_ACTION_RETURN, LUA_OK};
    return done;
  }
  load->result_status = rivetlua_b3_load_status(fault);
  int class_code = rivetlua_capi_load_error_b3(state, generation, token, fault);
  if (class_code == RV_A1_ERROR_ALLOCATION)
    load->result_status = LUA_ERRMEM;
  if (class_code <= 0) {
    rivetlua_capi_action_a1 rejected = {RV_A1_ACTION_REJECT,
                                          RV_A1_REJECT_INVALID_ACTION};
    return rejected;
  }
  rivetlua_capi_action_a1 raised = {RV_A1_ACTION_RAISE, class_code};
  return raised;
}

static void rivetlua_b3_load_raised(
    lua_State *state, void *context, rivetlua_capi_outcome_a1 *outcome) {
  rivetlua_b3_load_context *load = (rivetlua_b3_load_context *)context;
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (top == NULL || top->state != state || top->rust_action_active != 0 ||
      rivetlua_capi_trampoline_probe_a1(
          state, top->generation, top->token) != RV_A1_OK ||
      rivetlua_capi_pending_matches_a1(
          state, top->generation, top->token, outcome->value) != RV_A1_OK)
    abort();
  size_t error_top = (size_t)lua_gettop(state);
  int captured = rivetlua_capi_close_capture_error_b7(state, error_top);
  if (captured <= 0) abort();
  int closed = rivetlua_b7_close_drive(
      state, (size_t)load->original_top, (size_t)load->original_top,
      captured, 0);
  if (closed >= 0) abort();
  outcome->value = -closed;
  if (rivetlua_capi_pending_matches_a1(
          state, top->generation, top->token, outcome->value) != RV_A1_OK)
    abort();
}

static int rivetlua_b3_load_common(rivetlua_b3_load_context *load,
                                   lua_State *state) {
  load->session = NULL;
  load->result_status = 0;
  load->original_top = lua_gettop(state);
  rivetlua_capi_outcome_a1 outcome = rivetlua_capi_trampoline_protect_impl_a1(
      state, rivetlua_b3_load_action, load, rivetlua_b3_load_raised);
  rivetlua_capi_load_drop_b3(load->session);
  if (load->own_file && load->file != NULL) {
    (void)fclose(load->file);
    load->file = NULL;
  }
  if (outcome.kind == RV_A1_OUT_NORMAL) return outcome.value;
  if (outcome.kind == RV_A1_OUT_RAISED) {
    int class_code = 0;
    if (rivetlua_capi_error_consume_a1(state, &class_code) != RV_A1_OK)
      abort();
    if (load->result_status != 0)
      return class_code == RV_A1_ERROR_ALLOCATION
          ? LUA_ERRMEM : load->result_status;
    /* reader 的原錯誤或 __close 替代錯誤已在同一 checkpoint 歸位。 */
    return class_code == RV_A1_ERROR_ALLOCATION ? LUA_ERRMEM : LUA_ERRRUN;
  }
  return LUA_ERRMEM;
}

int lua_load(lua_State *state, lua_Reader reader, void *data,
             const char *chunkname, const char *mode) {
  rivetlua_b3_load_context load = {
    .reader = reader, .data = data, .chunkname = chunkname,
    .mode = mode, .file_style = 0, .file = NULL,
    .own_file = 0, .initial_fault = 0,
  };
  if (reader == NULL) load.initial_fault = RV_B3_SYNTAX;
  return rivetlua_b3_load_common(&load, state);
}

typedef struct {
  const char *bytes;
  size_t len;
  int used;
} rivetlua_b3_buffer;

static const char *rivetlua_b3_buffer_reader(
    lua_State *state, void *opaque, size_t *size) {
  rivetlua_b3_buffer *buffer = (rivetlua_b3_buffer *)opaque;
  (void)state;
  if (buffer->used) { *size = 0; return NULL; }
  buffer->used = 1;
  *size = buffer->len;
  return buffer->bytes;
}

int luaL_loadbufferx(lua_State *state, const char *bytes, size_t len,
                     const char *name, const char *mode) {
  rivetlua_b3_buffer buffer = {bytes, len, 0};
  rivetlua_b3_load_context load = {
    .reader = rivetlua_b3_buffer_reader, .data = &buffer,
    .chunkname = name, .mode = mode, .file_style = 0,
    .file = NULL, .own_file = 0,
    .initial_fault = bytes == NULL && len != 0 ? RV_B3_SYNTAX : 0,
  };
  return rivetlua_b3_load_common(&load, state);
}

int luaL_loadstring(lua_State *state, const char *source) {
  if (source == NULL)
    return luaL_loadbufferx(state, source, 1, source,
#if LUA_VERSION_NUM >= 505
                            "t"
#else
                            NULL
#endif
                            );
  return luaL_loadbufferx(state, source, strlen(source), source,
#if LUA_VERSION_NUM >= 505
                          "t"
#else
                          NULL
#endif
                          );
}

typedef struct { FILE *file; char bytes[4096]; } rivetlua_b3_file_reader;

static const char *rivetlua_b3_read_file(
    lua_State *state, void *opaque, size_t *size) {
  rivetlua_b3_file_reader *reader = (rivetlua_b3_file_reader *)opaque;
  (void)state;
  *size = fread(reader->bytes, 1, sizeof(reader->bytes), reader->file);
  return *size == 0 ? NULL : reader->bytes;
}

int luaL_loadfilex(lua_State *state, const char *filename, const char *mode) {
  FILE *file = filename == NULL ? stdin : fopen(filename, "rb");
  rivetlua_b3_file_reader reader = {file, {0}};
  rivetlua_b3_load_context load = {
    .reader = rivetlua_b3_read_file, .data = &reader,
    .chunkname = filename == NULL ? "=stdin" : filename,
    .mode = mode, .file_style = filename == NULL ? 2 : 1,
    .file = file, .own_file = filename != NULL && file != NULL,
    .initial_fault = file == NULL ? RV_B3_FILE : 0,
  };
  return rivetlua_b3_load_common(&load, state);
}

typedef struct {
  lua_Writer writer;
  void *data;
  int strip;
  int original_top;
  void *session;
  int output_status;
  rivetlua_b3_dump_start dump;
} rivetlua_b3_dump_context;

static rivetlua_capi_action_a1 rivetlua_b3_dump_action(
    void *opaque, uint64_t generation, uint64_t token, void *context) {
  lua_State *state = (lua_State *)opaque;
  rivetlua_b3_dump_context *dump = (rivetlua_b3_dump_context *)context;
  dump->dump = rivetlua_capi_dump_begin_b3(state, dump->strip);
  dump->session = dump->dump.pointer;
  if (dump->dump.fault != 0) {
    if (dump->dump.fault != RV_B3_MEMORY) {
      rivetlua_capi_action_a1 failed = {RV_A1_ACTION_RETURN, 1};
      return failed;
    }
    int class_code = rivetlua_capi_load_error_b3(
        state, generation, token, RV_B3_MEMORY);
    if (class_code <= 0) {
      rivetlua_capi_action_a1 rejected = {RV_A1_ACTION_REJECT,
                                            RV_A1_REJECT_INVALID_ACTION};
      return rejected;
    }
    rivetlua_capi_action_a1 raised = {RV_A1_ACTION_RAISE, class_code};
    return raised;
  }
  dump->output_status = dump->writer(
      state, dump->dump.data, dump->dump.len, dump->data);
#if LUA_VERSION_NUM >= 505
  if (dump->output_status == 0)
    dump->output_status = dump->writer(state, NULL, 0, dump->data);
  lua_settop(state, dump->original_top);
#endif
  rivetlua_capi_action_a1 done = {RV_A1_ACTION_RETURN,
                                  dump->output_status};
  return done;
}

int lua_dump(lua_State *state, lua_Writer writer, void *data, int strip) {
  if (writer == NULL) return 1;
  rivetlua_b3_dump_context dump = {
    .writer = writer, .data = data, .strip = strip,
    .original_top = lua_gettop(state), .session = NULL,
    .output_status = 0,
  };
  rivetlua_capi_outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, rivetlua_b3_dump_action, &dump);
  rivetlua_capi_dump_drop_b3(dump.session);
  if (outcome.kind == RV_A1_OUT_NORMAL) return outcome.value;
  if (outcome.kind == RV_A1_OUT_RAISED) {
    int class_code = 0;
    if (rivetlua_capi_error_consume_a1(state, &class_code) != RV_A1_OK)
      abort();
    return lua_error(state);
  }
  return 1;
}
