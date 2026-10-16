/* FZ-006：每個輸入 byte 的低四位是固定指令，高四位是小型整數參數。 */
#include <lua.h>
#include <lauxlib.h>
#include <rivetlua_abi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FZ_MAX_OPS 64
#define FZ_STACK_CAP 32
#define FZ_HEAP_CAP (1024u * 1024u)
#define FZ_ALLOC_SLOTS 4096

enum result { ACCEPTED = 0, REJECTED = 2, LIMIT = 3, FINDING = 4, BLOCKED = 5 };

typedef struct {
  void *pointers[FZ_ALLOC_SLOTS];
  size_t sizes[FZ_ALLOC_SLOTS];
  size_t live;
  size_t bytes;
  int inject_next;
  int inject_hit;
  int invalid_free;
  int heap_limit;
  int host_oom;
  unsigned normal_calls;
  unsigned error_calls;
  unsigned probe_calls;
  unsigned yield_calls;
  unsigned continuation_calls;
} case_context;

/* Lua allocator 契約：失敗的 realloc 保留舊 pointer；未知 pointer 絕不解參照或釋放。 */
static void *case_alloc(void *ud, void *ptr, size_t osize, size_t nsize) {
  case_context *ctx = (case_context *)ud;
  size_t slot = 0;
  size_t old_size = 0;
  void *next;
  int new_allocation = ptr == NULL;
  (void)osize;
  if (ptr != NULL) {
    while (slot < ctx->live && ctx->pointers[slot] != ptr) slot++;
    if (slot == ctx->live) {
      ctx->invalid_free = 1;
      return NULL;
    }
    old_size = ctx->sizes[slot];
  }
  if (nsize == 0) {
    if (ptr != NULL) {
      ctx->bytes -= old_size;
      ctx->live--;
      ctx->pointers[slot] = ctx->pointers[ctx->live];
      ctx->sizes[slot] = ctx->sizes[ctx->live];
      free(ptr);
    }
    return NULL;
  }
  if (ctx->inject_next) {
    ctx->inject_next = 0;
    ctx->inject_hit = 1;
    return NULL;
  }
  if ((new_allocation && ctx->live == FZ_ALLOC_SLOTS) ||
      nsize > FZ_HEAP_CAP - (ctx->bytes - old_size)) {
    ctx->heap_limit = 1;
    return NULL;
  }
  next = new_allocation ? malloc(nsize) : realloc(ptr, nsize);
  if (next == NULL) {
    ctx->host_oom = 1;
    return NULL;
  }
  ctx->bytes = ctx->bytes - old_size + nsize;
  if (new_allocation) slot = ctx->live++;
  ctx->pointers[slot] = next;
  ctx->sizes[slot] = nsize;
  return next;
}

static case_context *context_for(lua_State *state) {
  void *ud = NULL;
  (void)lua_getallocf(state, &ud);
  return (case_context *)ud;
}

static int fixed_error(lua_State *state) {
  lua_pushinteger(state, 901);
  return lua_error(state);
}

static int callback_value(lua_State *state) {
  case_context *ctx = context_for(state);
  int isnum = 0;
  lua_Integer value = lua_tointegerx(state, 1, &isnum);
  if (ctx == NULL || !isnum) return fixed_error(state);
  ctx->normal_calls++;
  lua_pushinteger(state, value + 1);
  return 1;
}

static int callback_source(lua_State *state) {
  case_context *ctx = context_for(state);
  if (ctx == NULL) return fixed_error(state);
  ctx->normal_calls++;
  lua_pushinteger(state, 42);
  return 1;
}

static int callback_upvalue(lua_State *state) {
  case_context *ctx = context_for(state);
  int has_capture = 0;
  int has_argument = 0;
  lua_Integer capture = lua_tointegerx(state, lua_upvalueindex(1), &has_capture);
  lua_Integer argument = lua_tointegerx(state, 1, &has_argument);
  if (ctx == NULL || !has_capture || !has_argument) return fixed_error(state);
  ctx->normal_calls++;
  lua_pushinteger(state, capture + argument);
  return 1;
}

static int callback_table(lua_State *state) {
  int isnum = 0;
  lua_Integer value = lua_tointegerx(state, 1, &isnum);
  if (!isnum) return fixed_error(state);
  lua_createtable(state, 1, 0);
  if (lua_type(state, -1) != LUA_TTABLE) return fixed_error(state);
  lua_pushinteger(state, value);
  lua_rawseti(state, -2, 1);
  if (lua_rawgeti(state, -1, 1) != LUA_TNUMBER ||
      lua_tointegerx(state, -1, &isnum) != value || !isnum)
    return fixed_error(state);
  return 1;
}

static int callback_error(lua_State *state) {
  case_context *ctx = context_for(state);
  if (ctx == NULL) return fixed_error(state);
  ctx->error_calls++;
  return fixed_error(state);
}

static int callback_alloc_probe(lua_State *state) {
  case_context *ctx = context_for(state);
  if (ctx == NULL) return fixed_error(state);
  ctx->probe_calls++;
  if (lua_newuserdatauv(state, 128, 0) == NULL) {
    /* 失敗後撤銷注入，讓錯誤物件仍在同一純 C pcall checkpoint 中建立。 */
    ctx->inject_next = 0;
    return fixed_error(state);
  }
  return 1;
}

static int callback_continue(lua_State *state, int status, lua_KContext context) {
  case_context *ctx = context_for(state);
  if (ctx == NULL || status != LUA_YIELD || context < 0 || context > 15)
    return fixed_error(state);
  ctx->continuation_calls++;
  lua_pushinteger(state, (lua_Integer)context + 18);
  return 1;
}

static int callback_yield(lua_State *state) {
  case_context *ctx = context_for(state);
  int isnum = 0;
  lua_Integer value = lua_tointegerx(state, 1, &isnum);
  if (ctx == NULL || !isnum || value < 0 || value > 15)
    return fixed_error(state);
  ctx->yield_calls++;
  lua_pushinteger(state, 17);
  return lua_yieldk(state, 1, (lua_KContext)value, callback_continue);
}

static int abi_matches(void) {
  rivetlua_abi_identity actual = rivetlua_abi_identity_v1();
  rivetlua_abi_identity expected = rivetlua_expected_abi_identity();
  return actual.revision == expected.revision &&
      actual.profile == expected.profile &&
      actual.numeric_config == expected.numeric_config &&
      actual.pointer_width_bits == expected.pointer_width_bits &&
      actual.endianness == expected.endianness &&
      actual.reserved_zero == expected.reserved_zero &&
      memcmp(actual.target, expected.target, sizeof(actual.target)) == 0 &&
      memcmp(actual.header_set_sha256, expected.header_set_sha256, 32) == 0 &&
      memcmp(actual.lua_h_sha256, expected.lua_h_sha256, 32) == 0 &&
      memcmp(actual.lauxlib_h_sha256, expected.lauxlib_h_sha256, 32) == 0 &&
      memcmp(actual.luaconf_h_sha256, expected.luaconf_h_sha256, 32) == 0 &&
      memcmp(actual.layout, expected.layout, sizeof(actual.layout)) == 0;
}

static int pushed_function(lua_State *state, lua_CFunction function) {
  lua_pushcfunction(state, function);
  return lua_type(state, -1) == LUA_TFUNCTION;
}

static enum result run_value(lua_State *state, case_context *ctx, unsigned argument,
                             int with_upvalue) {
  int before = lua_gettop(state);
  unsigned calls = ctx->normal_calls;
  int status;
  int isnum = 0;
  if (before > FZ_STACK_CAP - 2) return LIMIT;
  if (with_upvalue) {
    lua_pushinteger(state, (lua_Integer)argument);
    lua_pushcclosure(state, callback_upvalue, 1);
    if (lua_type(state, -1) != LUA_TFUNCTION) return LIMIT;
    lua_pushinteger(state, 1);
  } else {
    if (!pushed_function(state, callback_value)) return LIMIT;
    lua_pushinteger(state, (lua_Integer)argument);
  }
  status = lua_pcall(state, 1, 1, 0);
  if (status != LUA_OK || lua_gettop(state) != before + 1 ||
      ctx->normal_calls != calls + 1 ||
      lua_tointegerx(state, -1, &isnum) != (lua_Integer)argument + 1 || !isnum)
    return status == LUA_ERRMEM ? LIMIT : FINDING;
  return ACCEPTED;
}

static enum result run_table(lua_State *state, unsigned argument) {
  int before = lua_gettop(state);
  int isnum = 0;
  int status;
  if (before > FZ_STACK_CAP - 2) return LIMIT;
  if (!pushed_function(state, callback_table)) return LIMIT;
  lua_pushinteger(state, (lua_Integer)argument);
  status = lua_pcall(state, 1, 1, 0);
  if (status != LUA_OK || lua_gettop(state) != before + 1 ||
      lua_tointegerx(state, -1, &isnum) != (lua_Integer)argument || !isnum)
    return status == LUA_ERRMEM ? LIMIT : FINDING;
  return ACCEPTED;
}

static enum result run_error(lua_State *state, case_context *ctx) {
  int before = lua_gettop(state);
  unsigned calls = ctx->error_calls;
  int status;
  if (before >= FZ_STACK_CAP) return LIMIT;
  if (!pushed_function(state, callback_error)) return LIMIT;
  status = lua_pcall(state, 0, 1, 0);
  if (status != LUA_ERRRUN || lua_gettop(state) != before + 1 ||
      ctx->error_calls != calls + 1)
    return status == LUA_ERRMEM ? LIMIT : FINDING;
  lua_settop(state, before);
  return ACCEPTED;
}

static enum result run_alloc_fault(lua_State *state, case_context *ctx) {
  int before = lua_gettop(state);
  unsigned calls = ctx->probe_calls;
  int status;
  int after;
  if (before >= FZ_STACK_CAP) return LIMIT;
  if (!pushed_function(state, callback_alloc_probe)) return LIMIT;
  ctx->inject_hit = 0;
  ctx->inject_next = 1;
  status = lua_pcall(state, 0, 1, 0);
  ctx->inject_next = 0;
  after = lua_gettop(state);
  if (!ctx->inject_hit) return BLOCKED;
  if (ctx->probe_calls > calls + 1 || after < before || after > before + 1 ||
      (status != LUA_OK && status != LUA_ERRMEM && status != LUA_ERRRUN) ||
      (status == LUA_OK &&
       (ctx->probe_calls != calls + 1 || after != before + 1 ||
        lua_type(state, -1) != LUA_TUSERDATA)))
    return FINDING;
  lua_settop(state, before);
  return ACCEPTED;
}

static enum result run_yield(lua_State *state, case_context *ctx, unsigned argument) {
  int before = lua_gettop(state);
  unsigned started = ctx->yield_calls;
  unsigned continued = ctx->continuation_calls;
  int results = -1;
  int status;
  lua_State *child;
  if (before >= FZ_STACK_CAP) return LIMIT;
  child = lua_newthread(state);
  if (child == NULL || lua_gettop(state) != before + 1 ||
      lua_type(state, -1) != LUA_TTHREAD) return LIMIT;
  if (!pushed_function(child, callback_yield)) return LIMIT;
  lua_pushinteger(child, (lua_Integer)argument);
  status = lua_resume(child, state, 1, &results);
  if (status != LUA_YIELD || results != 1 || lua_gettop(child) != 1 ||
      lua_tointegerx(child, -1, NULL) != 17 ||
      ctx->yield_calls != started + 1 || ctx->continuation_calls != continued)
    return status == LUA_ERRMEM ? LIMIT : FINDING;
  lua_settop(child, 0);
  results = -1;
  status = lua_resume(child, state, 0, &results);
  if (status != LUA_OK || results != 1 || lua_gettop(child) != 1 ||
      lua_tointegerx(child, -1, NULL) != (lua_Integer)argument + 18 ||
      ctx->yield_calls != started + 1 || ctx->continuation_calls != continued + 1)
    return status == LUA_ERRMEM ? LIMIT : FINDING;
  lua_settop(child, 0);
  lua_settop(state, before);
  return ACCEPTED;
}

static enum result run_source(lua_State *state, case_context *ctx, int expect_error) {
  static const char success[] =
#if RIVETLUA_PROFILE_ID == 55
      "global fzhost; "
#endif
      "return fzhost()";
  static const char failure[] =
#if RIVETLUA_PROFILE_ID == 55
      "global fzhost; "
#endif
      "fzhost(); local x = nil; return x + 1";
  int before = lua_gettop(state);
  unsigned calls = ctx->normal_calls;
  int status;
  if (before >= FZ_STACK_CAP) return LIMIT;
  status = luaL_loadstring(state, expect_error ? failure : success);
  if (status != LUA_OK) return status == LUA_ERRMEM ? LIMIT : FINDING;
  status = lua_pcall(state, 0, 1, 0);
  if (lua_gettop(state) != before + 1 || ctx->normal_calls != calls + 1 ||
      status != (expect_error ? LUA_ERRRUN : LUA_OK) ||
      (!expect_error && lua_tointegerx(state, -1, NULL) != 42))
    return status == LUA_ERRMEM ? LIMIT : FINDING;
  lua_settop(state, before);
  return ACCEPTED;
}

static enum result run_op(lua_State *state, case_context *ctx, unsigned byte) {
  unsigned opcode = byte & 15u;
  unsigned argument = byte >> 4;
  int before = lua_gettop(state);
  int index;
  enum result result;
  if (before < 0 || before > FZ_STACK_CAP) return FINDING;
  switch (opcode) {
    case 0: /* nil */
      if (before >= FZ_STACK_CAP) return LIMIT;
      lua_pushnil(state);
      break;
    case 1: /* bool */
      if (before >= FZ_STACK_CAP) return LIMIT;
      lua_pushboolean(state, argument & 1u);
      break;
    case 2: /* integer */
      if (before >= FZ_STACK_CAP) return LIMIT;
      lua_pushinteger(state, (lua_Integer)argument);
      break;
    case 3: /* 只從實際存在的 stack slot 複製。 */
      if (before == 0) return REJECTED;
      if (before >= FZ_STACK_CAP) return LIMIT;
      index = (int)(argument % (unsigned)before) + 1;
      lua_pushvalue(state, index);
      break;
    case 4: /* pop */
      if (before == 0) return REJECTED;
      lua_settop(state, before - 1);
      break;
    case 5: return run_table(state, argument);
    case 6: /* registry pseudo-index 是 header 定義的固定有效索引。 */
      if (before >= FZ_STACK_CAP) return LIMIT;
      if (lua_rawgeti(state, LUA_REGISTRYINDEX, LUA_RIDX_GLOBALS) != LUA_TTABLE)
        return FINDING;
      break;
    case 7: return run_value(state, ctx, argument, 0);
    case 8: return run_error(state, ctx);
    case 9: return run_alloc_fault(state, ctx);
    case 10: return run_yield(state, ctx, argument);
    case 11: return run_value(state, ctx, argument, 1);
    case 12: return run_source(state, ctx, 0);
    case 13: return run_source(state, ctx, 1);
    case 14: /* 已存在位置的 read；從不把輸入當索引或 pointer。 */
      if (before == 0) return REJECTED;
      index = (int)(argument % (unsigned)before) + 1;
      if (lua_type(state, index) == LUA_TNONE || lua_gettop(state) != before)
        return FINDING;
      return ACCEPTED;
    default: return REJECTED;
  }
  result = lua_gettop(state) == before + (opcode == 4 ? -1 : 1)
      ? ACCEPTED : FINDING;
  return result;
}

static int report(enum result result) {
  switch (result) {
    case ACCEPTED: puts("ACCEPTED"); break;
    case REJECTED: puts("REJECTED"); break;
    case LIMIT: puts("LIMIT"); break;
    case FINDING: puts("FINDING"); break;
    case BLOCKED: puts("BLOCKED"); break;
  }
  return (int)result;
}

int main(void) {
  unsigned char input[FZ_MAX_OPS + 1];
  size_t length = fread(input, 1, sizeof(input), stdin);
  case_context ctx = {0};
  lua_State *state = NULL;
  enum result result = ACCEPTED;
  size_t i;
  if (ferror(stdin)) return report(LIMIT);
  if (length > FZ_MAX_OPS) return report(LIMIT);
  if (length == 0) return report(REJECTED);
  if (!abi_matches()) return report(BLOCKED);
#if RIVETLUA_PROFILE_ID == 55
  state = lua_newstate(case_alloc, &ctx, 0);
#elif RIVETLUA_PROFILE_ID == 54
  state = lua_newstate(case_alloc, &ctx);
#else
#error "FZ-006 僅支援固定 Lua 5.5.1 與 5.4.9 profile"
#endif
  if (state == NULL)
    return report(ctx.invalid_free || ctx.live != 0 ? FINDING : LIMIT);
  if (!lua_checkstack(state, FZ_STACK_CAP + 4) ||
      !pushed_function(state, callback_source)) {
    result = LIMIT;
    goto cleanup;
  }
  lua_setglobal(state, "fzhost");
  if (lua_gettop(state) != 0) {
    result = FINDING;
    goto cleanup;
  }
  for (i = 0; i < length; i++) {
    result = run_op(state, &ctx, input[i]);
    if (result != ACCEPTED || ctx.invalid_free || ctx.heap_limit || ctx.host_oom)
      break;
  }
cleanup:
  ctx.inject_next = 0;
  lua_close(state);
  if (ctx.invalid_free || ctx.live != 0 || ctx.bytes != 0) result = FINDING;
  else if (ctx.heap_limit || ctx.host_oom) result = LIMIT;
  return report(result);
}
