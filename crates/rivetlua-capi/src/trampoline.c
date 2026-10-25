#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <locale.h>

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#include "trampoline_codes.h"

/* 各語意 kind 有獨立固定 C 位址；真正執行仍進既有 Rust VM。 */
extern int rivetlua_capi_builtin_push_target(lua_State *state, int kind);
extern int rivetlua_capi_debug_hook_guard_c14(
    lua_State *state, int setting, int mask, int count, size_t numeric_text_len);
extern int rivetlua_capi_base_load_direct_b3(lua_State *state);
static int rivetlua_capi_base_load_b3(lua_State *state);
static void rivetlua_a2_callk_impl(lua_State *state, int nargs, int nresults,
                                   lua_KContext context, lua_KFunction continuation,
                                   int builtin_kind);
static void rivetlua_b5_operation_raise_message(
    lua_State *state, int status, int message);
static int rivetlua_capi_builtin_resume(lua_State *state, int status,
                                       lua_KContext context) {
  (void)status;
  (void)context;
  return lua_gettop(state);
}
/* 與 Rust CapiBuiltinId::allows_yield 同表：其餘官方 C body 的回呼
   經 lua_call／lua_getfield 等非續接邊界，不可由橋接 lua_callk 意外放行。 */
static int rivetlua_capi_builtin_allows_yield(int kind) {
  return kind == 1 || kind == 2 || kind == 4 || kind == 5 ||
         kind == 8 || kind == 11 || kind == 20 || kind == 119;
}
static int rivetlua_capi_builtin_body(lua_State *state, int kind) {
  int nargs = lua_gettop(state);
  int status = rivetlua_capi_builtin_push_target(state, kind);
  if (status != 0) rivetlua_b5_operation_raise_message(state, status, 0);
  lua_rotate(state, 1, 1);
  rivetlua_a2_callk_impl(state, nargs, LUA_MULTRET, 0,
                         rivetlua_capi_builtin_resume, kind);
  return lua_gettop(state);
}
#define RV_CAPI_BUILTIN(n) \
  static int rivetlua_capi_builtin_##n(lua_State *state) { \
    return rivetlua_capi_builtin_body(state, n); \
  }
RV_CAPI_BUILTIN(0)
RV_CAPI_BUILTIN(1)
RV_CAPI_BUILTIN(2)
RV_CAPI_BUILTIN(3)
RV_CAPI_BUILTIN(4)
RV_CAPI_BUILTIN(5)
RV_CAPI_BUILTIN(6)
RV_CAPI_BUILTIN(7)
RV_CAPI_BUILTIN(8)
RV_CAPI_BUILTIN(9)
RV_CAPI_BUILTIN(10)
RV_CAPI_BUILTIN(11)
RV_CAPI_BUILTIN(12)
RV_CAPI_BUILTIN(13)
RV_CAPI_BUILTIN(14)
RV_CAPI_BUILTIN(15)
RV_CAPI_BUILTIN(16)
RV_CAPI_BUILTIN(17)
RV_CAPI_BUILTIN(18)
RV_CAPI_BUILTIN(19)
RV_CAPI_BUILTIN(20)
RV_CAPI_BUILTIN(21)
RV_CAPI_BUILTIN(22)
RV_CAPI_BUILTIN(23)
RV_CAPI_BUILTIN(24)
RV_CAPI_BUILTIN(25)
RV_CAPI_BUILTIN(26)
RV_CAPI_BUILTIN(27)
RV_CAPI_BUILTIN(28)
RV_CAPI_BUILTIN(29)
RV_CAPI_BUILTIN(30)
RV_CAPI_BUILTIN(31)
RV_CAPI_BUILTIN(32)
RV_CAPI_BUILTIN(33)
RV_CAPI_BUILTIN(34)
RV_CAPI_BUILTIN(35)
RV_CAPI_BUILTIN(36)
RV_CAPI_BUILTIN(37)
static const char *const rivetlua_capi_hookkey_c14 = "_HOOKKEY";

static lua_State *rivetlua_capi_db_getthread_c14(lua_State *state, int *arg) {
  if (lua_isthread(state, 1)) {
    *arg = 1;
    return lua_tothread(state, 1);
  }
  *arg = 0;
  return state;
}

static void rivetlua_capi_db_checkstack_c14(
    lua_State *state, lua_State *target, int n) {
  if (state != target && !lua_checkstack(target, n))
    luaL_error(state, "stack overflow");
}

static void rivetlua_capi_hookf_c14(lua_State *state, lua_Debug *ar) {
  static const char *const names[] =
      {"call", "return", "line", "count", "tail call"};
  lua_getfield(state, LUA_REGISTRYINDEX, rivetlua_capi_hookkey_c14);
  lua_pushthread(state);
  if (lua_rawget(state, -2) == LUA_TFUNCTION) {
    lua_pushstring(state, names[(int)ar->event]);
    if (ar->currentline >= 0) lua_pushinteger(state, ar->currentline);
    else lua_pushnil(state);
    (void)lua_getinfo(state, "lS", ar);
    lua_call(state, 2, 0);
  }
}

static int rivetlua_capi_db_makemask_c14(const char *text, int count) {
  int mask = 0;
  if (strchr(text, 'c')) mask |= LUA_MASKCALL;
  if (strchr(text, 'r')) mask |= LUA_MASKRET;
  if (strchr(text, 'l')) mask |= LUA_MASKLINE;
  if (count > 0) mask |= LUA_MASKCOUNT;
  return mask;
}

static char *rivetlua_capi_db_unmakemask_c14(int mask, char *text) {
  int i = 0;
  if (mask & LUA_MASKCALL) text[i++] = 'c';
  if (mask & LUA_MASKRET) text[i++] = 'r';
  if (mask & LUA_MASKLINE) text[i++] = 'l';
  text[i] = '\0';
  return text;
}

static int rivetlua_capi_builtin_38(lua_State *state) {
  int arg, mask, count;
  lua_Hook func;
  lua_State *target = rivetlua_capi_db_getthread_c14(state, &arg);
  if (lua_isnoneornil(state, arg + 1)) {
    lua_settop(state, arg + 1);
    func = NULL; mask = 0; count = 0;
  } else {
    const char *text = luaL_checkstring(state, arg + 2);
    luaL_checktype(state, arg + 1, LUA_TFUNCTION);
    count = (int)luaL_optinteger(state, arg + 3, 0);
    func = rivetlua_capi_hookf_c14;
    mask = rivetlua_capi_db_makemask_c14(text, count);
  }
  size_t work = lua_type(state, arg + 3) == LUA_TSTRING
      ? lua_rawlen(state, arg + 3) : 0;
  int admission = rivetlua_capi_debug_hook_guard_c14(
      state, 1, mask, count, work);
  if (admission != 0) rivetlua_b5_operation_raise_message(state, admission, 0);
  if (!luaL_getsubtable(state, LUA_REGISTRYINDEX, rivetlua_capi_hookkey_c14)) {
    lua_pushliteral(state, "k");
    lua_setfield(state, -2, "__mode");
    lua_pushvalue(state, -1);
    lua_setmetatable(state, -2);
  }
  rivetlua_capi_db_checkstack_c14(state, target, 1);
  lua_pushthread(target); lua_xmove(target, state, 1);
  lua_pushvalue(state, arg + 1);
  lua_rawset(state, -3);
  lua_sethook(target, func, mask, count);
  return 0;
}

static int rivetlua_capi_builtin_39(lua_State *state) {
  int arg;
  lua_State *target = rivetlua_capi_db_getthread_c14(state, &arg);
  int admission = rivetlua_capi_debug_hook_guard_c14(state, 0, 0, 0, 0);
  if (admission != 0) rivetlua_b5_operation_raise_message(state, admission, 0);
  char text[5];
  int mask = lua_gethookmask(target);
  lua_Hook hook = lua_gethook(target);
  if (hook == NULL) {
    luaL_pushfail(state);
    return 1;
  } else if (hook != rivetlua_capi_hookf_c14) {
    lua_pushliteral(state, "external hook");
  } else {
    lua_getfield(state, LUA_REGISTRYINDEX, rivetlua_capi_hookkey_c14);
    rivetlua_capi_db_checkstack_c14(state, target, 1);
    lua_pushthread(target); lua_xmove(target, state, 1);
    lua_rawget(state, -2);
    lua_remove(state, -2);
  }
  lua_pushstring(state, rivetlua_capi_db_unmakemask_c14(mask, text));
  lua_pushinteger(state, lua_gethookcount(target));
  return 3;
}
RV_CAPI_BUILTIN(40)
RV_CAPI_BUILTIN(41)
RV_CAPI_BUILTIN(42)
RV_CAPI_BUILTIN(43)
RV_CAPI_BUILTIN(44)
RV_CAPI_BUILTIN(45)
RV_CAPI_BUILTIN(46)
RV_CAPI_BUILTIN(47)
RV_CAPI_BUILTIN(48)
RV_CAPI_BUILTIN(49)
RV_CAPI_BUILTIN(50)
RV_CAPI_BUILTIN(51)
RV_CAPI_BUILTIN(52)
RV_CAPI_BUILTIN(53)
RV_CAPI_BUILTIN(54)
RV_CAPI_BUILTIN(55)
RV_CAPI_BUILTIN(56)
RV_CAPI_BUILTIN(57)
RV_CAPI_BUILTIN(58)
RV_CAPI_BUILTIN(59)
RV_CAPI_BUILTIN(60)
RV_CAPI_BUILTIN(61)
RV_CAPI_BUILTIN(62)
RV_CAPI_BUILTIN(63)
RV_CAPI_BUILTIN(64)
RV_CAPI_BUILTIN(65)
RV_CAPI_BUILTIN(66)
RV_CAPI_BUILTIN(67)
RV_CAPI_BUILTIN(68)
RV_CAPI_BUILTIN(69)
RV_CAPI_BUILTIN(70)
RV_CAPI_BUILTIN(71)
RV_CAPI_BUILTIN(72)
RV_CAPI_BUILTIN(73)
RV_CAPI_BUILTIN(74)
RV_CAPI_BUILTIN(75)
RV_CAPI_BUILTIN(76)
RV_CAPI_BUILTIN(77)
RV_CAPI_BUILTIN(78)
RV_CAPI_BUILTIN(79)
RV_CAPI_BUILTIN(80)
RV_CAPI_BUILTIN(81)
RV_CAPI_BUILTIN(82)
RV_CAPI_BUILTIN(83)
RV_CAPI_BUILTIN(84)
RV_CAPI_BUILTIN(85)
RV_CAPI_BUILTIN(86)
RV_CAPI_BUILTIN(87)
RV_CAPI_BUILTIN(88)
RV_CAPI_BUILTIN(89)
RV_CAPI_BUILTIN(90)
RV_CAPI_BUILTIN(91)
RV_CAPI_BUILTIN(92)
RV_CAPI_BUILTIN(93)
RV_CAPI_BUILTIN(94)
RV_CAPI_BUILTIN(95)
RV_CAPI_BUILTIN(96)
RV_CAPI_BUILTIN(97)
RV_CAPI_BUILTIN(98)
RV_CAPI_BUILTIN(99)
RV_CAPI_BUILTIN(100)
RV_CAPI_BUILTIN(101)
RV_CAPI_BUILTIN(102)
RV_CAPI_BUILTIN(103)
RV_CAPI_BUILTIN(104)
RV_CAPI_BUILTIN(105)
RV_CAPI_BUILTIN(106)
RV_CAPI_BUILTIN(107)
RV_CAPI_BUILTIN(108)
RV_CAPI_BUILTIN(109)
RV_CAPI_BUILTIN(110)
RV_CAPI_BUILTIN(111)
RV_CAPI_BUILTIN(112)
RV_CAPI_BUILTIN(113)
RV_CAPI_BUILTIN(114)
RV_CAPI_BUILTIN(115)
RV_CAPI_BUILTIN(116)
static int rivetlua_capi_builtin_117(lua_State *state) {
  if (rivetlua_capi_base_load_direct_b3(state))
    return rivetlua_capi_base_load_b3(state);
  return rivetlua_capi_builtin_body(state, 117);
}
static int rivetlua_capi_loadfile_aux_b3(
    lua_State *state, int status, int environment) {
  if (status == LUA_OK) {
    if (environment != 0) {
      lua_pushvalue(state, environment);
      if (lua_setupvalue(state, -2, 1) == NULL) lua_pop(state, 1);
    }
    return 1;
  }
  luaL_pushfail(state);
  lua_insert(state, -2);
  return 2;
}
static int rivetlua_capi_builtin_118(lua_State *state) {
  if (!rivetlua_capi_base_load_direct_b3(state))
    return rivetlua_capi_builtin_body(state, 118);
  const char *filename = luaL_optstring(state, 1, NULL);
  const char *mode = luaL_optstring(state, 2, NULL);
#if LUA_VERSION_NUM >= 505
  if (mode != NULL && strchr(mode, 'B') != NULL)
    return luaL_argerror(state, 2, "invalid mode");
#endif
  int environment = lua_isnone(state, 3) ? 0 : 3;
  int status = luaL_loadfilex(state, filename, mode);
  return rivetlua_capi_loadfile_aux_b3(state, status, environment);
}
static int rivetlua_capi_dofile_continue_b3(
    lua_State *state, int status, lua_KContext context) {
  (void)status;
  (void)context;
  return lua_gettop(state) - 1;
}
static int rivetlua_capi_builtin_119(lua_State *state) {
  if (!rivetlua_capi_base_load_direct_b3(state))
    return rivetlua_capi_builtin_body(state, 119);
  const char *filename = luaL_optstring(state, 1, NULL);
  lua_settop(state, 1);
#if LUA_VERSION_NUM >= 505
  int status = luaL_loadfilex(state, filename, "bt");
#else
  int status = luaL_loadfilex(state, filename, NULL);
#endif
  if (status != LUA_OK) return lua_error(state);
  lua_callk(state, 0, LUA_MULTRET, 0, rivetlua_capi_dofile_continue_b3);
  return rivetlua_capi_dofile_continue_b3(state, 0, 0);
}
RV_CAPI_BUILTIN(120)
RV_CAPI_BUILTIN(121)
RV_CAPI_BUILTIN(122)
RV_CAPI_BUILTIN(123)
RV_CAPI_BUILTIN(124)
RV_CAPI_BUILTIN(125)
RV_CAPI_BUILTIN(126)
RV_CAPI_BUILTIN(127)
RV_CAPI_BUILTIN(128)
RV_CAPI_BUILTIN(129)
RV_CAPI_BUILTIN(130)
RV_CAPI_BUILTIN(131)
RV_CAPI_BUILTIN(132)
RV_CAPI_BUILTIN(133)
RV_CAPI_BUILTIN(134)
RV_CAPI_BUILTIN(135)
RV_CAPI_BUILTIN(136)
RV_CAPI_BUILTIN(137)
RV_CAPI_BUILTIN(138)
RV_CAPI_BUILTIN(139)
RV_CAPI_BUILTIN(140)
RV_CAPI_BUILTIN(141)
RV_CAPI_BUILTIN(142)
RV_CAPI_BUILTIN(143)
RV_CAPI_BUILTIN(144)
RV_CAPI_BUILTIN(145)
RV_CAPI_BUILTIN(146)
RV_CAPI_BUILTIN(147)
RV_CAPI_BUILTIN(148)
RV_CAPI_BUILTIN(149)
RV_CAPI_BUILTIN(150)
RV_CAPI_BUILTIN(151)
RV_CAPI_BUILTIN(152)
RV_CAPI_BUILTIN(153)
RV_CAPI_BUILTIN(154)
RV_CAPI_BUILTIN(155)
RV_CAPI_BUILTIN(156)
RV_CAPI_BUILTIN(157)
RV_CAPI_BUILTIN(158)
#undef RV_CAPI_BUILTIN

static const lua_CFunction rivetlua_capi_builtin_functions[] = {
  rivetlua_capi_builtin_0,
  rivetlua_capi_builtin_1,
  rivetlua_capi_builtin_2,
  rivetlua_capi_builtin_3,
  rivetlua_capi_builtin_4,
  rivetlua_capi_builtin_5,
  rivetlua_capi_builtin_6,
  rivetlua_capi_builtin_7,
  rivetlua_capi_builtin_8,
  rivetlua_capi_builtin_9,
  rivetlua_capi_builtin_10,
  rivetlua_capi_builtin_11,
  rivetlua_capi_builtin_12,
  rivetlua_capi_builtin_13,
  rivetlua_capi_builtin_14,
  rivetlua_capi_builtin_15,
  rivetlua_capi_builtin_16,
  rivetlua_capi_builtin_17,
  rivetlua_capi_builtin_18,
  rivetlua_capi_builtin_19,
  rivetlua_capi_builtin_20,
  rivetlua_capi_builtin_21,
  rivetlua_capi_builtin_22,
  rivetlua_capi_builtin_23,
  rivetlua_capi_builtin_24,
  rivetlua_capi_builtin_25,
  rivetlua_capi_builtin_26,
  rivetlua_capi_builtin_27,
  rivetlua_capi_builtin_28,
  rivetlua_capi_builtin_29,
  rivetlua_capi_builtin_30,
  rivetlua_capi_builtin_31,
  rivetlua_capi_builtin_32,
  rivetlua_capi_builtin_33,
  rivetlua_capi_builtin_34,
  rivetlua_capi_builtin_35,
  rivetlua_capi_builtin_36,
  rivetlua_capi_builtin_37,
  rivetlua_capi_builtin_38,
  rivetlua_capi_builtin_39,
  rivetlua_capi_builtin_40,
  rivetlua_capi_builtin_41,
  rivetlua_capi_builtin_42,
  rivetlua_capi_builtin_43,
  rivetlua_capi_builtin_44,
  rivetlua_capi_builtin_45,
  rivetlua_capi_builtin_46,
  rivetlua_capi_builtin_47,
  rivetlua_capi_builtin_48,
  rivetlua_capi_builtin_49,
  rivetlua_capi_builtin_50,
  rivetlua_capi_builtin_51,
  rivetlua_capi_builtin_52,
  rivetlua_capi_builtin_53,
  rivetlua_capi_builtin_54,
  rivetlua_capi_builtin_55,
  rivetlua_capi_builtin_56,
  rivetlua_capi_builtin_57,
  rivetlua_capi_builtin_58,
  rivetlua_capi_builtin_59,
  rivetlua_capi_builtin_60,
  rivetlua_capi_builtin_61,
  rivetlua_capi_builtin_62,
  rivetlua_capi_builtin_63,
  rivetlua_capi_builtin_64,
  rivetlua_capi_builtin_65,
  rivetlua_capi_builtin_66,
  rivetlua_capi_builtin_67,
  rivetlua_capi_builtin_68,
  rivetlua_capi_builtin_69,
  rivetlua_capi_builtin_70,
  rivetlua_capi_builtin_71,
  rivetlua_capi_builtin_72,
  rivetlua_capi_builtin_73,
  rivetlua_capi_builtin_74,
  rivetlua_capi_builtin_75,
  rivetlua_capi_builtin_76,
  rivetlua_capi_builtin_77,
  rivetlua_capi_builtin_78,
  rivetlua_capi_builtin_79,
  rivetlua_capi_builtin_80,
  rivetlua_capi_builtin_81,
  rivetlua_capi_builtin_82,
  rivetlua_capi_builtin_83,
  rivetlua_capi_builtin_84,
  rivetlua_capi_builtin_85,
  rivetlua_capi_builtin_86,
  rivetlua_capi_builtin_87,
  rivetlua_capi_builtin_88,
  rivetlua_capi_builtin_89,
  rivetlua_capi_builtin_90,
  rivetlua_capi_builtin_91,
  rivetlua_capi_builtin_92,
  rivetlua_capi_builtin_93,
  rivetlua_capi_builtin_94,
  rivetlua_capi_builtin_95,
  rivetlua_capi_builtin_96,
  rivetlua_capi_builtin_97,
  rivetlua_capi_builtin_98,
  rivetlua_capi_builtin_99,
  rivetlua_capi_builtin_100,
  rivetlua_capi_builtin_101,
  rivetlua_capi_builtin_102,
  rivetlua_capi_builtin_103,
  rivetlua_capi_builtin_104,
  rivetlua_capi_builtin_105,
  rivetlua_capi_builtin_106,
  rivetlua_capi_builtin_107,
  rivetlua_capi_builtin_108,
  rivetlua_capi_builtin_109,
  rivetlua_capi_builtin_110,
  rivetlua_capi_builtin_111,
  rivetlua_capi_builtin_112,
  rivetlua_capi_builtin_113,
  rivetlua_capi_builtin_114,
  rivetlua_capi_builtin_115,
  rivetlua_capi_builtin_116,
  rivetlua_capi_builtin_117,
  rivetlua_capi_builtin_118,
  rivetlua_capi_builtin_119,
  rivetlua_capi_builtin_120,
  rivetlua_capi_builtin_121,
  rivetlua_capi_builtin_122,
  rivetlua_capi_builtin_123,
  rivetlua_capi_builtin_124,
  rivetlua_capi_builtin_125,
  rivetlua_capi_builtin_126,
  rivetlua_capi_builtin_127,
  rivetlua_capi_builtin_128,
  rivetlua_capi_builtin_129,
  rivetlua_capi_builtin_130,
  rivetlua_capi_builtin_131,
  rivetlua_capi_builtin_132,
  rivetlua_capi_builtin_133,
  rivetlua_capi_builtin_134,
  rivetlua_capi_builtin_135,
  rivetlua_capi_builtin_136,
  rivetlua_capi_builtin_137,
  rivetlua_capi_builtin_138,
  rivetlua_capi_builtin_139,
  rivetlua_capi_builtin_140,
  rivetlua_capi_builtin_141,
  rivetlua_capi_builtin_142,
  rivetlua_capi_builtin_143,
  rivetlua_capi_builtin_144,
  rivetlua_capi_builtin_145,
  rivetlua_capi_builtin_146,
  rivetlua_capi_builtin_147,
  rivetlua_capi_builtin_148,
  rivetlua_capi_builtin_149,
  rivetlua_capi_builtin_150,
  rivetlua_capi_builtin_151,
  rivetlua_capi_builtin_152,
  rivetlua_capi_builtin_153,
  rivetlua_capi_builtin_154,
  rivetlua_capi_builtin_155,
  rivetlua_capi_builtin_156,
  rivetlua_capi_builtin_157,
  rivetlua_capi_builtin_158,
};

lua_CFunction rivetlua_capi_builtin_pointer(int kind) {
  if (kind < 0 || (size_t)kind >=
      sizeof(rivetlua_capi_builtin_functions) /
          sizeof(rivetlua_capi_builtin_functions[0]))
    return NULL;
  return rivetlua_capi_builtin_functions[kind];
}

int rivetlua_capi_builtin_kind(lua_CFunction function) {
  for (size_t index = 0;
       index < sizeof(rivetlua_capi_builtin_functions) /
                   sizeof(rivetlua_capi_builtin_functions[0]);
       ++index) {
    if (rivetlua_capi_builtin_functions[index] == function)
      return (int)index;
  }
  return -1;
}

/* FILE* 前綴及 closef 的所有解參照／跳轉均留在純 C callback frame。 */
FILE *rivetlua_capi_native_standard_file(int which) {
  switch (which) {
    case 0: return stdin;
    case 1: return stdout;
    case 2: return stderr;
    default: return NULL;
  }
}

int rivetlua_capi_native_file_fclose(lua_State *state) {
  luaL_Stream *stream = (luaL_Stream *)luaL_checkudata(state, 1, LUA_FILEHANDLE);
  errno = 0;
  return luaL_fileresult(state, fclose(stream->f) == 0, NULL);
}

int rivetlua_capi_native_file_pclose(lua_State *state) {
  luaL_Stream *stream = (luaL_Stream *)luaL_checkudata(state, 1, LUA_FILEHANDLE);
  errno = 0;
  return luaL_execresult(state, pclose(stream->f));
}

int rivetlua_capi_native_file_noclose(lua_State *state) {
  luaL_Stream *stream = (luaL_Stream *)luaL_checkudata(state, 1, LUA_FILEHANDLE);
  stream->closef = &rivetlua_capi_native_file_noclose;
  lua_pushnil(state);
  lua_pushliteral(state, "cannot close standard file");
  return 2;
}

int rivetlua_capi_native_file_dispatch(lua_State *state) {
  luaL_Stream *stream = (luaL_Stream *)luaL_checkudata(state, 1, LUA_FILEHANDLE);
  if (lua_rawlen(state, 1) < sizeof(luaL_Stream))
    return luaL_error(state, "invalid file handle size");
  if (stream->closef == NULL) return 0;
  lua_CFunction closef = stream->closef;
  stream->closef = NULL;
  return closef(state);
}

int rivetlua_capi_native_file_gc_dispatch(lua_State *state) {
  (void)rivetlua_capi_native_file_dispatch(state);
  return 0;
}

int rivetlua_capi_test_open_io(lua_State *state) {
  return luaopen_io(state);
}

static int rivetlua_capi_file_close_calls;
static int rivetlua_capi_file_close_second_arg;

void rivetlua_capi_test_file_close_reset(void) {
  rivetlua_capi_file_close_calls = 0;
  rivetlua_capi_file_close_second_arg = 0;
}

int rivetlua_capi_test_file_close_count(void) {
  return rivetlua_capi_file_close_calls;
}

int rivetlua_capi_test_file_close_second_arg(void) {
  return rivetlua_capi_file_close_second_arg;
}

int rivetlua_capi_test_file_close_values(lua_State *state) {
  luaL_Stream *stream = (luaL_Stream *)luaL_checkudata(state, 1, LUA_FILEHANDLE);
  size_t length = 0;
  const char *argument = lua_tolstring(state, 2, &length);
  if (argument != NULL && length == 6 && memcmp(argument, "marker", 6) == 0)
    rivetlua_capi_file_close_second_arg = 1;
  else if (argument != NULL && strstr(argument, "close-error") != NULL)
    rivetlua_capi_file_close_second_arg = 2;
  rivetlua_capi_file_close_calls++;
  errno = 0;
  if (fclose(stream->f) != 0)
    return luaL_fileresult(state, 0, NULL);
  lua_pushinteger(state, 17);
  lua_pushinteger(state, 29);
  return 2;
}

int rivetlua_capi_test_file_close_success(lua_State *state) {
  luaL_Stream *stream = (luaL_Stream *)luaL_checkudata(state, 1, LUA_FILEHANDLE);
  rivetlua_capi_file_close_calls++;
  return luaL_fileresult(state, fclose(stream->f) == 0, NULL);
}

int rivetlua_capi_test_file_close_error(lua_State *state) {
  luaL_Stream *stream = (luaL_Stream *)luaL_checkudata(state, 1, LUA_FILEHANDLE);
  rivetlua_capi_file_close_calls++;
  (void)fclose(stream->f);
  lua_pushliteral(state, "close failure");
  return lua_error(state);
}

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
  size_t warning_len;
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
  int32_t default_pending;
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
  /* B4/B5/resume 的 typed handoff；setjmp 後的寫入必須是 volatile。 */
  volatile unsigned close_triplets_b4;
  volatile unsigned handoff_ready_b4;
  volatile rivetlua_capi_callback_step_b4 handoff_b4;
} rivetlua_capi_checkpoint_a1;

static _Thread_local rivetlua_capi_checkpoint_a1 *rivetlua_capi_top_a1;
static _Thread_local rivetlua_capi_checkpoint_a1 *rivetlua_capi_b4_driver_top;
static _Thread_local rivetlua_capi_checkpoint_a1 *rivetlua_capi_b5_driver_top;
static _Thread_local rivetlua_capi_checkpoint_a1 *rivetlua_capi_resume_top_a5;
static _Thread_local rivetlua_capi_checkpoint_a1 *rivetlua_capi_b3_reader_child_top;

/* 僅 reader 本身直接呼叫的公開 API 需要局部保護；巢狀 driver 自行處理。 */
static int rivetlua_b3_reader_direct(lua_State *state) {
  return rivetlua_capi_b3_reader_child_top != NULL &&
         rivetlua_capi_top_a1 == rivetlua_capi_b3_reader_child_top &&
         rivetlua_capi_top_a1->state == state;
}

/* 僅比對 live TLS checkpoint 的 state 指標；-1 表示此 state 沒有活動 C 邊界。 */
int rivetlua_capi_yield_boundary_a5(const lua_State *state) {
  rivetlua_capi_checkpoint_a1 *target = rivetlua_capi_resume_top_a5;
  rivetlua_capi_checkpoint_a1 *cursor = rivetlua_capi_top_a1;
  if (state == NULL) return -1;
  if (target == NULL || target->state != state) {
    for (; cursor != NULL; cursor = cursor->previous)
      if (cursor->state == state) return 0;
    return -1;
  }
  for (; cursor != NULL && cursor != target; cursor = cursor->previous)
    if (cursor->state != state || cursor->yieldable_a5 == 0) return 0;
  return cursor == target ? 1 : 0;
}
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
extern int rivetlua_capi_c_depth_get_b13(lua_State *state);
extern int rivetlua_capi_c_depth_set_b13(lua_State *state, uint16_t depth);
extern int rivetlua_capi_pending_throw_depth_b13(lua_State *state);
extern int32_t rivetlua_capi_checkpoint_rewind_a5(
    void *state, uint64_t generation, uint64_t token, unsigned skipped);
extern int rivetlua_capi_yield_prepare_a5(
    lua_State *state, int nresults, lua_KContext context,
    lua_KFunction continuation);
extern int rivetlua_capi_hook_yield_mark_c16(lua_State *state);
extern rivetlua_capi_resume_setup_a5 rivetlua_capi_resume_prepare_a5(
    lua_State *state, lua_State *from, int nargs, int from_yieldable);
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
extern int rivetlua_capi_shutdown_scratch_prepare_b11(lua_State *state);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_shutdown_prepare_b11(
    lua_State *state);
extern int rivetlua_capi_close_drop_b11(lua_State *state);
extern int rivetlua_capi_close_idle_b11(lua_State *state);
extern int rivetlua_capi_process_exit_request_b11(
    lua_State *state, int *status, int *close);
extern int rivetlua_capi_process_exit_same_group_b11(
    lua_State *state, lua_State *other);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_resume_b4(
    lua_State *state, int count, int nresults);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_prepare_a2(
    lua_State *state, int nargs, int nresults, int protected_call,
    void *handler);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_builtin_prepare_a2(
    lua_State *state, int nargs, int nresults, int kind);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_resume_a2(
    lua_State *state, int count, int nresults);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_resume_error_a2(
    lua_State *state, int nresults);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_call_resume_overlay_a2(
    lua_State *state, int closer_class, int nresults);
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
extern int rivetlua_capi_getinfo_dispatch_c13(
    lua_State *state, const char *what, lua_Debug *ar);
extern rivetlua_capi_strict_result_b2 rivetlua_capi_pushlstring_dispatch_b14(
    lua_State *state, uint64_t generation, uint64_t token,
    const char *source, size_t length);
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
extern int rivetlua_capi_operation_panic_error_c18(
    lua_State *state, int class_code, int message);
extern int rivetlua_capi_public_settle_error_a2(
    lua_State *state, size_t base);
extern void rivetlua_capi_public_drop_handler_a2(void *handler);
extern lua_CFunction rivetlua_capi_panic_snapshot_a2(lua_State *state);

/* 公開 C API 的共用無保護出口；錯誤值已由 Rust 發布時不再覆寫。 */
static void rivetlua_a3_panic(lua_State *state, int prepared) {
  if (!prepared) (void)rivetlua_capi_generic_panic_error_a3(state);
  lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
  if (panicf != NULL) (void)panicf(state);
  abort();
}
extern int rivetlua_capi_call_abort_b4(lua_State *state);
extern int rivetlua_capi_call_depth_b7(lua_State *state);
extern int rivetlua_capi_call_handler_before_close_a2(lua_State *state);
extern int rivetlua_capi_call_abort_to_b7(lua_State *state, int depth);
extern int rivetlua_capi_toclose_prepare_b7(lua_State *state, int index);
extern rivetlua_capi_close_step_b7 rivetlua_capi_close_next_b7(
    lua_State *state, size_t target, size_t error_position, int nil_slot);
extern int rivetlua_capi_close_finish_slot_b7(lua_State *state, size_t position);
extern int rivetlua_capi_close_recycle_b7(lua_State *state);
extern int rivetlua_capi_close_capture_error_b7(
    lua_State *state, size_t trim_top);
extern int rivetlua_capi_close_finalize_error_b7(
    lua_State *state, size_t trim_top, uint64_t token, int error_class);
extern int rivetlua_capi_settop_direct_b7(lua_State *state, int index);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_operation_prepare_b5(
    lua_State *state, int kind, int operation, int left, int right, int count,
    int reader_protected);
extern rivetlua_capi_callback_step_b4 rivetlua_capi_operation_resume_b5(
    lua_State *state, int count, int nresults, int reader_protected);
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
_Static_assert(offsetof(rivetlua_capi_callback_step_b4, warning_len) ==
                   offsetof(rivetlua_capi_callback_step_b4, token) + sizeof(void *),
               "C/Rust warning length layout");
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
_Static_assert(offsetof(rivetlua_capi_warning_binding_b6, default_pending) ==
                   2 * sizeof(void *), "C/Rust warning pending offset");
_Static_assert(sizeof(rivetlua_capi_warning_binding_b6) == 3 * sizeof(void *),
               "C/Rust warning binding layout");

void rivetlua_capi_default_warning_install_b6(lua_State *state);
void lua_warning(lua_State *state, const char *message, int tocont) {
  rivetlua_capi_warning_binding_b6 binding =
      rivetlua_capi_warning_snapshot_b6(state);
  if (binding.default_pending) {
    lua_State *main_state = (lua_State *)binding.ud;
    if (main_state == NULL) return;
    /* snapshot 的 Rust 借用已結束，僅此純 C frame 安裝預設 callback。 */
    rivetlua_capi_default_warning_install_b6(main_state);
    binding = rivetlua_capi_warning_snapshot_b6(state);
  }
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
static int rivetlua_b7_close_drive_handoff(
    lua_State *state, size_t target, size_t trim_top, int initial_class,
    int nil_slot, int pause_on_error,
    rivetlua_capi_callback_step_b4 *handoff);
static int rivetlua_b7_close_drive_overlay(lua_State *state, size_t target,
                                            size_t trim_top, int initial_class,
                                            rivetlua_capi_callback_step_b4 *handoff);
static int rivetlua_b7_close_drive_forward(lua_State *state, size_t target,
                                           size_t trim_top, int nil_slot);
static int rivetlua_b11_close_drive(lua_State *state);
static void rivetlua_b11_process_exit_close_stack(lua_State *state);
static void rivetlua_b7_raise_existing(lua_State *state, int class_code);
static void rivetlua_b13_depth_error(lua_State *state, int class_code,
                                     const char *message) {
  lua_pushstring(state, message);
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (top != NULL && top->state == state && top->rust_action_active == 0 &&
      rivetlua_capi_error_prepare_a1(
          state, top->generation, top->token, class_code) == RV_A1_OK)
    rivetlua_b7_raise_existing(state, -class_code);
  abort();
}
static int rivetlua_b13_public_status(int class_code) {
  if (class_code == RV_A1_ERROR_HANDLING) return LUA_ERRERR;
  if (class_code == RV_A1_ERROR_ALLOCATION) return LUA_ERRMEM;
  return LUA_ERRRUN;
}
static int rivetlua_b10_invoke_step(
    lua_State *state, const rivetlua_capi_callback_step_b4 *step, int *count) {
  int exit_status = 0, exit_close = 0;
  if (rivetlua_capi_process_exit_request_b11(
          state, &exit_status, &exit_close) == 1 && exit_close &&
      rivetlua_capi_shutdown_scratch_prepare_b11(state) != 1)
    return 0;
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
  if (step->kind == 4 && step->token != NULL) {
    if (step->value == 0) {
      lua_warning(state, (const char *)step->token, step->event);
    } else {
      /* warning_len 已截於首個 NUL；只在純 C stack 上分段補終止符。
         callback 重入時，ExternalPending 的真根仍保住原位元組。 */
      const char *bytes = (const char *)step->token;
      size_t offset = 0;
      if (step->warning_len == 0) lua_warning(state, "", step->event);
      while (offset < step->warning_len) {
        char part[256];
        size_t count = step->warning_len - offset;
        if (count > sizeof(part) - 1) count = sizeof(part) - 1;
        memcpy(part, bytes + offset, count);
        part[count] = '\0';
        offset += count;
        lua_warning(state, part,
                    offset < step->warning_len ? 1 : step->event);
      }
    }
    *count = 0;
    return 1;
  }
  return 0;
}
/* 終止只跳至同一執行緒仍存活的純 C checkpoint，不跨越 Rust frame。 */
static void rivetlua_b4_raise_terminal_a1(lua_State *state) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  int status = 0, close = 0;
  int process_exit = rivetlua_capi_process_exit_request_b11(
      state, &status, &close);
  if (process_exit == 1 && !close) exit(status);
  if (top != NULL && top->rust_action_active == 0 &&
      (top->state == state ||
       (process_exit == 1 &&
        rivetlua_capi_process_exit_same_group_b11(state, top->state) == 1)))
    longjmp(top->jump, 3);
  if (process_exit == 1) {
    (void)rivetlua_b11_close_drive(state);
    /* 已接受的 C os.exit 不能返回公開 lua_pcall/lua_call。 */
    exit(status);
  }
}
static int rivetlua_b4_call_drive(lua_State *state, int nargs,
                                 int nresults, int public_call,
                                  int yieldable_a5, int builtin_kind,
                                   int protected_call, void *handler,
                                    rivetlua_capi_callback_step_b4 *handoff,
                                    const rivetlua_capi_callback_step_b4 *initial_step,
                                    int inherited_frame_depth) {
  if (state == NULL) return -1;
  int frame_depth = inherited_frame_depth >= 0
      ? inherited_frame_depth : rivetlua_capi_call_depth_b7(state);
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
  checkpoint.close_triplets_b4 = 0;
  checkpoint.handoff_ready_b4 = 0;
  rivetlua_capi_checkpoint_a1 *previous_b4 = rivetlua_capi_b4_driver_top;
  rivetlua_capi_top_a1 = &checkpoint;
  rivetlua_capi_b4_driver_top = &checkpoint;
  int c_depth_before = -1;
  int c_depth_error = 0;
  volatile int c_depth_active = 0;
  if (builtin_kind < 0 && initial_step == NULL) {
    c_depth_before = rivetlua_capi_c_depth_get_b13(state);
    if (c_depth_before < 0 || c_depth_before >= UINT16_MAX ||
        rivetlua_capi_c_depth_set_b13(state,
                                      (uint16_t)(c_depth_before + 1)) != 0) {
      c_depth_error = -1;
    } else {
      c_depth_active = 1;
      if (c_depth_before + 1 == 200) c_depth_error = RV_A1_ERROR_LUA;
      else if (c_depth_before + 1 >= 220)
        c_depth_error = RV_A1_ERROR_HANDLING;
    }
  }
  int result = -1;
  volatile int first = 1;
  /* A1 checkpoint 的跳轉目標仍在此純 C frame，絕不跨越 Rust frame。 */
  for (;;) {
    rivetlua_capi_callback_step_b4 step;
    int jumped = setjmp(checkpoint.jump);
    if (jumped == 4) {
      if (!checkpoint.handoff_ready_b4) abort();
      while (checkpoint.close_triplets_b4 != 0) {
        if (rivetlua_capi_close_recycle_b7(state) != 1) abort();
        checkpoint.close_triplets_b4--;
      }
      step.kind = checkpoint.handoff_b4.kind;
      step.value = checkpoint.handoff_b4.value;
      step.function = checkpoint.handoff_b4.function;
      step.hook = checkpoint.handoff_b4.hook;
      step.event = checkpoint.handoff_b4.event;
      step.currentline = checkpoint.handoff_b4.currentline;
      step.token = checkpoint.handoff_b4.token;
      step.warning_len = checkpoint.handoff_b4.warning_len;
      checkpoint.handoff_ready_b4 = 0;
      goto process_step_b4;
    }
    if (jumped == 3) {
      if (c_depth_active) {
        (void)rivetlua_capi_c_depth_set_b13(state, (uint16_t)c_depth_before);
        c_depth_active = 0;
      }
      result = -2;
      break;
    }
    if (jumped == 0) {
      if (!first) break;
      first = 0;
      if (c_depth_error < 0) break;
      if (c_depth_error != 0)
        rivetlua_b13_depth_error(
            state, c_depth_error,
            c_depth_error == RV_A1_ERROR_HANDLING
                ? "error in error handling" : "C stack overflow");
      if (initial_step != NULL) {
        step = *initial_step;
      } else {
        checkpoint.rust_action_active = 1;
        step = builtin_kind >= 0
            ? rivetlua_capi_builtin_prepare_a2(state, nargs, nresults, builtin_kind)
            : (public_call
                   ? rivetlua_capi_call_prepare_a2(
                         state, nargs, nresults, protected_call, handler)
                   : rivetlua_capi_call_prepare_b4(state, nargs, nresults));
        checkpoint.rust_action_active = 0;
      }
    } else {
      checkpoint.rust_action_active = 0;
      if (c_depth_active) {
        (void)rivetlua_capi_c_depth_set_b13(state, (uint16_t)c_depth_before);
        c_depth_active = 0;
      }
      if (rivetlua_capi_call_depth_b7(state) <= frame_depth) break;
      if (protected_call ||
          rivetlua_capi_call_handler_before_close_a2(state) == 1) {
        checkpoint.rust_action_active = 1;
        step = rivetlua_capi_call_resume_error_a2(state, nresults);
        checkpoint.rust_action_active = 0;
      } else {
        size_t trim_top = (size_t)lua_gettop(state);
        int error_class = rivetlua_capi_close_capture_error_b7(state, trim_top);
        if (error_class <= 0) break;
        rivetlua_capi_callback_step_b4 nested_step;
        int closed = rivetlua_b7_close_drive_handoff(
            state, 0, trim_top, error_class, 0, 0, &nested_step);
        if (closed == -3) {
          step = nested_step;
          goto process_step_b4;
        }
        if (!public_call) break;
        checkpoint.rust_action_active = 1;
        step = rivetlua_capi_call_resume_error_a2(state, nresults);
        checkpoint.rust_action_active = 0;
      }
    }
process_step_b4:
    while (step.kind == 1 || step.kind == 2 || step.kind == 4 || step.kind == 5) {
      if (step.kind == 5) {
        int current_depth = rivetlua_capi_call_depth_b7(state);
        if (current_depth < frame_depth) abort();
        if (current_depth == frame_depth) {
          if (handoff == NULL) abort();
          *handoff = step;
          result = -3;
          break;
        }
        size_t top = (size_t)lua_gettop(state);
        if (top == 0) break;
        rivetlua_capi_callback_step_b4 nested_step;
        int closed = rivetlua_b7_close_drive_overlay(
            state, 0, top - 1, step.value, &nested_step);
        if (closed == -3) {
          step = nested_step;
          continue;
        }
        checkpoint.rust_action_active = 1;
        step = rivetlua_capi_call_resume_overlay_a2(
            state, closed < 0 ? -closed : 0, nresults);
        checkpoint.rust_action_active = 0;
        continue;
      }
      int count = 0;
      if (!rivetlua_b10_invoke_step(state, &step, &count)) break;
      rivetlua_capi_callback_step_b4 nested_step;
      int handler_before_close = rivetlua_capi_call_handler_before_close_a2(state) == 1;
      int close_status = rivetlua_b7_close_drive_handoff(
          state, 0, (size_t)lua_gettop(state), 0, 0,
          handler_before_close, &nested_step);
      if (close_status == -3) {
        step = nested_step;
        continue;
      }
      if (close_status != 0 && !public_call && !handler_before_close) break;
      checkpoint.rust_action_active = 1;
      step = close_status == 0
          ? (public_call
                ? rivetlua_capi_call_resume_a2(state, count, nresults)
                : rivetlua_capi_call_resume_b4(state, count, nresults))
          : rivetlua_capi_call_resume_error_a2(state, nresults);
      checkpoint.rust_action_active = 0;
    }
    if (step.kind == 0) result = 0;
    else if (step.kind == -2) result = -2;
    break;
  }
  if (c_depth_active &&
      rivetlua_capi_c_depth_set_b13(state, (uint16_t)c_depth_before) != 0)
    result = -1;
  int exit_status = 0, exit_close = 0;
  if (rivetlua_capi_process_exit_request_b11(
          state, &exit_status, &exit_close) == 1) {
    rivetlua_b11_process_exit_close_stack(state);
    result = -2;
  }
  if (result != 0 && result != -3) {
    checkpoint.rust_action_active = 1;
    if (rivetlua_capi_call_abort_to_b7(state, frame_depth) != 1)
      result = -1;
  }
  checkpoint.rust_action_active = 0;
  rivetlua_capi_b4_driver_top = previous_b4;
  rivetlua_capi_top_a1 = checkpoint.previous;
  int32_t exited = rivetlua_capi_checkpoint_exit_a1(
      state, checkpoint.generation, checkpoint.token,
      checkpoint.previous_state_token);
  if (exited != RV_A1_OK) return -1;
  return result;
}

int rivetlua_capi_call_b4(lua_State *state, int nargs, int nresults) {
  return rivetlua_b4_call_drive(
      state, nargs, nresults, 0, 0, -1, 0, NULL, NULL, NULL, -1);
}

static int rivetlua_a2_call_drive(lua_State *state, int nargs, int nresults,
                                  int yieldable_a5, int builtin_kind,
                                   int protected_call, void *handler,
                                   rivetlua_capi_callback_step_b4 *handoff) {
  return rivetlua_b4_call_drive(state, nargs, nresults, 1,
                                yieldable_a5, builtin_kind,
                                 protected_call, handler, handoff, NULL, -1);
}

/* public void lua_call 的外層同步 B4 仍持有 fault overlay；只傳純 C POD。 */
static void rivetlua_b4_transfer_handoff(
    lua_State *state, const rivetlua_capi_callback_step_b4 *step) {
  rivetlua_capi_checkpoint_a1 *target = rivetlua_capi_top_a1;
  if (target == NULL ||
      (target != rivetlua_capi_b4_driver_top &&
       target != rivetlua_capi_b5_driver_top &&
       target != rivetlua_capi_resume_top_a5) ||
      target->state != state || target->rust_action_active != 0 ||
      target->handoff_ready_b4 || step->kind != 5)
    abort();
  if (rivetlua_capi_trampoline_probe_a1(
          state, target->generation, target->token) != RV_A1_OK)
    abort();
  target->handoff_b4.kind = step->kind;
  target->handoff_b4.value = step->value;
  target->handoff_b4.function = step->function;
  target->handoff_b4.hook = step->hook;
  target->handoff_b4.event = step->event;
  target->handoff_b4.currentline = step->currentline;
  target->handoff_b4.token = step->token;
  target->handoff_b4.warning_len = step->warning_len;
  target->handoff_ready_b4 = 1;
  longjmp(target->jump, 4);
}

static void rivetlua_a2_terminal_cleanup(lua_State *state, int registered,
                                         void *handler) {
  int status = 0, close = 0;
  if (rivetlua_capi_process_exit_request_b11(state, &status, &close) == 1) {
    rivetlua_b4_raise_terminal_a1(state);
    exit(status);
  }
  if (registered)
    (void)rivetlua_capi_continuation_step_a5(
        state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
  else
    rivetlua_capi_public_drop_handler_a2(handler);
  rivetlua_b4_raise_terminal_a1(state);
}

/* B5：同一 operation 的 callback、pending 與 stack 發布都留在純 C checkpoint。 */
static int rivetlua_b5_operation_drive(
    lua_State *state, int kind, int operation, int left, int right, int count,
    int *published) {
  if (state == NULL || published == NULL) return -RV_A1_ERROR_LUA;
  int reader_protected = rivetlua_b3_reader_direct(state);
  int result_count = kind == 7 ? 0 : 1;
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
  checkpoint.close_triplets_b4 = 0;
  checkpoint.handoff_ready_b4 = 0;
  rivetlua_capi_checkpoint_a1 *previous_b5 = rivetlua_capi_b5_driver_top;
  rivetlua_capi_top_a1 = &checkpoint;
  rivetlua_capi_b5_driver_top = &checkpoint;
  int status = -RV_A1_ERROR_LUA;
  rivetlua_capi_callback_step_b4 handoff_step;
  volatile int handoff_ready = 0;
  *published = 0;
  int terminal_exit = 0;
  /* callback 只在 Rust step 完整返回且 guard 清零後呼叫。 */
  int jumped = setjmp(checkpoint.jump);
  if (jumped == 3) {
    terminal_exit = 1;
  } else if (jumped == 4) {
    if (!checkpoint.handoff_ready_b4) abort();
    while (checkpoint.close_triplets_b4 != 0) {
      if (rivetlua_capi_close_recycle_b7(state) != 1) abort();
      checkpoint.close_triplets_b4--;
    }
    rivetlua_capi_callback_step_b4 fault;
    fault.kind = checkpoint.handoff_b4.kind;
    fault.value = checkpoint.handoff_b4.value;
    fault.function = checkpoint.handoff_b4.function;
    fault.hook = checkpoint.handoff_b4.hook;
    fault.event = checkpoint.handoff_b4.event;
    fault.currentline = checkpoint.handoff_b4.currentline;
    fault.token = checkpoint.handoff_b4.token;
    fault.warning_len = checkpoint.handoff_b4.warning_len;
    checkpoint.handoff_ready_b4 = 0;
    status = rivetlua_b4_call_drive(
        state, 0, result_count, 1, 0, -1, 0, NULL, &handoff_step,
        &fault, depth);
    handoff_ready = status == -3;
  } else if (jumped == 0) {
    checkpoint.rust_action_active = 1;
    rivetlua_capi_callback_step_b4 step =
        rivetlua_capi_operation_prepare_b5(
            state, kind, operation, left, right, count, reader_protected);
    checkpoint.rust_action_active = 0;
    while (step.kind == 1 || step.kind == 2 || step.kind == 4 || step.kind == 5) {
      if (step.kind == 5) {
        status = rivetlua_b4_call_drive(
            state, 0, result_count, 1, 0, -1, 0, NULL, &handoff_step,
            &step, depth);
        handoff_ready = status == -3;
        break;
      }
      int returned = 0;
      if (!rivetlua_b10_invoke_step(state, &step, &returned)) break;
      rivetlua_capi_callback_step_b4 nested_step;
      int handler_before_close =
          rivetlua_capi_call_handler_before_close_a2(state) == 1;
      int close_status = rivetlua_b7_close_drive_handoff(
          state, 0, (size_t)lua_gettop(state), 0, 0,
          reader_protected || handler_before_close, &nested_step);
      if (close_status == -3) {
        if (reader_protected) {
          status = rivetlua_b4_call_drive(
              state, 0, result_count, 1, 0, -1, 0, NULL, &handoff_step,
              &nested_step, depth);
          handoff_ready = status == -3;
        } else {
          handoff_step = nested_step;
          handoff_ready = 1;
          status = -3;
        }
        break;
      }
      if (close_status != 0) {
        if (reader_protected || handler_before_close) {
          checkpoint.rust_action_active = 1;
          rivetlua_capi_callback_step_b4 fault =
              rivetlua_capi_call_resume_error_a2(state, result_count);
          checkpoint.rust_action_active = 0;
          status = rivetlua_b4_call_drive(
              state, 0, result_count, 1, 0, -1, 0, NULL, &handoff_step,
              &fault, depth);
          handoff_ready = status == -3;
        } else {
          status = close_status;
        }
        break;
      }
      checkpoint.rust_action_active = 1;
      step = rivetlua_capi_operation_resume_b5(
          state, returned, result_count, reader_protected);
      checkpoint.rust_action_active = 0;
    }
    if (step.kind == -2) terminal_exit = 1;
    if (step.kind == 0) {
      *published = step.value;
      status = 0;
    } else if (step.kind < 0 && step.value > 0) {
      status = -step.value;
    }
  } else if (raised_status != 0) {
    status = -raised_status;
    if (rivetlua_capi_operation_depth_b5(state) > depth) {
      if (reader_protected ||
          rivetlua_capi_call_handler_before_close_a2(state) == 1) {
        checkpoint.rust_action_active = 1;
        rivetlua_capi_callback_step_b4 fault =
            rivetlua_capi_call_resume_error_a2(state, result_count);
        checkpoint.rust_action_active = 0;
        status = rivetlua_b4_call_drive(
            state, 0, result_count, 1, 0, -1, 0, NULL, &handoff_step,
            &fault, depth);
        handoff_ready = status == -3;
      } else {
        size_t trim_top = (size_t)lua_gettop(state);
        int error_class = rivetlua_capi_close_capture_error_b7(state, trim_top);
        if (error_class > 0)
          status = rivetlua_b7_close_drive(
              state, 0, trim_top, error_class, 0);
      }
    }
  }
  int exit_status = 0, exit_close = 0;
  if (rivetlua_capi_process_exit_request_b11(
          state, &exit_status, &exit_close) == 1)
    terminal_exit = 1;
  if (terminal_exit) rivetlua_b11_process_exit_close_stack(state);
  int preserved_reader_error = reader_protected && status < 0 &&
      status != -3 && !terminal_exit &&
      rivetlua_capi_pending_matches_a1(
          state, checkpoint.generation, checkpoint.token, -status) == RV_A1_OK;
  if (preserved_reader_error) {
    checkpoint.rust_action_active = 1;
    if (rivetlua_capi_operation_abort_to_b5(state, depth) != 1) abort();
    checkpoint.rust_action_active = 0;
    int class_code = 0;
    if (rivetlua_capi_error_consume_a1(state, &class_code) != RV_A1_OK ||
        class_code != -status) abort();
    *published = -1;
  } else if ((status != 0 && status != -3) || terminal_exit) {
    checkpoint.rust_action_active = 1;
    (void)rivetlua_capi_pending_cancel_a1(
        state, checkpoint.generation, checkpoint.token);
    (void)rivetlua_capi_operation_abort_to_b5(state, depth);
    checkpoint.rust_action_active = 0;
  }
  rivetlua_capi_b5_driver_top = previous_b5;
  rivetlua_capi_top_a1 = checkpoint.previous;
  int32_t exited = rivetlua_capi_checkpoint_exit_a1(
      state, checkpoint.generation, checkpoint.token,
      checkpoint.previous_state_token);
  if (exited != RV_A1_OK) return -RV_A1_ERROR_LUA;
  if (terminal_exit) rivetlua_b4_raise_terminal_a1(state);
  if (handoff_ready) rivetlua_b4_transfer_handoff(state, &handoff_step);
  return status;
}

static void rivetlua_b5_operation_raise_message(
    lua_State *state, int status, int message) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  int class_code = status < 0 ? -status : RV_A1_ERROR_LUA;
  if (top == NULL) {
    int prepared = rivetlua_capi_operation_panic_error_c18(
        state, class_code, message);
    rivetlua_a3_panic(state, prepared);
  }
  if (top->state != state || top->rust_action_active != 0) abort();
  rivetlua_capi_strict_result_b2 action = rivetlua_capi_operation_error_b5(
      state, top->generation, top->token, class_code, message);
  (void)rivetlua_b2_finish(state, top->generation, top->token, action);
  abort();
}

static void rivetlua_b5_operation_raise(lua_State *state, int status) {
  rivetlua_b5_operation_raise_message(state, status, 0);
}

int lua_getinfo(lua_State *state, const char *what, lua_Debug *ar) {
  /* Rust 已釋放 debug/stack 借用；L 的配置錯誤只在此 C frame 提出。 */
  int result = rivetlua_capi_getinfo_dispatch_c13(state, what, ar);
  if (result == -RV_A1_ERROR_ALLOCATION)
    rivetlua_b5_operation_raise(state, result);
  return result;
}

/* B5 checkpoint 已把原錯誤 slot 搬回 reader stack；由 child 原樣提出。 */
static void rivetlua_b5_operation_raise_result(
    lua_State *state, int status, int published) {
  if (published == -1) {
    rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
    int class_code = status < 0 ? -status : RV_A1_ERROR_LUA;
    if (rivetlua_b3_reader_direct(state) && top != NULL &&
        rivetlua_capi_error_prepare_a1(
            state, top->generation, top->token, class_code) == RV_A1_OK)
      rivetlua_b7_raise_existing(state, -class_code);
    abort();
  }
  rivetlua_b5_operation_raise(state, status);
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

static int rivetlua_b7_close_drive_inner(lua_State *state, size_t target,
                                         size_t trim_top, int initial_class,
                                          int nil_slot, int pause_on_error,
                                           rivetlua_capi_callback_step_b4 *handoff,
                                           int *error_replaced) {
  int error_class = initial_class;
  size_t error_position = initial_class > 0 ? (size_t)lua_gettop(state) : 0;
  int closed = 0;
  int new_error = 0;
  if (error_replaced != NULL) *error_replaced = 0;
  for (;;) {
    rivetlua_capi_close_step_b7 step = rivetlua_capi_close_next_b7(
        state, target, error_position, nil_slot);
    if (step.kind == 0) break;
    if (step.kind < 0) {
      /* 已有錯誤時覆寫其槽；同一 close walker 始終只保留最新一個錯誤。 */
      size_t error_trim = error_position != 0
          ? error_position - 1 : (size_t)lua_gettop(state);
      error_class = rivetlua_b7_capture_or_synthesize(
          state, error_trim, step.value, 3);
      error_position = (size_t)lua_gettop(state);
      new_error = 1;
      if (error_replaced != NULL) *error_replaced = 1;
      if (nil_slot || pause_on_error) break;
      continue;
    }
    closed++;
    if (step.kind == 2) {
      size_t call_top = (size_t)lua_gettop(state) - (size_t)step.value - 1;
      rivetlua_capi_checkpoint_a1 *driver_owner = rivetlua_capi_top_a1;
      if (driver_owner == NULL || driver_owner->state != state ||
          (driver_owner != rivetlua_capi_b4_driver_top &&
           driver_owner != rivetlua_capi_b5_driver_top &&
           driver_owner != rivetlua_capi_resume_top_a5))
        driver_owner = NULL;
      if (driver_owner != NULL) {
        if (driver_owner->close_triplets_b4 == ~0u) abort();
        driver_owner->close_triplets_b4++;
      }
      rivetlua_capi_callback_step_b4 nested_step;
      int call_status = rivetlua_b4_call_drive(
          state, step.value, 0, 0, 0, -1, 0, NULL, &nested_step, NULL, -1);
      if (rivetlua_capi_close_recycle_b7(state) != 1) abort();
      if (driver_owner != NULL) driver_owner->close_triplets_b4--;
      if (call_status == -3) {
        if (handoff == NULL) abort();
        *handoff = nested_step;
        return -3;
      }
      if (call_status == -2) {
        rivetlua_b4_raise_terminal_a1(state);
        return -RV_A1_ERROR_LUA;
      }
      if (call_status != 0) {
        size_t error_trim = error_position != 0
            ? error_position - 1 : call_top;
        error_class = rivetlua_b7_capture_or_synthesize(
            state, error_trim, RV_A1_ERROR_LUA, 3);
        error_position = (size_t)lua_gettop(state);
        new_error = 1;
        if (error_replaced != NULL) *error_replaced = 1;
        if (pause_on_error) break;
      }
    }
    if (nil_slot) break;
  }
  if (nil_slot && closed == 0 && error_class == 0) {
    error_class = rivetlua_b7_capture_or_synthesize(
        state, (size_t)lua_gettop(state), RV_A1_ERROR_LUA, 3);
    error_position = (size_t)lua_gettop(state);
  }
  if (error_class > 0 && (!pause_on_error || new_error)) {
    rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
    if (top == NULL || top->state != state || error_position == 0 ||
        rivetlua_capi_close_finalize_error_b7(
            state, trim_top, top->token, error_class) != 1)
      abort();
    return -error_class;
  }
  return 0;
}

static int rivetlua_b7_close_drive(lua_State *state, size_t target,
                                   size_t trim_top, int initial_class,
                                   int nil_slot) {
  return rivetlua_b7_close_drive_inner(
      state, target, trim_top, initial_class, nil_slot, 0, NULL, NULL);
}

static int rivetlua_b7_close_drive_handoff(
    lua_State *state, size_t target, size_t trim_top, int initial_class,
    int nil_slot, int pause_on_error,
    rivetlua_capi_callback_step_b4 *handoff) {
  return rivetlua_b7_close_drive_inner(
      state, target, trim_top, initial_class, nil_slot, pause_on_error, handoff,
      NULL);
}

/* message handler 已完成；每個新 closer 錯誤先交回同一 VM 保護邊界。 */
static int rivetlua_b7_close_drive_overlay(lua_State *state, size_t target,
                                            size_t trim_top, int initial_class,
                                            rivetlua_capi_callback_step_b4 *handoff) {
  return rivetlua_b7_close_drive_inner(
      state, target, trim_top, initial_class, 0, 1, handoff, NULL);
}

/* 無自有 checkpoint 的公開 C API 保留最近的 VM handler 控制權。 */
static int rivetlua_b7_close_drive_forward(lua_State *state, size_t target,
                                           size_t trim_top, int nil_slot) {
  rivetlua_capi_callback_step_b4 handoff;
  int pause = rivetlua_capi_call_handler_before_close_a2(state) == 1;
  int result = rivetlua_b7_close_drive_inner(
      state, target, trim_top, 0, nil_slot, pause, &handoff, NULL);
  if (result == -3) {
    rivetlua_b4_transfer_handoff(state, &handoff);
    abort();
  }
  return result;
}

/* C os.exit(true) 在撤銷 callback frame 前先關其目前 C stack 的 TBC。
   若 closer 再次退出，原純 C checkpoint 會接住跳轉並重掃餘下 closers。 */
static void rivetlua_b11_process_exit_close_stack(lua_State *state) {
  int status = 0, close = 0;
  if (rivetlua_capi_process_exit_request_b11(state, &status, &close) != 1)
    return;
  if (!close) exit(status);
  (void)rivetlua_capi_shutdown_scratch_prepare_b11(state);
  if (rivetlua_b7_close_drive(state, 0, 0, 0, 0) != 0) {
    int32_t error_class = 0;
    (void)rivetlua_capi_error_consume_a1(state, &error_class);
    (void)rivetlua_capi_settop_direct_b7(state, 0);
  }
}

static int rivetlua_b11_public_status(int internal) {
  int code = internal < 0 ? -internal : internal;
  return rivetlua_b13_public_status(code);
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
  int terminal_exit = 0;
  int jumped = setjmp(checkpoint.jump);
  if (jumped == 3) {
    terminal_exit = 1;
  } else if (jumped == 0) {
    checkpoint.rust_action_active = 1;
    rivetlua_capi_callback_step_b4 step =
        rivetlua_capi_test_resume_prepare_b11(state);
    checkpoint.rust_action_active = 0;
    while (step.kind == 1 || step.kind == 2 || step.kind == 4) {
      int count = 0;
      if (!rivetlua_b10_invoke_step(state, &step, &count)) break;
      if (rivetlua_b7_close_drive(state, 0, (size_t)lua_gettop(state), 0, 0)
          != 0) break;
      checkpoint.rust_action_active = 1;
      step = rivetlua_capi_call_resume_b4(state, count, LUA_MULTRET);
      checkpoint.rust_action_active = 0;
    }
    if (step.kind == -2) terminal_exit = 1;
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
  if (terminal_exit) rivetlua_b4_raise_terminal_a1(state);
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
  int terminal_exit_seen = 0;
  checkpoint.rust_action_active = 1;
  int start_status = rivetlua_capi_reset_start_a5(state);
  checkpoint.rust_action_active = 0;
  if (start_status != LUA_OK) {
    status = start_status;
    goto reset_exit_b11;
  }
  int initial_jump = setjmp(checkpoint.jump);
  if (initial_jump == 3) {
    terminal_exit_seen = 1;
    goto reset_exit_b11;
  }
  if (initial_jump != 0) goto reset_exit_b11;
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
        (overlay_status == LUA_ERRMEM ? RV_A1_ERROR_ALLOCATION :
         overlay_status == LUA_ERRERR ? RV_A1_ERROR_HANDLING : RV_A1_ERROR_LUA);
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
  while (step.kind == 1 || step.kind == 2 || step.kind == 3 || step.kind == 4) {
    if (step.kind == 3) {
      int prior_status = latest_error_status != LUA_OK ? latest_error_status : step.value;
      int original_class = prior_status == LUA_OK ? 0 :
          (prior_status == LUA_ERRMEM ? RV_A1_ERROR_ALLOCATION :
           prior_status == LUA_ERRERR ? RV_A1_ERROR_HANDLING : RV_A1_ERROR_LUA);
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
    int jumped = setjmp(checkpoint.jump);
    if (jumped == 3) {
      terminal_exit_seen = 1;
      goto reset_exit_b11;
    }
    if (jumped == 0) {
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
  if (step.kind == -2) {
    terminal_exit_seen = 1;
    goto reset_exit_b11;
  }
  if (step.kind == 0) {
    checkpoint.rust_action_active = 1;
    status = rivetlua_capi_reset_finish_b11(state, latest_error_status);
    checkpoint.rust_action_active = 0;
  } else {
    status = rivetlua_b11_public_status(step.value);
  }
reset_exit_b11: ;
  int exit_status = 0, exit_close = 0;
  if (rivetlua_capi_process_exit_request_b11(
          state, &exit_status, &exit_close) == 1)
    terminal_exit_seen = 1;
  if (terminal_exit_seen) rivetlua_b11_process_exit_close_stack(state);
  if ((status != LUA_OK || terminal_exit_seen) && frame_depth >= 0) {
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
  if (terminal_exit_seen) rivetlua_b4_raise_terminal_a1(state);
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
  if (rivetlua_capi_close_idle_b11(main_state) == 1)
    return rivetlua_capi_close_drop_b11(main_state) == 1;
  if (rivetlua_capi_shutdown_scratch_prepare_b11(main_state) != 1) return 0;
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
  int initial_jump = setjmp(checkpoint.jump);
  if (initial_jump == 3) {
    rivetlua_b11_process_exit_close_stack(main_state);
    checkpoint.rust_action_active = 1;
    if (rivetlua_capi_call_abort_to_b7(main_state, frame_depth) != 1)
      complete = 0;
    checkpoint.rust_action_active = 0;
  } else if (initial_jump != 0) {
    complete = 0;
  } else if (rivetlua_b7_close_drive(main_state, 0, 0, 0, 0) != 0) {
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
    int terminal_exit_seen = 0;
    while (step.kind == 1 || step.kind == 2 || step.kind == 4) {
      external_callback_seen = 1;
      volatile int callback_failed = 0;
      volatile int count = 0;
      int jumped = setjmp(checkpoint.jump);
      if (jumped == 3) {
        terminal_exit_seen = 1;
        break;
      }
      if (jumped == 0) {
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
    if (terminal_exit_seen) {
      rivetlua_b11_process_exit_close_stack(main_state);
      checkpoint.rust_action_active = 1;
      if (rivetlua_capi_call_abort_to_b7(main_state, frame_depth) != 1)
        complete = 0;
      checkpoint.rust_action_active = 0;
      if (complete) continue;
      break;
    }
    if (step.kind == -2) {
      rivetlua_b11_process_exit_close_stack(main_state);
      /* 巢狀 os.exit(true) 更新狀態碼後，繼續關閉剩餘 TBC 與 finalizer。 */
      continue;
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
  int exit_status = 0, exit_close = 0;
  int process_exit = rivetlua_capi_process_exit_request_b11(
      main_state, &exit_status, &exit_close);
  if (complete) {
    int dropped = rivetlua_capi_close_drop_b11(main_state) == 1;
    if (process_exit == 1) exit(exit_status);
    return dropped;
  }
  if (process_exit == 1) exit(exit_status);
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
  if (rivetlua_b3_reader_direct(state)) {
    int published = 0;
    int status = rivetlua_b5_operation_drive(
        state, setter ? 7 : 6, 0, index, 0, 0, &published);
    if (status != 0 || published != 1)
      rivetlua_b5_operation_raise_result(state, status, published);
    return;
  }
  int depth = rivetlua_capi_operation_depth_b5(state);
  if (depth < 0) rivetlua_a4_raise(state, -RV_A1_ERROR_LUA);
  rivetlua_capi_callback_step_b4 step =
      rivetlua_capi_table_prepare_a4a(state, index, setter);
  while (step.kind == 1 || step.kind == 2 || step.kind == 4) {
    int returned = 0;
    if (!rivetlua_b10_invoke_step(state, &step, &returned)) break;
    int close_status = rivetlua_b7_close_drive_forward(
        state, 0, (size_t)lua_gettop(state), 0);
    if (close_status != 0) {
      if (rivetlua_capi_operation_abort_to_b5(state, depth) != 0) abort();
      rivetlua_a4_raise(state, close_status);
    }
    step = rivetlua_capi_table_resume_a4a(state, returned, setter);
  }
  if (step.kind == 5) {
    rivetlua_b4_transfer_handoff(state, &step);
    abort();
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
    rivetlua_a3_panic(state, 0);
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

static void rivetlua_b2_requiref_loaded(lua_State *state, const char *modname,
                                        lua_CFunction openf, int glb) {
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

void luaL_requiref(lua_State *state, const char *modname,
                   lua_CFunction openf, int glb) {
  luaL_getsubtable(state, LUA_REGISTRYINDEX, LUA_LOADED_TABLE);
  rivetlua_b2_requiref_loaded(state, modname, openf, glb);
}

typedef struct rivetlua_b2_requiref_context {
  const char *name;
  lua_CFunction opener;
  int global;
  int (*private_loaded)(lua_State *);
  int status;
  struct rivetlua_b2_requiref_context *previous;
} rivetlua_b2_requiref_context;

static _Thread_local rivetlua_b2_requiref_context *rivetlua_b2_requiref_top;

static int rivetlua_b2_requiref_body(lua_State *state) {
  rivetlua_b2_requiref_context *context = rivetlua_b2_requiref_top;
  if (context == NULL) return luaL_error(state, "requiref context unavailable");
  if (context->private_loaded) {
    /* Rust 私有 callback 只在此 body 呼叫；opener 無法取得其函式指標。 */
    if (!context->private_loaded(state))
      return luaL_error(state, "private loaded table unavailable");
    rivetlua_b2_requiref_loaded(state, context->name,
                                context->opener, context->global);
  } else {
    luaL_requiref(state, context->name, context->opener, context->global);
  }
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
                                          lua_CFunction opener, int global,
                                          int (*private_loaded)(lua_State *)) {
  if (state == NULL || name == NULL || opener == NULL) return -1;
  rivetlua_b2_requiref_context request = {
      name, opener, global, private_loaded, LUA_ERRRUN, rivetlua_b2_requiref_top};
  rivetlua_b2_requiref_top = &request;
  rivetlua_capi_outcome_a1 outcome = rivetlua_capi_trampoline_protect_a1(
      state, rivetlua_b2_requiref_action, &request);
  rivetlua_b2_requiref_top = request.previous;
  if (outcome.kind == RV_A1_OUT_NORMAL) return request.status;
  if (outcome.kind != RV_A1_OUT_RAISED) return -1;
  int32_t error_class = 0;
  if (rivetlua_capi_error_consume_a1(state, &error_class) != RV_A1_OK) return -1;
  return rivetlua_b13_public_status(error_class);
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
  return rivetlua_b13_public_status(class_code);
}

static int rivetlua_a2_consume_settle(
    lua_State *state, size_t base, int *class_code, int *throw_depth) {
  if (throw_depth != NULL) {
    int depth = rivetlua_capi_pending_throw_depth_b13(state);
    if (depth < 0) return 0;
    *throw_depth = depth;
  }
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
  if (!lua_isyieldable(state))
    return luaL_error(state, "attempt to yield across a C-call boundary");
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
  if (nresults == 0 && continuation == NULL) {
    int marked = rivetlua_capi_hook_yield_mark_c16(state);
    if (marked < 0)
      rivetlua_b5_operation_raise_message(state, marked, 0);
    if (marked == 1) return 0;
  }
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
  /* 先記錄父 checkpoint；child checkpoint 進入後查詢會看到 child 邊界。 */
  int from_yieldable = from != NULL && lua_isyieldable(from);
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
  checkpoint.close_triplets_b4 = 0;
  checkpoint.handoff_ready_b4 = 0;
  rivetlua_capi_checkpoint_a1 *previous_resume = rivetlua_capi_resume_top_a5;
  rivetlua_capi_checkpoint_a1 *previous_b4 = rivetlua_capi_b4_driver_top;
  rivetlua_capi_checkpoint_a1 *previous_b5 = rivetlua_capi_b5_driver_top;
  rivetlua_capi_top_a1 = &checkpoint;
  rivetlua_capi_resume_top_a5 = &checkpoint;
  volatile size_t resume_base = 0;
  volatile int error_class = 0;
  int result = LUA_ERRRUN;
  int result_count = 0;
  int terminal_exit = 0;
  rivetlua_capi_callback_step_b4 step;
  int jumped = setjmp(checkpoint.jump);
  if (jumped == 3) {
    terminal_exit = 1;
    goto finish;
  }
  if (jumped == 2) {
    result = LUA_YIELD;
    result_count = lua_gettop(state);
    goto finish;
  }
  if (jumped == 4) {
    if (!checkpoint.handoff_ready_b4) abort();
    while (checkpoint.close_triplets_b4 != 0) {
      if (rivetlua_capi_close_recycle_b7(state) != 1) abort();
      checkpoint.close_triplets_b4--;
    }
    step.kind = checkpoint.handoff_b4.kind;
    step.value = checkpoint.handoff_b4.value;
    step.function = checkpoint.handoff_b4.function;
    step.hook = checkpoint.handoff_b4.hook;
    step.event = checkpoint.handoff_b4.event;
    step.currentline = checkpoint.handoff_b4.currentline;
    step.token = checkpoint.handoff_b4.token;
    step.warning_len = checkpoint.handoff_b4.warning_len;
    checkpoint.handoff_ready_b4 = 0;
    goto drive;
  }
  if (jumped == 1) {
    checkpoint.rust_action_active = 0;
    if (raised_status != 0) error_class = raised_status;
    if (rivetlua_capi_call_depth_b7(state) > frame_depth) {
      if (rivetlua_capi_call_handler_before_close_a2(state) == 1) {
        checkpoint.rust_action_active = 1;
        step = rivetlua_capi_call_resume_error_a2(state, LUA_MULTRET);
        checkpoint.rust_action_active = 0;
        goto drive;
      }
      size_t trim_top = (size_t)lua_gettop(state);
      int captured = rivetlua_capi_close_capture_error_b7(state, trim_top);
      if (captured <= 0) goto finish;
      rivetlua_capi_callback_step_b4 nested_step;
      int closed = rivetlua_b7_close_drive_handoff(
          state, 0, trim_top, captured, 0, 0, &nested_step);
      if (closed == -3) {
        step = nested_step;
        goto drive;
      }
      if (closed < 0) error_class = -closed;
      checkpoint.rust_action_active = 1;
      step = rivetlua_capi_call_resume_error_a2(state, LUA_MULTRET);
      checkpoint.rust_action_active = 0;
      goto drive;
    }
    result = rivetlua_b13_public_status(error_class);
    goto finish;
  }
  checkpoint.rust_action_active = 1;
  rivetlua_capi_resume_setup_a5 setup =
      rivetlua_capi_resume_prepare_a5(state, from, nargs, from_yieldable);
  checkpoint.rust_action_active = 0;
  if (setup.kind < 0) {
    result = setup.status;
    int top = lua_gettop(state);
    if (nargs >= 0 && nargs <= top) lua_settop(state, top - nargs);
    if (lua_pushstring(state, result == LUA_ERRMEM
            ? "not enough memory"
            : (setup.kind == -2 ? "C stack overflow"
                                : "cannot resume non-suspended coroutine")) == NULL)
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
    rivetlua_capi_callback_step_b4 nested_step;
    int handler_before_close =
        rivetlua_capi_call_handler_before_close_a2(state) == 1;
    int closed = rivetlua_b7_close_drive_handoff(
        state, 0, (size_t)lua_gettop(state), 0, 0,
        handler_before_close, &nested_step);
    if (closed == -3) {
      step = nested_step;
      goto drive;
    }
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
  while (step.kind == 1 || step.kind == 2 || step.kind == 4 || step.kind == 5) {
    if (step.kind == 5) {
      int current_depth = rivetlua_capi_call_depth_b7(state);
      if (current_depth <= frame_depth) abort();
      size_t top = (size_t)lua_gettop(state);
      if (top == 0) abort();
      rivetlua_capi_callback_step_b4 nested_step;
      int closed = rivetlua_b7_close_drive_overlay(
          state, 0, top - 1, step.value, &nested_step);
      if (closed == -3) {
        step = nested_step;
        continue;
      }
      checkpoint.rust_action_active = 1;
      step = rivetlua_capi_call_resume_overlay_a2(
          state, closed < 0 ? -closed : 0,
          rivetlua_capi_continuation_results_a5(state));
      checkpoint.rust_action_active = 0;
      continue;
    }
    int count = 0;
    if (!rivetlua_b10_invoke_step(state, &step, &count)) goto finish;
    rivetlua_capi_callback_step_b4 nested_step;
    int handler_before_close =
        rivetlua_capi_call_handler_before_close_a2(state) == 1;
    int closed = rivetlua_b7_close_drive_handoff(
        state, 0, (size_t)lua_gettop(state), 0, 0,
        handler_before_close, &nested_step);
    if (closed == -3) {
      step = nested_step;
      continue;
    }
    checkpoint.rust_action_active = 1;
    step = closed == 0
        ? rivetlua_capi_call_resume_a2(
              state, count, rivetlua_capi_continuation_results_a5(state))
        : rivetlua_capi_call_resume_error_a2(
              state, rivetlua_capi_continuation_results_a5(state));
    checkpoint.rust_action_active = 0;
  }
  if (step.kind == -2) {
    terminal_exit = 1;
    goto finish;
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
      rivetlua_capi_callback_step_b4 nested_step;
      int handler_before_close =
          rivetlua_capi_call_handler_before_close_a2(state) == 1;
      int closed = rivetlua_b7_close_drive_handoff(
          state, 0, (size_t)lua_gettop(state), 0, 0,
          handler_before_close, &nested_step);
      if (closed == -3) {
        step = nested_step;
        goto drive;
      }
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
                state, continuation_step.base, &class_code, NULL)) goto finish;
        int kstatus = rivetlua_a2_status(class_code);
        continuation_step = rivetlua_capi_continuation_step_a5(
            state, (size_t)depth, 1);
        int count = continuation_step.continuation(
            state, kstatus, continuation_step.context);
        rivetlua_capi_callback_step_b4 nested_step;
        int handler_before_close =
            rivetlua_capi_call_handler_before_close_a2(state) == 1;
        int closed = rivetlua_b7_close_drive_handoff(
            state, 0, (size_t)lua_gettop(state), 0, 0,
            handler_before_close, &nested_step);
        if (closed == -3) {
          step = nested_step;
          goto drive;
        }
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
finish: ;
  int exit_status = 0, exit_close = 0;
  if (rivetlua_capi_process_exit_request_b11(
          state, &exit_status, &exit_close) == 1)
    terminal_exit = 1;
  if (terminal_exit) rivetlua_b11_process_exit_close_stack(state);
  if ((result != LUA_YIELD || terminal_exit) &&
      rivetlua_capi_call_depth_b7(state) > frame_depth) {
    checkpoint.rust_action_active = 1;
    (void)rivetlua_capi_call_abort_to_b7(state, frame_depth);
    checkpoint.rust_action_active = 0;
  }
  /* lua_yieldk 會跨越內層 C frames；其 driver TLS 不能留在已失效的 stack frame。 */
  rivetlua_capi_b4_driver_top = previous_b4;
  rivetlua_capi_b5_driver_top = previous_b5;
  rivetlua_capi_resume_top_a5 = previous_resume;
  rivetlua_capi_top_a1 = checkpoint.previous;
  if (rivetlua_capi_checkpoint_exit_a1(
          state, checkpoint.generation, checkpoint.token,
          checkpoint.previous_state_token) != RV_A1_OK)
    return LUA_ERRRUN;
  if (terminal_exit) rivetlua_b4_raise_terminal_a1(state);
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
            rivetlua_a2_consume_settle(state, setup.base, &class_code, NULL))
          return rivetlua_a2_status(class_code);
      }
      return LUA_ERRRUN;
    }
    registered = 1;
  }
  int status = LUA_OK;
  rivetlua_capi_callback_step_b4 handoff;
  int driven = rivetlua_a2_call_drive(
      state, nargs, nresults, registered, -1, 1, setup.handler, &handoff);
  if (driven == -3) {
    if (registered)
      (void)rivetlua_capi_continuation_step_a5(
          state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
    rivetlua_capi_public_drop_handler_a2(setup.handler);
    rivetlua_b4_transfer_handoff(state, &handoff);
    abort();
  }
  if (driven == -2) {
    rivetlua_a2_terminal_cleanup(state, registered, setup.handler);
    return LUA_ERRRUN;
  }
  if (driven != 0) {
    int class_code = RV_A1_ERROR_LUA;
    if (!rivetlua_a2_consume_settle(state, setup.base, &class_code, NULL)) {
      if (registered)
        (void)rivetlua_capi_continuation_step_a5(
            state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
      else
        rivetlua_capi_public_drop_handler_a2(setup.handler);
      return LUA_ERRRUN;
    }
    status = rivetlua_a2_status(class_code);
  }
  if (registered)
    (void)rivetlua_capi_continuation_step_a5(
        state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
  else
    rivetlua_capi_public_drop_handler_a2(setup.handler);
  return status;
}

static void rivetlua_a2_callk_impl(lua_State *state, int nargs, int nresults,
                                   lua_KContext context, lua_KFunction continuation,
                                   int builtin_kind) {
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
  rivetlua_capi_callback_step_b4 handoff;
  int driven = rivetlua_a2_call_drive(
      state, nargs, nresults,
      registered && (builtin_kind < 0 ||
                     rivetlua_capi_builtin_allows_yield(builtin_kind)),
      builtin_kind, rivetlua_b3_reader_direct(state), NULL, &handoff);
  if (driven == -3) {
    if (registered)
      (void)rivetlua_capi_continuation_step_a5(
          state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
    rivetlua_b4_transfer_handoff(state, &handoff);
    abort();
  }
  if (driven == -2) {
    rivetlua_a2_terminal_cleanup(state, registered, NULL);
    return;
  }
  if (driven == 0) {
    if (registered)
      (void)rivetlua_capi_continuation_step_a5(
          state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
    return;
  }
  int class_code = RV_A1_ERROR_LUA;
  int throw_depth = 0;
  if (!rivetlua_a2_consume_settle(
          state, setup.base, &class_code, &throw_depth)) abort();
  if (registered)
    (void)rivetlua_capi_continuation_step_a5(
        state, (size_t)rivetlua_capi_call_depth_b7(state), 1);
  if (rivetlua_capi_c_depth_set_b13(state, (uint16_t)throw_depth) != 0)
    abort();
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (top != NULL && top->state == state && top->rust_action_active == 0 &&
      rivetlua_capi_error_prepare_a1(
          state, top->generation, top->token, class_code) == RV_A1_OK)
    rivetlua_b7_raise_existing(state, -class_code);
  lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
  if (panicf != NULL) (void)panicf(state);
  abort();
}

void lua_callk(lua_State *state, int nargs, int nresults,
               lua_KContext context, lua_KFunction continuation) {
  rivetlua_a2_callk_impl(state, nargs, nresults, context, continuation, -1);
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
  int terminal_exit = 0;
  checkpoint.rust_action_active = 1;
  rivetlua_capi_callback_step_b4 step = rivetlua_capi_gc_prepare_b8(
      state, what, bytes, first, second, third);
  checkpoint.rust_action_active = 0;
  if (step.kind >= 0) answer = step.value;
  for (; step.kind == 1 || step.kind == 2 || step.kind == 4;) {
    volatile int callback_failed = 0;
    volatile int count = 0;
    /* C finalizer 的錯誤只回到此 C checkpoint，再交給 protected VM boundary。 */
    int jumped = setjmp(checkpoint.jump);
    if (jumped == 3) {
      terminal_exit = 1;
      status = -RV_A1_ERROR_LUA;
      break;
    }
    if (jumped == 0) {
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
  if (!terminal_exit && step.kind == -2) {
    terminal_exit = 1;
    status = -RV_A1_ERROR_LUA;
  }
  if (!terminal_exit &&
      (step.kind < 0 || step.kind == 1 || step.kind == 2 || step.kind == 4))
    status = -(step.value > 0 ? step.value : RV_A1_ERROR_LUA);
  int exit_status = 0, exit_close = 0;
  if (rivetlua_capi_process_exit_request_b11(
          state, &exit_status, &exit_close) == 1)
    terminal_exit = 1;
  if (terminal_exit) rivetlua_b11_process_exit_close_stack(state);
  if (status != 0 || terminal_exit) {
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
  if (terminal_exit) rivetlua_b4_raise_terminal_a1(state);
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
  int result = rivetlua_b7_close_drive_forward(
      state, (size_t)position - 1, (size_t)lua_gettop(state), 1);
  if (result != 0) rivetlua_b7_raise_existing(state, result);
  if (rivetlua_capi_close_finish_slot_b7(state, (size_t)position - 1) != 1)
    rivetlua_b5_operation_raise_message(state, -RV_A1_ERROR_LUA, 3);
}

void lua_settop(lua_State *state, int index) {
  int top = lua_gettop(state);
  int64_t target = index >= 0 ? (int64_t)index : (int64_t)top + index + 1;
  if (target < 0 || target > INT32_MAX) {
    if (rivetlua_capi_top_a1 == NULL) return;
    rivetlua_b5_operation_raise_message(state, -RV_A1_ERROR_LUA, 3);
  }
  if (target < top) {
    int result = rivetlua_b7_close_drive_forward(state, (size_t)target,
                                                  (size_t)target, 0);
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
    rivetlua_b5_operation_raise_result(state, status, published);
}

void lua_concat(lua_State *state, int count) {
  if (count == 1) return;
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 1, 0, 0, 0, count, &published);
  if (status != 0 || published != 1)
    rivetlua_b5_operation_raise_result(state, status, published);
}

void lua_len(lua_State *state, int index) {
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 2, 0, index, 0, 0, &published);
  if (status != 0 || published != 1)
    rivetlua_b5_operation_raise_result(state, status, published);
}

int lua_compare(lua_State *state, int left, int right, int operation) {
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 3, operation, left, right, 0, &published);
  if (status != 0)
    rivetlua_b5_operation_raise_result(state, status, published);
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
    rivetlua_b5_operation_raise_result(state, status, published);
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

static int rivetlua_a3_global_name_from_top(lua_State *state, int top) {
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

static int rivetlua_a3_global_name(lua_State *state, lua_Debug *ar) {
  int top = lua_gettop(state);
  if (!lua_getinfo(state, "f", ar)) return 0;
  return rivetlua_a3_global_name_from_top(state, top);
}

static int rivetlua_a3_trace_global_name(
    lua_State *state, lua_State *source, lua_Debug *ar) {
  if (state == source) return rivetlua_a3_global_name(state, ar);
  int source_top = lua_gettop(source);
  if (!lua_getinfo(source, "fu", ar)) {
    lua_settop(source, source_top);
    return 0;
  }
  /* 官方零 upvalue C 函式是 light C value；其他 closure 不跨 VM 搬移。 */
  lua_CFunction function = ar->nups == 0 ? lua_tocfunction(source, -1) : NULL;
  lua_settop(source, source_top);
  if (function == NULL) return 0;
  int top = lua_gettop(state);
  lua_pushcfunction(state, function);
  return rivetlua_a3_global_name_from_top(state, top);
}

static void rivetlua_a3_func_name(
    lua_State *state, lua_State *source, lua_Debug *ar) {
#if LUA_VERSION_NUM < 505
  if (rivetlua_a3_trace_global_name(state, source, ar)) {
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
  else if (rivetlua_a3_trace_global_name(state, source, ar)) {
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
      rivetlua_a3_func_name(state, source, &ar);
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
  RV_A4B_GETMETAFIELD, RV_A4B_TESTUDATA, RV_A5_OPEN_STANDARD_LIBRARY,
  RV_A3_PUSHSTRING, RV_A3_CREATETABLE, RV_A3_FILERESULT,
  RV_A3_EXECRESULT, RV_A3_RAWSET, RV_A3_RAWSETI, RV_A3_RAWSETP
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
  if (top == NULL) rivetlua_a3_panic(state, 0);
  abort();
}

int luaopen_base(lua_State *state) {
  return rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 0, 0,
                             0, 0, NULL, NULL, NULL, NULL).value;
}

extern int rivetlua_capi_allow_file_load_b22(lua_State *state);

static void rivetlua_compat_setpath_b22(lua_State *state, const char *field,
                                        const char *variable, const char *fallback) {
  lua_getfield(state, LUA_REGISTRYINDEX, "LUA_NOENV");
  int noenv = lua_toboolean(state, -1);
  lua_pop(state, 1);
  const char *path = NULL;
  if (!noenv) {
    const char *versioned = lua_pushfstring(state, "%s%s", variable, LUA_VERSUFFIX);
    path = getenv(versioned);
    if (path == NULL) path = getenv(variable);
    lua_pop(state, 1);
  }
  const char *mark = path == NULL ? NULL : strstr(path, ";;");
  if (path == NULL) lua_pushstring(state, fallback);
  else if (mark == NULL) lua_pushstring(state, path);
  else {
    luaL_Buffer buffer;
    luaL_buffinit(state, &buffer);
    if (mark != path) {
      luaL_addlstring(&buffer, path, (size_t)(mark - path));
      luaL_addchar(&buffer, ';');
    }
    luaL_addstring(&buffer, fallback);
    if (mark[2] != '\0') {
      luaL_addchar(&buffer, ';');
      luaL_addstring(&buffer, mark + 2);
    }
    luaL_pushresult(&buffer);
  }
  lua_setfield(state, -2, field);
}

int luaopen_package(lua_State *state) {
  int result = rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 1, 0,
                                  0, 0, NULL, NULL, NULL, NULL).value;
  if (result == 1 && rivetlua_capi_allow_file_load_b22(state)) {
    rivetlua_compat_setpath_b22(state, "path", "LUA_PATH", LUA_PATH_DEFAULT);
    rivetlua_compat_setpath_b22(state, "cpath", "LUA_CPATH", LUA_CPATH_DEFAULT);
  }
  return result;
}

int luaopen_coroutine(lua_State *state) {
  return rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 2, 0,
                             0, 0, NULL, NULL, NULL, NULL).value;
}

int luaopen_table(lua_State *state) {
  return rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 3, 0,
                             0, 0, NULL, NULL, NULL, NULL).value;
}

int luaopen_io(lua_State *state) {
  return rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 4, 0,
                             0, 0, NULL, NULL, NULL, NULL).value;
}

int luaopen_os(lua_State *state) {
  return rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 5, 0,
                             0, 0, NULL, NULL, NULL, NULL).value;
}

int luaopen_string(lua_State *state) {
  return rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 6, 0,
                             0, 0, NULL, NULL, NULL, NULL).value;
}

int luaopen_math(lua_State *state) {
  return rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 7, 0,
                             0, 0, NULL, NULL, NULL, NULL).value;
}

int luaopen_utf8(lua_State *state) {
  return rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 8, 0,
                             0, 0, NULL, NULL, NULL, NULL).value;
}

int luaopen_debug(lua_State *state) {
  return rivetlua_a3_generic(state, NULL, RV_A5_OPEN_STANDARD_LIBRARY, 9, 0,
                             0, 0, NULL, NULL, NULL, NULL).value;
}

#if LUA_VERSION_NUM >= 505
void luaL_openselectedlibs(lua_State *state, int load, int preload) {
  static const struct {
    const char *name;
    lua_CFunction openf;
    int mask;
  } libraries[] = {
    {LUA_GNAME, luaopen_base, LUA_GLIBK},
    {LUA_LOADLIBNAME, luaopen_package, LUA_LOADLIBK},
    {LUA_COLIBNAME, luaopen_coroutine, LUA_COLIBK},
    {LUA_DBLIBNAME, luaopen_debug, LUA_DBLIBK},
    {LUA_IOLIBNAME, luaopen_io, LUA_IOLIBK},
    {LUA_MATHLIBNAME, luaopen_math, LUA_MATHLIBK},
    {LUA_OSLIBNAME, luaopen_os, LUA_OSLIBK},
    {LUA_STRLIBNAME, luaopen_string, LUA_STRLIBK},
    {LUA_TABLIBNAME, luaopen_table, LUA_TABLIBK},
    {LUA_UTF8LIBNAME, luaopen_utf8, LUA_UTF8LIBK}
  };
  size_t index;
  luaL_getsubtable(state, LUA_REGISTRYINDEX, LUA_PRELOAD_TABLE);
  for (index = 0; index < sizeof(libraries) / sizeof(libraries[0]); ++index) {
    if (load & libraries[index].mask) {
      luaL_requiref(state, libraries[index].name, libraries[index].openf, 1);
      lua_pop(state, 1);
    } else if (preload & libraries[index].mask) {
      lua_pushcfunction(state, libraries[index].openf);
      lua_setfield(state, -2, libraries[index].name);
    }
  }
  lua_pop(state, 1);
}
#else
void luaL_openlibs(lua_State *state) {
  static const struct {
    const char *name;
    lua_CFunction openf;
  } libraries[] = {
    {LUA_GNAME, luaopen_base},
    {LUA_LOADLIBNAME, luaopen_package},
    {LUA_COLIBNAME, luaopen_coroutine},
    {LUA_TABLIBNAME, luaopen_table},
    {LUA_IOLIBNAME, luaopen_io},
    {LUA_OSLIBNAME, luaopen_os},
    {LUA_STRLIBNAME, luaopen_string},
    {LUA_MATHLIBNAME, luaopen_math},
    {LUA_UTF8LIBNAME, luaopen_utf8},
    {LUA_DBLIBNAME, luaopen_debug}
  };
  size_t index;
  for (index = 0; index < sizeof(libraries) / sizeof(libraries[0]); ++index) {
    luaL_requiref(state, libraries[index].name, libraries[index].openf, 1);
    lua_pop(state, 1);
  }
}
#endif

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
  if (!lua_checkstack(state, space)) {
    if (message != NULL) luaL_error(state, "stack overflow (%s)", message);
    else luaL_error(state, "stack overflow");
  }
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

const char *lua_pushlstring(lua_State *state, const char *source, size_t length) {
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  uint64_t generation = top == NULL ? 0 : top->generation;
  uint64_t token = top == NULL ? 0 : top->token;
  rivetlua_capi_strict_result_b2 result = rivetlua_capi_pushlstring_dispatch_b14(
      state, generation, token, source, length);
  if (result.kind == RV_A1_ACTION_RETURN) return (const char *)result.pointer;
  if (result.kind == RV_A1_ACTION_RAISE)
    (void)rivetlua_b2_finish(state, generation, token, result);
  if (top == NULL) {
    (void)rivetlua_capi_generic_panic_error_a3(state);
    lua_CFunction panicf = rivetlua_capi_panic_snapshot_a2(state);
    if (panicf != NULL) (void)panicf(state);
  }
  abort();
}

const char *lua_pushstring(lua_State *state, const char *source) {
  return (const char *)rivetlua_a3_generic(
      state, NULL, RV_A3_PUSHSTRING, 0, 0,
      0, 0, NULL, source, NULL, NULL).pointer;
}

const char *lua_tolstring(lua_State *state, int index, size_t *length) {
  rivetlua_capi_aux_value_a4b result =
      rivetlua_a4b_aux_value(state, 7, index, 0, 0, NULL);
  if (length != NULL) *length = result.length;
  return result.pointer;
}

void lua_createtable(lua_State *state, int array, int hash) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_CREATETABLE, array, hash,
                            0, 0, NULL, NULL, NULL, NULL);
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

int luaL_fileresult(lua_State *state, int stat, const char *fname) {
  int saved_errno = errno;
  return rivetlua_a3_generic(state, NULL, RV_A3_FILERESULT, stat, 0,
      (lua_Integer)saved_errno, 0, NULL, fname, NULL, NULL).value;
}

int luaL_execresult(lua_State *state, int stat) {
  int saved_errno = errno;
  return rivetlua_a3_generic(state, NULL, RV_A3_EXECRESULT, stat, 0,
      (lua_Integer)saved_errno, 0, NULL, NULL, NULL, NULL).value;
}

void lua_rawset(lua_State *state, int index) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_RAWSET, index, 0,
                            0, 0, NULL, NULL, NULL, NULL);
}

void lua_rawseti(lua_State *state, int index, lua_Integer key) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_RAWSETI, index, 0,
                            key, 0, NULL, NULL, NULL, NULL);
}

void lua_rawsetp(lua_State *state, int index, const void *key) {
  (void)rivetlua_a3_generic(state, NULL, RV_A3_RAWSETP, index, 0,
                            0, 0, (void *)key, NULL, NULL, NULL);
}

/* 測試入口須為純 C frame；failpoint 於 frame 建立後、目標 API 前才啟用。 */
extern uint64_t rivetlua_capi_test_inject_offset_a4a(lua_State *state, uint64_t offset);
extern int rivetlua_capi_test_limit_current_b14(lua_State *state);
static _Thread_local int rivetlua_capi_b14_after_api;

static _Thread_local int rivetlua_capi_b15_close_oom_calls;
static _Thread_local int rivetlua_capi_b15_close_oom_after;

void rivetlua_capi_test_close_oom_reset_b15(void) {
  rivetlua_capi_b15_close_oom_calls = 0;
  rivetlua_capi_b15_close_oom_after = 0;
}

int rivetlua_capi_test_close_oom_calls_b15(void) {
  return rivetlua_capi_b15_close_oom_calls;
}

int rivetlua_capi_test_close_oom_after_b15(void) {
  return rivetlua_capi_b15_close_oom_after;
}

int rivetlua_capi_test_close_oom_finalizer_b15(lua_State *state) {
  rivetlua_capi_b15_close_oom_calls++;
  lua_createtable(state, 32, 32);
  rivetlua_capi_b15_close_oom_after++;
  return 0;
}

void rivetlua_capi_test_reset_after_api_b14(void) {
  rivetlua_capi_b14_after_api = 0;
}

int rivetlua_capi_test_after_api_b14(void) {
  return rivetlua_capi_b14_after_api;
}

static void rivetlua_capi_test_arm_result_b14(lua_State *state) {
  if (lua_type(state, 1) != LUA_TNUMBER) return;
  int code = (int)lua_tointeger(state, 1);
  int armed = code == -1
      ? rivetlua_capi_test_limit_current_b14(state)
      : rivetlua_capi_test_inject_point_a4a(state, code);
  if (armed != 1) (void)luaL_error(state, "B14 failure injection setup");
}

int rivetlua_capi_test_fileresult_oom_b14(lua_State *state) {
  errno = lua_type(state, 1) == LUA_TNUMBER && lua_tointeger(state, 1) == -1 ? 0 : 2;
  rivetlua_capi_test_arm_result_b14(state);
  int result = luaL_fileresult(state, 0, NULL);
  rivetlua_capi_b14_after_api = 1;
  return result;
}

int rivetlua_capi_test_execresult_oom_b14(lua_State *state) {
  errno = 0;
  rivetlua_capi_test_arm_result_b14(state);
  int result = luaL_execresult(state, 7 << 8);
  rivetlua_capi_b14_after_api = 1;
  return result;
}

int rivetlua_capi_test_rawset_b14(lua_State *state) {
  lua_rawset(state, 1);
  rivetlua_capi_b14_after_api = 1;
  return 0;
}

int rivetlua_capi_test_rawset_injected_b14(lua_State *state) {
  uint64_t offset = (uint64_t)lua_tointeger(state, 1);
  if (rivetlua_capi_test_inject_offset_a4a(state, offset) == 0)
    return luaL_error(state, "B14 failure injection setup");
  lua_rawset(state, 2);
  rivetlua_capi_b14_after_api = 1;
  return 0;
}

int rivetlua_capi_test_rawset_bad_table_b14(lua_State *state) {
  lua_rawset(state, -1);
  return 0;
}

int rivetlua_capi_test_rawsetp_b14(lua_State *state) {
  lua_rawsetp(state, 1, NULL);
  rivetlua_capi_b14_after_api = 1;
  return 0;
}

int rivetlua_capi_test_rawsetp_injected_b14(lua_State *state) {
  if (rivetlua_capi_test_inject_point_a4a(state, 7) != 1)
    return luaL_error(state, "B14 failure injection setup");
  lua_rawsetp(state, 1, NULL);
  rivetlua_capi_b14_after_api = 1;
  return 0;
}

int rivetlua_capi_test_rawseti_b14(lua_State *state) {
  if (lua_toboolean(state, 1) &&
      rivetlua_capi_test_inject_point_a4a(state, 7) != 1)
    return luaL_error(state, "B14 failure injection setup");
  lua_rawseti(state, 2, 97);
  rivetlua_capi_b14_after_api = 1;
  return 0;
}

int rivetlua_capi_test_pushlstring_oom_b14(lua_State *state) {
  static const char value[] = "b14 long binary string allocation probe\0tail";
  if (lua_toboolean(state, 1) &&
      rivetlua_capi_test_inject_point_a4a(state, 6) != 1)
    return luaL_error(state, "B14 failure injection setup");
  lua_pushlstring(state, value, sizeof(value) - 1);
  rivetlua_capi_b14_after_api = 1;
  return 1;
}

int rivetlua_capi_test_pushstring_oom_b14(lua_State *state) {
  if (lua_toboolean(state, 1) &&
      rivetlua_capi_test_inject_point_a4a(state, 6) != 1)
    return luaL_error(state, "B14 failure injection setup");
  lua_pushstring(state, "b14 long string allocation probe");
  rivetlua_capi_b14_after_api = 1;
  return 1;
}

int rivetlua_capi_test_tolstring_oom_b14(lua_State *state) {
  lua_pushnumber(state, 12345.75);
  if (lua_toboolean(state, 1) &&
      rivetlua_capi_test_inject_point_a4a(state, 6) != 1)
    return luaL_error(state, "B14 failure injection setup");
  (void)lua_tolstring(state, -1, NULL);
  rivetlua_capi_b14_after_api = 1;
  return 1;
}

int rivetlua_capi_test_createtable_oom_b14(lua_State *state) {
  if (lua_toboolean(state, 1) &&
      rivetlua_capi_test_inject_point_a4a(state, 1) != 1)
    return luaL_error(state, "B14 failure injection setup");
  lua_createtable(state, 32, 32);
  rivetlua_capi_b14_after_api = 1;
  return 1;
}

const char *luaL_tolstring(lua_State *state, int index, size_t *length) {
  index = lua_absindex(state, index);
  int published = 0;
  int status = rivetlua_b5_operation_drive(
      state, 5, 0, index, 0, 0, &published);
  if (status != 0)
    rivetlua_b5_operation_raise_result(state, status, published);
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
  if (top == NULL)
    rivetlua_a3_panic(state, action.kind == RV_A1_ACTION_RAISE);
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
  if (top == NULL)
    rivetlua_a3_panic(state, result.kind == RV_A1_ACTION_RAISE);
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
typedef void (*rivetlua_capi_terminal_cleanup_a1)(void *context);

static rivetlua_capi_outcome_a1 rivetlua_capi_trampoline_protect_impl_a1(
    void *state, rivetlua_capi_action_fn_a1 action_fn, void *context,
    rivetlua_capi_raised_hook_a1 raised_hook,
    rivetlua_capi_terminal_cleanup_a1 terminal_cleanup) {
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
  int terminal_exit = 0;
  int jumped = setjmp(checkpoint.jump);
  if (jumped == 0) {
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
  } else if (jumped == 3) {
    terminal_exit = 1;
    /* 本 C frame 不再返回 caller；先釋放 B3 reader／writer 擁有的資源。 */
    if (terminal_cleanup != NULL) terminal_cleanup(context);
    rivetlua_b11_process_exit_close_stack((lua_State *)state);
    outcome.kind = RV_A1_OUT_REJECTED;
    outcome.value = RV_A1_REJECT_INVALID_ACTION;
    (void)rivetlua_capi_pending_cancel_a1(
        state, checkpoint.generation, checkpoint.token);
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
  if (terminal_exit) rivetlua_b4_raise_terminal_a1((lua_State *)state);
  return outcome;
}

rivetlua_capi_outcome_a1 rivetlua_capi_trampoline_protect_a1(
    void *state, rivetlua_capi_action_fn_a1 action_fn, void *context) {
  return rivetlua_capi_trampoline_protect_impl_a1(
      state, action_fn, context, NULL, NULL);
}

/* B3：C reader／writer frame 是唯一 callback 與 longjmp 邊界。Rust session
   只在 callback 已返回時短借 VM，並由本 frame 在所有退出路徑釋放。 */
typedef struct { void *pointer; int32_t fault; } rivetlua_b3_load_start;
typedef struct {
  int32_t fault;
  int32_t stopped_class;
  int32_t terminal;
  int32_t yield_attempt;
} rivetlua_b3_load_drive;
#if LUA_VERSION_NUM >= 505
typedef struct {
  void *pointer;
  const void *data;
  size_t len;
  int32_t fault;
} rivetlua_b3_dump_start;
#else
typedef union {
  uint64_t alignment;
  unsigned char bytes[256];
} rivetlua_b3_dump54_storage;
typedef struct {
  const void *data;
  size_t len;
  unsigned char inline_bytes[16];
  int32_t fault;
  int32_t done;
} rivetlua_b3_dump54_next;
#endif

extern rivetlua_b3_load_start rivetlua_capi_load_begin_b3(
    lua_State *state, const char *name, int file_style);
extern rivetlua_b3_load_drive rivetlua_capi_load_drive_b3(
    lua_State *state, void *session, void *context, const char *mode);
extern int rivetlua_capi_load_finish_b3(
    lua_State *state, void *session, const char *mode);
extern void rivetlua_capi_load_drop_b3(void *session);
extern int rivetlua_capi_load_error_b3(
    lua_State *state, uint64_t generation, uint64_t token, int fault,
    const char *filename, const char *reason, int operation, void *session);
extern int rivetlua_capi_restore_reader_stack_b3(
    lua_State *state, int original_top);
#if LUA_VERSION_NUM >= 505
extern rivetlua_b3_dump_start rivetlua_capi_dump_begin_b3(
    lua_State *state, int strip);
extern void rivetlua_capi_dump_drop_b3(void *session);
#else
extern int rivetlua_capi_dump54_prepare_b3(
    lua_State *state, int strip, void *storage);
extern rivetlua_b3_dump54_next rivetlua_capi_dump54_next_b3(void *storage);
extern void rivetlua_capi_dump54_drop_b3(void *storage);
#endif
enum { RV_B3_SYNTAX = 1, RV_B3_MEMORY = 2, RV_B3_BUDGET = 3,
       RV_B3_FILE = 4, RV_B3_POLICY = 5, RV_B3_OUTPUT_LIMIT = 6 };
enum { RV_B3_FILE_OPEN = 0, RV_B3_FILE_REOPEN = 1, RV_B3_FILE_READ = 2 };

typedef struct {
  FILE *file;
  unsigned n;
  char bytes[BUFSIZ];
  int error_number;
} rivetlua_b3_file_reader;

typedef struct {
  lua_Reader reader;
  void *data;
  const char *chunkname;
  const char *mode;
  int file_style;
  FILE *file;
  int own_file;
  const char *filename;
  int file_errno;
  int file_operation;
  int initial_fault;
  int result_status;
  int original_top;
  void *session;
  const char *piece;
  size_t piece_len;
  size_t piece_at;
  int piece_fresh;
  int reader_eof;
} rivetlua_b3_load_context;

typedef struct {
  const char *data;
  size_t len;
  int32_t status; /* 0=片段，-1=結束，-2=待提出錯誤，-3=終止，-4=yield */
  int32_t new_piece;
  int32_t class_code;
} rivetlua_b3_reader_piece;

/* Rust parser 可在 stack 上；reader 的任何跳轉都只落在此純 C child frame。 */
rivetlua_b3_reader_piece rivetlua_b3_reader_peek_c(
    lua_State *state, void *context) {
  rivetlua_b3_load_context *load = (rivetlua_b3_load_context *)context;
  rivetlua_b3_reader_piece result = {NULL, 0, RV_B3_BUDGET, 0, 0};
  if (load == NULL || load->reader == NULL || load->session == NULL) return result;
  if (load->piece_at == load->piece_len && !load->reader_eof) {
    load->piece = NULL;
    load->piece_len = 0;
    load->piece_at = 0;
    load->piece_fresh = 0;
    rivetlua_capi_checkpoint_a1 *outer = rivetlua_capi_top_a1;
    if (outer == NULL || outer->state != state || outer->rust_action_active != 0)
      abort();
    rivetlua_capi_checkpoint_a1 child = {0};
    volatile int32_t raised_status = 0;
    child.previous = outer;
    child.state = state;
    child.generation = outer->generation;
    child.token = outer->token;
    child.raised_status = &raised_status;
    child.yieldable_a5 = 0;
    rivetlua_capi_checkpoint_a1 *previous_reader_child =
        rivetlua_capi_b3_reader_child_top;
    rivetlua_capi_top_a1 = &child;
    rivetlua_capi_b3_reader_child_top = &child;
    int jumped = setjmp(child.jump);
    if (jumped == 0) {
      size_t size = 0;
      const char *piece = load->reader(state, load->data, &size);
      rivetlua_capi_top_a1 = outer;
      rivetlua_capi_b3_reader_child_top = previous_reader_child;
      if (load->file != NULL && ferror(load->file)) {
        int saved = ((rivetlua_b3_file_reader *)load->data)->error_number;
        load->file_errno = saved;
        load->file_operation = RV_B3_FILE_READ;
        result.status = RV_B3_FILE;
        return result;
      }
      if (piece == NULL || size == 0) {
        load->reader_eof = 1;
      } else {
        load->piece = piece;
        load->piece_len = size;
        load->piece_fresh = 1;
      }
    } else {
      rivetlua_capi_top_a1 = outer;
      rivetlua_capi_b3_reader_child_top = previous_reader_child;
      result.status = jumped == 1 ? -2 : jumped == 2 ? -4 : jumped == 3 ? -3 : RV_B3_BUDGET;
      result.class_code = raised_status;
      return result;
    }
  }
  if (load->reader_eof) { result.status = -1; return result; }
  if (load->piece == NULL || load->piece_at >= load->piece_len) return result;
  result.data = load->piece + load->piece_at;
  result.len = load->piece_len - load->piece_at;
  result.status = 0;
  result.new_piece = load->piece_fresh;
  load->piece_fresh = 0;
  return result;
}

int rivetlua_b3_reader_consume_c(void *context, size_t bytes) {
  rivetlua_b3_load_context *load = (rivetlua_b3_load_context *)context;
  if (load == NULL || bytes == 0 || load->piece_at > load->piece_len ||
      bytes > load->piece_len - load->piece_at)
    return 0;
  load->piece_at += bytes;
  return 1;
}

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
  if (fault == 0) {
#if LUA_VERSION_NUM < 505
    if (load->file != NULL) errno = 0;  /* 5.4 在 lua_load 前重設 errno。 */
#endif
    rivetlua_b3_load_drive driven = rivetlua_capi_load_drive_b3(
        state, load->session, load, load->mode);
    if (driven.terminal) {
      /* Rust parser 已正常展開；外層 B3 checkpoint 才處理終止與唯一 cleanup。 */
      rivetlua_b4_raise_terminal_a1(state);
      abort();
    }
    if (driven.yield_attempt) {
      (void)luaL_error(state, "attempt to yield across a C-call boundary");
      abort();
    }
    if (driven.stopped_class != 0) {
      if (load->own_file && load->file != NULL) {
        (void)fclose(load->file);
        load->file = NULL;
      }
      rivetlua_capi_action_a1 raised = {RV_A1_ACTION_RAISE,
                                        driven.stopped_class};
      return raised;
    }
    fault = driven.fault;
  }
  if (load->file != NULL && ferror(load->file)) {
    int saved = ((rivetlua_b3_file_reader *)load->data)->error_number;
    load->file_errno = saved;
    load->file_operation = RV_B3_FILE_READ;
    fault = RV_B3_FILE;
  }
  if (fault == RV_B3_FILE && load->file_operation == RV_B3_FILE_READ) {
#if LUA_VERSION_NUM >= 505
    errno = 0;  /* 5.5 先取得 readstatus，再清除無用的讀取 errno。 */
#else
    errno = load->file_errno;
#endif
  }
  if (load->own_file && load->file != NULL) {
    (void)fclose(load->file);
    load->file = NULL;
  }
  if (fault == RV_B3_FILE && load->file_operation == RV_B3_FILE_READ)
    load->file_errno = errno;
#if LUA_VERSION_NUM >= 505
  /* 不再取用任何 piece 指標；成功時才還原 5.5 reader stack。 */
  load->piece = NULL;
  load->piece_len = load->piece_at = 0;
  if (fault == 0) {
    int restore_fault = rivetlua_capi_restore_reader_stack_b3(
        state, load->original_top);
    if (restore_fault != 0) fault = restore_fault;
  }
#endif
  if (fault == 0)
    fault = rivetlua_capi_load_finish_b3(state, load->session, load->mode);
  if (fault == 0) {
    rivetlua_capi_action_a1 done = {RV_A1_ACTION_RETURN, LUA_OK};
    return done;
  }
  load->result_status = rivetlua_b3_load_status(fault);
  const char *reason = fault == RV_B3_FILE && load->file_errno != 0
      ? strerror(load->file_errno) : NULL;
  int class_code = rivetlua_capi_load_error_b3(
      state, generation, token, fault, load->filename, reason,
      load->file_operation, load->session);
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
  int error_replaced = 0;
  int closed = rivetlua_b7_close_drive_inner(
      state, (size_t)load->original_top, (size_t)load->original_top,
      captured, 0, 0, NULL, &error_replaced);
  if (closed >= 0) abort();
  if (error_replaced) load->result_status = 0;
  outcome->value = -closed;
  if (rivetlua_capi_pending_matches_a1(
          state, top->generation, top->token, outcome->value) != RV_A1_OK)
    abort();
}

static void rivetlua_b3_load_cleanup(void *context) {
  rivetlua_b3_load_context *load = (rivetlua_b3_load_context *)context;
  if (load->session != NULL) {
    rivetlua_capi_load_drop_b3(load->session);
    load->session = NULL;
  }
  if (load->own_file && load->file != NULL) {
    (void)fclose(load->file);
    load->file = NULL;
  }
}

static int rivetlua_b3_load_common(rivetlua_b3_load_context *load,
                                   lua_State *state) {
  load->session = NULL;
  load->result_status = 0;
  load->original_top = lua_gettop(state);
  load->piece = NULL;
  load->piece_len = load->piece_at = 0;
  load->piece_fresh = load->reader_eof = 0;
  rivetlua_capi_outcome_a1 outcome = rivetlua_capi_trampoline_protect_impl_a1(
      state, rivetlua_b3_load_action, load, rivetlua_b3_load_raised,
      rivetlua_b3_load_cleanup);
  rivetlua_b3_load_cleanup(load);
  if (outcome.kind == RV_A1_OUT_NORMAL) return outcome.value;
  if (outcome.kind == RV_A1_OUT_RAISED) {
    int class_code = 0;
    if (rivetlua_capi_error_consume_a1(state, &class_code) != RV_A1_OK)
      abort();
    if (load->result_status != 0)
      return class_code == RV_A1_ERROR_ALLOCATION ||
                     class_code == RV_A1_ERROR_HANDLING
          ? rivetlua_b13_public_status(class_code) : load->result_status;
    /* reader 的原錯誤或 __close 替代錯誤已在同一 checkpoint 歸位。 */
    return rivetlua_b13_public_status(class_code);
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

/* lua_load 已保護 reader；內層 pcall 的錯誤須保留原物件與狀態類別。 */
static void rivetlua_b3_raise_reader_result(lua_State *state, int status) {
  int class_code = status == LUA_ERRMEM ? RV_A1_ERROR_ALLOCATION
      : status == LUA_ERRERR ? RV_A1_ERROR_HANDLING : RV_A1_ERROR_LUA;
  rivetlua_capi_checkpoint_a1 *top = rivetlua_capi_top_a1;
  if (top != NULL && top->state == state && top->rust_action_active == 0 &&
      rivetlua_capi_error_prepare_a1(
          state, top->generation, top->token, class_code) == RV_A1_OK)
    rivetlua_b7_raise_existing(state, -class_code);
  abort();
}

static const char *rivetlua_b3_base_load_reader(
    lua_State *state, void *data, size_t *size) {
  luaL_checkstack(state, 2, "too many nested functions");
#if LUA_VERSION_NUM >= 505
  int *first = (int *)data;
  if (*first) *first = 0;
  else lua_pop(state, 1);
#else
  (void)data;
#endif
  lua_pushvalue(state, 1);
  int status = lua_pcallk(state, 0, 1, 0, 0, NULL);
  if (status != LUA_OK) rivetlua_b3_raise_reader_result(state, status);
  if (lua_isnil(state, -1)) {
#if LUA_VERSION_NUM < 505
    lua_pop(state, 1);
#endif
    *size = 0;
    return NULL;
  }
  if (!lua_isstring(state, -1))
    luaL_error(state, "reader function must return a string");
#if LUA_VERSION_NUM >= 505
  return lua_tolstring(state, -1, size);
#else
  lua_replace(state, 5);
  return lua_tolstring(state, 5, size);
#endif
}

static int rivetlua_capi_base_load_b3(lua_State *state) {
  size_t length = 0;
  const char *source = lua_tolstring(state, 1, &length);
#if LUA_VERSION_NUM >= 505
  const char *mode = luaL_optstring(state, 3, NULL);
  if (mode != NULL && strchr(mode, 'B') != NULL)
    return luaL_argerror(state, 3, "invalid mode");
#else
  const char *mode = luaL_optstring(state, 3, "bt");
#endif
  int env = !lua_isnone(state, 4) ? 4 : 0;
  int status;
  if (source != NULL) {
    const char *chunkname = luaL_optstring(state, 2, source);
    status = luaL_loadbufferx(state, source, length, chunkname, mode);
  } else {
    const char *chunkname = luaL_optstring(state, 2, "=(load)");
    luaL_checktype(state, 1, LUA_TFUNCTION);
#if LUA_VERSION_NUM >= 505
    int first = 1;
    status = lua_load(state, rivetlua_b3_base_load_reader, &first, chunkname, mode);
#else
    lua_settop(state, 5);
    status = lua_load(state, rivetlua_b3_base_load_reader, NULL, chunkname, mode);
#endif
  }
  if (status == LUA_OK) {
    if (env != 0) {
      lua_pushvalue(state, env);
      if (lua_setupvalue(state, -2, 1) == NULL) lua_pop(state, 1);
    }
    return 1;
  }
  luaL_pushfail(state);
  lua_insert(state, -2);
  return 2;
}

typedef struct {
  int kind;
  int calls;
} rivetlua_b3_reader_jump_probe;

/* 第二次回呼時從純 C frame 提出錯誤，驗證 child checkpoint 接住跳轉。 */
static const char *rivetlua_b3_reader_jump(lua_State *state, void *data,
                                           size_t *size) {
  rivetlua_b3_reader_jump_probe *probe =
      (rivetlua_b3_reader_jump_probe *)data;
  probe->calls++;
  if (probe->calls == 1) {
    *size = 7;
    return "return ";
  }
  *size = 0;
  if (probe->kind == 1)
    (void)lua_yieldk(state, 0, 0, NULL);
  else
    (void)luaL_error(state, "reader failed");
  return NULL;
}

int rivetlua_capi_test_load_reader_jump_b3(lua_State *state, int kind,
                                           int *calls) {
  rivetlua_b3_reader_jump_probe probe = {kind, 0};
  int status = lua_load(state, rivetlua_b3_reader_jump, &probe,
                        "=reader-jump", "t");
  if (calls != NULL) *calls = probe.calls;
  return status;
}

typedef struct {
  int operation;
  int calls;
  int close_calls;
  int saw_error;
} rivetlua_b3_reader_nested_probe;

static int rivetlua_b3_reader_nested_close(lua_State *state) {
  rivetlua_b3_reader_nested_probe *probe =
      (rivetlua_b3_reader_nested_probe *)lua_touserdata(state, lua_upvalueindex(1));
  if (probe == NULL) abort();
  probe->close_calls++;
  size_t length = 0;
  const char *error = lua_tolstring(state, 2, &length);
  static const char expected[] = "reader nested fault";
  probe->saw_error = error != NULL && length == sizeof(expected) - 1 &&
      memcmp(error, expected, length) == 0;
  return 0;
}

static int rivetlua_b3_reader_nested_fault(lua_State *state) {
  lua_pushliteral(state, "reader nested fault");
  return lua_error(state);
}

/* 一般 C reader 直接使用未保護 lua_call 或帶 metamethod 的 B5 operation。 */
static const char *rivetlua_b3_reader_nested(lua_State *state, void *data,
                                            size_t *size) {
  rivetlua_b3_reader_nested_probe *probe =
      (rivetlua_b3_reader_nested_probe *)data;
  probe->calls++;
  if (probe->calls == 1) {
    *size = 7;
    return "return ";
  }
  lua_newtable(state);
  lua_newtable(state);
  lua_pushlightuserdata(state, probe);
  lua_pushcclosure(state, rivetlua_b3_reader_nested_close, 1);
  lua_setfield(state, -2, "__close");
  lua_setmetatable(state, -2);
  lua_toclose(state, -1);
  if (probe->operation == 0) {
    lua_pushcfunction(state, rivetlua_b3_reader_nested_fault);
    lua_call(state, 0, 0);
  } else if (probe->operation == 1) {
    lua_newtable(state);
    lua_newtable(state);
    lua_pushcfunction(state, rivetlua_b3_reader_nested_fault);
    lua_setfield(state, -2, "__add");
    lua_setmetatable(state, -2);
    lua_pushvalue(state, -1);
    lua_arith(state, LUA_OPADD);
  } else if (probe->operation == 2) {
    lua_newtable(state);
    lua_newtable(state);
    lua_pushcfunction(state, rivetlua_b3_reader_nested_fault);
    lua_setfield(state, -2, "__index");
    lua_setmetatable(state, -2);
    lua_pushliteral(state, "missing");
    (void)lua_gettable(state, -2);
  } else {
    lua_newtable(state);
    lua_newtable(state);
    lua_pushcfunction(state, rivetlua_b3_reader_nested_fault);
    lua_setfield(state, -2, "__newindex");
    lua_setmetatable(state, -2);
    lua_pushliteral(state, "missing");
    lua_pushinteger(state, 1);
    lua_settable(state, -3);
  }
  *size = 0;
  return NULL;
}

int rivetlua_capi_test_load_reader_nested_b3(
    lua_State *state, int operation, int *calls,
    int *close_calls, int *saw_error) {
  rivetlua_b3_reader_nested_probe probe = {operation, 0, 0, 0};
  int status = lua_load(state, rivetlua_b3_reader_nested, &probe,
                        "=reader-nested", "t");
  if (calls != NULL) *calls = probe.calls;
  if (close_calls != NULL) *close_calls = probe.close_calls;
  if (saw_error != NULL) *saw_error = probe.saw_error;
  return status;
}

/* 第二次回呼從 os.exit 終止，測試純 C child 接住 parser 仍存活時的終止。 */
static const char *rivetlua_b3_reader_terminal(lua_State *state, void *data,
                                               size_t *size) {
  int *calls = (int *)data;
  (*calls)++;
  if (*calls == 1) {
    *size = 7;
    return "return ";
  }
  lua_getglobal(state, "os");
  lua_getfield(state, -1, "exit");
  lua_pushinteger(state, 29);
  lua_pushboolean(state, 0);
  lua_call(state, 2, 0);
  *size = 0;
  return NULL;
}

int rivetlua_capi_test_load_reader_terminal_b3(lua_State *state, int *calls) {
  return lua_load(state, rivetlua_b3_reader_terminal, calls,
                  "=reader-terminal", "t");
}

#if LUA_VERSION_NUM >= 505
typedef struct {
  int rethrow;
  int calls;
  int close_calls;
  int saw_error;
} rivetlua_b3_reader_close_probe;

static int rivetlua_b3_reader_close(lua_State *state) {
  rivetlua_b3_reader_close_probe *probe =
      (rivetlua_b3_reader_close_probe *)lua_touserdata(state, lua_upvalueindex(1));
  if (probe == NULL) abort();
  probe->close_calls++;
  const char expected[] = "invalid or incompatible Lua chunk";
  size_t error_len = 0;
  const char *error = lua_type(state, 2) == LUA_TSTRING
      ? lua_tolstring(state, 2, &error_len) : NULL;
  probe->saw_error = error != NULL && error_len == sizeof(expected) - 1 &&
      memcmp(error, expected, error_len) == 0;
  if (probe->rethrow) {
    /* 使用完全相同的錯誤物件，狀態碼仍須變成新 closer 的 LUA_ERRRUN。 */
    lua_pushvalue(state, 2);
    return lua_error(state);
  }
  return 0;
}

static const char *rivetlua_b3_reader_with_close(lua_State *state, void *data,
                                                 size_t *size) {
  rivetlua_b3_reader_close_probe *probe =
      (rivetlua_b3_reader_close_probe *)data;
  probe->calls++;
  if (probe->calls != 1) {
    *size = 0;
    return NULL;
  }
  lua_newtable(state);
  lua_newtable(state);
  lua_pushlightuserdata(state, probe);
  lua_pushcclosure(state, rivetlua_b3_reader_close, 1);
  lua_setfield(state, -2, "__close");
  lua_setmetatable(state, -2);
  lua_toclose(state, -1);
  *size = sizeof("local then ") - 1;
  return "local then ";
}

int rivetlua_capi_test_load_reader_close_b3(
    lua_State *state, int rethrow, int *calls, int *close_calls,
    int *saw_error) {
  rivetlua_b3_reader_close_probe probe = {rethrow, 0, 0, 0};
  int status = lua_load(state, rivetlua_b3_reader_with_close, &probe,
                        "=reader-close", "t");
  if (calls != NULL) *calls = probe.calls;
  if (close_calls != NULL) *close_calls = probe.close_calls;
  if (saw_error != NULL) *saw_error = probe.saw_error;
  return status;
}
#endif

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

static const char *rivetlua_b3_read_file(
    lua_State *state, void *opaque, size_t *size) {
  rivetlua_b3_file_reader *reader = (rivetlua_b3_file_reader *)opaque;
  (void)state;
  if (reader->n != 0) {
    *size = reader->n;
    reader->n = 0;
    return reader->bytes;
  }
  if (feof(reader->file)) { *size = 0; return NULL; }
  *size = fread(reader->bytes, 1, sizeof(reader->bytes), reader->file);
  if (ferror(reader->file))
    reader->error_number = errno;
  return *size == 0 ? NULL : reader->bytes;
}

static int rivetlua_b3_skip_bom(FILE *file) {
  int c = getc(file);
  if (c == 0xEF && getc(file) == 0xBB && getc(file) == 0xBF)
    return getc(file);
  return c;
}

static int rivetlua_b3_skip_comment(FILE *file, int *first) {
  int c = *first = rivetlua_b3_skip_bom(file);
  if (c != '#') return 0;
  do { c = getc(file); } while (c != EOF && c != '\n');
  *first = getc(file);
  return 1;
}

int luaL_loadfilex(lua_State *state, const char *filename, const char *mode) {
  int permitted = rivetlua_capi_allow_file_load_b22(state);
  FILE *file = NULL;
  int open_errno = 0;
  if (permitted) {
    if (filename == NULL) file = stdin;
    else {
      errno = 0;
      file = fopen(filename, "r");
      if (file == NULL) open_errno = errno;
    }
  }
  rivetlua_b3_file_reader reader = {.file = file, .n = 0, .error_number = 0};
  rivetlua_b3_load_context load = {
    .reader = rivetlua_b3_read_file, .data = &reader,
    .chunkname = filename == NULL ? "=stdin" : filename,
    .mode = mode, .file_style = filename == NULL ? 2 : 1,
    .file = file, .own_file = filename != NULL && file != NULL,
    .filename = filename, .file_errno = open_errno,
    .file_operation = RV_B3_FILE_OPEN,
    .initial_fault = !permitted ? RV_B3_POLICY : file == NULL ? RV_B3_FILE : 0,
  };
  if (load.initial_fault == 0) {
    int first;
    if (rivetlua_b3_skip_comment(file, &first))
      reader.bytes[reader.n++] = '\n';
    if (first == 0x1B) {
      reader.n = 0;
      if (filename != NULL) {
        errno = 0;
        FILE *reopened = freopen(filename, "rb", file);
        if (reopened == NULL) {
          load.file_errno = errno;
          load.file_operation = RV_B3_FILE_REOPEN;
          load.initial_fault = RV_B3_FILE;
          load.file = reader.file = NULL;
          load.own_file = 0;
        } else {
          load.file = reader.file = file = reopened;
          (void)rivetlua_b3_skip_comment(file, &first);
        }
      }
    }
    if (load.initial_fault == 0) {
      if (first != EOF) reader.bytes[reader.n++] = (char)first;
      if (ferror(file)) {
        reader.error_number = errno;
        load.file_errno = reader.error_number;
        load.file_operation = RV_B3_FILE_READ;
        load.initial_fault = RV_B3_FILE;
      }
    }
  }
  return rivetlua_b3_load_common(&load, state);
}

typedef struct {
  lua_Writer writer;
  void *data;
  int strip;
  int original_top;
#if LUA_VERSION_NUM >= 505
  void *session;
  int output_status;
  rivetlua_b3_dump_start dump;
#else
  rivetlua_b3_dump54_storage storage;
  int prepared;
  int output_status;
#endif
} rivetlua_b3_dump_context;

static rivetlua_capi_action_a1 rivetlua_b3_dump_fault_action(
    lua_State *state, uint64_t generation, uint64_t token, int fault) {
  if (fault != RV_B3_MEMORY) {
    rivetlua_capi_action_a1 failed = {RV_A1_ACTION_RETURN, 1};
    return failed;
  }
  int class_code = rivetlua_capi_load_error_b3(
      state, generation, token, RV_B3_MEMORY, NULL, NULL, 0, NULL);
  if (class_code <= 0) {
    rivetlua_capi_action_a1 rejected = {RV_A1_ACTION_REJECT,
                                          RV_A1_REJECT_INVALID_ACTION};
    return rejected;
  }
  rivetlua_capi_action_a1 raised = {RV_A1_ACTION_RAISE, class_code};
  return raised;
}

static rivetlua_capi_action_a1 rivetlua_b3_dump_action(
    void *opaque, uint64_t generation, uint64_t token, void *context) {
  lua_State *state = (lua_State *)opaque;
  rivetlua_b3_dump_context *dump = (rivetlua_b3_dump_context *)context;
#if LUA_VERSION_NUM >= 505
  dump->dump = rivetlua_capi_dump_begin_b3(state, dump->strip);
  dump->session = dump->dump.pointer;
  if (dump->dump.fault != 0)
    return rivetlua_b3_dump_fault_action(state, generation, token,
                                        dump->dump.fault);
  dump->output_status = dump->writer(
      state, dump->dump.data, dump->dump.len, dump->data);
  if (dump->output_status == 0)
    dump->output_status = dump->writer(state, NULL, 0, dump->data);
  lua_settop(state, dump->original_top);
#else
  int fault = rivetlua_capi_dump54_prepare_b3(
      state, dump->strip, &dump->storage);
  if (fault != 0)
    return rivetlua_b3_dump_fault_action(state, generation, token, fault);
  dump->prepared = 1;
  for (;;) {
    rivetlua_b3_dump54_next piece = rivetlua_capi_dump54_next_b3(&dump->storage);
    if (piece.fault != 0)
      return rivetlua_b3_dump_fault_action(state, generation, token, piece.fault);
    if (piece.done) break;
    if (piece.len == 0) continue;
    const void *bytes = piece.data != NULL ? piece.data : piece.inline_bytes;
    dump->output_status = dump->writer(state, bytes, piece.len, dump->data);
    if (dump->output_status != 0) break;
  }
#endif
  rivetlua_capi_action_a1 done = {RV_A1_ACTION_RETURN,
                                  dump->output_status};
  return done;
}

static void rivetlua_b3_dump_cleanup(void *context) {
  rivetlua_b3_dump_context *dump = (rivetlua_b3_dump_context *)context;
#if LUA_VERSION_NUM >= 505
  if (dump->session != NULL) {
    rivetlua_capi_dump_drop_b3(dump->session);
    dump->session = NULL;
  }
#else
  if (dump->prepared) {
    rivetlua_capi_dump54_drop_b3(&dump->storage);
    dump->prepared = 0;
  }
#endif
}

int lua_dump(lua_State *state, lua_Writer writer, void *data, int strip) {
  if (writer == NULL) return 1;
  rivetlua_b3_dump_context dump = {0};
  dump.writer = writer;
  dump.data = data;
  dump.strip = strip;
  dump.original_top = lua_gettop(state);
  rivetlua_capi_outcome_a1 outcome = rivetlua_capi_trampoline_protect_impl_a1(
      state, rivetlua_b3_dump_action, &dump, NULL,
      rivetlua_b3_dump_cleanup);
  rivetlua_b3_dump_cleanup(&dump);
  if (outcome.kind == RV_A1_OUT_NORMAL) return outcome.value;
  if (outcome.kind == RV_A1_OUT_RAISED) {
    int class_code = 0;
    if (rivetlua_capi_error_consume_a1(state, &class_code) != RV_A1_OK)
      abort();
    return lua_error(state);
  }
  return 1;
}

/* 測試專用：dump 的記憶體錯誤只穿過純 C protected frame。 */
static int rivetlua_capi_test_discard_dump_b3(
    lua_State *state, const void *bytes, size_t len, void *data) {
  (void)state;
  (void)bytes;
  (void)len;
  (void)data;
  return 0;
}

static int rivetlua_capi_test_dump_call_b3(lua_State *state) {
  int status = lua_dump(state, rivetlua_capi_test_discard_dump_b3, NULL, 0);
  if (status != 0) {
    lua_pushinteger(state, status);
    return 1;
  }
  return 0;
}

void rivetlua_capi_test_prepare_dump_b3(lua_State *state) {
  /* 拒絕注入前先備好 C callback；原函式留在 stack，複本為唯一參數。 */
  lua_pushcclosure(state, rivetlua_capi_test_dump_call_b3, 0);
  lua_pushvalue(state, -2);
}

#if LUA_VERSION_NUM < 505
typedef struct {
  int outer_calls;
  int nested_calls;
  int nested_status;
  int gc_status;
  size_t outer_bytes;
  size_t nested_bytes;
} rivetlua_b3_dump54_observation;

static int rivetlua_b3_dump54_nested_writer(
    lua_State *state, const void *bytes, size_t len, void *data) {
  (void)state;
  (void)bytes;
  rivetlua_b3_dump54_observation *seen = data;
  seen->nested_calls++;
  seen->nested_bytes += len;
  return 0;
}

static int rivetlua_b3_dump54_outer_writer(
    lua_State *state, const void *bytes, size_t len, void *data) {
  (void)bytes;
  rivetlua_b3_dump54_observation *seen = data;
  seen->outer_calls++;
  seen->outer_bytes += len;
  if (seen->outer_calls == 1) {
    seen->nested_status = lua_dump(
        state, rivetlua_b3_dump54_nested_writer, seen, 1);
    lua_settop(state, 0);
    seen->gc_status = lua_gc(state, LUA_GCCOLLECT, 0);
  }
  return 0;
}

static int rivetlua_b3_dump54_reentry_call(lua_State *state) {
  rivetlua_b3_dump54_observation *seen =
      lua_touserdata(state, lua_upvalueindex(1));
  lua_pushvalue(state, 1);
  int status = lua_dump(state, rivetlua_b3_dump54_outer_writer, seen, 0);
  lua_pushinteger(state, status);
  return 1;
}

void rivetlua_capi_test_prepare_dump54_reentry_b3(
    lua_State *state, rivetlua_b3_dump54_observation *seen) {
  lua_pushlightuserdata(state, seen);
  lua_pushcclosure(state, rivetlua_b3_dump54_reentry_call, 1);
  lua_pushvalue(state, -2);
  lua_remove(state, -3);
}
#endif

/* Compatibility 原生模組：Rust 只持有 dlopen lease，Lua 錯誤在純 C frame 提出。 */
extern int rivetlua_capi_compat_load_symbol_b22(
    lua_State *state, const char *path, const char *symbol,
    lua_CFunction *out, const char **diagnostic);

int rivetlua_capi_compat_loadlib_b22(lua_State *state) {
  const char *path = luaL_checkstring(state, 1);
  const char *symbol = luaL_checkstring(state, 2);
  lua_CFunction function = NULL;
  const char *diagnostic = NULL;
  int only_global = symbol[0] == '*';
  int stage = rivetlua_capi_compat_load_symbol_b22(
      state, path, symbol, &function, &diagnostic);
  /* Rust 保留票據已釋放；記憶體錯誤只在純 C checkpoint 提出。 */
  if (stage == 4)
    rivetlua_b5_operation_raise(state, -RV_A1_ERROR_ALLOCATION);
  if (stage == 0) {
    if (only_global) lua_pushboolean(state, 1);
    else lua_pushcclosure(state, function, 0);
    return 1;
  }
  lua_pushstring(state, diagnostic != NULL ? diagnostic : "native loader failed");
  luaL_pushfail(state);
  lua_insert(state, -2);
  lua_pushstring(state, stage == 1 ? "open" : "init");
  return 3;
}

static const char *rivetlua_compat_next_file_b22(char **path, char *end) {
  char *name = *path;
  if (name == end) return NULL;
  if (*name == '\0') { *name = ';'; name++; }
  char *separator = strchr(name, ';');
  if (separator == NULL) separator = end;
  *separator = '\0';
  *path = separator;
  return name;
}

static void rivetlua_compat_missing_b22(lua_State *state, const char *path) {
  luaL_Buffer message;
  luaL_buffinit(state, &message);
  luaL_addstring(&message, "no file '");
  luaL_addgsub(&message, path, ";", "'\n\tno file '");
  luaL_addstring(&message, "'");
  luaL_pushresult(&message);
}

static const char *rivetlua_compat_find_b22(
    lua_State *state, const char *name) {
  lua_getfield(state, lua_upvalueindex(1), "cpath");
  const char *cpath = lua_tostring(state, -1);
  if (cpath == NULL) luaL_error(state, "'package.cpath' must be a string");
  if (strchr(name, '.') != NULL) name = luaL_gsub(state, name, ".", "/");
  luaL_Buffer paths;
  luaL_buffinit(state, &paths);
  luaL_addgsub(&paths, cpath, "?", name);
  luaL_addchar(&paths, '\0');
  char *cursor = luaL_buffaddr(&paths);
  char *end = cursor + luaL_bufflen(&paths) - 1;
  const char *candidate;
  while ((candidate = rivetlua_compat_next_file_b22(&cursor, end)) != NULL) {
    FILE *file = fopen(candidate, "r");
    if (file != NULL) {
      fclose(file);
      return lua_pushstring(state, candidate);
    }
  }
  luaL_pushresult(&paths);
  rivetlua_compat_missing_b22(state, lua_tostring(state, -1));
  return NULL;
}

static int rivetlua_compat_open_function_b22(
    lua_State *state, const char *path, const char *name,
    lua_CFunction *function, const char **diagnostic) {
  const char *translated = luaL_gsub(state, name, ".", "_");
  const char *mark = strchr(translated, '-');
  if (mark != NULL) {
    const char *prefix = lua_pushlstring(state, translated, (size_t)(mark - translated));
    const char *symbol = lua_pushfstring(state, "luaopen_%s", prefix);
    int stage = rivetlua_capi_compat_load_symbol_b22(
        state, path, symbol, function, diagnostic);
    if (stage != 2) return stage;
    translated = mark + 1;
  }
  const char *symbol = lua_pushfstring(state, "luaopen_%s", translated);
  return rivetlua_capi_compat_load_symbol_b22(
      state, path, symbol, function, diagnostic);
}

static int rivetlua_capi_compat_search_b22(lua_State *state, int root) {
  const char *name = luaL_checkstring(state, 1);
  const char *dot = strchr(name, '.');
  if (root && dot == NULL) return 0;
  /* 所有暫存字串均由 Lua stack／luaL_Buffer 保活，錯誤跳轉不遺失 malloc。 */
  const char *lookup = root
      ? lua_pushlstring(state, name, (size_t)(dot - name)) : name;
  const char *candidate = rivetlua_compat_find_b22(state, lookup);
  if (candidate == NULL) return 1;
  lua_CFunction function = NULL;
  const char *diagnostic = NULL;
  int stage = rivetlua_compat_open_function_b22(
      state, candidate, name, &function, &diagnostic);
  if (stage == 4)
    rivetlua_b5_operation_raise(state, -RV_A1_ERROR_ALLOCATION);
  if (stage == 2 && root) {
    lua_pushfstring(state, "no module '%s' in file '%s'", name, candidate);
    return 1;
  }
  if (stage != 0) {
    const char *message = lua_pushstring(
        state, diagnostic != NULL ? diagnostic : "native loader failed");
    return luaL_error(state, "error loading module '%s' from file '%s':\n\t%s",
                      name, candidate, message);
  }
  lua_pushcclosure(state, function, 0);
  lua_pushstring(state, candidate);
  return 2;
}

int rivetlua_capi_compat_searcher_b22(lua_State *state) {
  return rivetlua_capi_compat_search_b22(state, 0);
}

int rivetlua_capi_compat_root_searcher_b22(lua_State *state) {
  return rivetlua_capi_compat_search_b22(state, 1);
}
