/* 由 tests/p16/generate_manifest.py 產生；只編譯，不連結或執行。 */
/* A16：條件式相容 API 編譯探測，不代表 Lua 5.5 預設啟用。 */
#define LUA_COMPAT_5_3
#ifndef LUA_COMPAT_APIINTCASTS
#define LUA_COMPAT_APIINTCASTS
#endif
#include "lua.h"
#include "lauxlib.h"
#include "rivetlua_abi.h"
#include <stddef.h>
_Static_assert(sizeof(lua_Integer) == 8, "i64");
_Static_assert(sizeof(lua_Number) == 8, "f64");
_Static_assert(sizeof(rivetlua_abi_identity) == 248, "ABI identity size");
static const char *rivetlua_p16_b2_vf_probe(lua_State *state, const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  const char *result = lua_pushvfstring(state, fmt, args);
  va_end(args);
  return result;
}
void rivetlua_p16_surface_probe(void) {
  (void)&luaL_addgsub;
  (void)&luaL_addlstring;
  (void)&luaL_addstring;
  (void)&luaL_addvalue;
  (void)&luaL_argerror;
  (void)&luaL_buffinit;
  (void)&luaL_buffinitsize;
  (void)&luaL_callmeta;
  (void)&luaL_checkany;
  (void)&luaL_checkinteger;
  (void)&luaL_checklstring;
  (void)&luaL_checknumber;
  (void)&luaL_checkoption;
  (void)&luaL_checkstack;
  (void)&luaL_checktype;
  (void)&luaL_checkudata;
  (void)&luaL_checkversion_;
  (void)&luaL_error;
  (void)&luaL_execresult;
  (void)&luaL_fileresult;
  (void)&luaL_getmetafield;
  (void)&luaL_getsubtable;
  (void)&luaL_gsub;
  (void)&luaL_len;
  (void)&luaL_loadbufferx;
  (void)&luaL_loadfilex;
  (void)&luaL_loadstring;
  (void)&luaL_newmetatable;
  (void)&luaL_newstate;
  (void)&luaL_optinteger;
  (void)&luaL_optlstring;
  (void)&luaL_optnumber;
  (void)&luaL_prepbuffsize;
  (void)&luaL_pushresult;
  (void)&luaL_pushresultsize;
  (void)&luaL_ref;
  (void)&luaL_requiref;
  (void)&luaL_setfuncs;
  (void)&luaL_setmetatable;
  (void)&luaL_testudata;
  (void)&luaL_tolstring;
  (void)&luaL_traceback;
  (void)&luaL_typeerror;
  (void)&luaL_unref;
  (void)&luaL_where;
  (void)&lua_absindex;
  (void)&lua_arith;
  (void)&lua_atpanic;
  (void)&lua_callk;
  (void)&lua_checkstack;
  (void)&lua_close;
  (void)&lua_closeslot;
  (void)&lua_closethread;
  (void)&lua_compare;
  (void)&lua_concat;
  (void)&lua_copy;
  (void)&lua_createtable;
  (void)&lua_dump;
  (void)&lua_error;
  (void)&lua_gc;
  (void)&lua_getallocf;
  (void)&lua_getfield;
  (void)&lua_getglobal;
  (void)&lua_gethook;
  (void)&lua_gethookcount;
  (void)&lua_gethookmask;
  (void)&lua_geti;
  (void)&lua_getinfo;
  (void)&lua_getiuservalue;
  (void)&lua_getlocal;
  (void)&lua_getmetatable;
  (void)&lua_getstack;
  (void)&lua_gettable;
  (void)&lua_gettop;
  (void)&lua_getupvalue;
  (void)&lua_iscfunction;
  (void)&lua_isinteger;
  (void)&lua_isnumber;
  (void)&lua_isstring;
  (void)&lua_isuserdata;
  (void)&lua_isyieldable;
  (void)&lua_len;
  (void)&lua_load;
  (void)&lua_newstate;
  (void)&lua_newthread;
  (void)&lua_newuserdatauv;
  (void)&lua_next;
  (void)&lua_pcallk;
  (void)&lua_pushboolean;
  (void)&lua_pushcclosure;
  (void)&lua_pushfstring;
  (void)&lua_pushinteger;
  (void)&lua_pushlightuserdata;
  (void)&lua_pushlstring;
  (void)&lua_pushnil;
  (void)&lua_pushnumber;
  (void)&lua_pushstring;
  (void)&lua_pushthread;
  (void)&lua_pushvalue;
  (void)&lua_pushvfstring;
  (void)&lua_rawequal;
  (void)&lua_rawget;
  (void)&lua_rawgeti;
  (void)&lua_rawgetp;
  (void)&lua_rawlen;
  (void)&lua_rawset;
  (void)&lua_rawseti;
  (void)&lua_rawsetp;
  (void)&lua_resetthread;
  (void)&lua_resume;
  (void)&lua_rotate;
  (void)&lua_setallocf;
  (void)&lua_setcstacklimit;
  (void)&lua_setfield;
  (void)&lua_setglobal;
  (void)&lua_sethook;
  (void)&lua_seti;
  (void)&lua_setiuservalue;
  (void)&lua_setlocal;
  (void)&lua_setmetatable;
  (void)&lua_settable;
  (void)&lua_settop;
  (void)&lua_setupvalue;
  (void)&lua_setwarnf;
  (void)&lua_status;
  (void)&lua_stringtonumber;
  (void)&lua_toboolean;
  (void)&lua_tocfunction;
  (void)&lua_toclose;
  (void)&lua_tointegerx;
  (void)&lua_tolstring;
  (void)&lua_tonumberx;
  (void)&lua_topointer;
  (void)&lua_tothread;
  (void)&lua_touserdata;
  (void)&lua_type;
  (void)&lua_typename;
  (void)&lua_upvalueid;
  (void)&lua_upvaluejoin;
  (void)&lua_version;
  (void)&lua_warning;
  (void)&lua_xmove;
  (void)&lua_yieldk;
  (void)sizeof(luaL_Buffer);
  (void)sizeof(luaL_Reg);
  (void)sizeof(luaL_Stream);
  (void)sizeof(lua_Alloc);
  (void)sizeof(lua_CFunction);
  (void)sizeof(lua_Debug);
  (void)sizeof(lua_Hook);
  (void)sizeof(lua_Integer);
  (void)sizeof(lua_KContext);
  (void)sizeof(lua_KFunction);
  (void)sizeof(lua_Number);
  (void)sizeof(lua_Reader);
  (void)sizeof(lua_State *);
  (void)sizeof(lua_Unsigned);
  (void)sizeof(lua_WarnFunction);
  (void)sizeof(lua_Writer);
  (void)sizeof(luaL_Buffer);
  (void)_Alignof(luaL_Buffer);
  (void)sizeof(luaL_Reg);
  (void)_Alignof(luaL_Reg);
  (void)sizeof(luaL_Stream);
  (void)_Alignof(luaL_Stream);
  (void)sizeof(lua_Debug);
  (void)_Alignof(lua_Debug);
  (void)offsetof(luaL_Buffer, L);
  (void)offsetof(luaL_Buffer, b);
  (void)offsetof(luaL_Buffer, init);
  (void)offsetof(luaL_Buffer, n);
  (void)offsetof(luaL_Buffer, size);
  (void)offsetof(luaL_Reg, func);
  (void)offsetof(luaL_Reg, name);
  (void)offsetof(luaL_Stream, closef);
  (void)offsetof(luaL_Stream, f);
  (void)offsetof(lua_Debug, currentline);
  (void)offsetof(lua_Debug, event);
  (void)offsetof(lua_Debug, ftransfer);
  (void)offsetof(lua_Debug, i_ci);
  (void)offsetof(lua_Debug, istailcall);
  (void)offsetof(lua_Debug, isvararg);
  (void)offsetof(lua_Debug, lastlinedefined);
  (void)offsetof(lua_Debug, linedefined);
  (void)offsetof(lua_Debug, name);
  (void)offsetof(lua_Debug, namewhat);
  (void)offsetof(lua_Debug, nparams);
  (void)offsetof(lua_Debug, ntransfer);
  (void)offsetof(lua_Debug, nups);
  (void)offsetof(lua_Debug, short_src);
  (void)offsetof(lua_Debug, source);
  (void)offsetof(lua_Debug, srclen);
  (void)offsetof(lua_Debug, what);
  /* P16 macro expansion: luaL_addchar */
  (void)luaL_addchar((luaL_Buffer *)0, 'x');
  /* P16 macro expansion: luaL_prepbuffer */
  (void)luaL_prepbuffer((luaL_Buffer *)0);
  /* P16 macro expansion: luaL_checkversion */
  (void)luaL_checkversion((lua_State *)0);
  /* P16 macro expansion: luaL_getmetatable */
  (void)luaL_getmetatable((lua_State *)0, "named");
  /* P16 macro expansion: lua_pushliteral */
  (void)lua_pushliteral((lua_State *)0, "literal");
  /* P16 macro expansion: lua_tostring */
  (void)lua_tostring((lua_State *)0, 1);
  /* P16 macro expansion: lua_tonumber */
  (void)lua_tonumber((lua_State *)0, 1);
  /* P16 macro expansion: lua_tointeger */
  (void)lua_tointeger((lua_State *)0, 1);
  /* P16 macro expansion: luaL_opt */
  (void)luaL_opt((lua_State *)0, luaL_checkinteger, 1, (lua_Integer)0);
  /* P16 macro expansion: luaL_checkunsigned */
  (void)luaL_checkunsigned((lua_State *)0, 1);
  /* P16 macro expansion: luaL_optunsigned */
  (void)luaL_optunsigned((lua_State *)0, 1, (lua_Unsigned)0);
  /* P16 macro expansion: luaL_checkint */
  (void)luaL_checkint((lua_State *)0, 1);
  /* P16 macro expansion: luaL_optint */
  (void)luaL_optint((lua_State *)0, 1, 0);
  /* P16 macro expansion: luaL_checklong */
  (void)luaL_checklong((lua_State *)0, 1);
  /* P16 macro expansion: luaL_checkstring */
  (void)luaL_checkstring((lua_State *)0, 1);
  /* P16 macro expansion: luaL_optlong */
  (void)luaL_optlong((lua_State *)0, 1, 0L);
  /* P16 macro expansion: luaL_optstring */
  (void)luaL_optstring((lua_State *)0, 1, "fallback");
  /* P16 macro expansion: luaL_pushfail */
  (void)luaL_pushfail((lua_State *)0);
  /* P16 macro expansion: lua_pop */
  (void)lua_pop((lua_State *)0, 1);
  /* P16 macro expansion: lua_newtable */
  (void)lua_newtable((lua_State *)0);
  /* P16 macro expansion: lua_pushglobaltable */
  (void)lua_pushglobaltable((lua_State *)0);
  /* P16 macro expansion: lua_equal */
  (void)lua_equal((lua_State *)0, 1, 2);
  /* P16 macro expansion: lua_lessthan */
  (void)lua_lessthan((lua_State *)0, 1, 2);
  /* P16 macro expansion: lua_upvalueindex */
  (void)lua_upvalueindex(1);
  /* P16 macro expansion: lua_pushcfunction */
  (void)lua_pushcfunction((lua_State *)0, (lua_CFunction)0);
  /* P16 macro expansion: luaL_newlibtable */
  (void)luaL_newlibtable((lua_State *)0, ((const luaL_Reg[]){{"entry", (lua_CFunction)0}, {NULL, (lua_CFunction)0}}));
  /* P16 macro expansion: lua_register */
  (void)lua_register((lua_State *)0, "entry", (lua_CFunction)0);
  /* P16 macro expansion: luaL_newlib */
  (void)luaL_newlib((lua_State *)0, ((const luaL_Reg[]){{"entry", (lua_CFunction)0}, {NULL, (lua_CFunction)0}}));
  /* P16 macro expansion: luaL_bufflen */
  (void)luaL_bufflen(&(luaL_Buffer){0});
  /* P16 macro expansion: luaL_buffaddr */
  (void)luaL_buffaddr(&(luaL_Buffer){0});
  /* P16 macro expansion: luaL_addsize */
  (void)luaL_addsize(&(luaL_Buffer){0}, 0);
  /* P16 macro expansion: luaL_buffsub */
  (void)luaL_buffsub(&(luaL_Buffer){0}, 0);
  /* P16 macro expansion: lua_insert */
  (void)lua_insert((lua_State *)0, 1);
  /* P16 macro expansion: lua_remove */
  (void)lua_remove((lua_State *)0, 1);
  /* P16 macro expansion: lua_replace */
  (void)lua_replace((lua_State *)0, LUA_REGISTRYINDEX);
  /* P16 macro expansion: lua_pushunsigned */
  (void)lua_pushunsigned((lua_State *)0, 1u);
  /* P16 macro expansion: lua_tounsignedx */
  (void)lua_tounsignedx((lua_State *)0, 1, (int *)0);
  /* P16 macro expansion: lua_tounsigned */
  (void)lua_tounsigned((lua_State *)0, 1);
  /* P16 macro expansion: lua_call */
  (void)lua_call((lua_State *)0, 0, 0);
  /* P16 macro expansion: lua_pcall */
  (void)lua_pcall((lua_State *)0, 0, 0, 0);
  /* P16 macro expansion: lua_yield */
  (void)lua_yield((lua_State *)0, 0);
  /* P16 macro expansion: luaL_argcheck */
  (void)luaL_argcheck((lua_State *)0, 1, 1, "message");
  /* P16 macro expansion: luaL_argexpected */
  (void)luaL_argexpected((lua_State *)0, 1, 1, "number");
  /* B2：固定 header 的嚴格 auxiliary 與真 va_list 呼叫形狀。 */
  luaL_checktype((lua_State *)0, 1, LUA_TNUMBER);
  luaL_checkany((lua_State *)0, 1);
  (void)luaL_checkudata((lua_State *)0, 1, "B2Thing");
  (void)luaL_checkoption((lua_State *)0, 1, "a", (const char *const[]){"a", NULL});
  (void)lua_pushfstring((lua_State *)0, "%d", 1);
  (void)rivetlua_p16_b2_vf_probe((lua_State *)0, "%d", 1);
  /* B3：固定 header 的三個 thread 函式真實呼叫形狀。 */
  (void)lua_newthread((lua_State *)0);
  (void)lua_tothread((lua_State *)0, 1);
  (void)lua_pushthread((lua_State *)0);
  /* B12：固定 header 的 registry destination 實際呼叫形狀。 */
  lua_copy((lua_State *)0, 1, LUA_REGISTRYINDEX);
  /* B13：固定 header 的刪除目前鍵後續走呼叫形狀。 */
  lua_createtable((lua_State *)0, 2, 0);
  lua_pushinteger((lua_State *)0, 1);
  lua_pushnil((lua_State *)0);
  lua_rawset((lua_State *)0, -3);
  lua_pushinteger((lua_State *)0, 1);
  (void)lua_next((lua_State *)0, -2);
  /* B6：兩個 warning 符號以固定 header 真實呼叫形狀探測。 */
  lua_setwarnf((lua_State *)0, (lua_WarnFunction)0, (void *)0);
  lua_warning((lua_State *)0, "warning", 1);
  /* B7：固定 header to-close 函式真實呼叫形狀。 */
  lua_toclose((lua_State *)0, 1);
  lua_closeslot((lua_State *)0, 1);
  /* B8：固定 header 的 GC varargs 命令與參數型別。 */
  (void)lua_gc((lua_State *)0, LUA_GCCOLLECT);
  (void)lua_gc((lua_State *)0, LUA_GCSTEP, 0);
  /* B11：固定 header 的 close、thread reset 與 from 參數實際呼叫形狀。 */
  (void)lua_closethread((lua_State *)0, (lua_State *)0);
  (void)lua_resetthread((lua_State *)0);
  lua_close((lua_State *)0);
  /* B10：固定 header 的 debug 查詢、local 與 hook 實際呼叫形狀。 */
  (void)lua_getstack((lua_State *)0, 0, (lua_Debug *)0);
  (void)lua_getinfo((lua_State *)0, "nSlutr", (lua_Debug *)0);
  (void)lua_getlocal((lua_State *)0, (const lua_Debug *)0, 1);
  (void)lua_setlocal((lua_State *)0, (const lua_Debug *)0, 1);
  lua_sethook((lua_State *)0, (lua_Hook)0, LUA_MASKCALL, 1);
  (void)lua_gethook((lua_State *)0);
  (void)lua_gethookmask((lua_State *)0);
  (void)lua_gethookcount((lua_State *)0);
  luaL_where((lua_State *)0, 0);
}
#if defined(LUAI_DDEC)
/* 清單巨集：LUAI_DDEC */
#endif
#if defined(LUAI_DDEF)
/* 清單巨集：LUAI_DDEF */
#endif
#if defined(LUAI_FUNC)
/* 清單巨集：LUAI_FUNC */
#endif
#if defined(LUAI_IS32INT)
/* 清單巨集：LUAI_IS32INT */
#endif
#if defined(LUAI_MAXALIGN)
/* 清單巨集：LUAI_MAXALIGN */
#endif
#if defined(LUAI_MAXSTACK)
/* 清單巨集：LUAI_MAXSTACK */
#endif
#if defined(LUAI_UACINT)
/* 清單巨集：LUAI_UACINT */
#endif
#if defined(LUAI_UACNUMBER)
/* 清單巨集：LUAI_UACNUMBER */
#endif
#if defined(LUALIB_API)
/* 清單巨集：LUALIB_API */
#endif
#if defined(LUAL_BUFFERSIZE)
/* 清單巨集：LUAL_BUFFERSIZE */
#endif
#if defined(LUAL_NUMSIZES)
/* 清單巨集：LUAL_NUMSIZES */
#endif
#if defined(LUAMOD_API)
/* 清單巨集：LUAMOD_API */
#endif
#if defined(LUA_32BITS)
/* 清單巨集：LUA_32BITS */
#endif
#if defined(LUA_API)
/* 清單巨集：LUA_API */
#endif
#if defined(LUA_AUTHORS)
/* 清單巨集：LUA_AUTHORS */
#endif
#if defined(LUA_C89_NUMBERS)
/* 清單巨集：LUA_C89_NUMBERS */
#endif
#if defined(LUA_CDIR)
/* 清單巨集：LUA_CDIR */
#endif
#if defined(LUA_COMPAT_APIINTCASTS)
/* 清單巨集：LUA_COMPAT_APIINTCASTS */
#endif
#if defined(LUA_COMPAT_LT_LE)
/* 清單巨集：LUA_COMPAT_LT_LE */
#endif
#if defined(LUA_COMPAT_MATHLIB)
/* 清單巨集：LUA_COMPAT_MATHLIB */
#endif
#if defined(LUA_COPYRIGHT)
/* 清單巨集：LUA_COPYRIGHT */
#endif
#if defined(LUA_CPATH_DEFAULT)
/* 清單巨集：LUA_CPATH_DEFAULT */
#endif
#if defined(LUA_DIRSEP)
/* 清單巨集：LUA_DIRSEP */
#endif
#if defined(LUA_DL_DLL)
/* 清單巨集：LUA_DL_DLL */
#endif
#if defined(LUA_ERRERR)
/* 清單巨集：LUA_ERRERR */
#endif
#if defined(LUA_ERRFILE)
/* 清單巨集：LUA_ERRFILE */
#endif
#if defined(LUA_ERRMEM)
/* 清單巨集：LUA_ERRMEM */
#endif
#if defined(LUA_ERRRUN)
/* 清單巨集：LUA_ERRRUN */
#endif
#if defined(LUA_ERRSYNTAX)
/* 清單巨集：LUA_ERRSYNTAX */
#endif
#if defined(LUA_EXEC_DIR)
/* 清單巨集：LUA_EXEC_DIR */
#endif
#if defined(LUA_EXTRASPACE)
/* 清單巨集：LUA_EXTRASPACE */
#endif
#if defined(LUA_FILEHANDLE)
/* 清單巨集：LUA_FILEHANDLE */
#endif
#if defined(LUA_FLOAT_DEFAULT)
/* 清單巨集：LUA_FLOAT_DEFAULT */
#endif
#if defined(LUA_FLOAT_DOUBLE)
/* 清單巨集：LUA_FLOAT_DOUBLE */
#endif
#if defined(LUA_FLOAT_FLOAT)
/* 清單巨集：LUA_FLOAT_FLOAT */
#endif
#if defined(LUA_FLOAT_LONGDOUBLE)
/* 清單巨集：LUA_FLOAT_LONGDOUBLE */
#endif
#if defined(LUA_FLOAT_TYPE)
/* 清單巨集：LUA_FLOAT_TYPE */
#endif
#if defined(LUA_GCCOLLECT)
/* 清單巨集：LUA_GCCOLLECT */
#endif
#if defined(LUA_GCCOUNT)
/* 清單巨集：LUA_GCCOUNT */
#endif
#if defined(LUA_GCCOUNTB)
/* 清單巨集：LUA_GCCOUNTB */
#endif
#if defined(LUA_GCGEN)
/* 清單巨集：LUA_GCGEN */
#endif
#if defined(LUA_GCINC)
/* 清單巨集：LUA_GCINC */
#endif
#if defined(LUA_GCISRUNNING)
/* 清單巨集：LUA_GCISRUNNING */
#endif
#if defined(LUA_GCRESTART)
/* 清單巨集：LUA_GCRESTART */
#endif
#if defined(LUA_GCSETPAUSE)
/* 清單巨集：LUA_GCSETPAUSE */
#endif
#if defined(LUA_GCSETSTEPMUL)
/* 清單巨集：LUA_GCSETSTEPMUL */
#endif
#if defined(LUA_GCSTEP)
/* 清單巨集：LUA_GCSTEP */
#endif
#if defined(LUA_GCSTOP)
/* 清單巨集：LUA_GCSTOP */
#endif
#if defined(LUA_GNAME)
/* 清單巨集：LUA_GNAME */
#endif
#if defined(LUA_HOOKCALL)
/* 清單巨集：LUA_HOOKCALL */
#endif
#if defined(LUA_HOOKCOUNT)
/* 清單巨集：LUA_HOOKCOUNT */
#endif
#if defined(LUA_HOOKLINE)
/* 清單巨集：LUA_HOOKLINE */
#endif
#if defined(LUA_HOOKRET)
/* 清單巨集：LUA_HOOKRET */
#endif
#if defined(LUA_HOOKTAILCALL)
/* 清單巨集：LUA_HOOKTAILCALL */
#endif
#if defined(LUA_IDSIZE)
/* 清單巨集：LUA_IDSIZE */
#endif
#if defined(LUA_IGMARK)
/* 清單巨集：LUA_IGMARK */
#endif
#if defined(LUA_INTEGER)
/* 清單巨集：LUA_INTEGER */
#endif
#if defined(LUA_INTEGER_FMT)
/* 清單巨集：LUA_INTEGER_FMT */
#endif
#if defined(LUA_INTEGER_FRMLEN)
/* 清單巨集：LUA_INTEGER_FRMLEN */
#endif
#if defined(LUA_INT_DEFAULT)
/* 清單巨集：LUA_INT_DEFAULT */
#endif
#if defined(LUA_INT_INT)
/* 清單巨集：LUA_INT_INT */
#endif
#if defined(LUA_INT_LONG)
/* 清單巨集：LUA_INT_LONG */
#endif
#if defined(LUA_INT_LONGLONG)
/* 清單巨集：LUA_INT_LONGLONG */
#endif
#if defined(LUA_INT_TYPE)
/* 清單巨集：LUA_INT_TYPE */
#endif
#if defined(LUA_KCONTEXT)
/* 清單巨集：LUA_KCONTEXT */
#endif
#if defined(LUA_LDIR)
/* 清單巨集：LUA_LDIR */
#endif
#if defined(LUA_LOADED_TABLE)
/* 清單巨集：LUA_LOADED_TABLE */
#endif
#if defined(LUA_MASKCALL)
/* 清單巨集：LUA_MASKCALL */
#endif
#if defined(LUA_MASKCOUNT)
/* 清單巨集：LUA_MASKCOUNT */
#endif
#if defined(LUA_MASKLINE)
/* 清單巨集：LUA_MASKLINE */
#endif
#if defined(LUA_MASKRET)
/* 清單巨集：LUA_MASKRET */
#endif
#if defined(LUA_MAXINTEGER)
/* 清單巨集：LUA_MAXINTEGER */
#endif
#if defined(LUA_MAXUNSIGNED)
/* 清單巨集：LUA_MAXUNSIGNED */
#endif
#if defined(LUA_MININTEGER)
/* 清單巨集：LUA_MININTEGER */
#endif
#if defined(LUA_MINSTACK)
/* 清單巨集：LUA_MINSTACK */
#endif
#if defined(LUA_MULTRET)
/* 清單巨集：LUA_MULTRET */
#endif
#if defined(LUA_NOREF)
/* 清單巨集：LUA_NOREF */
#endif
#if defined(LUA_NUMBER)
/* 清單巨集：LUA_NUMBER */
#endif
#if defined(LUA_NUMBER_FMT)
/* 清單巨集：LUA_NUMBER_FMT */
#endif
#if defined(LUA_NUMBER_FRMLEN)
/* 清單巨集：LUA_NUMBER_FRMLEN */
#endif
#if defined(LUA_NUMTAGS)
/* 清單巨集：LUA_NUMTAGS */
#endif
#if defined(LUA_NUMTYPES)
/* 清單巨集：LUA_NUMTYPES */
#endif
#if defined(LUA_OK)
/* 清單巨集：LUA_OK */
#endif
#if defined(LUA_OPADD)
/* 清單巨集：LUA_OPADD */
#endif
#if defined(LUA_OPBAND)
/* 清單巨集：LUA_OPBAND */
#endif
#if defined(LUA_OPBNOT)
/* 清單巨集：LUA_OPBNOT */
#endif
#if defined(LUA_OPBOR)
/* 清單巨集：LUA_OPBOR */
#endif
#if defined(LUA_OPBXOR)
/* 清單巨集：LUA_OPBXOR */
#endif
#if defined(LUA_OPDIV)
/* 清單巨集：LUA_OPDIV */
#endif
#if defined(LUA_OPEQ)
/* 清單巨集：LUA_OPEQ */
#endif
#if defined(LUA_OPIDIV)
/* 清單巨集：LUA_OPIDIV */
#endif
#if defined(LUA_OPLE)
/* 清單巨集：LUA_OPLE */
#endif
#if defined(LUA_OPLT)
/* 清單巨集：LUA_OPLT */
#endif
#if defined(LUA_OPMOD)
/* 清單巨集：LUA_OPMOD */
#endif
#if defined(LUA_OPMUL)
/* 清單巨集：LUA_OPMUL */
#endif
#if defined(LUA_OPPOW)
/* 清單巨集：LUA_OPPOW */
#endif
#if defined(LUA_OPSHL)
/* 清單巨集：LUA_OPSHL */
#endif
#if defined(LUA_OPSHR)
/* 清單巨集：LUA_OPSHR */
#endif
#if defined(LUA_OPSUB)
/* 清單巨集：LUA_OPSUB */
#endif
#if defined(LUA_OPUNM)
/* 清單巨集：LUA_OPUNM */
#endif
#if defined(LUA_PATH_DEFAULT)
/* 清單巨集：LUA_PATH_DEFAULT */
#endif
#if defined(LUA_PATH_MARK)
/* 清單巨集：LUA_PATH_MARK */
#endif
#if defined(LUA_PATH_SEP)
/* 清單巨集：LUA_PATH_SEP */
#endif
#if defined(LUA_PRELOAD_TABLE)
/* 清單巨集：LUA_PRELOAD_TABLE */
#endif
#if defined(LUA_REFNIL)
/* 清單巨集：LUA_REFNIL */
#endif
#if defined(LUA_REGISTRYINDEX)
/* 清單巨集：LUA_REGISTRYINDEX */
#endif
#if defined(LUA_RELEASE)
/* 清單巨集：LUA_RELEASE */
#endif
#if defined(LUA_RIDX_GLOBALS)
/* 清單巨集：LUA_RIDX_GLOBALS */
#endif
#if defined(LUA_RIDX_LAST)
/* 清單巨集：LUA_RIDX_LAST */
#endif
#if defined(LUA_RIDX_MAINTHREAD)
/* 清單巨集：LUA_RIDX_MAINTHREAD */
#endif
#if defined(LUA_ROOT)
/* 清單巨集：LUA_ROOT */
#endif
#if defined(LUA_SHRDIR)
/* 清單巨集：LUA_SHRDIR */
#endif
#if defined(LUA_SIGNATURE)
/* 清單巨集：LUA_SIGNATURE */
#endif
#if defined(LUA_TBOOLEAN)
/* 清單巨集：LUA_TBOOLEAN */
#endif
#if defined(LUA_TFUNCTION)
/* 清單巨集：LUA_TFUNCTION */
#endif
#if defined(LUA_TLIGHTUSERDATA)
/* 清單巨集：LUA_TLIGHTUSERDATA */
#endif
#if defined(LUA_TNIL)
/* 清單巨集：LUA_TNIL */
#endif
#if defined(LUA_TNONE)
/* 清單巨集：LUA_TNONE */
#endif
#if defined(LUA_TNUMBER)
/* 清單巨集：LUA_TNUMBER */
#endif
#if defined(LUA_TSTRING)
/* 清單巨集：LUA_TSTRING */
#endif
#if defined(LUA_TTABLE)
/* 清單巨集：LUA_TTABLE */
#endif
#if defined(LUA_TTHREAD)
/* 清單巨集：LUA_TTHREAD */
#endif
#if defined(LUA_TUSERDATA)
/* 清單巨集：LUA_TUSERDATA */
#endif
#if defined(LUA_UNSIGNED)
/* 清單巨集：LUA_UNSIGNED */
#endif
#if defined(LUA_USE_C89)
/* 清單巨集：LUA_USE_C89 */
#endif
#if defined(LUA_USE_DLOPEN)
/* 清單巨集：LUA_USE_DLOPEN */
#endif
#if defined(LUA_USE_POSIX)
/* 清單巨集：LUA_USE_POSIX */
#endif
#if defined(LUA_USE_WINDOWS)
/* 清單巨集：LUA_USE_WINDOWS */
#endif
#if defined(LUA_VDIR)
/* 清單巨集：LUA_VDIR */
#endif
#if defined(LUA_VERSION)
/* 清單巨集：LUA_VERSION */
#endif
#if defined(LUA_VERSION_MAJOR)
/* 清單巨集：LUA_VERSION_MAJOR */
#endif
#if defined(LUA_VERSION_MINOR)
/* 清單巨集：LUA_VERSION_MINOR */
#endif
#if defined(LUA_VERSION_NUM)
/* 清單巨集：LUA_VERSION_NUM */
#endif
#if defined(LUA_VERSION_RELEASE)
/* 清單巨集：LUA_VERSION_RELEASE */
#endif
#if defined(LUA_VERSION_RELEASE_NUM)
/* 清單巨集：LUA_VERSION_RELEASE_NUM */
#endif
#if defined(LUA_YIELD)
/* 清單巨集：LUA_YIELD */
#endif
#if defined(l_floatatt)
/* 清單巨集：l_floatatt */
#endif
#if defined(l_floor)
/* 清單巨集：l_floor */
#endif
#if defined(l_likely)
/* 清單巨集：l_likely */
#endif
#if defined(l_mathop)
/* 清單巨集：l_mathop */
#endif
#if defined(l_sprintf)
/* 清單巨集：l_sprintf */
#endif
#if defined(l_unlikely)
/* 清單巨集：l_unlikely */
#endif
#if defined(lauxlib_h)
/* 清單巨集：lauxlib_h */
#endif
#if defined(luaL_addchar)
/* 清單巨集：luaL_addchar */
#endif
#if defined(luaL_addsize)
/* 清單巨集：luaL_addsize */
#endif
#if defined(luaL_argcheck)
/* 清單巨集：luaL_argcheck */
#endif
#if defined(luaL_argexpected)
/* 清單巨集：luaL_argexpected */
#endif
#if defined(luaL_buffaddr)
/* 清單巨集：luaL_buffaddr */
#endif
#if defined(luaL_bufflen)
/* 清單巨集：luaL_bufflen */
#endif
#if defined(luaL_buffsub)
/* 清單巨集：luaL_buffsub */
#endif
#if defined(luaL_checkint)
/* 清單巨集：luaL_checkint */
#endif
#if defined(luaL_checklong)
/* 清單巨集：luaL_checklong */
#endif
#if defined(luaL_checkstring)
/* 清單巨集：luaL_checkstring */
#endif
#if defined(luaL_checkunsigned)
/* 清單巨集：luaL_checkunsigned */
#endif
#if defined(luaL_checkversion)
/* 清單巨集：luaL_checkversion */
#endif
#if defined(luaL_dofile)
/* 清單巨集：luaL_dofile */
#endif
#if defined(luaL_dostring)
/* 清單巨集：luaL_dostring */
#endif
#if defined(luaL_getmetatable)
/* 清單巨集：luaL_getmetatable */
#endif
#if defined(luaL_intop)
/* 清單巨集：luaL_intop */
#endif
#if defined(luaL_loadbuffer)
/* 清單巨集：luaL_loadbuffer */
#endif
#if defined(luaL_loadfile)
/* 清單巨集：luaL_loadfile */
#endif
#if defined(luaL_newlib)
/* 清單巨集：luaL_newlib */
#endif
#if defined(luaL_newlibtable)
/* 清單巨集：luaL_newlibtable */
#endif
#if defined(luaL_opt)
/* 清單巨集：luaL_opt */
#endif
#if defined(luaL_optint)
/* 清單巨集：luaL_optint */
#endif
#if defined(luaL_optlong)
/* 清單巨集：luaL_optlong */
#endif
#if defined(luaL_optstring)
/* 清單巨集：luaL_optstring */
#endif
#if defined(luaL_optunsigned)
/* 清單巨集：luaL_optunsigned */
#endif
#if defined(luaL_prepbuffer)
/* 清單巨集：luaL_prepbuffer */
#endif
#if defined(luaL_pushfail)
/* 清單巨集：luaL_pushfail */
#endif
#if defined(luaL_typename)
/* 清單巨集：luaL_typename */
#endif
#if defined(lua_assert)
/* 清單巨集：lua_assert */
#endif
#if defined(lua_call)
/* 清單巨集：lua_call */
#endif
#if defined(lua_equal)
/* 清單巨集：lua_equal */
#endif
#if defined(lua_getextraspace)
/* 清單巨集：lua_getextraspace */
#endif
#if defined(lua_getlocaledecpoint)
/* 清單巨集：lua_getlocaledecpoint */
#endif
#if defined(lua_getuservalue)
/* 清單巨集：lua_getuservalue */
#endif
#if defined(lua_h)
/* 清單巨集：lua_h */
#endif
#if defined(lua_insert)
/* 清單巨集：lua_insert */
#endif
#if defined(lua_integer2str)
/* 清單巨集：lua_integer2str */
#endif
#if defined(lua_isboolean)
/* 清單巨集：lua_isboolean */
#endif
#if defined(lua_isfunction)
/* 清單巨集：lua_isfunction */
#endif
#if defined(lua_islightuserdata)
/* 清單巨集：lua_islightuserdata */
#endif
#if defined(lua_isnil)
/* 清單巨集：lua_isnil */
#endif
#if defined(lua_isnone)
/* 清單巨集：lua_isnone */
#endif
#if defined(lua_isnoneornil)
/* 清單巨集：lua_isnoneornil */
#endif
#if defined(lua_istable)
/* 清單巨集：lua_istable */
#endif
#if defined(lua_isthread)
/* 清單巨集：lua_isthread */
#endif
#if defined(lua_lessthan)
/* 清單巨集：lua_lessthan */
#endif
#if defined(lua_newtable)
/* 清單巨集：lua_newtable */
#endif
#if defined(lua_newuserdata)
/* 清單巨集：lua_newuserdata */
#endif
#if defined(lua_number2str)
/* 清單巨集：lua_number2str */
#endif
#if defined(lua_number2strx)
/* 清單巨集：lua_number2strx */
#endif
#if defined(lua_numbertointeger)
/* 清單巨集：lua_numbertointeger */
#endif
#if defined(lua_objlen)
/* 清單巨集：lua_objlen */
#endif
#if defined(lua_pcall)
/* 清單巨集：lua_pcall */
#endif
#if defined(lua_pointer2str)
/* 清單巨集：lua_pointer2str */
#endif
#if defined(lua_pop)
/* 清單巨集：lua_pop */
#endif
#if defined(lua_pushcfunction)
/* 清單巨集：lua_pushcfunction */
#endif
#if defined(lua_pushglobaltable)
/* 清單巨集：lua_pushglobaltable */
#endif
#if defined(lua_pushliteral)
/* 清單巨集：lua_pushliteral */
#endif
#if defined(lua_pushunsigned)
/* 清單巨集：lua_pushunsigned */
#endif
#if defined(lua_register)
/* 清單巨集：lua_register */
#endif
#if defined(lua_remove)
/* 清單巨集：lua_remove */
#endif
#if defined(lua_replace)
/* 清單巨集：lua_replace */
#endif
#if defined(lua_setuservalue)
/* 清單巨集：lua_setuservalue */
#endif
#if defined(lua_str2number)
/* 清單巨集：lua_str2number */
#endif
#if defined(lua_strlen)
/* 清單巨集：lua_strlen */
#endif
#if defined(lua_strx2number)
/* 清單巨集：lua_strx2number */
#endif
#if defined(lua_tointeger)
/* 清單巨集：lua_tointeger */
#endif
#if defined(lua_tonumber)
/* 清單巨集：lua_tonumber */
#endif
#if defined(lua_tostring)
/* 清單巨集：lua_tostring */
#endif
#if defined(lua_tounsigned)
/* 清單巨集：lua_tounsigned */
#endif
#if defined(lua_tounsignedx)
/* 清單巨集：lua_tounsignedx */
#endif
#if defined(lua_upvalueindex)
/* 清單巨集：lua_upvalueindex */
#endif
#if defined(lua_writeline)
/* 清單巨集：lua_writeline */
#endif
#if defined(lua_writestring)
/* 清單巨集：lua_writestring */
#endif
#if defined(lua_writestringerror)
/* 清單巨集：lua_writestringerror */
#endif
#if defined(lua_yield)
/* 清單巨集：lua_yield */
#endif
#if defined(luaconf_h)
/* 清單巨集：luaconf_h */
#endif
#if defined(luai_apicheck)
/* 清單巨集：luai_apicheck */
#endif
#if defined(luai_likely)
/* 清單巨集：luai_likely */
#endif
#if defined(luai_unlikely)
/* 清單巨集：luai_unlikely */
#endif
