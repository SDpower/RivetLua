#include "lua.h"
#include "lauxlib.h"

#include <stddef.h>
#include <stdio.h>

static void p16_integer(const char *name, unsigned long long value) {
  printf("P16_VALUE %s NUM %llu\n", name, value);
}

static void p16_string(const char *name, const char *value) {
  printf("P16_VALUE %s STR ", name);
  for (const unsigned char *byte = (const unsigned char *)value; *byte; ++byte)
    printf("%02x", *byte);
  putchar('\n');
}

#define P16_VALUE(name) _Generic((name), char *: p16_string, const char *: p16_string, default: p16_integer)(#name, (name))
#define P16_TYPE(name) printf("P16_VALUE %s TYPE %zu %zu %d\n", #name, sizeof(name), _Alignof(name), _Generic(((name)0), int:1, long:2, long long:3, unsigned int:4, unsigned long:5, unsigned long long:6, float:7, double:8, long double:9, default:0))

int main(void) {
#ifdef LUAL_BUFFERSIZE
  P16_VALUE(LUAL_BUFFERSIZE);
#endif
#ifdef LUAL_NUMSIZES
  P16_VALUE(LUAL_NUMSIZES);
#endif
#ifdef LUA_AUTHORS
  P16_VALUE(LUA_AUTHORS);
#endif
#ifdef LUA_CDIR
  P16_VALUE(LUA_CDIR);
#endif
#ifdef LUA_COPYRIGHT
  P16_VALUE(LUA_COPYRIGHT);
#endif
#ifdef LUA_CPATH_DEFAULT
  P16_VALUE(LUA_CPATH_DEFAULT);
#endif
#ifdef LUA_DIRSEP
  P16_VALUE(LUA_DIRSEP);
#endif
#ifdef LUA_DL_DLL
  P16_VALUE(LUA_DL_DLL);
#endif
#ifdef LUA_ERRERR
  P16_VALUE(LUA_ERRERR);
#endif
#ifdef LUA_ERRFILE
  P16_VALUE(LUA_ERRFILE);
#endif
#ifdef LUA_ERRMEM
  P16_VALUE(LUA_ERRMEM);
#endif
#ifdef LUA_ERRRUN
  P16_VALUE(LUA_ERRRUN);
#endif
#ifdef LUA_ERRSYNTAX
  P16_VALUE(LUA_ERRSYNTAX);
#endif
#ifdef LUA_EXEC_DIR
  P16_VALUE(LUA_EXEC_DIR);
#endif
#ifdef LUA_EXTRASPACE
  P16_VALUE(LUA_EXTRASPACE);
#endif
#ifdef LUA_FILEHANDLE
  P16_VALUE(LUA_FILEHANDLE);
#endif
#ifdef LUA_FLOAT_DEFAULT
  P16_VALUE(LUA_FLOAT_DEFAULT);
#endif
#ifdef LUA_FLOAT_DOUBLE
  P16_VALUE(LUA_FLOAT_DOUBLE);
#endif
#ifdef LUA_FLOAT_FLOAT
  P16_VALUE(LUA_FLOAT_FLOAT);
#endif
#ifdef LUA_FLOAT_LONGDOUBLE
  P16_VALUE(LUA_FLOAT_LONGDOUBLE);
#endif
#ifdef LUA_GCCOLLECT
  P16_VALUE(LUA_GCCOLLECT);
#endif
#ifdef LUA_GCCOUNT
  P16_VALUE(LUA_GCCOUNT);
#endif
#ifdef LUA_GCCOUNTB
  P16_VALUE(LUA_GCCOUNTB);
#endif
#ifdef LUA_GCGEN
  P16_VALUE(LUA_GCGEN);
#endif
#ifdef LUA_GCINC
  P16_VALUE(LUA_GCINC);
#endif
#ifdef LUA_GCISRUNNING
  P16_VALUE(LUA_GCISRUNNING);
#endif
#ifdef LUA_GCPARAM
  P16_VALUE(LUA_GCPARAM);
#endif
#ifdef LUA_GCPMAJORMINOR
  P16_VALUE(LUA_GCPMAJORMINOR);
#endif
#ifdef LUA_GCPMINORMAJOR
  P16_VALUE(LUA_GCPMINORMAJOR);
#endif
#ifdef LUA_GCPMINORMUL
  P16_VALUE(LUA_GCPMINORMUL);
#endif
#ifdef LUA_GCPN
  P16_VALUE(LUA_GCPN);
#endif
#ifdef LUA_GCPPAUSE
  P16_VALUE(LUA_GCPPAUSE);
#endif
#ifdef LUA_GCPSTEPMUL
  P16_VALUE(LUA_GCPSTEPMUL);
#endif
#ifdef LUA_GCPSTEPSIZE
  P16_VALUE(LUA_GCPSTEPSIZE);
#endif
#ifdef LUA_GCRESTART
  P16_VALUE(LUA_GCRESTART);
#endif
#ifdef LUA_GCSETPAUSE
  P16_VALUE(LUA_GCSETPAUSE);
#endif
#ifdef LUA_GCSETSTEPMUL
  P16_VALUE(LUA_GCSETSTEPMUL);
#endif
#ifdef LUA_GCSTEP
  P16_VALUE(LUA_GCSTEP);
#endif
#ifdef LUA_GCSTOP
  P16_VALUE(LUA_GCSTOP);
#endif
#ifdef LUA_GNAME
  P16_VALUE(LUA_GNAME);
#endif
#ifdef LUA_HOOKCALL
  P16_VALUE(LUA_HOOKCALL);
#endif
#ifdef LUA_HOOKCOUNT
  P16_VALUE(LUA_HOOKCOUNT);
#endif
#ifdef LUA_HOOKLINE
  P16_VALUE(LUA_HOOKLINE);
#endif
#ifdef LUA_HOOKRET
  P16_VALUE(LUA_HOOKRET);
#endif
#ifdef LUA_HOOKTAILCALL
  P16_VALUE(LUA_HOOKTAILCALL);
#endif
#ifdef LUA_IDSIZE
  P16_VALUE(LUA_IDSIZE);
#endif
#ifdef LUA_IGMARK
  P16_VALUE(LUA_IGMARK);
#endif
#ifdef LUA_INTEGER_FMT
  P16_VALUE(LUA_INTEGER_FMT);
#endif
#ifdef LUA_INTEGER_FRMLEN
  P16_VALUE(LUA_INTEGER_FRMLEN);
#endif
#ifdef LUA_INT_DEFAULT
  P16_VALUE(LUA_INT_DEFAULT);
#endif
#ifdef LUA_INT_INT
  P16_VALUE(LUA_INT_INT);
#endif
#ifdef LUA_INT_LONG
  P16_VALUE(LUA_INT_LONG);
#endif
#ifdef LUA_INT_LONGLONG
  P16_VALUE(LUA_INT_LONGLONG);
#endif
#ifdef LUA_LDIR
  P16_VALUE(LUA_LDIR);
#endif
#ifdef LUA_LOADED_TABLE
  P16_VALUE(LUA_LOADED_TABLE);
#endif
#ifdef LUA_MASKCALL
  P16_VALUE(LUA_MASKCALL);
#endif
#ifdef LUA_MASKCOUNT
  P16_VALUE(LUA_MASKCOUNT);
#endif
#ifdef LUA_MASKLINE
  P16_VALUE(LUA_MASKLINE);
#endif
#ifdef LUA_MASKRET
  P16_VALUE(LUA_MASKRET);
#endif
#ifdef LUA_MAXINTEGER
  P16_VALUE(LUA_MAXINTEGER);
#endif
#ifdef LUA_MAXUNSIGNED
  P16_VALUE(LUA_MAXUNSIGNED);
#endif
#ifdef LUA_MININTEGER
  P16_VALUE(LUA_MININTEGER);
#endif
#ifdef LUA_MINSTACK
  P16_VALUE(LUA_MINSTACK);
#endif
#ifdef LUA_MULTRET
  P16_VALUE(LUA_MULTRET);
#endif
#ifdef LUA_N2SBUFFSZ
  P16_VALUE(LUA_N2SBUFFSZ);
#endif
#ifdef LUA_NOREF
  P16_VALUE(LUA_NOREF);
#endif
#ifdef LUA_NUMBER_FMT
  P16_VALUE(LUA_NUMBER_FMT);
#endif
#ifdef LUA_NUMBER_FMT_N
  P16_VALUE(LUA_NUMBER_FMT_N);
#endif
#ifdef LUA_NUMBER_FRMLEN
  P16_VALUE(LUA_NUMBER_FRMLEN);
#endif
#ifdef LUA_NUMTAGS
  P16_VALUE(LUA_NUMTAGS);
#endif
#ifdef LUA_NUMTYPES
  P16_VALUE(LUA_NUMTYPES);
#endif
#ifdef LUA_OK
  P16_VALUE(LUA_OK);
#endif
#ifdef LUA_OPADD
  P16_VALUE(LUA_OPADD);
#endif
#ifdef LUA_OPBAND
  P16_VALUE(LUA_OPBAND);
#endif
#ifdef LUA_OPBNOT
  P16_VALUE(LUA_OPBNOT);
#endif
#ifdef LUA_OPBOR
  P16_VALUE(LUA_OPBOR);
#endif
#ifdef LUA_OPBXOR
  P16_VALUE(LUA_OPBXOR);
#endif
#ifdef LUA_OPDIV
  P16_VALUE(LUA_OPDIV);
#endif
#ifdef LUA_OPEQ
  P16_VALUE(LUA_OPEQ);
#endif
#ifdef LUA_OPIDIV
  P16_VALUE(LUA_OPIDIV);
#endif
#ifdef LUA_OPLE
  P16_VALUE(LUA_OPLE);
#endif
#ifdef LUA_OPLT
  P16_VALUE(LUA_OPLT);
#endif
#ifdef LUA_OPMOD
  P16_VALUE(LUA_OPMOD);
#endif
#ifdef LUA_OPMUL
  P16_VALUE(LUA_OPMUL);
#endif
#ifdef LUA_OPPOW
  P16_VALUE(LUA_OPPOW);
#endif
#ifdef LUA_OPSHL
  P16_VALUE(LUA_OPSHL);
#endif
#ifdef LUA_OPSHR
  P16_VALUE(LUA_OPSHR);
#endif
#ifdef LUA_OPSUB
  P16_VALUE(LUA_OPSUB);
#endif
#ifdef LUA_OPUNM
  P16_VALUE(LUA_OPUNM);
#endif
#ifdef LUA_PATH_DEFAULT
  P16_VALUE(LUA_PATH_DEFAULT);
#endif
#ifdef LUA_PATH_MARK
  P16_VALUE(LUA_PATH_MARK);
#endif
#ifdef LUA_PATH_SEP
  P16_VALUE(LUA_PATH_SEP);
#endif
#ifdef LUA_PRELOAD_TABLE
  P16_VALUE(LUA_PRELOAD_TABLE);
#endif
#ifdef LUA_READLINELIB
  P16_VALUE(LUA_READLINELIB);
#endif
#ifdef LUA_REFNIL
  P16_VALUE(LUA_REFNIL);
#endif
#ifdef LUA_REGISTRYINDEX
  P16_VALUE(LUA_REGISTRYINDEX);
#endif
#ifdef LUA_RELEASE
  P16_VALUE(LUA_RELEASE);
#endif
#ifdef LUA_RIDX_GLOBALS
  P16_VALUE(LUA_RIDX_GLOBALS);
#endif
#ifdef LUA_RIDX_LAST
  P16_VALUE(LUA_RIDX_LAST);
#endif
#ifdef LUA_RIDX_MAINTHREAD
  P16_VALUE(LUA_RIDX_MAINTHREAD);
#endif
#ifdef LUA_ROOT
  P16_VALUE(LUA_ROOT);
#endif
#ifdef LUA_SHRDIR
  P16_VALUE(LUA_SHRDIR);
#endif
#ifdef LUA_SIGNATURE
  P16_VALUE(LUA_SIGNATURE);
#endif
#ifdef LUA_TBOOLEAN
  P16_VALUE(LUA_TBOOLEAN);
#endif
#ifdef LUA_TFUNCTION
  P16_VALUE(LUA_TFUNCTION);
#endif
#ifdef LUA_TLIGHTUSERDATA
  P16_VALUE(LUA_TLIGHTUSERDATA);
#endif
#ifdef LUA_TNIL
  P16_VALUE(LUA_TNIL);
#endif
#ifdef LUA_TNONE
  P16_VALUE(LUA_TNONE);
#endif
#ifdef LUA_TNUMBER
  P16_VALUE(LUA_TNUMBER);
#endif
#ifdef LUA_TSTRING
  P16_VALUE(LUA_TSTRING);
#endif
#ifdef LUA_TTABLE
  P16_VALUE(LUA_TTABLE);
#endif
#ifdef LUA_TTHREAD
  P16_VALUE(LUA_TTHREAD);
#endif
#ifdef LUA_TUSERDATA
  P16_VALUE(LUA_TUSERDATA);
#endif
#ifdef LUA_VDIR
  P16_VALUE(LUA_VDIR);
#endif
#ifdef LUA_VERSION
  P16_VALUE(LUA_VERSION);
#endif
#ifdef LUA_VERSION_MAJOR
  P16_VALUE(LUA_VERSION_MAJOR);
#endif
#ifdef LUA_VERSION_MAJOR_N
  P16_VALUE(LUA_VERSION_MAJOR_N);
#endif
#ifdef LUA_VERSION_MINOR
  P16_VALUE(LUA_VERSION_MINOR);
#endif
#ifdef LUA_VERSION_MINOR_N
  P16_VALUE(LUA_VERSION_MINOR_N);
#endif
#ifdef LUA_VERSION_NUM
  P16_VALUE(LUA_VERSION_NUM);
#endif
#ifdef LUA_VERSION_RELEASE
  P16_VALUE(LUA_VERSION_RELEASE);
#endif
#ifdef LUA_VERSION_RELEASE_N
  P16_VALUE(LUA_VERSION_RELEASE_N);
#endif
#ifdef LUA_VERSION_RELEASE_NUM
  P16_VALUE(LUA_VERSION_RELEASE_NUM);
#endif
#ifdef LUA_YIELD
  P16_VALUE(LUA_YIELD);
#endif
#ifdef LUAI_IS32INT
  P16_VALUE(LUAI_IS32INT);
#endif
#ifdef LUA_32BITS
  P16_VALUE(LUA_32BITS);
#endif
#ifdef LUA_C89_NUMBERS
  P16_VALUE(LUA_C89_NUMBERS);
#endif
#ifdef LUA_INT_TYPE
  P16_VALUE(LUA_INT_TYPE);
#endif
#ifdef LUA_FLOAT_TYPE
  P16_VALUE(LUA_FLOAT_TYPE);
#endif
#ifdef LUA_COMPAT_GLOBAL
  P16_VALUE(LUA_COMPAT_GLOBAL);
#endif
#ifdef LUAI_MAXSTACK
  P16_VALUE(LUAI_MAXSTACK);
#endif
#ifdef LUA_NUMBER
  P16_TYPE(LUA_NUMBER);
#endif
#ifdef LUAI_UACNUMBER
  P16_TYPE(LUAI_UACNUMBER);
#endif
#ifdef LUAI_UACINT
  P16_TYPE(LUAI_UACINT);
#endif
#ifdef LUA_UNSIGNED
  P16_TYPE(LUA_UNSIGNED);
#endif
#ifdef LUA_INTEGER
  P16_TYPE(LUA_INTEGER);
#endif
#ifdef LUA_KCONTEXT
  P16_TYPE(LUA_KCONTEXT);
#endif
#ifdef LUAI_MAXALIGN
  struct p16_maxalign { LUAI_MAXALIGN; };
  printf("P16_VALUE LUAI_MAXALIGN LAYOUT %zu %zu\n", sizeof(struct p16_maxalign), _Alignof(struct p16_maxalign));
#endif
  printf("P16_VALUE luaL_Buffer.L OFFSET %zu SIZE %zu\n", offsetof(luaL_Buffer, L), sizeof(((luaL_Buffer *)0)->L));
  printf("P16_VALUE luaL_Buffer.b OFFSET %zu SIZE %zu\n", offsetof(luaL_Buffer, b), sizeof(((luaL_Buffer *)0)->b));
  printf("P16_VALUE luaL_Buffer.init OFFSET %zu SIZE %zu\n", offsetof(luaL_Buffer, init), sizeof(((luaL_Buffer *)0)->init));
  printf("P16_VALUE luaL_Buffer.n OFFSET %zu SIZE %zu\n", offsetof(luaL_Buffer, n), sizeof(((luaL_Buffer *)0)->n));
  printf("P16_VALUE luaL_Buffer.size OFFSET %zu SIZE %zu\n", offsetof(luaL_Buffer, size), sizeof(((luaL_Buffer *)0)->size));
  printf("P16_VALUE luaL_Reg.func OFFSET %zu SIZE %zu\n", offsetof(luaL_Reg, func), sizeof(((luaL_Reg *)0)->func));
  printf("P16_VALUE luaL_Reg.name OFFSET %zu SIZE %zu\n", offsetof(luaL_Reg, name), sizeof(((luaL_Reg *)0)->name));
  printf("P16_VALUE luaL_Stream.closef OFFSET %zu SIZE %zu\n", offsetof(luaL_Stream, closef), sizeof(((luaL_Stream *)0)->closef));
  printf("P16_VALUE luaL_Stream.f OFFSET %zu SIZE %zu\n", offsetof(luaL_Stream, f), sizeof(((luaL_Stream *)0)->f));
  printf("P16_VALUE lua_Debug.currentline OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, currentline), sizeof(((lua_Debug *)0)->currentline));
  printf("P16_VALUE lua_Debug.event OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, event), sizeof(((lua_Debug *)0)->event));
#if LUA_VERSION_NUM >= 505
  printf("P16_VALUE lua_Debug.extraargs OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, extraargs), sizeof(((lua_Debug *)0)->extraargs));
#endif
  printf("P16_VALUE lua_Debug.ftransfer OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, ftransfer), sizeof(((lua_Debug *)0)->ftransfer));
  printf("P16_VALUE lua_Debug.i_ci OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, i_ci), sizeof(((lua_Debug *)0)->i_ci));
  printf("P16_VALUE lua_Debug.istailcall OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, istailcall), sizeof(((lua_Debug *)0)->istailcall));
  printf("P16_VALUE lua_Debug.isvararg OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, isvararg), sizeof(((lua_Debug *)0)->isvararg));
  printf("P16_VALUE lua_Debug.lastlinedefined OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, lastlinedefined), sizeof(((lua_Debug *)0)->lastlinedefined));
  printf("P16_VALUE lua_Debug.linedefined OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, linedefined), sizeof(((lua_Debug *)0)->linedefined));
  printf("P16_VALUE lua_Debug.name OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, name), sizeof(((lua_Debug *)0)->name));
  printf("P16_VALUE lua_Debug.namewhat OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, namewhat), sizeof(((lua_Debug *)0)->namewhat));
  printf("P16_VALUE lua_Debug.nparams OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, nparams), sizeof(((lua_Debug *)0)->nparams));
  printf("P16_VALUE lua_Debug.ntransfer OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, ntransfer), sizeof(((lua_Debug *)0)->ntransfer));
  printf("P16_VALUE lua_Debug.nups OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, nups), sizeof(((lua_Debug *)0)->nups));
  printf("P16_VALUE lua_Debug.short_src OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, short_src), sizeof(((lua_Debug *)0)->short_src));
  printf("P16_VALUE lua_Debug.source OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, source), sizeof(((lua_Debug *)0)->source));
  printf("P16_VALUE lua_Debug.srclen OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, srclen), sizeof(((lua_Debug *)0)->srclen));
  printf("P16_VALUE lua_Debug.what OFFSET %zu SIZE %zu\n", offsetof(lua_Debug, what), sizeof(((lua_Debug *)0)->what));
  return 0;
}
