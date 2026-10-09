#!/usr/bin/env python3
"""核對固定 Lua header，產生 P16-1 逐項清單與 C 編譯探針。"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INCLUDE = ROOT / "include" / "rivetlua"
PROFILES = {
    "lua55": {
        "release": "5.5.1",
        "case_profile": "lua55-i64f64",
        "archive_sha256": "1c4b4068d67061f2a2231ad2b5422e77acea1487ea9890f6320af614f4373dce",
        "files": {
            "lua.h": "5e00319e803893f4310b1206394c80b82f03f42609b40ceb306d92a6740d828e",
            "lauxlib.h": "007608c5e2abd231a9f61dc6cf4080ff6d4b54c845aa87b08162b5c778960443",
            "luaconf.h": "1e617ae6f206d701018941b64ed61851da4ffc3573a0f96b73ebe64e340bfb5d",
        },
    },
    "lua54": {
        "release": "5.4.9",
        "case_profile": "lua54-i64f64",
        "archive_sha256": "2335b6c582a52654f94612bf10d2f4672805d05329aa6568b1d8cd9e5c6fb8e6",
        "files": {
            "lua.h": "06138352a12f0710bc214eb3a2e134889979cadc9a7a761a4e43dafa926419af",
            "lauxlib.h": "2d9e18e577a6062646268e7f7228264c28bd9b972c186e1af81b8357179c0ab4",
            "luaconf.h": "af243c94bee6d2601383e8b65ed66a0d1b4ab3b7418ff903fcd0679912160e3a",
        },
    },
}
HEADERS = ("lua.h", "lauxlib.h", "luaconf.h")
OUTPUT = ROOT / "tests" / "p16" / "abi-manifest.toml"
RUST_HASHES = ROOT / "crates" / "rivetlua-capi" / "src" / "manifest.rs"
C_ABI_HEADER = INCLUDE / "rivetlua_abi.h"
P16_SURFACE_MACRO_EXPANSIONS = {
    "luaL_addchar": (("lua54", "lua55"), "(void)luaL_addchar((luaL_Buffer *)0, 'x');"),
    "luaL_prepbuffer": (("lua54", "lua55"), "(void)luaL_prepbuffer((luaL_Buffer *)0);"),
    "luaL_checkversion": (("lua54", "lua55"), "(void)luaL_checkversion((lua_State *)0);"),
    "luaL_getmetatable": (("lua54", "lua55"), '(void)luaL_getmetatable((lua_State *)0, "named");'),
    "lua_pushliteral": (("lua54", "lua55"), '(void)lua_pushliteral((lua_State *)0, "literal");'),
    "lua_tostring": (("lua54", "lua55"), "(void)lua_tostring((lua_State *)0, 1);"),
    "lua_tonumber": (("lua54", "lua55"), "(void)lua_tonumber((lua_State *)0, 1);"),
    "lua_tointeger": (("lua54", "lua55"), "(void)lua_tointeger((lua_State *)0, 1);"),
    "luaL_opt": (("lua54", "lua55"), "(void)luaL_opt((lua_State *)0, luaL_checkinteger, 1, (lua_Integer)0);"),
    "luaL_checkunsigned": (("lua54", "lua55"), "(void)luaL_checkunsigned((lua_State *)0, 1);"),
    "luaL_optunsigned": (("lua54", "lua55"), "(void)luaL_optunsigned((lua_State *)0, 1, (lua_Unsigned)0);"),
    "luaL_checkint": (("lua54", "lua55"), "(void)luaL_checkint((lua_State *)0, 1);"),
    "luaL_optint": (("lua54", "lua55"), "(void)luaL_optint((lua_State *)0, 1, 0);"),
    "luaL_checklong": (("lua54", "lua55"), "(void)luaL_checklong((lua_State *)0, 1);"),
    "luaL_checkstring": (("lua54", "lua55"), "(void)luaL_checkstring((lua_State *)0, 1);"),
    "luaL_optlong": (("lua54", "lua55"), "(void)luaL_optlong((lua_State *)0, 1, 0L);"),
    "luaL_optstring": (("lua54", "lua55"), '(void)luaL_optstring((lua_State *)0, 1, "fallback");'),
    "luaL_pushfail": (("lua54", "lua55"), "(void)luaL_pushfail((lua_State *)0);"),
    "lua_pop": (("lua54", "lua55"), "(void)lua_pop((lua_State *)0, 1);"),
    "lua_newtable": (("lua54", "lua55"), "(void)lua_newtable((lua_State *)0);"),
    "lua_pushglobaltable": (("lua54", "lua55"), "(void)lua_pushglobaltable((lua_State *)0);"),
    "lua_equal": (("lua54", "lua55"), "(void)lua_equal((lua_State *)0, 1, 2);"),
    "lua_lessthan": (("lua54", "lua55"), "(void)lua_lessthan((lua_State *)0, 1, 2);"),
    "lua_upvalueindex": (("lua54", "lua55"), "(void)lua_upvalueindex(1);"),
    "lua_pushcfunction": (("lua54", "lua55"), "(void)lua_pushcfunction((lua_State *)0, (lua_CFunction)0);"),
    "luaL_newlibtable": (("lua54", "lua55"), '(void)luaL_newlibtable((lua_State *)0, ((const luaL_Reg[]){{"entry", (lua_CFunction)0}, {NULL, (lua_CFunction)0}}));'),
    "lua_register": (("lua54", "lua55"), '(void)lua_register((lua_State *)0, "entry", (lua_CFunction)0);'),
    "luaL_newlib": (("lua54", "lua55"), '(void)luaL_newlib((lua_State *)0, ((const luaL_Reg[]){{"entry", (lua_CFunction)0}, {NULL, (lua_CFunction)0}}));'),
    "luaL_bufflen": (("lua54", "lua55"), "(void)luaL_bufflen(&(luaL_Buffer){0});"),
    "luaL_buffaddr": (("lua54", "lua55"), "(void)luaL_buffaddr(&(luaL_Buffer){0});"),
    "luaL_addsize": (("lua54", "lua55"), "(void)luaL_addsize(&(luaL_Buffer){0}, 0);"),
    "luaL_buffsub": (("lua54", "lua55"), "(void)luaL_buffsub(&(luaL_Buffer){0}, 0);"),
    "lua_insert": (("lua54", "lua55"), "(void)lua_insert((lua_State *)0, 1);"),
    "lua_remove": (("lua54", "lua55"), "(void)lua_remove((lua_State *)0, 1);"),
    "lua_replace": (("lua54", "lua55"), "(void)lua_replace((lua_State *)0, LUA_REGISTRYINDEX);"),
    "lua_pushunsigned": (("lua54",), "(void)lua_pushunsigned((lua_State *)0, 1u);"),
    "lua_tounsignedx": (("lua54",), "(void)lua_tounsignedx((lua_State *)0, 1, (int *)0);"),
    "lua_tounsigned": (("lua54",), "(void)lua_tounsigned((lua_State *)0, 1);"),
    "lua_call": (("lua54", "lua55"), "(void)lua_call((lua_State *)0, 0, 0);"),
    "lua_pcall": (("lua54", "lua55"), "(void)lua_pcall((lua_State *)0, 0, 0, 0);"),
    "lua_yield": (("lua54", "lua55"), "(void)lua_yield((lua_State *)0, 0);"),
    "luaL_argcheck": (("lua54", "lua55"), '(void)luaL_argcheck((lua_State *)0, 1, 1, "message");'),
    "luaL_argexpected": (("lua54", "lua55"), '(void)luaL_argexpected((lua_State *)0, 1, 1, "number");'),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def header_set_sha256(profile: str) -> str:
    digest = hashlib.sha256(b"RivetLua-SDK-headers-v1\0")
    for name in HEADERS:
        data = (INCLUDE / profile / name).read_bytes()
        digest.update(len(name).to_bytes(8, "big"))
        digest.update(name.encode())
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def validate_inputs() -> None:
    for profile, spec in PROFILES.items():
        for name, expected in spec["files"].items():
            path = INCLUDE / profile / name
            actual = sha256(path.read_bytes())
            if actual != expected:
                raise ValueError(f"固定 header 雜湊不符：{path}: {actual}")


def without_comments(text: str) -> str:
    result: list[str] = []
    index = 0
    quote = ""
    while index < len(text):
        char = text[index]
        if quote:
            result.append(char)
            index += 1
            if char == "\\" and index < len(text):
                result.append(text[index])
                index += 1
            elif char == quote:
                quote = ""
            continue
        if char in ('"', "'"):
            quote = char
            result.append(char)
            index += 1
            continue
        if text.startswith("/*", index):
            end = text.find("*/", index + 2)
            if end < 0:
                raise ValueError("未終止的 C 區塊註解")
            segment = text[index:end + 2]
            result.extend("\n" if part == "\n" else " " for part in segment)
            index = end + 2
            continue
        if text.startswith("//", index):
            end = text.find("\n", index + 2)
            if end < 0:
                end = len(text)
            result.extend(" " for _ in text[index:end])
            index = end
            continue
        result.append(char)
        index += 1
    return "".join(result)


def condition_by_line(text: str) -> list[str]:
    stack: list[str] = []
    result = [""]
    for line in text.splitlines():
        stripped = line.strip()
        if re.match(r"#\s*(if|ifdef|ifndef)\b", stripped):
            stack.append(stripped)
        elif re.match(r"#\s*(elif|else)\b", stripped):
            if stack:
                stack[-1] = stripped
        elif re.match(r"#\s*endif\b", stripped):
            if stack:
                stack.pop()
        result.append(" && ".join(stack))
    return result


def normalize(value: str) -> str:
    result: list[str] = []
    index = 0
    quote = ""
    space = False
    while index < len(value):
        char = value[index]
        if quote:
            result.append(char)
            index += 1
            if char == "\\" and index < len(value):
                result.append(value[index])
                index += 1
            elif char == quote:
                quote = ""
            continue
        if char.isspace():
            space = True
            index += 1
            continue
        if space and result:
            result.append(" ")
        space = False
        result.append(char)
        if char in ('"', "'"):
            quote = char
        index += 1
    return "".join(result)


def add(rows: list[dict[str, object]], *, profile: str, header: str, line: int,
        kind: str, name: str, definition: str, condition: str) -> None:
    if not name:
        raise ValueError(f"缺少名稱：{profile}/{header}:{line}/{kind}")
    rows.append({
        "profile": profile,
        "header": header,
        "line": line,
        "kind": kind,
        "name": name,
        "definition": normalize(definition),
        "condition": condition,
    })


def scan_macros(rows: list[dict[str, object]], profile: str, header: str,
                text: str, conditions: list[str]) -> None:
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        start = index + 1
        if not re.match(r"^\s*#\s*define\s+", line):
            index += 1
            continue
        body = line
        while body.rstrip().endswith("\\") and index + 1 < len(lines):
            index += 1
            body = body.rstrip()[:-1] + " " + lines[index]
        match = re.match(r"^\s*#\s*define\s+([A-Za-z_]\w*)(\([^)]*\))?", body)
        if match is None:
            raise ValueError(f"無法解析巨集：{profile}/{header}:{start}")
        name, parameters = match.group(1), match.group(2)
        config = name in {
            "LUA_API", "LUALIB_API", "LUA_INT_TYPE", "LUA_FLOAT_TYPE",
            "LUA_INTEGER", "LUA_NUMBER", "LUA_UNSIGNED", "LUA_KCONTEXT",
            "LUA_32BITS", "LUA_C89_NUMBERS", "LUA_USE_C89",
        } or name.startswith(("LUA_USE_", "LUA_COMPAT_"))
        kind = ("macro" if parameters is not None or config
                else "constant" if name.startswith(("LUA_", "LUAL_"))
                else "macro")
        add(rows, profile=profile, header=header, line=start, kind=kind,
            name=name, definition=body, condition=conditions[start])
        index += 1


def scan_functions(rows: list[dict[str, object]], profile: str, header: str,
                   text: str, conditions: list[str]) -> None:
    if header == "luaconf.h":
        return
    cleaned = without_comments(text)
    matches = list(re.finditer(r"(?ms)^[ \t]*(LUA_API|LUALIB_API)\s+(.+?);", cleaned))
    for match in matches:
        name_match = re.search(r"\(\s*(lua(?:L)?_[A-Za-z0-9_]+)\s*\)\s*\(", match.group())
        if name_match is None:
            raise ValueError(f"無法解析公開函式：{profile}/{header}:{match.group()[:80]}")
        line = cleaned.count("\n", 0, match.start()) + 1
        add(rows, profile=profile, header=header, line=line, kind="function",
            name=name_match.group(1), definition=match.group(), condition=conditions[line])


def declaration_end(text: str, start: int) -> int:
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == ";" and depth == 0:
            return index + 1
    raise ValueError(f"未終止的 C 宣告：{text[start:start + 80]}")


def scan_typedefs(rows: list[dict[str, object]], profile: str, header: str,
                  text: str, conditions: list[str]) -> None:
    cleaned = without_comments(text)
    for match in re.finditer(r"(?m)^[ \t]*typedef\b", cleaned):
        end = declaration_end(cleaned, match.start())
        body = cleaned[match.start():end]
        pointer = re.search(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)", body)
        ending = re.search(r"([A-Za-z_]\w*)\s*;\s*$", body)
        name = pointer.group(1) if pointer else ending.group(1) if ending else ""
        line = cleaned.count("\n", 0, match.start()) + 1
        kind = "opaque_type" if re.fullmatch(r"\s*typedef\s+struct\s+lua_State\s+lua_State\s*;\s*", body) else "type"
        add(rows, profile=profile, header=header, line=line, kind=kind,
            name=name, definition=body, condition=conditions[line])


def struct_fields(body: str) -> list[tuple[str, str]]:
    fields: list[tuple[str, str]] = []
    depth = 0
    start = 0
    for index, char in enumerate(body):
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
        elif char == ";" and depth == 0:
            declaration = normalize(body[start:index])
            start = index + 1
            if not declaration:
                continue
            nested = re.search(r"\}\s*([A-Za-z_]\w*)$", declaration)
            ordinary = re.search(r"([A-Za-z_]\w*)\s*(?:\[[^]]+\])?$", declaration)
            name = nested.group(1) if nested else ordinary.group(1) if ordinary else ""
            if not name:
                raise ValueError(f"無法解析公開欄位：{declaration}")
            fields.append((name, declaration + ";"))
    return fields


def scan_layout(rows: list[dict[str, object]], profile: str, header: str,
                text: str, conditions: list[str]) -> None:
    cleaned = without_comments(text)
    for match in re.finditer(r"(?m)^[ \t]*(?:typedef\s+)?struct\s+(lua\w+)\s*\{", cleaned):
        name = match.group(1)
        opening = cleaned.index("{", match.start(), match.end())
        depth = 1
        closing = opening + 1
        while depth:
            if cleaned[closing] == "{":
                depth += 1
            elif cleaned[closing] == "}":
                depth -= 1
            closing += 1
        line = cleaned.count("\n", 0, match.start()) + 1
        condition = conditions[line]
        for kind, definition in (
            ("layout", cleaned[match.start():declaration_end(cleaned, match.start())]),
            ("size", f"sizeof({name})"),
            ("alignment", f"_Alignof({name})"),
        ):
            add(rows, profile=profile, header=header, line=line, kind=kind,
                name=name, definition=definition, condition=condition)
        for field, declaration in struct_fields(cleaned[opening + 1:closing - 1]):
            add(rows, profile=profile, header=header, line=line, kind="layout_field",
                name=f"{name}.{field}", definition=declaration, condition=condition)


LUA_API_COMPAT_MACROS = {
    "lua_strlen": "lua_rawlen",
    "lua_objlen": "lua_rawlen",
    "lua_equal": "lua_compare",
    "lua_lessthan": "lua_compare",
}

# 這些 luaconf.h 巨集僅用 C 型別、libc、算術或格式轉換；不呼叫 Lua API。
PURE_LUACONF_MACROS = {
    "lua_number2str", "lua_numbertointeger", "lua_str2number",
    "lua_integer2str", "lua_strx2number", "lua_pointer2str",
    "lua_number2strx", "lua_getlocaledecpoint",
}

# lua.h/lauxlib.h 的其餘小寫公開 API 巨集即使只是算 index／欄位，
# 仍需後續 VM stack、buffer 或 handle 契約，不能因 header 已有展開式而結案。
PURE_PUBLIC_MACROS = {
    ("lua.h", "lua_h"),
    ("lauxlib.h", "lauxlib_h"),
    ("lauxlib.h", "luaL_intop"),
    ("lauxlib.h", "lua_assert"),
    ("lauxlib.h", "lua_writestring"),
    ("lauxlib.h", "lua_writeline"),
    ("lauxlib.h", "lua_writestringerror"),
}

P16_3_API_MACROS = {"lua_call", "lua_pcall", "lua_yield", "luaL_argcheck", "luaL_argexpected"}
P16_5_API_MACROS = {"luaL_loadfile", "luaL_loadbuffer", "luaL_dofile", "luaL_dostring"}
P16_5_API_FUNCTIONS = {
    "lua_load", "lua_dump", "luaL_loadfilex", "luaL_loadbufferx", "luaL_loadstring",
}
P16_5_LOAD_TESTS = {
    "lua_load": "load_reader_fragments_preserve_prefix_and_publish_closure",
    "lua_dump": "dump_official_roundtrip_and_writer_status_keep_stack",
    "luaL_loadfilex": "loadfile_modes_missing_file_preserve_prefix_and_reuse",
    "luaL_loadbufferx": "loadbuffer_text_modes_empty_and_syntax_preserve_prefix",
    "luaL_loadstring": "loadstring_uses_fixed_profile_mode",
}
P16_5_MACRO_RUST_TESTS = {
    "luaL_loadfile": (("load_api.rs", "loadfile_modes_missing_file_preserve_prefix_and_reuse"),),
    "luaL_loadbuffer": (("load_api.rs", "loadbuffer_text_modes_empty_and_syntax_preserve_prefix"),),
    "luaL_dostring": (
        ("load_api.rs", "loadstring_uses_fixed_profile_mode"),
        ("public_callback_error.rs", "public_sync_call_pcall_and_group_panic_binding"),
    ),
    "luaL_dofile": (
        ("load_api.rs", "loadfile_modes_missing_file_preserve_prefix_and_reuse"),
        ("public_callback_error.rs", "public_sync_call_pcall_and_group_panic_binding"),
    ),
}

# 固定的 P16 core API effect 逐列清單；驗收 C fixture 對每個 ID 均實際連結執行。
P16_CORE_API_EFFECT_IDS = frozenset("""\
lua54:lauxlib.h:function:luaL_argerror:53
lua54:lauxlib.h:function:luaL_typeerror:54
lua54:lauxlib.h:function:luaL_error:76
lua54:lauxlib.h:function:luaL_fileresult:81
lua54:lauxlib.h:function:luaL_execresult:82
lua54:lauxlib.h:macro:luaL_newlibtable:127
lua54:lauxlib.h:macro:luaL_argcheck:133
lua54:lauxlib.h:macro:luaL_argexpected:136
lua54:lauxlib.h:macro:luaL_checkstring:139
lua54:lauxlib.h:macro:luaL_optstring:140
lua54:lauxlib.h:macro:luaL_typename:142
lua54:lauxlib.h:macro:luaL_getmetatable:150
lua54:lauxlib.h:macro:luaL_opt:152
lua54:lauxlib.h:macro:luaL_bufflen:203
lua54:lauxlib.h:macro:luaL_buffaddr:204
lua54:lauxlib.h:macro:luaL_addsize:211
lua54:lauxlib.h:macro:luaL_buffsub:213
lua54:lauxlib.h:function:luaL_buffinit:215
lua54:lauxlib.h:macro:luaL_checkunsigned:284
lua54:lauxlib.h:macro:luaL_optunsigned:285
lua54:lauxlib.h:macro:luaL_checkint:288
lua54:lauxlib.h:macro:luaL_optint:289
lua54:lauxlib.h:macro:luaL_checklong:291
lua54:lauxlib.h:macro:luaL_optlong:292
lua54:lua.h:macro:lua_upvalueindex:45
lua54:lua.h:function:lua_version:172
lua54:lua.h:function:lua_absindex:178
lua54:lua.h:function:lua_gettop:179
lua54:lua.h:function:lua_settop:180
lua54:lua.h:function:lua_checkstack:184
lua54:lua.h:function:lua_isnumber:193
lua54:lua.h:function:lua_isstring:194
lua54:lua.h:function:lua_isuserdata:197
lua54:lua.h:function:lua_typename:199
lua54:lua.h:function:lua_tonumberx:201
lua54:lua.h:function:lua_tointegerx:202
lua54:lua.h:function:lua_tolstring:204
lua54:lua.h:function:lua_rawlen:205
lua54:lua.h:function:lua_rawequal:237
lua54:lua.h:function:lua_pushlstring:247
lua54:lua.h:function:lua_pushstring:248
lua54:lua.h:function:lua_getglobal:261
lua54:lua.h:function:lua_rawget:265
lua54:lua.h:function:lua_rawgeti:266
lua54:lua.h:function:lua_rawgetp:267
lua54:lua.h:function:lua_createtable:269
lua54:lua.h:function:lua_rawset:282
lua54:lua.h:function:lua_rawseti:283
lua54:lua.h:function:lua_rawsetp:284
lua54:lua.h:macro:lua_call:294
lua54:lua.h:macro:lua_pcall:298
lua54:lua.h:function:lua_yieldk:309
lua54:lua.h:macro:lua_yield:316
lua54:lua.h:function:lua_error:349
lua54:lua.h:function:lua_stringtonumber:356
lua54:lua.h:macro:lua_getextraspace:371
lua54:lua.h:macro:lua_tonumber:373
lua54:lua.h:macro:lua_tointeger:374
lua54:lua.h:macro:lua_newtable:378
lua54:lua.h:macro:lua_isfunction:384
lua54:lua.h:macro:lua_istable:385
lua54:lua.h:macro:lua_islightuserdata:386
lua54:lua.h:macro:lua_isnil:387
lua54:lua.h:macro:lua_isboolean:388
lua54:lua.h:macro:lua_isthread:389
lua54:lua.h:macro:lua_isnone:390
lua54:lua.h:macro:lua_isnoneornil:391
lua54:lua.h:macro:lua_pushliteral:393
lua54:lua.h:macro:lua_pushglobaltable:395
lua54:lua.h:macro:lua_tostring:398
lua54:lua.h:function:lua_setcstacklimit:473
lua54:luaconf.h:macro:lua_strlen:381
lua54:luaconf.h:macro:lua_objlen:383
lua54:luaconf.h:macro:lua_equal:385
lua54:luaconf.h:macro:lua_lessthan:386
lua55:lauxlib.h:function:luaL_argerror:53
lua55:lauxlib.h:function:luaL_typeerror:54
lua55:lauxlib.h:function:luaL_error:76
lua55:lauxlib.h:function:luaL_fileresult:81
lua55:lauxlib.h:function:luaL_execresult:82
lua55:lauxlib.h:function:luaL_alloc:84
lua55:lauxlib.h:function:luaL_makeseed:106
lua55:lauxlib.h:macro:luaL_newlibtable:132
lua55:lauxlib.h:macro:luaL_argcheck:138
lua55:lauxlib.h:macro:luaL_argexpected:141
lua55:lauxlib.h:macro:luaL_checkstring:144
lua55:lauxlib.h:macro:luaL_optstring:145
lua55:lauxlib.h:macro:luaL_typename:147
lua55:lauxlib.h:macro:luaL_getmetatable:155
lua55:lauxlib.h:macro:luaL_opt:157
lua55:lauxlib.h:macro:luaL_bufflen:197
lua55:lauxlib.h:macro:luaL_buffaddr:198
lua55:lauxlib.h:macro:luaL_addsize:205
lua55:lauxlib.h:macro:luaL_buffsub:207
lua55:lauxlib.h:function:luaL_buffinit:209
lua55:lauxlib.h:macro:luaL_checkunsigned:254
lua55:lauxlib.h:macro:luaL_optunsigned:255
lua55:lauxlib.h:macro:luaL_checkint:258
lua55:lauxlib.h:macro:luaL_optint:259
lua55:lauxlib.h:macro:luaL_checklong:261
lua55:lauxlib.h:macro:luaL_optlong:262
lua55:lua.h:macro:lua_upvalueindex:44
lua55:lua.h:function:lua_version:171
lua55:lua.h:function:lua_absindex:177
lua55:lua.h:function:lua_gettop:178
lua55:lua.h:function:lua_settop:179
lua55:lua.h:function:lua_checkstack:183
lua55:lua.h:function:lua_isnumber:192
lua55:lua.h:function:lua_isstring:193
lua55:lua.h:function:lua_isuserdata:196
lua55:lua.h:function:lua_typename:198
lua55:lua.h:function:lua_tonumberx:200
lua55:lua.h:function:lua_tointegerx:201
lua55:lua.h:function:lua_tolstring:203
lua55:lua.h:function:lua_rawlen:204
lua55:lua.h:function:lua_rawequal:236
lua55:lua.h:function:lua_pushlstring:246
lua55:lua.h:function:lua_pushstring:249
lua55:lua.h:function:lua_getglobal:262
lua55:lua.h:function:lua_rawget:266
lua55:lua.h:function:lua_rawgeti:267
lua55:lua.h:function:lua_rawgetp:268
lua55:lua.h:function:lua_createtable:270
lua55:lua.h:function:lua_rawset:283
lua55:lua.h:function:lua_rawseti:284
lua55:lua.h:function:lua_rawsetp:285
lua55:lua.h:macro:lua_call:295
lua55:lua.h:macro:lua_pcall:299
lua55:lua.h:function:lua_yieldk:310
lua55:lua.h:macro:lua_yield:317
lua55:lua.h:function:lua_error:367
lua55:lua.h:function:lua_numbertocstring:375
lua55:lua.h:function:lua_stringtonumber:376
lua55:lua.h:macro:lua_getextraspace:391
lua55:lua.h:macro:lua_tonumber:393
lua55:lua.h:macro:lua_tointeger:394
lua55:lua.h:macro:lua_newtable:398
lua55:lua.h:macro:lua_isfunction:404
lua55:lua.h:macro:lua_istable:405
lua55:lua.h:macro:lua_islightuserdata:406
lua55:lua.h:macro:lua_isnil:407
lua55:lua.h:macro:lua_isboolean:408
lua55:lua.h:macro:lua_isthread:409
lua55:lua.h:macro:lua_isnone:410
lua55:lua.h:macro:lua_isnoneornil:411
lua55:lua.h:macro:lua_pushliteral:413
lua55:lua.h:macro:lua_pushglobaltable:415
lua55:lua.h:macro:lua_tostring:418
lua55:luaconf.h:macro:lua_strlen:365
lua55:luaconf.h:macro:lua_objlen:367
lua55:luaconf.h:macro:lua_equal:369
lua55:luaconf.h:macro:lua_lessthan:370
""".splitlines())
# 這些列沒有 API 本身的具名 Rust 測試，沿用既有跨契約具名測試。
P16_CORE_CROSS_CONTRACT = dict(
    (parts[0], (parts[1], parts[2]))
    for parts in (
        line.split("|") for line in """\
lua54:lauxlib.h:function:luaL_argerror:53|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua54:lauxlib.h:function:luaL_typeerror:54|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua54:lauxlib.h:function:luaL_error:76|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua54:lauxlib.h:macro:luaL_argcheck:133|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua54:lauxlib.h:macro:luaL_argexpected:136|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua54:lauxlib.h:macro:luaL_bufflen:203|aux_buffer|aux_buffer_small_inline_binary_and_empty_appends
lua54:lauxlib.h:macro:luaL_buffaddr:204|aux_buffer|aux_buffer_small_inline_binary_and_empty_appends
lua54:lauxlib.h:macro:luaL_addsize:211|aux_buffer|aux_buffer_small_inline_binary_and_empty_appends
lua54:lauxlib.h:macro:luaL_buffsub:213|aux_buffer|aux_buffer_small_inline_binary_and_empty_appends
lua54:lua.h:macro:lua_upvalueindex:45|public_upvalue_a4b|public_c_closure_pseudovalue_write_persists_a4b
lua54:lua.h:macro:lua_call:294|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua54:lua.h:macro:lua_pcall:298|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua54:lua.h:function:lua_yieldk:309|public_yield_resume_a5|suspended_c_upvalue_survives_gc_and_releases_child_charge_a5
lua54:lua.h:macro:lua_yield:316|public_yield_resume_a5|suspended_c_upvalue_survives_gc_and_releases_child_charge_a5
lua54:lua.h:function:lua_error:349|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua55:lauxlib.h:function:luaL_argerror:53|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua55:lauxlib.h:function:luaL_typeerror:54|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua55:lauxlib.h:function:luaL_error:76|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua55:lauxlib.h:macro:luaL_argcheck:138|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua55:lauxlib.h:macro:luaL_argexpected:141|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua55:lauxlib.h:macro:luaL_bufflen:197|aux_buffer|aux_buffer_small_inline_binary_and_empty_appends
lua55:lauxlib.h:macro:luaL_buffaddr:198|aux_buffer|aux_buffer_small_inline_binary_and_empty_appends
lua55:lauxlib.h:macro:luaL_addsize:205|aux_buffer|aux_buffer_small_inline_binary_and_empty_appends
lua55:lauxlib.h:macro:luaL_buffsub:207|aux_buffer|aux_buffer_small_inline_binary_and_empty_appends
lua55:lua.h:macro:lua_upvalueindex:44|public_upvalue_a4b|public_c_closure_pseudovalue_write_persists_a4b
lua55:lua.h:macro:lua_call:295|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua55:lua.h:macro:lua_pcall:299|public_callback_error|public_sync_call_pcall_and_group_panic_binding
lua55:lua.h:function:lua_yieldk:310|public_yield_resume_a5|suspended_c_upvalue_survives_gc_and_releases_child_charge_a5
lua55:lua.h:macro:lua_yield:317|public_yield_resume_a5|suspended_c_upvalue_survives_gc_and_releases_child_charge_a5
lua55:lua.h:function:lua_error:367|public_callback_error|public_sync_call_pcall_and_group_panic_binding
""".splitlines()
    )
)

# A2～A5 的固定 header C fixture 與具名 Rust 測試已覆蓋這十六種 API。
P16_3_A2_IMPLEMENTED = {
    ("function", "lua_atpanic"), ("function", "lua_callk"),
    ("function", "lua_pcallk"), ("function", "lua_error"),
    ("macro", "lua_call"), ("macro", "lua_pcall"),
}
P16_3_A3_IMPLEMENTED = {
    ("function", "luaL_argerror"), ("function", "luaL_typeerror"),
    ("function", "luaL_error"), ("function", "luaL_traceback"),
    ("macro", "luaL_argcheck"), ("macro", "luaL_argexpected"),
}
P16_3_A4A_IMPLEMENTED = {("function", "luaL_callmeta")}
P16_3_A5_IMPLEMENTED = {
    ("function", "lua_yieldk"), ("function", "lua_resume"),
    ("macro", "lua_yield"),
}
P16_3_IMPLEMENTED = (
    P16_3_A2_IMPLEMENTED | P16_3_A3_IMPLEMENTED
    | P16_3_A4A_IMPLEMENTED | P16_3_A5_IMPLEMENTED
)

# P16-2A1 只結案不依賴後續 registry/callback/錯誤物件的完整固定 header 效果。
# 其餘即使已有正常路徑程式碼，也維持 NOT_IMPLEMENTED 至錯誤及邊界語意驗收。
P16_2A1_IMPLEMENTED = {
    ("function", "lua_absindex"): "stack_lifecycle_indices_settop_rotate_copy_and_pseudo_boundaries",
    ("function", "lua_gettop"): "stack_lifecycle_indices_settop_rotate_copy_and_pseudo_boundaries",
    ("function", "lua_checkstack"): "stack_lifecycle_checkstack_limit_failure_and_refund",
    ("function", "lua_typename"): "stack_lifecycle_scalar_types_and_numeric_boundaries",
    ("macro", "lua_getextraspace"): "stack_lifecycle_state_layout_extraspace_and_move",
    ("opaque_type", "lua_State"): "stack_lifecycle_state_layout_extraspace_and_move",
}

# P16-2A2 的 byte string／數值字串入口；巨集的固定 header 展開式直接落到已驗收 primitive。
P16_2A2_IMPLEMENTED = {
    ("function", "lua_pushlstring"): "string_stack_push_empty_embedded_null_and_nil_contract",
    ("function", "lua_pushstring"): "string_stack_push_empty_embedded_null_and_nil_contract",
    ("function", "lua_tolstring"): "string_stack_tolstring_number_replaces_slot_and_numbertocstring_does_not",
    ("function", "lua_stringtonumber"): "string_stack_numeric_string_coercion_and_stringtonumber_boundaries",
    ("function", "lua_isnumber"): "string_stack_numeric_string_coercion_and_stringtonumber_boundaries",
    ("function", "lua_isstring"): "string_stack_numeric_string_coercion_and_stringtonumber_boundaries",
    ("function", "lua_tonumberx"): "string_stack_numeric_string_coercion_and_stringtonumber_boundaries",
    ("function", "lua_tointegerx"): "string_stack_numeric_string_coercion_and_stringtonumber_boundaries",
    ("macro", "lua_tostring"): "string_stack_tolstring_number_replaces_slot_and_numbertocstring_does_not",
    ("macro", "lua_tonumber"): "string_stack_numeric_string_coercion_and_stringtonumber_boundaries",
    ("macro", "lua_tointeger"): "string_stack_numeric_string_coercion_and_stringtonumber_boundaries",
    ("macro", "lua_pushliteral"): "string_stack_push_empty_embedded_null_and_nil_contract",
}
P16_2A2_LUA55_ONLY = {
    ("function", "lua_numbertocstring"): "string_stack_tolstring_number_replaces_slot_and_numbertocstring_does_not",
}

# P16-2A3 僅結案真實 table 的 raw integer 入口；lightuserdata substrate 不額外結案。
P16_2A3_IMPLEMENTED = {
    ("function", "lua_createtable"): "table_stack_create_publication_failures_active_gc_are_atomic",
    ("function", "lua_rawgeti"): "table_stack_raw_integer_boundaries_relative_indices_and_stack_effect",
    ("function", "lua_rawseti"): "table_stack_rawset_failure_matrix_and_generational_barrier",
    ("macro", "lua_newtable"): "table_stack_create_zero_nonzero_hints_and_invalid_inputs",
}

# P16-2A4 原驗收以真正的 C stack table/index 為基線；A5 擴充 registry pseudo-index。
P16_2A4_IMPLEMENTED = {
    ("function", "lua_rawget"): "raw_table_get_string_key_and_returned_root_failures_are_atomic",
    ("function", "lua_rawset"): "raw_table_set_string_key_resize_and_barrier_failures_are_atomic",
    ("function", "lua_rawgetp"): "raw_table_pointer_keys_include_null_and_share_generic_address_class",
    ("function", "lua_rawsetp"): "raw_table_pointer_set_and_get_failure_preserve_slots_and_table",
    ("function", "lua_rawequal"): "raw_table_rawequal_full_scalar_string_pointer_and_identity_matrix",
}

# P16-2A5 只結案固定 header 展開到 rawgeti(registry, 2) 的 global table 巨集。
P16_2A5_IMPLEMENTED = {
    ("macro", "lua_pushglobaltable"): "registry_stack_a5_matrix",
}
P16_2A5_REGISTRY_EVIDENCE = (
    "crates/rivetlua-capi/tests/registry_stack.rs:registry_stack_a5_matrix:lua55+lua54:PASS"
)

# P16-2A6 結案 raw length 與固定 header 的直接轉送別名；A28 補 full userdata 證據。
P16_2A6_IMPLEMENTED = {
    ("function", "lua_rawlen"): "raw_len_a6_matrix",
    ("macro", "lua_strlen"): "raw_len_a6_matrix",
    ("macro", "lua_objlen"): "raw_len_a6_matrix",
}

# P16-2A7 只結案直接以 lua_type／lua_typename 展開的固定 type predicate 巨集。
P16_2A7_IMPLEMENTED = {
    ("macro", "lua_isfunction"): "type_predicates_a7_matrix",
    ("macro", "lua_istable"): "type_predicates_a7_matrix",
    ("macro", "lua_islightuserdata"): "type_predicates_a7_matrix",
    ("macro", "lua_isnil"): "type_predicates_a7_matrix",
    ("macro", "lua_isboolean"): "type_predicates_a7_matrix",
    ("macro", "lua_isthread"): "type_predicates_a7_matrix",
    ("macro", "lua_isnone"): "type_predicates_a7_matrix",
    ("macro", "lua_isnoneornil"): "type_predicates_a7_matrix",
    ("macro", "luaL_typename"): "type_predicates_a7_matrix",
}

# P16-2A8 scalar introspection；A28 補 full userdata 實物證據。
P16_2A8_IMPLEMENTED = {
    ("function", "lua_version"): "scalar_introspection_a8_matrix",
    ("function", "lua_isuserdata"): "scalar_introspection_a8_matrix",
}

P16_2A9_IMPLEMENTED = {
    ("function", "lua_next"): "next_stack_a9_matrix",
}

# A10 僅結案無 callback／upvalue 依賴的純 stack mutation 與 scalar push。
P16_2A10_IMPLEMENTED = {
    ("function", "lua_settop"): "primitive_stack_a10_matrix",
    ("function", "lua_rotate"): "primitive_stack_a10_matrix",
    ("function", "lua_xmove"): "primitive_stack_a10_matrix",
    ("function", "lua_pushnil"): "primitive_stack_a10_matrix",
    ("function", "lua_pushboolean"): "primitive_stack_a10_matrix",
    ("function", "lua_pushinteger"): "primitive_stack_a10_matrix",
    ("function", "lua_pushnumber"): "primitive_stack_a10_matrix",
    ("function", "lua_pushlightuserdata"): "primitive_stack_a10_matrix",
    ("macro", "lua_pop"): "primitive_stack_a10_matrix",
    ("macro", "lua_insert"): "primitive_stack_a10_matrix",
    ("macro", "lua_remove"): "primitive_stack_a10_matrix",
    ("macro", "luaL_pushfail"): "primitive_stack_a10_matrix",
}
P16_2A10_LUA54_ONLY = {
    ("macro", "lua_pushunsigned"): "primitive_stack_a10_matrix",
}

# A11 僅結案純 scalar 讀取；upvalue pseudo-index 仍等待 callback context。
P16_2A11_IMPLEMENTED = {
    ("function", "lua_type"): "scalar_read_a11_matrix",
    ("function", "lua_isinteger"): "scalar_read_a11_matrix",
    ("function", "lua_toboolean"): "scalar_read_a11_matrix",
}
P16_2A11_LUA54_ONLY = {
    ("macro", "lua_tounsignedx"): "scalar_read_a11_matrix",
    ("macro", "lua_tounsigned"): "scalar_read_a11_matrix",
}

# A12 結案 stack／registry source 與 registry destination；upvalue context 待後片。
P16_2A12_IMPLEMENTED = {
    ("function", "lua_pushvalue"): "value_copy_a12_matrix",
    ("function", "lua_copy"): "value_copy_a12_matrix",
    ("macro", "lua_replace"): "value_copy_a12_matrix",
}

# A13 只結案兩版 auxiliary reference 函式；無效 handle 依 P16 安全限制拒絕。
P16_2A13_IMPLEMENTED = {
    ("function", "luaL_ref"): "refs_a13_matrix",
    ("function", "luaL_unref"): "refs_a13_matrix",
}

P16_2A14_IMPLEMENTED = {
    ("function", "luaL_makeseed"): "scalar_introspection_a8_matrix",
}

P16_2A15_IMPLEMENTED = {
    ("function", "luaL_checkstack"): "aux_stack_a15_matrix",
}

P16_2A16_IMPLEMENTED = {
    ("function", "luaL_checknumber"): "aux_numeric_a16_matrix",
    ("function", "luaL_optnumber"): "aux_numeric_a16_matrix",
    ("function", "luaL_checkinteger"): "aux_numeric_a16_matrix",
    ("function", "luaL_optinteger"): "aux_numeric_a16_matrix",
    ("macro", "luaL_opt"): "aux_numeric_a16_matrix",
    ("macro", "luaL_checkunsigned"): "aux_numeric_a16_matrix",
    ("macro", "luaL_optunsigned"): "aux_numeric_a16_matrix",
    ("macro", "luaL_checkint"): "aux_numeric_a16_matrix",
    ("macro", "luaL_optint"): "aux_numeric_a16_matrix",
    ("macro", "luaL_checklong"): "aux_numeric_a16_matrix",
    ("macro", "luaL_optlong"): "aux_numeric_a16_matrix",
}

P16_2A18_IMPLEMENTED = {
    ("function", "luaL_checklstring"): "aux_string_a18_matrix",
    ("function", "luaL_optlstring"): "aux_string_a18_matrix",
    ("macro", "luaL_checkstring"): "aux_string_a18_matrix",
    ("macro", "luaL_optstring"): "aux_string_a18_matrix",
}

P16_2A19_IMPLEMENTED = {
    ("function", "lua_getmetatable"): "metatable_stack_a19_matrix",
    ("function", "lua_setmetatable"): "metatable_stack_a19_matrix",
}

P16_2A20_IMPLEMENTED = {
    ("function", "luaL_getmetafield"): "metafield_stack_a20_matrix",
}

P16_2A21_IMPLEMENTED = {
    ("function", "lua_getglobal"): "table_getters_a21_matrix",
    ("function", "lua_gettable"): "table_getters_a21_matrix",
    ("function", "lua_getfield"): "table_getters_a21_matrix",
    ("function", "lua_geti"): "table_getters_a21_matrix",
    ("macro", "luaL_getmetatable"): "table_getters_a21_matrix",
}

P16_2A22_IMPLEMENTED = {
    ("function", "lua_settable"): "table_setters_a22_matrix",
    ("function", "lua_seti"): "table_setters_a22_matrix",
}

P16_2A23_IMPLEMENTED = {
    ("function", "lua_setglobal"): "named_table_setters_a23_matrix",
    ("function", "lua_setfield"): "named_table_setters_a23_matrix",
}

P16_2A24_IMPLEMENTED = {
    ("function", "luaL_getsubtable"): "aux_table_a24_matrix",
}

P16_2A25_IMPLEMENTED = {
    ("function", "luaL_newmetatable"): "aux_metatable_a25_matrix",
}

P16_2A26_IMPLEMENTED = {
    ("function", "luaL_setmetatable"): "aux_metatable_a26_set_matrix",
}

P16_2A28_IMPLEMENTED = {
    ("function", "lua_newuserdatauv"): "full_userdata_a28_matrix",
    ("function", "lua_touserdata"): "full_userdata_a28_matrix",
}

P16_2A29_IMPLEMENTED = {
    ("function", "lua_getiuservalue"): "userdata_values_a29_matrix",
    ("function", "lua_setiuservalue"): "userdata_values_a29_matrix",
    ("macro", "lua_getuservalue"): "userdata_values_a29_matrix",
    ("macro", "lua_setuservalue"): "userdata_values_a29_matrix",
}

P16_2A31_IMPLEMENTED = {
    ("function", "luaL_testudata"): "aux_userdata_a31_matrix",
}

# A32 僅以 A28 已驗收的 userdata 實物矩陣結案固定 header 建構巨集。
P16_2A32_IMPLEMENTED = {
    ("macro", "lua_newuserdata"): "full_userdata_a28_matrix",
}

P16_2A33_IMPLEMENTED = {
    ("function", "luaL_newstate"): "c_owned_default_state_a33_matrix",
}

P16_2A34_IMPLEMENTED = {
    ("macro", "luaL_bufflen"): "buffer_macros_a34_runtime",
    ("macro", "luaL_buffaddr"): "buffer_macros_a34_runtime",
    ("macro", "luaL_addsize"): "buffer_macros_a34_runtime",
    ("macro", "luaL_buffsub"): "buffer_macros_a34_runtime",
}

P16_2A35_IMPLEMENTED = {
    ("macro", "lua_upvalueindex"): "upvalue_index_a35_runtime",
    ("macro", "luaL_newlibtable"): P16_2A3_IMPLEMENTED[("function", "lua_createtable")],
}

P16_2A36_IMPLEMENTED = {
    ("function", "lua_status"): "main_state_status_a36_matrix",
    ("function", "lua_isyieldable"): "main_state_status_a36_matrix",
}

P16_2A37_IMPLEMENTED = {
    ("function", "lua_topointer"): "pointer_identity_a37_matrix",
}

P16_2A38_IMPLEMENTED = {
    ("function", "luaL_buffinit"): "buffer_init_a38_matrix",
}

P16_2A39_IMPLEMENTED = {
    ("function", "lua_setcstacklimit"): "cstack_limit_a39_matrix",
}

P16_2A40_IMPLEMENTED = {
    ("function", "luaL_fileresult"): "file_result_a40_matrix",
}

P16_2A41_IMPLEMENTED = {
    ("function", "luaL_execresult"): "exec_result_a41_matrix",
}

P16_2A42_IMPLEMENTED = {
    ("function", "luaL_len"): "aux_len_a42_matrix",
}

P16_2A42_EVIDENCE = (
    "RETURN_CONVENTION=LUA_LEN_THEN_EXACT_LUA_TOINTEGERX"
    ";STACK_EFFECT=NET_STACK_UNCHANGED"
    ";TABLE_USERDATA_LUA_C_CCLOSURE_LEN_EVENT"
    ";INTEGRAL_FLOAT_NUMERIC_STRING_ACCEPTED"
    ";NONINTEGER_AND_TYPE_ERROR_C_ONLY_TRAMPOLINE"
    ";C_CLOSURE_UPVALUE_PSEUDOINDEX"
    ";crates/rivetlua-capi/tests/value_operations.rs:"
    "raw_and_c_metamethod_compare_and_len_b5:lua55+lua54:PASS"
    ";tests/p16/value_operations_b5.c:C_LINK_RUN:lua55+lua54:PASS"
)

P16_2A43_IMPLEMENTED = {
    ("function", "lua_pushcclosure"): "c_closure_a43_255_boundary_table_key_and_sibling",
    ("function", "lua_iscfunction"): "c_closure_a43_light_identity_and_round_trip",
    ("function", "lua_tocfunction"): "c_closure_a43_light_identity_and_round_trip",
    ("function", "lua_getupvalue"): "c_closure_a43_capture_get_setup_and_id",
    ("function", "lua_setupvalue"): "c_closure_a43_capture_get_setup_and_id",
    ("function", "lua_upvalueid"): "c_closure_a43_capture_get_setup_and_id",
    ("function", "lua_upvaluejoin"): "c_closure_a43_capture_get_setup_and_id",
    ("macro", "lua_pushcfunction"): "c_closure_a43_light_identity_and_round_trip",
}

P16_2A44_IMPLEMENTED = {
    ("function", "luaL_setfuncs"): "aux_setfuncs_a44_matrix",
}

P16_2A45_IMPLEMENTED = {
    ("function", "luaL_gsub"): "aux_gsub_a45_matrix",
}

P16_2A46_IMPLEMENTED = {
    ("function", "luaL_alloc"): "aux_alloc_a46_matrix",
}

P16_2A47_IMPLEMENTED = {
    ("function", "lua_compare"): "compare_a47_raw_subset_matrix",
    ("macro", "lua_equal"): "compare_a47_raw_subset_matrix",
    ("macro", "lua_lessthan"): "compare_a47_raw_subset_matrix",
}

P16_2A47_EVIDENCE = (
    "COMPARE_EQ_NIL_BOOLEAN_INT_FLOAT_PRECISION_NAN_SIGNED_ZERO"
    ";BYTE_STRING_EMBEDDED_NUL_C_LOCALE_ORDER_LIGHTUSERDATA_CFUNCTION_OBJECT_IDENTITY_REGISTRY"
    ";TABLE_USERDATA_EQ_AND_ORDER_LUA_C_METAMETHODS"
    ";LUA54_REVERSE_LT_LE_FALLBACK;LUA55_LE_ERROR_WITHOUT_EVENT"
    ";INVALID_INDEX_ZERO;VALID_TYPE_ERROR_C_ONLY_TRAMPOLINE"
    ";C_CLOSURE_UPVALUE_PSEUDOINDEX"
    ";ACTIVE_GC_INCREMENTAL_AND_GENERATIONAL"
    ";crates/rivetlua-capi/tests/value_operations.rs:raw_and_c_metamethod_compare_and_len_b5:lua55+lua54:PASS"
    ";crates/rivetlua-runtime/tests/capi_value_operations.rs:lua54_less_equal_uses_reverse_less_when_le_absent_b5:PASS"
    ";tests/p16/value_operations_b5.c:C_LINK_RUN:lua55+lua54:PASS"
)

P16_2A47_MACRO_DEFINITIONS = {
    "lua_equal": "#define lua_equal(L,idx1,idx2) lua_compare(L,(idx1),(idx2),LUA_OPEQ)",
    "lua_lessthan": "#define lua_lessthan(L,idx1,idx2) lua_compare(L,(idx1),(idx2),LUA_OPLT)",
}

P16_2A48_IMPLEMENTED = {
    ("function", "luaL_checkversion_"): "aux_checkversion_a48_normal_priority_exact_bytes_and_nested_top",
    ("macro", "luaL_checkversion"): "aux_checkversion_a48_normal_priority_exact_bytes_and_nested_top",
}

P16_2A48_EVIDENCE = (
    "OFFICIAL_NUMERIC_TYPES_PRIORITY_AND_EXACT_BYTES"
    ";VERSION_MISMATCH_LUA_PERCENT_F_FORMAT"
    ";C_ONLY_CHECKPOINT_JUMP_AFTER_RUST_RETURN"
    ";NESTED_TOP_AND_NO_CHECKPOINT_FATAL_ABORT"
    ";PENDING_CONSUME_SINGLE_SLOT;ROOT_LEDGER_GC_ATOMICITY"
    ";PREALLOCATED_EMERGENCY_ALLOCATION_ERROR"
    ";tests/p16/checkversion_a48.c:C_LINK_CALL:NOT_RUN"
    ";A48_RUNTIME_VERIFICATION:NOT_RUN"
)

P16_2A49_IMPLEMENTED = {
    ("function", "luaL_prepbuffsize"): "aux_buffer_prepbuffsize_and_pushresultsize_commit_direct_bytes",
    ("function", "luaL_addlstring"): "aux_buffer_small_inline_binary_and_empty_appends",
    ("function", "luaL_addstring"): "aux_buffer_small_inline_binary_and_empty_appends",
    ("function", "luaL_addvalue"): "aux_buffer_addvalue_pops_only_top_value_and_appends_its_bytes",
    ("function", "luaL_pushresult"): "aux_buffer_repeated_growth_preserves_content_and_stack_anchor",
    ("function", "luaL_pushresultsize"): "aux_buffer_prepbuffsize_and_pushresultsize_commit_direct_bytes",
    ("function", "luaL_buffinitsize"): "aux_buffer_buffinitsize_commits_only_directly_written_bytes",
    ("function", "luaL_addgsub"): "aux_buffer_addgsub_zero_and_multiple_nonempty_matches",
    ("macro", "luaL_addchar"): "C_LINK_RUN",
    ("macro", "luaL_prepbuffer"): "C_LINK_RUN",
}

P16_2A49_EVIDENCE = (
    "OFFICIAL_BUFFER_PLACEHOLDER_BOX_RESULT_STACK_LIFETIME"
    ";STATE_ALLOCATOR_ROOT_LEDGER_GC"
    ";BINARY_NUL_ALIAS_OVERLAP_GROWTH"
    ";C_ONLY_ERROR_JUMP_AFTER_RUST_RETURN"
    ";BUFFER_OVERFLOW_INLINE_AND_BOX_ERROR_CLEANUP"
    ";BUFFER_GROW_ALLOCATION_FAILPOINT_USERDATA_BYTES"
    ";crates/rivetlua-capi/tests/buffer_init.rs:buffer_overflow_a49_cleans_anchor_roots_and_ledger:lua55+lua54:PASS"
    ";crates/rivetlua-capi/tests/buffer_init.rs:buffer_grow_a49_allocation_failure_cleans_anchor_and_retries:lua55+lua54:PASS"
    ";tests/p16/aux_buffer_a49.c:C_LINK_RUN:PASS"
)

# P16-2 B0 是固定 header 巨集片，與 allocator A50 編號無關。
P16_2B0_IMPLEMENTED = {
    ("macro", "lua_register"): "header_registration_b0_rust_primitive_contract",
    ("macro", "luaL_newlib"): "header_registration_b0_rust_primitive_contract",
}

P16_2B0_MACRO_DEFINITIONS = {
    "lua_register": "#define lua_register(L,n,f) (lua_pushcfunction(L, (f)), lua_setglobal(L, (n)))",
    "luaL_newlib": "#define luaL_newlib(L,l) (luaL_checkversion(L), luaL_newlibtable(L,l), luaL_setfuncs(L,l,0))",
}

P16_2B0_MACRO_SEQUENCES = {
    "lua_register": "COMMA_SEQUENCE_PUSHCLOSURE_THEN_SETGLOBAL",
    "luaL_newlib": "COMMA_SEQUENCE_CHECKVERSION_THEN_NEWLIBTABLE_THEN_SETFUNCS",
}

P16_2A50_IMPLEMENTED = {
    ("function", "lua_newstate"): "custom_allocator_tracks_public_domains_and_close_releases_every_token_once",
    ("function", "lua_getallocf"): "custom_allocator_tracks_public_domains_and_close_releases_every_token_once",
    ("function", "lua_setallocf"): "setallocf_routes_new_tokens_and_old_token_frees_through_current_binding",
}

P16_2A50_EVIDENCE = (
    "tests/p16/allocator_state_a50.c:C_LINK_RUN:lua55+lua54:PASS"
    ";crates/rivetlua-capi/tests/allocator_state.rs:"
    "null_allocator_fails_without_callback_and_default_state_works:lua55+lua54:PASS"
    ";crates/rivetlua-capi/tests/allocator_state.rs:"
    "rejected_admission_does_not_fallback_and_state_can_retry:lua55+lua54:PASS"
    ";STATE_AND_VM_ADMISSION_BEFORE_RUST_BACKING"
    ";NONZERO_TOKEN_MOVE_ONLY_AND_EXACTLY_ONCE_REFUND"
    ";SETALLOCF_CURRENT_BINDING_FOR_OLD_TOKEN_REFUND"
    ";C_CALLBACK_REENTRY_FAIL_CLOSED"
    ";C_CHECKPOINT_ALLOCATION_ERROR_CLASS_5_AND_RETRY"
    ";CLOSE_STATE_TOKEN_LAST"
    ";CLOSE_FINALIZER_CALLBACK:B11_PASS"
)

P16_2B2_IMPLEMENTED = {
    ("function", "luaL_checktype"): "aux_strict_b2_error_bytes_pending_and_recovery",
    ("function", "luaL_checkany"): "aux_strict_b2_error_bytes_pending_and_recovery",
    ("function", "luaL_checkudata"): "aux_strict_b2_userdata_ordinal_gc_and_named_failure",
    ("function", "luaL_checkoption"): "aux_strict_b2_success_and_conversion",
    ("function", "lua_pushvfstring"): "format_b2_varargs_stack_bytes_and_long_result",
    ("function", "lua_pushfstring"): "format_b2_varargs_stack_bytes_and_long_result",
}

P16_2B2_ROW_IDS = {
    f"{profile}:{header}:function:{name}:{line}"
    for profile in PROFILES
    for header, name, line in (
        ("lauxlib.h", "luaL_checktype", 67),
        ("lauxlib.h", "luaL_checkany", 68),
        ("lauxlib.h", "luaL_checkudata", 73),
        ("lauxlib.h", "luaL_checkoption", 78),
        ("lua.h", "lua_pushvfstring", 250 if profile == "lua55" else 249),
        ("lua.h", "lua_pushfstring", 252 if profile == "lua55" else 251),
    )
}

P16_2B2_EVIDENCE = (
    "tests/p16/strict_format_b2.c:C_LINK_RUN:lua55+lua54:PASS"
    ";OFFICIAL_5_4_9_AND_5_5_1_FORMAT_AND_STRICT_AUX"
    ";C_VARIADIC_AND_TRUE_VA_LIST"
    ";C_ONLY_CHECKPOINT_JUMP_AFTER_RUST_RETURN"
    ";PENDING_EXACT_BYTES_AND_SINGLE_SLOT"
    ";ALLOCATOR_REJECTION_FAILPOINT_ORDINAL_ROOT_LEDGER_GC_RETRY"
    ";NO_CHECKPOINT_SIGABRT_SUBPROCESS"
    ";LUA55_VFSTRING_MEMORY_NULL_TOP_ERROR"
    ";PUSHFSTRING_RAISES_AFTER_VA_END"
    ";LUA54_DIRECT_RAISE"
    ";CHECKPOINT_ADMISSION_REJECTION:FAIL_STOP_NO_RESERVED_ERROR_SLOT"
    ";P16_3_PUBLIC_DEBUG_CALLBACK_FRAMES:A3_LOCAL_PASS"
)

P16_2B3_IMPLEMENTED = {
    ("function", "lua_newthread"): "main_and_child_thread_identity_b3",
    ("function", "lua_tothread"): "main_and_child_thread_identity_b3",
    ("function", "lua_pushthread"): "main_and_child_thread_identity_b3",
}

P16_2B3_ROW_IDS = {
    f"{profile}:lua.h:function:{name}:{line}"
    for profile in PROFILES
    for name, line in (
        ("lua_newthread", 165),
        ("lua_tothread", 207 if profile == "lua55" else 208),
        ("lua_pushthread", 256 if profile == "lua55" else 255),
    )
}

P16_2B3_MAIN_CHILD_EVIDENCE = (
    "crates/rivetlua-capi/tests/coroutine_identity.rs:"
    "main_and_child_thread_identity_b3:lua55+lua54:PASS"
)

P16_2B3_EVIDENCE = (
    "tests/p16/coroutine_identity_b3.c:C_LINK_RUN:lua55+lua54:PASS"
    ";crates/rivetlua-capi/tests/coroutine_identity.rs:"
    "grandchild_extraspace_comes_from_main_b3:lua55+lua54:PASS"
    ";crates/rivetlua-capi/tests/coroutine_identity.rs:"
    "child_attachment_follows_reachability_and_refunds_host_charge_b3:lua55+lua54:PASS"
    ";crates/rivetlua-capi/tests/coroutine_identity.rs:"
    "child_creation_failpoints_refund_and_retry_b3:lua55+lua54:PASS"
    ";crates/rivetlua-capi/tests/coroutine_identity.rs:"
    "main_owner_drop_and_busy_foreign_calls_fail_closed_b3:lua55+lua54:PASS"
    ";crates/rivetlua-runtime/src/heap.rs:"
    "transaction_rolls_back_and_attachment_drops_with_coroutine:PASS"
    ";MAIN_COROUTINE_REGISTRY_ROOT_AND_STABLE_CONTROL_POINTER"
    ";WEAK_GROUP_NO_CYCLE_AND_ATTACHMENT_GC_RECLAIM"
    ";CHILD_STACK_HOSTHANDLE_ROOT_ATOMIC_PUBLICATION"
    ";C_ONLY_LONGJMP_AFTER_RUST_RETURN_CLASS_5_CONSUME_RETRY"
    ";LUA_RESET_CLOSE_RESUME_YIELD:A5_LOCAL_PASS"
)

P16_2B5_IMPLEMENTED = {
    ("function", "lua_arith"): "fixed_header_operation_symbols_preserve_stack_effects_b5",
    ("function", "lua_concat"): "fixed_header_operation_symbols_preserve_stack_effects_b5",
    ("function", "lua_len"): "raw_and_c_metamethod_compare_and_len_b5",
    ("function", "luaL_tolstring"): "tolstring_vendor_fallback_and_c_metamethod_b5",
}

P16_2B6_IMPLEMENTED = {
    ("function", "lua_setwarnf"): "warning_binding_is_global_and_preserves_pointer_and_integer_b6",
    ("function", "lua_warning"): "warning_callback_can_reenter_replace_nest_and_collect_b6",
}

P16_2B7_IMPLEMENTED = {
    ("function", "lua_toclose"): "nil_and_false_do_not_claim_stack_positions_b7",
    ("function", "lua_closeslot"): "false_nil_skip_mark_and_closeslot_then_settop_are_lifo_b7",
}

P16_2B8_IMPLEMENTED = {
    ("function", "lua_gc"): "gc_command_numbering_and_varargs_b8",
}

P16_2B9_IMPLEMENTED = {
    ("function", "lua_pushexternalstring"): "external_pointer_identity_embedded_nul_and_gc_b9",
}

P16_2B9_ROW_ID = "lua55:lua.h:function:lua_pushexternalstring:247"

P16_2B10_IMPLEMENTED = {
    ("function", "lua_getstack"): "profile_layout_and_callback_frame_basics_b10b1",
    ("function", "lua_getinfo"): "getinfo_function_only_selectors_and_failure_are_atomic_b10b1",
    ("function", "lua_getlocal"): "suspended_coroutine_local_vararg_write_and_revision_b10b1",
    ("function", "lua_setlocal"): "suspended_coroutine_local_vararg_write_and_revision_b10b1",
    ("function", "lua_sethook"): "hook_main_and_coroutine_bindings_are_independent_b10b2",
    ("function", "lua_gethook"): "hook_getters_roundtrip_red_b10b2",
    ("function", "lua_gethookmask"): "hook_getters_roundtrip_red_b10b2",
    ("function", "lua_gethookcount"): "hook_getters_roundtrip_red_b10b2",
    ("function", "luaL_where"): "getinfo_function_only_selectors_and_failure_are_atomic_b10b1",
}

P16_2B10_ROW_IDS = {
    f"{profile}:{header}:function:{name}:{line}"
    for profile in PROFILES
    for header, name, line in (
        ("lauxlib.h", "luaL_where", 75),
        ("lua.h", "lua_getstack", 470 if profile == "lua55" else 457),
        ("lua.h", "lua_getinfo", 471 if profile == "lua55" else 458),
        ("lua.h", "lua_getlocal", 472 if profile == "lua55" else 459),
        ("lua.h", "lua_setlocal", 473 if profile == "lua55" else 460),
        ("lua.h", "lua_sethook", 481 if profile == "lua55" else 468),
        ("lua.h", "lua_gethook", 482 if profile == "lua55" else 469),
        ("lua.h", "lua_gethookmask", 483 if profile == "lua55" else 470),
        ("lua.h", "lua_gethookcount", 484 if profile == "lua55" else 471),
    )
}

P16_2B11_ROW_IDS = {
    "lua54:lua.h:function:lua_close:164",
    "lua54:lua.h:function:lua_closethread:166",
    "lua54:lua.h:function:lua_resetthread:167",
    "lua55:lua.h:function:lua_close:164",
    "lua55:lua.h:function:lua_closethread:166",
    "lua55:lua.h:macro:lua_resetthread:440",
}

def b11_evidence(profile: str, name: str) -> str:
    common = (
        f"tests/p16/surface_{profile}.c:COMPILE_ONLY"
        ";tests/p16/state_close_reset_b11.c:C_LINK_RUN:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/state_close_reset.rs:thread_reset_closes_overlay_and_rejects_foreign_from_b11:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/state_close_reset.rs:overlay_closes_before_runtime_context_and_runtime_error_replaces_b11:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/state_close_reset.rs:reset_prepare_allocation_failure_preserves_overlay_close_mark_b11:lua55+lua54:PASS"
        ";crates/rivetlua-runtime/tests/state_close_reset.rs:reset_suspended_thread_closes_lifo_and_returns_idle_b11:PASS"
        ";crates/rivetlua-runtime/tests/state_close_reset.rs:prepared_reset_parked_arena_allocation_rolls_back_and_retries_b11:PASS"
        ";C_ONLY_CHECKPOINT_LONGJMP_AND_NO_RUST_BORROW_ACROSS_CALLBACK"
    )
    if name == "lua_close":
        return (
            common
            + ";crates/rivetlua-capi/tests/state_close_reset.rs:child_pointer_close_runs_main_pending_close_b11:lua55+lua54:PASS"
            ";crates/rivetlua-capi/tests/allocator_state.rs:custom_allocator_tracks_public_domains_and_close_releases_every_token_once:lua55+lua54:PASS"
            ";crates/rivetlua-runtime/tests/state_close_reset.rs:shutdown_reverse_order_error_continues_and_requeues_new_work_b11:PASS"
            ";CHILD_TO_MAIN_AND_OVERLAY_BEFORE_FINALIZERS;ROOTED_REGISTERED_REVERSE_ORDER_ERROR_CONTINUE"
            ";FINALIZER_NEW_WORK_REQUEUE_AND_ALLOCATOR_STATE_TOKEN_LAST"
            ";LUA55_EXTERNAL_STRING_FREE_EXACTLY_ONCE"
        )
    if name == "lua_resetthread" and profile == "lua55":
        return common + ";include/rivetlua/lua55/lua.h:lua_resetthread:DIRECT_EXPANSION_TO_CLOSETHREAD_NULL;HEADER_MACRO_RUNTIME"
    return (
        common
        + ";crates/rivetlua-capi/tests/state_close_reset.rs:reset_allocation_failure_keeps_idle_state_retryable_b11:lua55+lua54:PASS"
        ";crates/rivetlua-runtime/tests/state_close_reset.rs:reset_close_error_replaces_success_and_clears_old_execution_b11:PASS"
        + (
            ";crates/rivetlua-capi/tests/state_close_reset.rs:self_close_from_running_c_callback_never_returns_b11:lua55:PASS"
            ";LUA55_SELF_CLOSE_NONRETURNING_RESUME_STATUS"
            if profile == "lua55" else ";LUA54_FUNCTION_RESET_SEMANTICS"
        )
        + ";OVERLAY_LIFO_BEFORE_RUNTIME_CLOSE;SUCCESS_EMPTY_ERROR_SINGLE_SLOT;ROLLBACK_RETRY"
    )

def b10_evidence(profile: str, name: str) -> str:
    return (
        f"tests/p16/surface_{profile}.c:COMPILE_ONLY"
        f";crates/rivetlua-capi/tests/debug_api.rs:{P16_2B10_IMPLEMENTED[('function', name)]}:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/debug_api.rs:hook_callback_frame_and_token_refusal_retry_b10b2:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/debug_api.rs:native_debug_tail_fixture_selector_has_all_hook_events_b10c:lua55+lua54:PASS"
        ";crates/rivetlua-runtime/tests/debug_adapter.rs:debug_adapter_hook_frame_and_snapshot_allocation_rollback:PASS"
        ";tests/p16/debug_api_b10.c:C_LINK_RUN:lua55+lua54:PASS"
        ";OPAQUE_ICI_TOKEN_AND_NATIVE_DEBUG_METADATA;MAIN_COROUTINE_HOOK_ISOLATION"
        ";REAL_CALL_RETURN_LINE_COUNT_TAIL_AND_LOCAL_WRITE;HOOK_REPLACE_DISABLE"
        ";C_ONLY_LONGJMP_PENDING_CONSUME_RETRY;OVERLAY_ALLOCATION_ROLLBACK"
    )

def b9_evidence() -> str:
    return (
        "tests/p16/surface_lua55.c:COMPILE_ONLY"
        ";crates/rivetlua-runtime/tests/external_string.rs:external_string_bytes_root_gc_and_vm_drop_b9:PASS"
        ";crates/rivetlua-runtime/tests/external_string.rs:external_string_unpublished_failures_drop_once_and_roll_back_b9:PASS"
        ";crates/rivetlua-runtime/tests/external_string.rs:external_long_key_shares_owner_and_is_content_equal_b9:PASS"
        ";crates/rivetlua-runtime/tests/external_string.rs:external_weak_mode_bytes_drive_gc_and_release_once_b9:PASS"
        ";crates/rivetlua-capi/tests/external_string.rs:external_pointer_identity_embedded_nul_and_gc_b9:lua55:PASS"
        ";crates/rivetlua-capi/tests/external_string.rs:external_table_roundtrip_and_fixed_buffer_b9:lua55:PASS"
        ";crates/rivetlua-capi/tests/external_string.rs:external_admission_failure_calls_owner_once_and_retries_b9:lua55:PASS"
        ";crates/rivetlua-capi/tests/external_string.rs:external_empty_string_releases_on_state_drop_b9:lua55:PASS"
        ";crates/rivetlua-capi/tests/external_string.rs:external_stack_publication_failure_rolls_back_b9:lua55:PASS"
        ";tests/p16/external_string_b9.c:C_LINK_RUN:lua55:PASS"
        ";ORIGINAL_POINTER_AND_ALLOCATOR_CAPTURE;EXACT_ONCE_GC_DROP_AND_ROLLBACK"
        ";EXTERNAL_CONTENT_UNCHARGED;SHARED_LONG_CANONICAL_KEY"
        ";C_ONLY_PROTECTED_ALLOCATION_RAISE_AFTER_OWNER_RELEASE"
    )

P16_2B8_ROW_IDS = {
    "lua54:lua.h:function:lua_gc:342",
    "lua55:lua.h:function:lua_gc:360",
}

def b8_evidence(profile: str) -> str:
    return (
        f"tests/p16/surface_{profile}.c:COMPILE_ONLY"
        ";crates/rivetlua-capi/tests/gc_controls.rs:gc_command_numbering_and_varargs_b8:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/gc_controls.rs:c_finalizer_drains_inside_outer_callback_b8:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/gc_controls.rs:gc_prepare_allocation_failure_retries_on_same_state_b8:lua55+lua54:PASS"
        ";crates/rivetlua-runtime/src/heap.rs:gc_param_step_tests::typed_gc_control_profile_defaults_b8:PASS"
        ";crates/rivetlua-runtime/src/heap.rs:gc_param_step_tests::typed_gc_control_minor_debt_keeps_last_major_base_b8:PASS"
        ";crates/rivetlua-runtime/src/heap.rs:gc_param_step_tests::typed_gc_control_lua54_minor_major_refreshes_cached_threshold_b8:PASS"
        ";crates/rivetlua-runtime/src/heap.rs:gc_param_step_tests::typed_gc_control_major_followup_ignores_host_charges_b8:PASS"
        ";crates/rivetlua-runtime/src/heap.rs:gc_param_step_tests::typed_gc_control_inc_to_gen_resets_followup_and_bases_b8:PASS"
        ";crates/rivetlua-runtime/src/heap.rs:gc_param_step_tests::typed_gc_control_zero_step_uses_profile_step_size_b8:PASS"
        ";crates/rivetlua-runtime/src/heap.rs:gc_param_step_tests::typed_gc_control_generational_parameters_change_cycle_selection:PASS"
        ";crates/rivetlua-runtime/src/heap.rs:gc_param_step_tests::typed_gc_control_incremental_parameters_change_threshold_and_work:PASS"
        ";crates/rivetlua-runtime/tests/gc_controls.rs:stopped_manual_work_and_inflight_mode_switch_b8:PASS"
        ";crates/rivetlua-runtime/tests/external_execution.rs:gc_control_error_finalizer_warns_and_continues_b8:PASS"
        ";tests/p16/gc_controls_b8.c:C_LINK_RUN:lua55+lua54:PASS"
        ";FIXED_PROFILE_VARARGS_AND_DEFAULTS;COMMITTED_LEDGER_COUNT"
        ";SIX_LUA55_PARAMETERS_AFFECT_GC_WORK;STOP_MANUAL_CYCLE_AND_MODE_SWITCH"
        ";PARKED_OUTER_FINALIZER_PROTECTED_ERROR_AND_RETRY;MARK_RESERVE_ROLLBACK"
    )

P16_2B7_ROW_IDS = {
    f"{profile}:lua.h:function:{name}:{line}"
    for profile in PROFILES
    for name, line in (
        ("lua_toclose", 381 if profile == "lua55" else 361),
        ("lua_closeslot", 382 if profile == "lua55" else 362),
    )
}

def b7_evidence(profile: str, name: str) -> str:
    return (
        f"tests/p16/surface_{profile}.c:COMPILE_ONLY"
        f";crates/rivetlua-capi/tests/to_close_slots.rs:{P16_2B7_IMPLEMENTED[('function', name)]}:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/to_close_slots.rs:arithmetic_callback_closes_mark_before_b5_resume_b7:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/to_close_slots.rs:mark_allocation_rejection_rolls_back_and_same_state_retries_b7:lua55+lua54:PASS"
        ";crates/rivetlua-runtime/tests/external_execution.rs:nested_callback_abort_preserves_outer_close_unwind_b7:PASS"
        ";tests/p16/to_close_slots_b7.c:C_LINK_RUN:lua55+lua54:PASS"
        ";POSITION_MARK_LIFO_AND_NIL_FALSE_SKIP;STRICT_MISSING_CLOSE_ATOMIC"
        ";SAME_PARKED_EXECUTION_NESTED_CLOSE_AND_ERROR_REPLACEMENT"
        ";CALLBACK_RETURN_AND_ERROR_CLOSE_AFTER_C_FRAME;INCREMENTAL_GENERATIONAL_GC_ROOTS"
        ";MARK_ALLOCATION_ORDINAL_ROLLBACK_RETRY;C_ONLY_LONGJMP_CONSUME_RETRY"
        ";THREAD_RESET_FINAL_STATE_CLOSE:B11_PASS"
    )

P16_2B6_ROW_IDS = {
    f"{profile}:lua.h:function:{name}:{line}"
    for profile in PROFILES
    for name, line in (
        ("lua_setwarnf", 323 if profile == "lua55" else 322),
        ("lua_warning", 324 if profile == "lua55" else 323),
    )
}

def b6_evidence(profile: str, name: str) -> str:
    test = P16_2B6_IMPLEMENTED[("function", name)]
    return (
        f"tests/p16/surface_{profile}.c:COMPILE_ONLY"
        f";crates/rivetlua-capi/tests/warning_callback.rs:{test}:lua55+lua54:PASS"
        ";crates/rivetlua-capi/tests/warning_callback.rs:warning_binding_outlives_main_owner_while_sibling_is_alive_b6:lua55+lua54:PASS"
        ";tests/p16/warning_callback_b6.c:C_LINK_RUN:lua55+lua54:PASS"
        ";GLOBAL_STATE_BINDING_SNAPSHOT;EXACT_UD_MSG_POINTER_TOCONT"
        ";CALLBACK_REENTRY_REPLACE_NESTED_GC;C_ONLY_LONGJMP_CONSUME_RETRY"
    )

P16_2B5_ROW_IDS = {
    f"{profile}:{header}:function:{name}:{line}"
    for profile in PROFILES
    for header, name, line in (
        ("lauxlib.h", "luaL_tolstring", 52),
        ("lua.h", "lua_arith", 230 if profile == "lua55" else 231),
        ("lua.h", "lua_concat", 371 if profile == "lua55" else 353),
        ("lua.h", "lua_len", 372 if profile == "lua55" else 354),
    )
}

P16_2B5_EVIDENCE = (
    "tests/p16/value_operations_b5.c:C_LINK_RUN:lua55+lua54:PASS"
    ";crates/rivetlua-runtime/tests/capi_value_operations.rs:"
    "typed_operation_uses_vm_execution_for_raw_and_external_results_b5:PASS"
    ";crates/rivetlua-capi/tests/value_operations.rs:"
    "callback_operation_lua_metamethod_c_callback_and_gc_share_execution_b5:lua55+lua54:PASS"
    ";crates/rivetlua-capi/tests/value_operations.rs:"
    "operation_named_and_ordinal_allocation_failures_restore_state_b5:lua55+lua54:PASS"
    ";SAME_PARKED_EXECUTION_PENDINGOP_FRAME_AND_ROOTS"
    ";C_ONLY_LONGJMP_AFTER_RUST_RETURN"
    ";INCREMENTAL_GENERATIONAL_GC_AND_RETRY"
)

def b5_evidence(profile: str, name: str) -> str:
    test = P16_2B5_IMPLEMENTED[("function", name)]
    return (
        f"tests/p16/surface_{profile}.c:COMPILE_ONLY"
        f";crates/rivetlua-capi/tests/value_operations.rs:{test}:lua55+lua54:PASS"
        f";{P16_2B5_EVIDENCE}"
    )

def b3_evidence(profile: str, name: str) -> str:
    rust = P16_2B3_MAIN_CHILD_EVIDENCE
    return (
        f"tests/p16/surface_{profile}.c:COMPILE_ONLY;{rust};{P16_2B3_EVIDENCE}"
        f";tests/p16/public_yield_resume_a5.c:C_LINK_RUN:{profile}:PASS"
    )

def b2_evidence(profile: str, name: str) -> str:
    rust = (
        "crates/rivetlua-capi/tests/aux_strict_format.rs:"
        f"{P16_2B2_IMPLEMENTED[('function', name)]}:lua55+lua54:PASS"
    )
    if name == "lua_pushvfstring":
        rust += ";DIRECT_VA_LIST:C_FIXTURE_ONLY"
    return (
        f"tests/p16/surface_{profile}.c:COMPILE_ONLY;{rust};{P16_2B2_EVIDENCE}"
        f";tests/p16/public_aux_error_a3.c:C_LINK_RUN:{profile}:PASS"
    )


def implemented_p16_2_rows(profile: str) -> dict[tuple[str, str], tuple[str, str]]:
    result = {key: ("stack_lifecycle.rs", test) for key, test in P16_2A1_IMPLEMENTED.items()}
    result.update({key: ("string_stack.rs", test) for key, test in P16_2A2_IMPLEMENTED.items()})
    result.update({key: ("table_stack.rs", test) for key, test in P16_2A3_IMPLEMENTED.items()})
    result.update({key: ("raw_table.rs", test) for key, test in P16_2A4_IMPLEMENTED.items()})
    result.update({key: ("registry_stack.rs", test) for key, test in P16_2A5_IMPLEMENTED.items()})
    result.update({key: ("raw_len.rs", test) for key, test in P16_2A6_IMPLEMENTED.items()})
    result.update({key: ("type_predicates.rs", test) for key, test in P16_2A7_IMPLEMENTED.items()})
    result.update({key: ("scalar_introspection.rs", test) for key, test in P16_2A8_IMPLEMENTED.items()})
    result.update({key: ("next_stack.rs", test) for key, test in P16_2A9_IMPLEMENTED.items()})
    result.update({key: ("primitive_stack.rs", test) for key, test in P16_2A10_IMPLEMENTED.items()})
    result.update({key: ("scalar_read.rs", test) for key, test in P16_2A11_IMPLEMENTED.items()})
    result.update({key: ("value_copy.rs", test) for key, test in P16_2A12_IMPLEMENTED.items()})
    result.update({key: ("refs.rs", test) for key, test in P16_2A13_IMPLEMENTED.items()})
    result.update({key: ("aux_stack.rs", test) for key, test in P16_2A15_IMPLEMENTED.items()})
    result.update({key: ("aux_numeric.rs", test) for key, test in P16_2A16_IMPLEMENTED.items()})
    result.update({key: ("aux_string.rs", test) for key, test in P16_2A18_IMPLEMENTED.items()})
    result.update({key: ("metatable_stack.rs", test) for key, test in P16_2A19_IMPLEMENTED.items()})
    result.update({key: ("metafield_stack.rs", test) for key, test in P16_2A20_IMPLEMENTED.items()})
    result.update({key: ("table_getters.rs", test) for key, test in P16_2A21_IMPLEMENTED.items()})
    result.update({key: ("table_setters.rs", test) for key, test in P16_2A22_IMPLEMENTED.items()})
    result.update({key: ("named_table_setters.rs", test) for key, test in P16_2A23_IMPLEMENTED.items()})
    result.update({key: ("aux_table.rs", test) for key, test in P16_2A24_IMPLEMENTED.items()})
    result.update({key: ("aux_metatable.rs", test) for key, test in P16_2A25_IMPLEMENTED.items()})
    result.update({key: ("aux_metatable.rs", test) for key, test in P16_2A26_IMPLEMENTED.items()})
    result.update({key: ("full_userdata.rs", test) for key, test in P16_2A28_IMPLEMENTED.items()})
    result.update({key: ("userdata_values.rs", test) for key, test in P16_2A29_IMPLEMENTED.items()})
    result.update({key: ("aux_userdata.rs", test) for key, test in P16_2A31_IMPLEMENTED.items()})
    result.update({key: ("full_userdata.rs", test) for key, test in P16_2A32_IMPLEMENTED.items()})
    result.update({key: ("stack_lifecycle.rs", test) for key, test in P16_2A33_IMPLEMENTED.items()})
    result.update({key: (f"buffer_macros_{profile}.c", test) for key, test in P16_2A34_IMPLEMENTED.items()})
    result[("macro", "lua_upvalueindex")] = (
        f"upvalue_index_{profile}.c", P16_2A35_IMPLEMENTED[("macro", "lua_upvalueindex")]
    )
    result[("macro", "luaL_newlibtable")] = (
        "table_stack.rs", P16_2A35_IMPLEMENTED[("macro", "luaL_newlibtable")]
    )
    result.update({key: ("stack_lifecycle.rs", test) for key, test in P16_2A36_IMPLEMENTED.items()})
    result.update({key: ("scalar_read.rs", test) for key, test in P16_2A37_IMPLEMENTED.items()})
    result.update({key: ("buffer_init.rs", test) for key, test in P16_2A38_IMPLEMENTED.items()})
    result.update({key: ("file_result.rs", test) for key, test in P16_2A40_IMPLEMENTED.items()})
    result.update({key: ("exec_result.rs", test) for key, test in P16_2A41_IMPLEMENTED.items()})
    result.update({key: ("aux_len.rs", test) for key, test in P16_2A42_IMPLEMENTED.items()})
    result.update({key: ("c_closure.rs", test) for key, test in P16_2A43_IMPLEMENTED.items()})
    result.update({key: ("aux_setfuncs.rs", test) for key, test in P16_2A44_IMPLEMENTED.items()})
    result.update({key: ("aux_string.rs", test) for key, test in P16_2A45_IMPLEMENTED.items()})
    if profile == "lua55":
        result.update({key: ("scalar_introspection.rs", test) for key, test in P16_2A46_IMPLEMENTED.items()})
    result.update({key: ("raw_table.rs", test) for key, test in P16_2A47_IMPLEMENTED.items()})
    result.update({key: ("aux_checkversion.rs", test) for key, test in P16_2A48_IMPLEMENTED.items()})
    result.update({key: ("aux_buffer.rs", test) for key, test in P16_2A49_IMPLEMENTED.items()})
    result.update({key: ("header_registration.rs", test) for key, test in P16_2B0_IMPLEMENTED.items()})
    result.update({key: ("allocator_state.rs", test) for key, test in P16_2A50_IMPLEMENTED.items()})
    result.update({key: ("aux_strict_format.rs", test) for key, test in P16_2B2_IMPLEMENTED.items()})
    result.update({key: ("coroutine_identity.rs", test) for key, test in P16_2B3_IMPLEMENTED.items()})
    result.update({key: ("value_operations.rs", test) for key, test in P16_2B5_IMPLEMENTED.items()})
    result.update({key: ("warning_callback.rs", test) for key, test in P16_2B6_IMPLEMENTED.items()})
    result.update({key: ("to_close_slots.rs", test) for key, test in P16_2B7_IMPLEMENTED.items()})
    result.update({key: ("gc_controls.rs", test) for key, test in P16_2B8_IMPLEMENTED.items()})
    result.update({key: ("debug_api.rs", test) for key, test in P16_2B10_IMPLEMENTED.items()})
    result.update({
        ("function", "lua_close"): ("state_close_reset.rs", "child_pointer_close_runs_main_pending_close_b11"),
        ("function", "lua_closethread"): ("state_close_reset.rs", "thread_reset_closes_overlay_and_rejects_foreign_from_b11"),
        (("macro" if profile == "lua55" else "function"), "lua_resetthread"):
            ("state_close_reset.rs", "thread_reset_closes_overlay_and_rejects_foreign_from_b11"),
    })
    if profile == "lua55":
        result.update({key: ("external_string.rs", test) for key, test in P16_2B9_IMPLEMENTED.items()})
    if profile == "lua54":
        result.update({key: ("stack_lifecycle.rs", test) for key, test in P16_2A39_IMPLEMENTED.items()})
    if profile == "lua55":
        result.update({key: ("scalar_introspection.rs", test) for key, test in P16_2A14_IMPLEMENTED.items()})
    if profile == "lua55":
        result.update({key: ("string_stack.rs", test) for key, test in P16_2A2_LUA55_ONLY.items()})
    else:
        result.update({key: ("primitive_stack.rs", test) for key, test in P16_2A10_LUA54_ONLY.items()})
        result.update({key: ("scalar_read.rs", test) for key, test in P16_2A11_LUA54_ONLY.items()})
    return result


def classify(row: dict[str, object]) -> tuple[str, str]:
    name, header, kind = str(row["name"]), str(row["header"]), str(row["kind"])
    if kind == "function":
        if name in P16_5_API_FUNCTIONS:
            return "P16-5", "IMPLEMENTED"
        if name == "luaL_requiref":
            return "P16-4", "NOT_IMPLEMENTED"
        if name in {"lua_callk", "lua_pcallk", "lua_yieldk", "lua_resume", "lua_error", "lua_atpanic", "luaL_error", "luaL_argerror", "luaL_typeerror", "luaL_callmeta", "luaL_traceback"}:
            return "P16-3", "NOT_IMPLEMENTED"
        return "P16-2", "NOT_IMPLEMENTED"
    if kind == "opaque_type":
        return "P16-2", "NOT_IMPLEMENTED"
    if kind == "macro":
        if header == "luaconf.h":
            if name in LUA_API_COMPAT_MACROS:
                callee = LUA_API_COMPAT_MACROS[name]
                if not re.search(rf"\b{callee}\s*\(", str(row["definition"])):
                    raise ValueError(f"相容巨集未展開至預期 Lua API：{row['id']}")
                return "P16-2", "NOT_IMPLEMENTED"
            if name.startswith(("lua_", "luaL_")) and name not in PURE_LUACONF_MACROS:
                raise ValueError(f"luaconf.h 小寫公開巨集尚未語意分類：{row['id']}")
            return "P16-1", "HEADER_ONLY"
        if (header, name) in PURE_PUBLIC_MACROS:
            return "P16-1", "HEADER_ONLY"
        if name.startswith(("lua_", "luaL_")):
            if name in P16_3_API_MACROS:
                return "P16-3", "NOT_IMPLEMENTED"
            if name in P16_5_API_MACROS:
                return "P16-5", "IMPLEMENTED"
            return "P16-2", "NOT_IMPLEMENTED"
    return "P16-1", "HEADER_ONLY"


def assert_classification(rows: list[dict[str, object]]) -> None:
    expected = {
        ("lua.h", "lua_h"): ("P16-1", "HEADER_ONLY"),
        ("lauxlib.h", "luaL_intop"): ("P16-1", "HEADER_ONLY"),
        ("luaconf.h", "lua_str2number"): ("P16-1", "HEADER_ONLY"),
        ("luaconf.h", "lua_integer2str"): ("P16-1", "HEADER_ONLY"),
        ("luaconf.h", "lua_getlocaledecpoint"): ("P16-1", "HEADER_ONLY"),
        ("luaconf.h", "lua_strlen"): ("P16-2", "IMPLEMENTED"),
        ("luaconf.h", "lua_objlen"): ("P16-2", "IMPLEMENTED"),
        ("luaconf.h", "lua_equal"): ("P16-2", "IMPLEMENTED"),
        ("luaconf.h", "lua_lessthan"): ("P16-2", "IMPLEMENTED"),
        ("lua.h", "lua_upvalueindex"): ("P16-2", "IMPLEMENTED"),
        ("lauxlib.h", "luaL_newlibtable"): ("P16-2", "IMPLEMENTED"),
        ("lua.h", "lua_register"): ("P16-2", "IMPLEMENTED"),
        ("lauxlib.h", "luaL_newlib"): ("P16-2", "IMPLEMENTED"),
        ("lua.h", "lua_newuserdata"): ("P16-2", "IMPLEMENTED"),
        ("lauxlib.h", "luaL_bufflen"): ("P16-2", "IMPLEMENTED"),
        ("lauxlib.h", "luaL_buffaddr"): ("P16-2", "IMPLEMENTED"),
        ("lauxlib.h", "luaL_addsize"): ("P16-2", "IMPLEMENTED"),
        ("lauxlib.h", "luaL_buffsub"): ("P16-2", "IMPLEMENTED"),
        ("lua.h", "lua_call"): ("P16-3", "IMPLEMENTED"),
        ("lauxlib.h", "luaL_argcheck"): ("P16-3", "IMPLEMENTED"),
        ("lauxlib.h", "luaL_loadfile"): ("P16-5", "IMPLEMENTED"),
    }
    for profile in PROFILES:
        for (header, name), result in expected.items():
            matches = [row for row in rows if row["profile"] == profile and row["header"] == header and row["name"] == name and row["kind"] == "macro"]
            if not matches or any((row["owner_step"], row["implementation_status"]) != result for row in matches):
                raise ValueError(f"巨集分類回歸：{profile}/{header}/{name} 預期 {result}")
    for name in ("lua_assert", "lua_writestring", "lua_writeline", "lua_writestringerror"):
        matches = [row for row in rows if row["profile"] == "lua54" and row["header"] == "lauxlib.h" and row["name"] == name]
        if not matches or any((row["owner_step"], row["implementation_status"]) != ("P16-1", "HEADER_ONLY") for row in matches):
            raise ValueError(f"純 libc 巨集分類回歸：lua54/lauxlib.h/{name}")
    unfinished_p16_1 = [row["id"] for row in rows if row["owner_step"] == "P16-1" and row["implementation_status"] == "NOT_IMPLEMENTED"]
    if unfinished_p16_1:
        raise ValueError(f"P16-1 未實作列須逐項解釋：{unfinished_p16_1[:8]}")
    for profile in PROFILES:
        actual = {(str(row["kind"]), str(row["name"])) for row in rows
                  if row["profile"] == profile and row["owner_step"] == "P16-2"
                  and row["implementation_status"] == "IMPLEMENTED"}
        if actual != implemented_p16_2_rows(profile).keys():
            raise ValueError(f"P16-2 已結案列與測試不符：{profile}: {actual}")
    a10_keys = P16_2A10_IMPLEMENTED.keys() | P16_2A10_LUA54_ONLY.keys()
    b13_rows = [row for row in rows if row["kind"] == "function" and row["name"] == "lua_next"]
    b13_markers = (
        "DELETED_CURRENT_KEY:B13_PASS",
        "crates/rivetlua-capi/tests/next_stack.rs:next_stack_deleted_current_key_b13:lua55+lua54:PASS",
        "crates/rivetlua-runtime/tests/capi_table_adapter.rs:capi_raw_next_deleted_current_key_b13:lua55+lua54:PASS",
        "crates/rivetlua-runtime/tests/p13_contracts.rs:p13_basic_next_deleted_current_key_b13:lua55+lua54:PASS",
        "tests/p16/deleted_current_next_b13.c:lua55+lua54:COMPILE_LINK_RUN_PASS",
    )
    if (
        len(b13_rows) != 2
        or {str(row["profile"]) for row in b13_rows} != set(PROFILES)
        or any(
            row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["implementation_mapping"] != "rivetlua-capi::stack::lua_next"
            or any(marker not in str(row["evidence"]) for marker in b13_markers)
            or "DELETED_CURRENT_KEY:NOT_IMPLEMENTED" in str(row["evidence"])
            or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"])
            for row in b13_rows
        )
    ):
        raise ValueError("G2-B13 僅兩版 lua_next 列應保留 mapping/status 與完整具名證據")
    a10_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in a10_keys]
    if len(a10_rows) != 26 or Counter(str(row["profile"]) for row in a10_rows) != {"lua54": 13, "lua55": 13}:
        raise ValueError("P16-2A10 精確列數必須為兩版各 13 列")
    if any(row["implementation_status"] != "IMPLEMENTED" or row["owner_step"] != "P16-2" for row in a10_rows):
        raise ValueError("P16-2A10 指定列必須全部結案且仍屬 P16-2")
    a10_functions = [row for row in a10_rows if row["kind"] == "function"]
    expected_functions = {
        (profile, name)
        for profile in PROFILES
        for kind, name in P16_2A10_IMPLEMENTED
        if kind == "function"
    }
    if (
        len(a10_functions) != 16
        or {(str(row["profile"]), str(row["name"])) for row in a10_functions} != expected_functions
        or any(row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}" for row in a10_functions)
    ):
        raise ValueError("P16-2A10 兩版各八個 function mapping 必須指向 stack module")
    a11_keys = P16_2A11_IMPLEMENTED.keys() | P16_2A11_LUA54_ONLY.keys()
    a11_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in a11_keys]
    if len(a11_rows) != 8 or Counter(str(row["profile"]) for row in a11_rows) != {"lua54": 5, "lua55": 3}:
        raise ValueError("P16-2A11 精確列數必須為 lua54 五列、lua55 三列")
    if any(row["implementation_status"] != "IMPLEMENTED" or row["owner_step"] != "P16-2" for row in a11_rows):
        raise ValueError("P16-2A11 指定列必須全部結案且仍屬 P16-2")
    a11_functions = [row for row in a11_rows if row["kind"] == "function"]
    expected_a11_functions = {
        (profile, name)
        for profile in PROFILES
        for kind, name in P16_2A11_IMPLEMENTED
        if kind == "function"
    }
    if (
        len(a11_functions) != 6
        or {(str(row["profile"]), str(row["name"])) for row in a11_functions} != expected_a11_functions
        or any(row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}" for row in a11_functions)
    ):
        raise ValueError("P16-2A11 兩版各三個 function mapping 必須指向 stack module")
    a11_macros = [row for row in a11_rows if row["kind"] == "macro"]
    if len(a11_macros) != 2 or any(
        row["profile"] != "lua54"
        or row["implementation_mapping"] != f"include/rivetlua/lua54/{row['header']}::{row['name']}"
        or "DIRECT_EXPANSION" not in str(row["evidence"])
        for row in a11_macros
    ):
        raise ValueError("P16-2A11 unsigned 巨集必須只屬 lua54、保留 header mapping 與直接展開證據")
    a12_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A12_IMPLEMENTED]
    if len(a12_rows) != 6 or Counter(str(row["profile"]) for row in a12_rows) != {"lua54": 3, "lua55": 3}:
        raise ValueError("P16-2A12 精確列數必須為兩版各三列")
    if any(row["implementation_status"] != "IMPLEMENTED" or row["owner_step"] != "P16-2" for row in a12_rows):
        raise ValueError("P16-2A12 指定列必須全部結案且仍屬 P16-2")
    if any(
        "crates/rivetlua-capi/tests/value_copy.rs:value_copy_a12_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS" not in str(row["evidence"])
        or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"])
        or (
            "REGISTRY_DESTINATION:" in str(row["evidence"])
            if row["name"] == "lua_pushvalue"
            else (
                "REGISTRY_DESTINATION:PASS" not in str(row["evidence"])
                or "crates/rivetlua-capi/tests/value_copy.rs:registry_destination_b12_matrix:lua55+lua54:PASS" not in str(row["evidence"])
                or "tests/p16/registry_destination_b12.c:lua55+lua54:COMPILE_LINK_RUN_PASS" not in str(row["evidence"])
            )
        )
        for row in a12_rows
    ):
        raise ValueError("P16-2A12 證據須依 symbol 包含具名矩陣與適用限制")
    a12_functions = [row for row in a12_rows if row["kind"] == "function"]
    if len(a12_functions) != 4 or any(
        row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
        for row in a12_functions
    ):
        raise ValueError("P16-2A12 四個 function mapping 必須指向 stack module")
    a12_macros = [row for row in a12_rows if row["kind"] == "macro"]
    if len(a12_macros) != 2 or any(
        row["implementation_mapping"] != f"include/rivetlua/{row['profile']}/{row['header']}::lua_replace"
        or "lua_replace:DIRECT_EXPANSION" not in str(row["evidence"])
        or f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY" not in str(row["evidence"])
        for row in a12_macros
    ):
        raise ValueError("P16-2A12 replace 巨集須保留 header mapping 與直接展開／編譯證據")
    a13_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A13_IMPLEMENTED]
    if len(a13_rows) != 4 or Counter(str(row["profile"]) for row in a13_rows) != {"lua54": 2, "lua55": 2}:
        raise ValueError("P16-2A13 必須精確結案兩版各兩個 function")
    if any(
        row["implementation_status"] != "IMPLEMENTED"
        or row["owner_step"] != "P16-2"
        or row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
        or "crates/rivetlua-capi/tests/refs.rs:refs_a13_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or "INVALID_REFERENCE_FAIL_CLOSED" not in str(row["evidence"])
        or "VALID_HANDLE_PRECONDITION:SAME_TABLE_ACTIVE_REF" not in str(row["evidence"])
        or "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS" not in str(row["evidence"])
        or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"])
        or (row["profile"] == "lua55" and (
            P16_2B3_MAIN_CHILD_EVIDENCE not in str(row["evidence"])
            or "MAINTHREAD_REGISTRY_ENTRY:B3_PASS" not in str(row["evidence"])
        ))
        for row in a13_rows
    ):
        raise ValueError("P16-2A13 mapping、具名矩陣與限制證據回歸")
    a14_rows = [
        row for row in rows
        if row["header"] == "lauxlib.h" and row["kind"] == "function" and row["name"] == "luaL_makeseed"
    ]
    if (
        len(a14_rows) != 1
        or a14_rows[0]["id"] != "lua55:lauxlib.h:function:luaL_makeseed:106"
        or a14_rows[0]["profile"] != "lua55"
        or a14_rows[0]["implementation_status"] != "IMPLEMENTED"
        or a14_rows[0]["owner_step"] != "P16-2"
        or a14_rows[0]["implementation_mapping"] != "rivetlua-capi::luaL_makeseed"
        or "crates/rivetlua-capi/tests/scalar_introspection.rs:scalar_introspection_a8_matrix:lua55:PASS" not in str(a14_rows[0]["evidence"])
        or "TEST_CALLS_HELPER:makeseed_a14_matrix" not in str(a14_rows[0]["evidence"])
        or "crates/rivetlua-capi/src/lib.rs:seed_tests::makeseed_fixed_vectors:lua55:PASS" not in str(a14_rows[0]["evidence"])
        or "STATE_UNUSED_NULL_VALID_BUSY" not in str(a14_rows[0]["evidence"])
        or "STATE_PURITY:STACK_ROOTS_LEDGER_GC_TRACE" not in str(a14_rows[0]["evidence"])
        or "CRYPTOGRAPHIC_ENTROPY:NOT_CLAIMED" not in str(a14_rows[0]["evidence"])
    ):
        raise ValueError("P16-2A14 必須只結案 lua55 的 makeseed row 並保留指定 mapping／矩陣／固定向量證據")
    a15_rows = [
        row for row in rows
        if row["header"] == "lauxlib.h" and row["kind"] == "function" and row["name"] == "luaL_checkstack"
    ]
    if (
        len(a15_rows) != 2
        or Counter(str(row["profile"]) for row in a15_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_checkstack"
            or "crates/rivetlua-capi/tests/aux_stack.rs:aux_stack_a15_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or "NORMAL_RESERVATION:PASS" not in str(row["evidence"])
            or "FAULT_TRACE:EXPECTED_SINGLE_ATTEMPT" not in str(row["evidence"])
            or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"])
            or "MESSAGE_ERROR_PATH:NOT_EXERCISED" not in str(row["evidence"])
            for row in a15_rows
        )
    ):
        raise ValueError("P16-2A15 必須精確結案兩版 checkstack row 並保留具名矩陣、normal reserve 與限制證據")
    a16_rows = [
        row for row in rows
        if row["header"] == "lauxlib.h"
        and (str(row["kind"]), str(row["name"])) in P16_2A16_IMPLEMENTED
    ]
    if (
        len(a16_rows) != 22
        or Counter(str(row["profile"]) for row in a16_rows) != {"lua54": 11, "lua55": 11}
        or any(row["implementation_status"] != "IMPLEMENTED" or row["owner_step"] != "P16-2" for row in a16_rows)
    ):
        raise ValueError("P16-2A16 必須精確結案兩版各四個 function 與七個 macro")
    a16_functions = [row for row in a16_rows if row["kind"] == "function"]
    if (
        len(a16_functions) != 8
        or any(
            row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
            or "crates/rivetlua-capi/tests/aux_numeric.rs:aux_numeric_a16_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or "NORMAL_NUMERIC_COERCION:PASS" not in str(row["evidence"])
            or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"])
            or "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS" not in str(row["evidence"])
            or (
                row["name"] in {"luaL_optnumber", "luaL_optinteger"}
                and "NONE_NIL_DEFAULT_ONLY:PASS" not in str(row["evidence"])
            )
            for row in a16_functions
        )
    ):
        raise ValueError("P16-2A16 numeric functions 須指向 stack module 並保留 coercion/default 限制證據")
    a16_macros = [row for row in a16_rows if row["kind"] == "macro"]
    if len(a16_macros) != 14 or any(
        row["implementation_mapping"] != f"include/rivetlua/{row['profile']}/lauxlib.h::{row['name']}"
        or f"include/rivetlua/{row['profile']}/lauxlib.h:{row['name']}:DIRECT_EXPANSION" not in str(row["evidence"])
        or f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY" not in str(row["evidence"])
        for row in a16_macros
    ):
        raise ValueError("P16-2A16 macros 須保留固定 header mapping 與 compile-only 展開證據")
    luaL_opt_rows = [row for row in a16_macros if row["name"] == "luaL_opt"]
    if len(luaL_opt_rows) != 2 or any(
        "crates/rivetlua-capi/tests/type_predicates.rs:type_predicates_a7_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or "GENERIC_FUNCTION_CALLER_PROVIDED" not in str(row["evidence"])
        or "C_LINK_CALL:NOT_RUN" not in str(row["evidence"])
        for row in luaL_opt_rows
    ):
        raise ValueError("P16-2A16 luaL_opt 須保留 A7 none/nil 證據且不得宣稱 C link/call")
    compat_macros = [row for row in a16_macros if row["name"] != "luaL_opt"]
    if len(compat_macros) != 12 or any(
        "crates/rivetlua-capi/tests/aux_numeric.rs:aux_numeric_a16_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or "UNDERLYING_INTEGER_FUNCTIONS:PASS" not in str(row["evidence"])
        or "C_CAST_SEMANTICS:HEADER_DEFINED" not in str(row["evidence"])
        or "C_RUNTIME_CALL:NOT_RUN" not in str(row["evidence"])
        for row in compat_macros
    ):
        raise ValueError("P16-2A16 compat casts 須限定為 header 定義並標示 underlying functions 測試與未做 C runtime call")
    a18_rows = [
        row for row in rows
        if row["header"] == "lauxlib.h"
        and (str(row["kind"]), str(row["name"])) in P16_2A18_IMPLEMENTED
    ]
    if (
        len(a18_rows) != 8
        or Counter(str(row["profile"]) for row in a18_rows) != {"lua54": 4, "lua55": 4}
        or any(row["implementation_status"] != "IMPLEMENTED" or row["owner_step"] != "P16-2" for row in a18_rows)
    ):
        raise ValueError("P16-2A18 必須精確結案兩版各兩個 function 與兩個 macro")
    a18_functions = [row for row in a18_rows if row["kind"] == "function"]
    if (
        len(a18_functions) != 4
        or any(
            row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
            or "crates/rivetlua-capi/tests/aux_string.rs:aux_string_a18_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or "NORMAL_STRING_NUMBER_COERCION:PASS" not in str(row["evidence"])
            or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"])
            or "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS" not in str(row["evidence"])
            or (
                row["name"] == "luaL_optlstring"
                and (
                    "NONE_NIL_DEFAULT_ONLY:PASS" not in str(row["evidence"])
                    or "DEFAULT_C_STRING_LENGTH:PASS" not in str(row["evidence"])
                )
            )
            for row in a18_functions
        )
    ):
        raise ValueError("P16-2A18 string functions 須指向 stack module 並保留 coercion/default 限制證據")
    a18_macros = [row for row in a18_rows if row["kind"] == "macro"]
    if len(a18_macros) != 4 or any(
        row["implementation_mapping"] != f"include/rivetlua/{row['profile']}/lauxlib.h::{row['name']}"
        or f"include/rivetlua/{row['profile']}/lauxlib.h:{row['name']}:DIRECT_EXPANSION" not in str(row["evidence"])
        or f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY" not in str(row["evidence"])
        or "crates/rivetlua-capi/tests/aux_string.rs:aux_string_a18_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or "C_RUNTIME_CALL:NOT_RUN" not in str(row["evidence"])
        for row in a18_macros
    ):
        raise ValueError("P16-2A18 string macros 須保留 header mapping、直接展開與 compile-only 證據")
    a19_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A19_IMPLEMENTED]
    if len(a19_rows) != 4 or Counter(str(row["profile"]) for row in a19_rows) != {"lua54": 2, "lua55": 2}:
        raise ValueError("P16-2A19 必須精確結案兩版各兩個 function")
    a19_tags = (
        "TABLE_METATABLE:PASS",
        "REGISTRY_PSEUDOINDEX:PASS",
        "GC_BARRIER_FINALIZER_WEAK:PASS",
        "PRIMITIVE_TYPE_METATABLES:A4A_LOCAL_PASS",
        "FULL_USERDATA_METATABLE:PASS",
        "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS",
    )
    if any(
        row["implementation_status"] != "IMPLEMENTED"
        or row["owner_step"] != "P16-2"
        or row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
        or "crates/rivetlua-capi/tests/metatable_stack.rs:metatable_stack_a19_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or "crates/rivetlua-capi/tests/userdata_metatable.rs:userdata_metatable_a30_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or any(tag not in str(row["evidence"]) for tag in a19_tags)
        or "TABLE_METATABLE_ONLY:PASS" in str(row["evidence"])
        or "FULL_USERDATA_METATABLE:NOT_IMPLEMENTED" in str(row["evidence"])
        or (row["name"] == "lua_setmetatable" and "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"]))
        for row in a19_rows
    ):
        raise ValueError("P16-2A19 mapping、具名矩陣與 metatable 範圍限制回歸")
    a20_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A20_IMPLEMENTED]
    if len(a20_rows) != 2 or Counter(str(row["profile"]) for row in a20_rows) != {"lua54": 1, "lua55": 1}:
        raise ValueError("P16-2A20 必須精確結案兩版各一個 function")
    a20_tags = (
        "TABLE_METATABLE:PASS",
        "REGISTRY_PSEUDOINDEX:PASS",
        "PRIMITIVE_TYPE_METATABLES:A4A_LOCAL_PASS",
        "FULL_USERDATA_METATABLE:PASS",
        "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS",
        "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS",
    )
    if any(
        row["implementation_status"] != "IMPLEMENTED"
        or row["owner_step"] != "P16-2"
        or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_getmetafield"
        or "crates/rivetlua-capi/tests/metafield_stack.rs:metafield_stack_a20_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or "crates/rivetlua-capi/tests/userdata_metatable.rs:userdata_metatable_a30_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or any(tag not in str(row["evidence"]) for tag in a20_tags)
        or "TABLE_METATABLE_ONLY:PASS" in str(row["evidence"])
        or "FULL_USERDATA_METATABLE:NOT_IMPLEMENTED" in str(row["evidence"])
        for row in a20_rows
    ):
        raise ValueError("P16-2A20 mapping、具名矩陣與 metatable 範圍限制回歸")
    a21_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A21_IMPLEMENTED]
    if len(a21_rows) != 10 or Counter(str(row["profile"]) for row in a21_rows) != {"lua54": 5, "lua55": 5}:
        raise ValueError("P16-2A21 必須精確結案兩版各四 function 與一 macro")
    a21_common = (
        "DIRECT_TABLE_PATH:PASS",
        "METAMETHOD_CALLBACK:A4A_LOCAL_PASS",
        "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS",
    )
    if any(
        row["implementation_status"] != "IMPLEMENTED"
        or row["owner_step"] != "P16-2"
        or "crates/rivetlua-capi/tests/table_getters.rs:table_getters_a21_matrix:lua55+lua54:PASS" not in str(row["evidence"])
        or (
            row["kind"] == "function" and (
                row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
                or any(tag not in str(row["evidence"]) for tag in a21_common)
                or (
                    row["name"] == "lua_getglobal"
                    and "GLOBAL_TABLE:PASS" not in str(row["evidence"])
                )
                or (
                    row["name"] != "lua_getglobal" and any(tag not in str(row["evidence"]) for tag in (
                        "REGISTRY_PSEUDOINDEX:PASS",
                        "PRIMITIVE_TARGET:A4A_LOCAL_PASS",
                        "FULL_USERDATA_TARGET:A4A_LOCAL_PASS",
                        "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS",
                    ))
                )
            )
        )
        or (
            row["kind"] == "macro" and (
                row["implementation_mapping"] != f"include/rivetlua/{row['profile']}/lauxlib.h::luaL_getmetatable"
                or "UNDERLYING_GETFIELD:PASS" not in str(row["evidence"])
                or f"include/rivetlua/{row['profile']}/lauxlib.h:luaL_getmetatable:DIRECT_EXPANSION" not in str(row["evidence"])
                or f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY" not in str(row["evidence"])
                or "C_RUNTIME_CALL:NOT_RUN" not in str(row["evidence"])
            )
        )
        for row in a21_rows
    ):
        raise ValueError("P16-2A21 mapping、具名矩陣、direct table 範圍與 macro 展開證據回歸")
    a22_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A22_IMPLEMENTED]
    a22_tags = (
        "DIRECT_TABLE_PATH:PASS",
        "REGISTRY_PSEUDOINDEX:PASS",
        "GC_BARRIER_WEAK:PASS",
        "METAMETHOD_CALLBACK:A4A_LOCAL_PASS",
        "PRIMITIVE_TARGET:A4A_LOCAL_PASS",
        "FULL_USERDATA_TARGET:A4A_LOCAL_PASS",
        "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS",
        "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS",
    )
    if (
        len(a22_rows) != 4
        or Counter(str(row["profile"]) for row in a22_rows) != {"lua54": 2, "lua55": 2}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
            or "crates/rivetlua-capi/tests/table_setters.rs:table_setters_a22_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a22_tags)
            for row in a22_rows
        )
    ):
        raise ValueError("P16-2A22 mapping、具名矩陣、direct table 與 GC 範圍限制回歸")
    a23_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A23_IMPLEMENTED]
    a23_tags = (
        "DIRECT_TABLE_PATH:PASS",
        "BYTE_KEY_PUBLICATION_CLEANUP:PASS",
        "GC_BARRIER_WEAK:PASS",
        "METAMETHOD_CALLBACK:A4A_LOCAL_PASS",
        "PRIMITIVE_TARGET:A4A_LOCAL_PASS",
        "FULL_USERDATA_TARGET:A4A_LOCAL_PASS",
        "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS",
        "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS",
    )
    if (
        len(a23_rows) != 4
        or Counter(str(row["profile"]) for row in a23_rows) != {"lua54": 2, "lua55": 2}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
            or "crates/rivetlua-capi/tests/named_table_setters.rs:named_table_setters_a23_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a23_tags)
            or (
                ("GLOBALS_TABLE:PASS" not in str(row["evidence"]) or "REGISTRY_RIDX_GLOBALS:PASS" not in str(row["evidence"]))
                if row["name"] == "lua_setglobal"
                else "REGISTRY_PSEUDOINDEX:PASS" not in str(row["evidence"])
            )
            for row in a23_rows
        )
    ):
        raise ValueError("P16-2A23 mapping、具名矩陣、key 發布及範圍限制回歸")
    a24_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A24_IMPLEMENTED]
    a24_tags = (
        "DIRECT_TABLE_PATH:PASS",
        "REGISTRY_PSEUDOINDEX:PASS",
        "GET_OR_CREATE_ATOMIC:PASS",
        "BYTE_KEY_PUBLICATION_CLEANUP:PASS",
        "GC_BARRIER_WEAK:PASS",
        "METAMETHOD_CALLBACK:A4A_LOCAL_PASS",
        "PRIMITIVE_TARGET:A4A_LOCAL_PASS",
        "FULL_USERDATA_TARGET:A4A_LOCAL_PASS",
        "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS",
        "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS",
    )
    if (
        len(a24_rows) != 2
        or Counter(str(row["profile"]) for row in a24_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_getsubtable"
            or "crates/rivetlua-capi/tests/aux_table.rs:aux_table_a24_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a24_tags)
            for row in a24_rows
        )
    ):
        raise ValueError("P16-2A24 mapping、具名矩陣、原子 get-or-create 與範圍限制回歸")
    a25_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A25_IMPLEMENTED]
    a25_tags = (
        "REGISTRY_EXISTING_NONNIL:PASS",
        "RAW_NAME_FIELD:PASS",
        "ATOMIC_TWO_EDGE_PUBLICATION:PASS",
        "GC_ROOT_BARRIER:PASS",
        "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS",
    )
    if (
        len(a25_rows) != 2
        or Counter(str(row["profile"]) for row in a25_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_newmetatable"
            or "crates/rivetlua-capi/tests/aux_metatable.rs:aux_metatable_a25_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a25_tags)
            for row in a25_rows
        )
    ):
        raise ValueError("P16-2A25 mapping、具名矩陣、registry nonnil 與原子發布回歸")
    a26_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A26_IMPLEMENTED]
    a26_tags = (
        "REGISTRY_TABLE_SET:PASS",
        "REGISTRY_NIL_CLEAR:PASS",
        "TABLE_TARGET:PASS",
        "ROOT_GC_FINALIZER_WEAK:PASS",
        "REGISTRY_NON_TABLE_FAIL_CLOSED:PASS",
        "ALLOCATION_FAILURE_ATOMIC:PASS",
        "FULL_USERDATA_TARGET:PASS",
        "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS",
    )
    if (
        len(a26_rows) != 2
        or Counter(str(row["profile"]) for row in a26_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_setmetatable"
            or "crates/rivetlua-capi/tests/aux_metatable.rs:aux_metatable_a26_set_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or "crates/rivetlua-capi/tests/userdata_metatable.rs:userdata_metatable_a30_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a26_tags)
            or "TABLE_ONLY_TARGET:PASS" in str(row["evidence"])
            or "FULL_USERDATA_TARGET:A4A_LOCAL_PASS" in str(row["evidence"])
            for row in a26_rows
        )
    ):
        raise ValueError("P16-2A26 mapping、具名矩陣、registry table/nil 與錯誤限制回歸")
    a28_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A28_IMPLEMENTED]
    if (
        len(a28_rows) != 4
        or Counter(str(row["profile"]) for row in a28_rows) != {"lua54": 2, "lua55": 2}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
            or "crates/rivetlua-capi/tests/full_userdata.rs:full_userdata_a28_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"])
            for row in a28_rows
        )
    ):
        raise ValueError("P16-2A28 四個 function mapping、具名矩陣或限制回歸")
    for name in ("lua_rawlen", "lua_isuserdata", "lua_type", "lua_strlen", "lua_objlen", "lua_newuserdata"):
        related = [row for row in rows if row["name"] == name]
        if len(related) != 2 or any("full_userdata_a28_matrix:lua55+lua54:PASS" not in str(row["evidence"]) for row in related):
            raise ValueError(f"P16-2A28 {name} 的 full userdata 證據回歸")
    a29_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A29_IMPLEMENTED]
    if (
        len(a29_rows) != 8
        or Counter(str(row["profile"]) for row in a29_rows) != {"lua54": 4, "lua55": 4}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != (
                f"rivetlua-capi::stack::{row['name']}"
                if row["kind"] == "function"
                else f"include/rivetlua/{row['profile']}/lua.h::{row['name']}"
            )
            or "crates/rivetlua-capi/tests/userdata_values.rs:userdata_values_a29_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS" not in str(row["evidence"])
            or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"])
            or (
                row["kind"] == "macro"
                and (
                    "DIRECT_FORWARD_USERVALUE_INDEX_1" not in str(row["evidence"])
                    or f"tests/p16/surface_{row['profile']}.c:COMPILE_ONLY" not in str(row["p17_use"])
                    or "C_RUNTIME_CALL:NOT_RUN" not in str(row["evidence"])
                )
            )
            for row in a29_rows
        )
    ):
        raise ValueError("P16-2A29 uservalue function／macro mapping、具名矩陣或限制回歸")
    a31_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A31_IMPLEMENTED]
    a31_tags = (
        "RAW_METATABLE_IDENTITY:PASS",
        "STACK_BALANCE_TEMP_ROOT_GC:PASS",
        "ALLOCATION_FAILURE_ATOMIC:PASS",
        "CHECKUDATA_ERROR_TRAMPOLINE:B2_PASS",
        "PRIMITIVE_TYPE_METATABLES:A4A_LOCAL_PASS",
        "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS",
        "INTERNAL_FILE_PAYLOAD:NOT_C_FULL_USERDATA",
        "C_LINK_CALL:NOT_RUN",
        "OFFICIAL_MODULES:NOT_RUN",
    )
    if (
        len(a31_rows) != 2
        or Counter(str(row["profile"]) for row in a31_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_testudata"
            or "crates/rivetlua-capi/tests/aux_userdata.rs:aux_userdata_a31_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a31_tags)
            for row in a31_rows
        )
    ):
        raise ValueError("P16-2A31 testudata mapping、具名矩陣或限制回歸")
    a32_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A32_IMPLEMENTED]
    if (
        len(a32_rows) != 2
        or Counter(str(row["profile"]) for row in a32_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lua.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != f"include/rivetlua/{row['profile']}/lua.h::lua_newuserdata"
            or row["definition"] != "#define lua_newuserdata(L,s) lua_newuserdatauv(L,s,1)"
            or f"crates/rivetlua-capi/tests/full_userdata.rs:full_userdata_a28_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or f"include/rivetlua/{row['profile']}/lua.h:lua_newuserdata:DIRECT_FORWARD_NUVALUE_1" not in str(row["evidence"])
            or f"tests/p16/surface_{row['profile']}.c:COMPILE_ONLY" not in str(row["evidence"])
            or "C_RUNTIME_CALL:NOT_RUN" not in str(row["evidence"])
            or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" not in str(row["evidence"])
            for row in a32_rows
        )
    ):
        raise ValueError("P16-2A32 必須精確結案兩版 lua_newuserdata 巨集並保留 A28 轉送與限制證據")
    check_rows = [row for row in rows if row["kind"] == "function" and row["name"] == "luaL_checkudata"]
    if (
        len(check_rows) != 2
        or Counter(str(row["profile"]) for row in check_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::luaL_checkudata"
            or row["evidence"] != b2_evidence(str(row["profile"]), "luaL_checkudata")
            for row in check_rows
        )
    ):
        raise ValueError("P16-2 B2 checkudata 必須沿 A31 identity 完成嚴格錯誤契約")
    a33_rows = [row for row in rows if row["kind"] == "function" and row["name"] == "luaL_newstate"]
    a33_tags = (
        "DEFAULT_C_OWNED_STATE:PASS", "EXTRASPACE:PASS", "REGISTRY:PASS",
        "GLOBALS:PASS", "VM_ISOLATION:PASS", "DROP:PASS",
        "CUSTOM_ALLOCATOR:A50:PASS", "MAINTHREAD_REGISTRY_ENTRY:B3_PASS",
        "CLOSE_FINALIZER_CALLBACK:B11_PASS",
    )
    if (
        len(a33_rows) != 2
        or Counter(str(row["profile"]) for row in a33_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lauxlib.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_newstate"
            or "crates/rivetlua-capi/tests/stack_lifecycle.rs:c_owned_default_state_a33_matrix:lua55+lua54:PASS" not in str(row["evidence"])
            or P16_2B3_MAIN_CHILD_EVIDENCE not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a33_tags)
            or f"AUX_DEFAULT_WARNING_INITIAL:{'ON' if row['profile'] == 'lua55' else 'OFF'}:B6_PASS" not in str(row["evidence"])
            or "AUX_WARNING_ON_OFF_MULTIPART_PREFIX_NEWLINE:B6_PASS" not in str(row["evidence"])
            for row in a33_rows
        )
    ):
        raise ValueError("P16-2A33 newstate 兩列 mapping、矩陣或保留限制回歸")
    a34_rows = [
        row for row in rows
        if (str(row["kind"]), str(row["name"])) in P16_2A34_IMPLEMENTED
    ]
    a34_definitions = {
        "luaL_bufflen": "#define luaL_bufflen(bf) ((bf)->n)",
        "luaL_buffaddr": "#define luaL_buffaddr(bf) ((bf)->b)",
        "luaL_addsize": "#define luaL_addsize(B,s) ((B)->n += (s))",
        "luaL_buffsub": "#define luaL_buffsub(B,s) ((B)->n -= (s))",
    }
    if (
        len(a34_rows) != 8
        or Counter(str(row["profile"]) for row in a34_rows) != {"lua54": 4, "lua55": 4}
        or any(
            row["header"] != "lauxlib.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"]
            != f"include/rivetlua/{row['profile']}/lauxlib.h::{row['name']}"
            or row["definition"] != a34_definitions.get(str(row["name"]))
            or f"tests/p16/buffer_macros_{row['profile']}.c:HEADER_MACRO_RUNTIME:PASS"
            not in str(row["evidence"])
            or f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY"
            not in str(row["evidence"])
            or f"tests/p16/surface_{row['profile']}.c:COMPILE_ONLY" not in str(row["p17_use"])
            or "RIVETLUA_C_LINK_CALL:NOT_RUN" not in str(row["evidence"])
            or (
                f"include/rivetlua/{row['profile']}/lauxlib.h:{row['name']}:"
                + (
                    "DIRECT_PUBLIC_FIELD_ACCESS"
                    if row["name"] in {"luaL_bufflen", "luaL_buffaddr"}
                    else "DIRECT_N_FIELD_ADD"
                    if row["name"] == "luaL_addsize"
                    else "DIRECT_N_FIELD_SUB"
                )
            ) not in str(row["evidence"])
            for row in a34_rows
        )
    ):
        raise ValueError("P16-2A34 buffer 巨集兩版定義、mapping、runtime/surface 證據或限制回歸")
    a35_rows = [
        row for row in rows
        if (str(row["kind"]), str(row["name"])) in P16_2A35_IMPLEMENTED
    ]
    a35_definitions = {
        "lua_upvalueindex": "#define lua_upvalueindex(i) (LUA_REGISTRYINDEX - (i))",
        "luaL_newlibtable": (
            "#define luaL_newlibtable(L,l) "
            "lua_createtable(L, 0, sizeof(l)/sizeof((l)[0]) - 1)"
        ),
    }
    a35_matrix = (
        "crates/rivetlua-capi/tests/table_stack.rs:"
        "table_stack_create_publication_failures_active_gc_are_atomic:lua55+lua54:PASS"
    )
    if (
        len(a35_rows) != 4
        or Counter(str(row["profile"]) for row in a35_rows) != {"lua54": 2, "lua55": 2}
        or any(
            row["header"] != ("lua.h" if row["name"] == "lua_upvalueindex" else "lauxlib.h")
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"]
            != f"include/rivetlua/{row['profile']}/{row['header']}::{row['name']}"
            or row["definition"] != a35_definitions.get(str(row["name"]))
            or f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY"
            not in str(row["evidence"])
            or f"tests/p16/surface_{row['profile']}.c:COMPILE_ONLY" not in str(row["p17_use"])
            or (
                row["name"] == "lua_upvalueindex"
                and (
                    f"tests/p16/upvalue_index_{row['profile']}.c:UPVALUE_INDEX_RUNTIME:PASS"
                    not in str(row["evidence"])
                    or f"include/rivetlua/{row['profile']}/lua.h:lua_upvalueindex:"
                    "DIRECT_REGISTRY_INDEX_SUBTRACTION" not in str(row["evidence"])
                    or "UPVALUE_PSEUDOINDEX_CONSUMERS:A4B_LOCAL_PASS"
                    not in str(row["evidence"])
                    or "RIVETLUA_C_LINK_CALL:NOT_RUN" not in str(row["evidence"])
                )
            )
            or (
                row["name"] == "luaL_newlibtable"
                and (
                    a35_matrix not in str(row["evidence"])
                    or f"include/rivetlua/{row['profile']}/lauxlib.h:luaL_newlibtable:"
                    "DIRECT_FORWARD_CREATETABLE_NARR_0_NREC_ARRAY_MINUS_SENTINEL"
                    not in str(row["evidence"])
                    or "CALLER_ARRAY_WITH_SENTINEL_PRECONDITION" not in str(row["evidence"])
                    or "C_RUNTIME_CALL:NOT_RUN" not in str(row["evidence"])
                )
            )
            for row in a35_rows
        )
    ):
        raise ValueError("P16-2A35 upvalue/newlibtable 定義、mapping、evidence 或限制回歸")
    close_rows = [row for row in rows if row["kind"] == "function" and row["name"] == "lua_close"]
    if (
        len(close_rows) != 2
        or Counter(str(row["profile"]) for row in close_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lua.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::trampoline.c::lua_close"
            or row["evidence"] != b11_evidence(str(row["profile"]), "lua_close")
            for row in close_rows
        )
    ):
        raise ValueError("P16-2 B11 close finalizer 契約回歸")
    a36_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A36_IMPLEMENTED]
    a36_tags = (
        "PUBLIC_MAIN_STATE:LUA_OK",
        "MAIN_STATE_NOT_YIELDABLE",
        "RUST_OVERLAY_NOT_PUBLIC_CHILD",
        "STACK_ROOTS_LEDGER_ALLOCATION_GC_TRACE:UNCHANGED",
        "COROUTINE_CHILD_STATE:B3_PASS",
        "CALLBACK_CONTEXT:A5_LOCAL_PASS",
    )
    if (
        len(a36_rows) != 4
        or Counter(str(row["profile"]) for row in a36_rows) != {"lua54": 2, "lua55": 2}
        or any(
            row["header"] != "lua.h"
            or row["kind"] != "function"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
            or "crates/rivetlua-capi/tests/stack_lifecycle.rs:main_state_status_a36_matrix:lua55+lua54:PASS"
            not in str(row["evidence"])
            or P16_2B3_MAIN_CHILD_EVIDENCE not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a36_tags)
            for row in a36_rows
        )
    ):
        raise ValueError("P16-2A36 status/isyieldable 四列 mapping、矩陣或限制回歸")
    a36_reserved = {
        (profile, kind, name): owner
        for profile in PROFILES
        for kind, name, owner in (
            ("function", "lua_closethread", "P16-2"),
            ("function", "lua_resume", "P16-3"),
            ("function", "lua_yieldk", "P16-3"),
            ("macro", "lua_yield", "P16-3"),
            (("function" if profile == "lua54" else "macro"), "lua_resetthread", "P16-2"),
        )
    }
    reserved_rows = {
        (str(row["profile"]), str(row["kind"]), str(row["name"])): row
        for row in rows
        if row["name"] in {
            "lua_closethread",
            "lua_resume", "lua_yieldk", "lua_yield", "lua_resetthread",
        }
    }
    if reserved_rows.keys() != a36_reserved.keys() or any(
        reserved_rows[key]["implementation_status"] != (
            "IMPLEMENTED" if key[2] in {"lua_closethread", "lua_resetthread", "lua_resume", "lua_yieldk", "lua_yield"}
            else "NOT_IMPLEMENTED"
        )
        or reserved_rows[key]["owner_step"] != owner
        for key, owner in a36_reserved.items()
    ):
        raise ValueError("P16-2A36 coroutine/callback 相關 rows owner 或 B11 狀態回歸")
    a37_rows = [row for row in rows if (row["kind"], row["name"]) in P16_2A37_IMPLEMENTED]
    a37_tags = (
        "OPAQUE_NON_DEREFERENCEABLE_RUNTIME_TOKEN",
        "FULL_USERDATA_MEMORY_BLOCK",
        "LIGHTUSERDATA_VALUE",
        "VM_GENERATION_VALIDATED",
        "STACK_ROOTS_LEDGER_ALLOCATION_GC_TRACE_UNCHANGED",
        "C_LINK_CALL:NOT_RUN",
    )
    if (
        len(a37_rows) != 2
        or Counter(str(row["profile"]) for row in a37_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lua.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::lua_topointer"
            or "crates/rivetlua-capi/tests/scalar_read.rs:pointer_identity_a37_matrix:lua55+lua54:PASS"
            not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a37_tags)
            for row in a37_rows
        )
    ):
        raise ValueError("P16-2A37 topointer 兩列 mapping、矩陣或限制回歸")
    a38_rows = [row for row in rows if (row["kind"], row["name"]) in P16_2A38_IMPLEMENTED]
    a38_tags = (
        "PUBLIC_PREFIX_FIELDS",
        "B_EQUALS_INIT_BUFFER",
        "SIZE_LUAL_BUFFERSIZE_1024",
        "N_ZERO",
        "STATE_POINTER",
        "INIT_BYTES_UNCHANGED",
        "STACK_LIGHTUSERDATA_PLACEHOLDER",
        "GROWTH_ROOTED_USERDATA_BOX",
        "RESULT_REPLACES_ANCHOR",
    )
    if (
        len(a38_rows) != 2
        or Counter(str(row["profile"]) for row in a38_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lauxlib.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_buffinit"
            or "crates/rivetlua-capi/tests/buffer_init.rs:buffer_init_a38_matrix:lua55+lua54:PASS"
            not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a38_tags)
            for row in a38_rows
        )
    ):
        raise ValueError("P16-2A38 buffinit 兩列 mapping、矩陣或限制回歸")
    a39_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A39_IMPLEMENTED]
    a39_tags = (
        "LUA54_ONLY",
        "OFFICIAL_5_4_9_NOOP",
        "RETURNS_LUAI_MAXCCALLS_200",
        "LIMIT_IGNORED",
        "STATE_VALIDATED",
        "STACK_ROOTS_LEDGER_ALLOCATION_GC_TRACE_STATUS_UNCHANGED",
        "C_LINK_CALL:NOT_RUN",
    )
    if (
        len(a39_rows) != 1
        or a39_rows[0]["profile"] != "lua54"
        or a39_rows[0]["header"] != "lua.h"
        or a39_rows[0]["kind"] != "function"
        or a39_rows[0]["implementation_status"] != "IMPLEMENTED"
        or a39_rows[0]["owner_step"] != "P16-2"
        or a39_rows[0]["implementation_mapping"] != "rivetlua-capi::stack::lua_setcstacklimit"
        or "crates/rivetlua-capi/tests/stack_lifecycle.rs:cstack_limit_a39_matrix:lua54:PASS"
        not in str(a39_rows[0]["evidence"])
        or any(tag not in str(a39_rows[0]["evidence"]) for tag in a39_tags)
        or any(row["profile"] == "lua55" and row["name"] == "lua_setcstacklimit" for row in rows)
    ):
        raise ValueError("P16-2A39 lua_setcstacklimit 僅限 lua54，mapping、矩陣或限制回歸")
    a40_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A40_IMPLEMENTED]
    a40_tags = (
        "ERRNO_CAPTURED_BEFORE_STATE_API",
        "STAT_NONZERO_TRUE_ONE_RESULT",
        "STAT_ZERO_NIL_MESSAGE_ERRNO_THREE_RESULTS",
        "FNAME_RAW_BYTES_PREFIX",
        "ERRNO_ZERO_NO_EXTRA_INFO",
        "FAILPOINT_ATOMIC",
        "ACTIVE_GC_STRING_ROOTED",
        "EXECRESULT:A41_PASS",
        "C_LINK_CALL:NOT_RUN",
    )
    if (
        len(a40_rows) != 2
        or Counter(str(row["profile"]) for row in a40_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lauxlib.h"
            or row["kind"] != "function"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_fileresult"
            or "crates/rivetlua-capi/tests/file_result.rs:file_result_a40_matrix:lua55+lua54:PASS"
            not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a40_tags)
            for row in a40_rows
        )
    ):
        raise ValueError("P16-2A40 fileresult 兩版 mapping、矩陣或限制回歸")
    a41_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A41_IMPLEMENTED]
    a41_tags = (
        "ERRNO_CAPTURED_BEFORE_STATE_API",
        "NONZERO_STAT_ERRNO_TO_FILERESULT",
        "POSIX_WAIT_STATUS_DECODE",
        "EXIT_ZERO_TRUE_EXIT_ZERO",
        "EXIT_NONZERO_NIL_EXIT_CODE",
        "SIGNAL_NIL_SIGNAL_NUMBER",
        "STOPPED_STATUS_UNCHANGED_EXIT",
        "THREE_RESULT_ATOMIC",
        "FAILPOINT_ATOMIC",
        "ACTIVE_GC_STRING_ROOTED",
        "C_LINK_CALL:NOT_RUN",
    )
    if (
        len(a41_rows) != 2
        or Counter(str(row["profile"]) for row in a41_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lauxlib.h"
            or row["kind"] != "function"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_execresult"
            or "crates/rivetlua-capi/tests/exec_result.rs:exec_result_a41_matrix:lua55+lua54:PASS"
            not in str(row["evidence"])
            or any(tag not in str(row["evidence"]) for tag in a41_tags)
            for row in a41_rows
        )
    ):
        raise ValueError("P16-2A41 execresult 兩版 mapping、矩陣或限制回歸")
    a42_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A42_IMPLEMENTED]
    a42_contract = f";{P16_2A42_EVIDENCE}"
    if (
        len(a42_rows) != 2
        or Counter(str(row["profile"]) for row in a42_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lauxlib.h"
            or row["kind"] != "function"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_len"
            or "crates/rivetlua-capi/tests/aux_len.rs:aux_len_a42_matrix:lua55+lua54:PASS"
            not in str(row["evidence"])
            or a42_contract not in str(row["evidence"])
            for row in a42_rows
        )
    ):
        raise ValueError("P16-2A42 luaL_len 兩版 mapping、矩陣或契約回歸")
    a43_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A43_IMPLEMENTED]
    if (
        len(a43_rows) != 16
        or Counter(str(row["profile"]) for row in a43_rows) != {"lua54": 8, "lua55": 8}
        or any(
            row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["implementation_mapping"] != (
                f"rivetlua-capi::stack::{row['name']}" if row["kind"] == "function"
                else f"include/rivetlua/{row['profile']}/lua.h::lua_pushcfunction"
            )
            or "C_LINK_CALL:NOT_RUN" not in str(row["evidence"])
            for row in a43_rows
        )
        or any(
            "UNPUBLISHED_TRANSACTION_GC_DEFERRED_TO_NEXT_SAFE_ALLOCATION" not in str(row["evidence"])
            for row in a43_rows if row["name"] == "lua_pushcclosure"
        )
        or any(
            f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY"
            not in str(row["evidence"])
            for row in a43_rows if row["kind"] == "macro"
        )
    ):
        raise ValueError("P16-2A43 兩版八列、mapping、GC 延後與巨集展開證據回歸")
    a44_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A44_IMPLEMENTED]
    if (
        len(a44_rows) != 2
        or Counter(str(row["profile"]) for row in a44_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lauxlib.h"
            or row["kind"] != "function"
            or row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_setfuncs"
            or "crates/rivetlua-capi/tests/aux_setfuncs.rs:aux_setfuncs_a44_matrix:lua55+lua54:PASS"
            not in str(row["evidence"])
            or "PER_ENTRY_ATOMIC;ORIGINAL_CAPTURES_POP_AFTER_ALL_SUCCESS" not in str(row["evidence"])
            or "LUA_REGISTER:NOT_IMPLEMENTED" in str(row["evidence"])
            or "LUAL_NEWLIB:NOT_IMPLEMENTED" in str(row["evidence"])
            for row in a44_rows
        )
    ):
        raise ValueError("P16-2A44 luaL_setfuncs 兩版 mapping 與交易證據回歸")
    a45_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A45_IMPLEMENTED]
    a45_evidence = (
        "crates/rivetlua-capi/tests/aux_string.rs:aux_gsub_a45_matrix:lua55+lua54:PASS"
        ";NONEMPTY_PATTERN_CALLER_PRECONDITION;EMPTY_PATTERN_FAIL_CLOSED"
        ";NULL_STATE_S_P_R_FAIL_CLOSED;STACK_EFFECT=-0,+1,m"
        ";LEFT_TO_RIGHT_NONOVERLAPPING;REPLACEMENT_NOT_RESCANNED;FIRST_NUL_CSTRING"
        ";CHECKED_LENGTH_FIRST_PASS;EXACT_ACCOUNTED_STRINGVIEW_SECOND_PASS"
        ";RETURN_EQUALS_TOP_TOLSTRING;ROOTED_BYTESTRING_SLOT_CLONE_LIFETIME"
        ";ALLOCATION_ORDINALS:7:Host,Host,Host,LuaHeap,LuaHeap,LuaHeap,Host"
        ";NAMED_FAILPOINTS:STRING_BYTES,SLOT,OBJECT,OBJECT_INITIALIZE,ROOT,HOST_LEASE"
        ";ACTIVE_GC:INCREMENTAL_GENERATIONAL_MARK_WORK;COLLECT_EVERY_ALLOCATION:BOTH"
        ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS;C_LINK_CALL:NOT_RUN"
    )
    if (
        len(a45_rows) != 2
        or Counter(str(row["profile"]) for row in a45_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lauxlib.h"
            or row["kind"] != "function"
            or row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["implementation_mapping"] != "rivetlua-capi::stack::luaL_gsub"
            or a45_evidence not in str(row["evidence"])
            for row in a45_rows
        )
    ):
        raise ValueError("P16-2A45 luaL_gsub 兩版 mapping、限制或交易證據回歸")
    a46_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A46_IMPLEMENTED]
    a46_evidence = (
        "crates/rivetlua-capi/tests/scalar_introspection.rs:aux_alloc_a46_matrix:lua55:PASS"
        ";LUA55_ONLY;UD_OSIZE_IGNORED;NSIZE_ZERO_FREE_AND_NULL"
        ";NULL_PTR_REALLOC_ALLOC;GROW_SHRINK_PREFIX_PRESERVED"
        ";REALLOC_FAILURE_OLD_BLOCK_REMAINS_VALID"
        ";C_HEAP_ONLY_NO_VM_STATE_LEDGER_GC"
        ";VALID_C_ALLOCATOR_POINTER_PRECONDITION;C_LINK_CALL:NOT_RUN"
    )
    if (
        len(a46_rows) != 1
        or Counter(str(row["profile"]) for row in a46_rows) != {"lua55": 1}
        or any(
            row["header"] != "lauxlib.h"
            or row["kind"] != "function"
            or row["line"] != 84
            or row["profile_difference"] != "only-lua55"
            or row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["implementation_mapping"] != "rivetlua-capi::luaL_alloc"
            or a46_evidence not in str(row["evidence"])
            for row in a46_rows
        )
    ):
        raise ValueError("P16-2A46 luaL_alloc 必須只結案 lua55 row 並保留 C allocator 契約證據")
    a47_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A47_IMPLEMENTED]
    expected_a47_lines = {
        "lua54": {"lua_compare": 238, "lua_equal": 385, "lua_lessthan": 386},
        "lua55": {"lua_compare": 237, "lua_equal": 369, "lua_lessthan": 370},
    }
    if (
        len(a47_rows) != 6
        or Counter(str(row["profile"]) for row in a47_rows) != {"lua54": 3, "lua55": 3}
        or any(
            row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["line"] != expected_a47_lines[str(row["profile"])][str(row["name"])]
            or P16_2A47_EVIDENCE not in str(row["evidence"])
            or (
                row["kind"] == "function"
                and (
                    row["header"] != "lua.h"
                    or row["implementation_mapping"] != "rivetlua-capi::stack::lua_compare"
                    or "tests/p16/surface_" + str(row["profile"]) + ".c:COMPILE_ONLY" not in str(row["evidence"])
                )
            )
            or (
                row["kind"] == "macro"
                and (
                    row["header"] != "luaconf.h"
                    or row["implementation_mapping"]
                    != f"include/rivetlua/{row['profile']}/luaconf.h::{row['name']}"
                    or row["definition"] != P16_2A47_MACRO_DEFINITIONS[str(row["name"])]
                    or row["profile_difference"] != "same"
                    or "MACRO_EXPANSION_COMPILE_ONLY" not in str(row["evidence"])
                    or (
                        row["profile"] == "lua54"
                        and "LUA_COMPAT_5_3_ENABLED_FOR_OFFICIAL_HEADER_MACROS" not in str(row["evidence"])
                    )
                )
            )
            for row in a47_rows
        )
    ):
        raise ValueError("P16-2A47 lua_compare aliases 必須精確結案六列並鎖定固定巨集定義／C 展開證據")
    a48_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A48_IMPLEMENTED]
    if (
        len(a48_rows) != 4
        or Counter(str(row["profile"]) for row in a48_rows) != {"lua54": 2, "lua55": 2}
        or any(
            row["header"] != "lauxlib.h"
            or row["line"] != (46 if row["kind"] == "function" else 47)
            or row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["profile_difference"] != "same"
            or P16_2A48_EVIDENCE not in str(row["evidence"])
            or (
                row["kind"] == "function"
                and row["implementation_mapping"] != "rivetlua-capi::luaL_checkversion_"
            )
            or (
                row["kind"] == "macro"
                and (
                    row["implementation_mapping"] != f"include/rivetlua/{row['profile']}/lauxlib.h::luaL_checkversion"
                    or row["definition"] != "#define luaL_checkversion(L) luaL_checkversion_(L, LUA_VERSION_NUM, LUAL_NUMSIZES)"
                    or f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY"
                    not in str(row["evidence"])
                )
            )
            for row in a48_rows
        )
    ):
        raise ValueError("P16-2A48 checkversion 必須精確四列並保留固定巨集／未執行驗證證據")
    a49_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A49_IMPLEMENTED]
    if (
        len(a49_rows) != 20
        or Counter(str(row["profile"]) for row in a49_rows) != {"lua54": 10, "lua55": 10}
        or any(
            row["header"] != "lauxlib.h"
            or row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or P16_2A49_EVIDENCE not in str(row["evidence"])
            or (row["kind"] == "macro" and f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY" not in str(row["evidence"]))
            for row in a49_rows
        )
    ):
        raise ValueError("P16-2A49 buffer 兩版 20 列語意與巨集證據回歸")
    b0_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2B0_IMPLEMENTED]
    expected_b0_headers = {"lua_register": "lua.h", "luaL_newlib": "lauxlib.h"}
    expected_b0_pairs = Counter({
        (profile, name): 1
        for profile in PROFILES
        for name in P16_2B0_MACRO_DEFINITIONS
    })
    if (
        len(b0_rows) != 4
        or Counter(str(row["profile"]) for row in b0_rows) != {"lua54": 2, "lua55": 2}
        or Counter((str(row["profile"]), str(row["name"])) for row in b0_rows) != expected_b0_pairs
        or any(
            row["header"] != expected_b0_headers.get(str(row["name"]))
            or row["kind"] != "macro"
            or row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["profile_difference"] != "same"
            or row["implementation_mapping"]
            != f"include/rivetlua/{row['profile']}/{row['header']}::{row['name']}"
            or row["definition"] != P16_2B0_MACRO_DEFINITIONS.get(str(row["name"]))
            or f"crates/rivetlua-capi/tests/header_registration.rs:{P16_2B0_IMPLEMENTED[(str(row['kind']), str(row['name']))]}:lua55+lua54:PASS"
            not in str(row["evidence"])
            or f"include/rivetlua/{row['profile']}/{row['header']}:{row['name']}:"
            + P16_2B0_MACRO_SEQUENCES[str(row["name"])] not in str(row["evidence"])
            or f"tests/p16/register_newlib_b0.c:HEADER_MACRO_RUNTIME:PASS" not in str(row["evidence"])
            or "tests/p16/register_newlib_b0.c:C_LINK_RUN:PASS" not in str(row["evidence"])
            or f"tests/p16/surface_{row['profile']}.c:MACRO_EXPANSION_COMPILE_ONLY" not in str(row["evidence"])
            or f"tests/p16/surface_{row['profile']}.c:COMPILE_ONLY" not in str(row["p17_use"])
            for row in b0_rows
        )
    ):
        raise ValueError("P16-2 B0 固定 header 巨集片必須精確四列並保留 Rust、C 執行與 surface 證據")
    a50_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2A50_IMPLEMENTED]
    if (
        len(a50_rows) != 6
        or Counter(str(row["profile"]) for row in a50_rows) != {"lua54": 3, "lua55": 3}
        or any(
            row["header"] != "lua.h"
            or row["owner_step"] != "P16-2"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["implementation_mapping"] != f"rivetlua-capi::stack::{row['name']}"
            or P16_2A50_EVIDENCE not in str(row["evidence"])
            for row in a50_rows
        )
    ):
        raise ValueError("P16-2A50 allocator 三函式兩版 mapping、證據或狀態回歸")
    b2_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2B2_IMPLEMENTED]
    if (
        len(b2_rows) != 12
        or {str(row["id"]) for row in b2_rows} != P16_2B2_ROW_IDS
        or Counter(str(row["profile"]) for row in b2_rows) != {"lua54": 6, "lua55": 6}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != f"rivetlua-capi::{row['name']}"
            or row["evidence"] != b2_evidence(str(row["profile"]), str(row["name"]))
            for row in b2_rows
        )
    ):
        raise ValueError("P16-2 B2 僅准精確結案兩版六函式與指定 mapping／evidence")
    b3_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2B3_IMPLEMENTED]
    if (
        len(b3_rows) != 6
        or {str(row["id"]) for row in b3_rows} != P16_2B3_ROW_IDS
        or Counter(str(row["profile"]) for row in b3_rows) != {"lua54": 3, "lua55": 3}
        or any(
            row["header"] != "lua.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != (
                f"rivetlua-capi::stack::{row['name']}"
                if row["name"] == "lua_tothread" else f"rivetlua-capi::{row['name']}"
            )
            or row["evidence"] != b3_evidence(str(row["profile"]), str(row["name"]))
            for row in b3_rows
        )
    ):
        raise ValueError("P16-2 B3 thread 身分僅准精確結案兩版三函式")
    b5_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2B5_IMPLEMENTED]
    if (
        len(b5_rows) != 8
        or {str(row["id"]) for row in b5_rows} != P16_2B5_ROW_IDS
        or Counter(str(row["profile"]) for row in b5_rows) != {"lua54": 4, "lua55": 4}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != f"rivetlua-capi::{row['name']}"
            or row["evidence"] != b5_evidence(str(row["profile"]), str(row["name"]))
            for row in b5_rows
        )
    ):
        raise ValueError("P16-2 B5 僅准精確結案兩版四個 value operation 函式")
    b6_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2B6_IMPLEMENTED]
    if (
        len(b6_rows) != 4
        or {str(row["id"]) for row in b6_rows} != P16_2B6_ROW_IDS
        or Counter(str(row["profile"]) for row in b6_rows) != {"lua54": 2, "lua55": 2}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != f"rivetlua-capi::{row['name']}"
            or row["evidence"] != b6_evidence(str(row["profile"]), str(row["name"]))
            for row in b6_rows
        )
    ):
        raise ValueError("P16-2 B6 僅准精確結案兩版 warning 函式")
    b7_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2B7_IMPLEMENTED]
    if (
        len(b7_rows) != 4
        or {str(row["id"]) for row in b7_rows} != P16_2B7_ROW_IDS
        or Counter(str(row["profile"]) for row in b7_rows) != {"lua54": 2, "lua55": 2}
        or any(
            row["header"] != "lua.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != f"rivetlua-capi::{row['name']}"
            or row["evidence"] != b7_evidence(str(row["profile"]), str(row["name"]))
            for row in b7_rows
        )
    ):
        raise ValueError("P16-2 B7 僅准精確結案兩版 to-close 函式")
    b8_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2B8_IMPLEMENTED]
    if (
        len(b8_rows) != 2
        or {str(row["id"]) for row in b8_rows} != P16_2B8_ROW_IDS
        or Counter(str(row["profile"]) for row in b8_rows) != {"lua54": 1, "lua55": 1}
        or any(
            row["header"] != "lua.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != "rivetlua-capi::lua_gc"
            or row["evidence"] != b8_evidence(str(row["profile"]))
            for row in b8_rows
        )
    ):
        raise ValueError("P16-2 B8 僅准精確結案兩版 lua_gc")
    b9_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2B9_IMPLEMENTED]
    if (
        len(b9_rows) != 1
        or str(b9_rows[0]["id"]) != P16_2B9_ROW_ID
        or b9_rows[0]["header"] != "lua.h"
        or b9_rows[0]["implementation_status"] != "IMPLEMENTED"
        or b9_rows[0]["owner_step"] != "P16-2"
        or b9_rows[0]["implementation_mapping"] != "rivetlua-capi::lua_pushexternalstring"
        or b9_rows[0]["evidence"] != b9_evidence()
    ):
        raise ValueError("P16-2 B9 僅准精確結案 Lua55 external string")
    b10_rows = [row for row in rows if (str(row["kind"]), str(row["name"])) in P16_2B10_IMPLEMENTED]
    if (
        len(b10_rows) != 18
        or {str(row["id"]) for row in b10_rows} != P16_2B10_ROW_IDS
        or Counter(str(row["profile"]) for row in b10_rows) != {"lua54": 9, "lua55": 9}
        or any(
            row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != (
                "rivetlua-capi::luaL_where"
                if row["name"] == "luaL_where"
                else f"rivetlua-capi::stack::{row['name']}"
            )
            or row["evidence"] != b10_evidence(str(row["profile"]), str(row["name"]))
            for row in b10_rows
        )
    ):
        raise ValueError("P16-2 B10 僅准精確結案兩版各九個 debug 函式")
    b11_rows = [row for row in rows if str(row["id"]) in P16_2B11_ROW_IDS]
    if (
        len(b11_rows) != 6
        or Counter(str(row["profile"]) for row in b11_rows) != {"lua54": 3, "lua55": 3}
        or any(
            row["header"] != "lua.h"
            or row["implementation_status"] != "IMPLEMENTED"
            or row["owner_step"] != "P16-2"
            or row["implementation_mapping"] != (
                "include/rivetlua/lua55/lua.h::lua_resetthread"
                if row["kind"] == "macro"
                else f"rivetlua-capi::trampoline.c::{row['name']}"
            )
            or row["evidence"] != b11_evidence(str(row["profile"]), str(row["name"]))
            for row in b11_rows
        )
    ):
        raise ValueError("P16-2 B11 僅准精確結案兩版 close/reset 共六列")
    evidence_markers = {
        "CLOSE_FINALIZER_CALLBACK:B11_PASS": {
            "lua54:lauxlib.h:function:luaL_newstate:101",
            "lua54:lua.h:function:lua_newstate:163",
            "lua54:lua.h:function:lua_getallocf:358",
            "lua54:lua.h:function:lua_setallocf:359",
            "lua55:lauxlib.h:function:luaL_newstate:104",
            "lua55:lua.h:function:lua_newstate:163",
            "lua55:lua.h:function:lua_getallocf:378",
            "lua55:lua.h:function:lua_setallocf:379",
        },
        "THREAD_RESET_FINAL_STATE_CLOSE:B11_PASS": {
            "lua54:lua.h:function:lua_toclose:361",
            "lua54:lua.h:function:lua_closeslot:362",
            "lua55:lua.h:function:lua_toclose:381",
            "lua55:lua.h:function:lua_closeslot:382",
        },
        "EXECRESULT:A41_PASS": {
            "lua54:lauxlib.h:function:luaL_fileresult:81",
            "lua55:lauxlib.h:function:luaL_fileresult:81",
        },
    }
    for marker, expected_ids in evidence_markers.items():
        actual_ids = {
            str(row["id"])
            for row in rows
            if marker in str(row["evidence"])
        }
        if actual_ids != expected_ids:
            raise ValueError(f"P16 evidence marker {marker} 列數或 ID 回歸：{sorted(actual_ids)}")
    stale_evidence_markers = (
        "CLOSE_FINALIZER_CALLBACK:NOT_IMPLEMENTED",
        "THREAD_RESET_FINAL_STATE_CLOSE:B11_NOT_IMPLEMENTED",
        "EXECRESULT:NOT_IMPLEMENTED",
        "ACTUAL_DEPTH_LIMIT:NOT_IMPLEMENTED",
        "ERROR_TRAMPOLINE:NOT_IMPLEMENTED",
        "UPVALUE_PSEUDOINDEX:NOT_IMPLEMENTED",
        "C_CALLBACK_INVOCATION:NOT_IMPLEMENTED",
        "METAMETHOD_CALLBACK:NOT_IMPLEMENTED",
        "PRIMITIVE_TARGET:NOT_IMPLEMENTED",
        "FULL_USERDATA_TARGET:NOT_IMPLEMENTED",
        "P16_3_PUBLIC_DEBUG_CALLBACK_FRAMES:NOT_IMPLEMENTED",
        "LUA_RESET_CLOSE_RESUME_YIELD:NOT_IMPLEMENTED",
        "CALLBACK_CONTEXT:NOT_IMPLEMENTED",
        "OPEN_LUA_UPVALUE_ACCESS:NOT_IMPLEMENTED",
        "LUA_UPVALUE_NAME:NOT_IMPLEMENTED",
        "PRIMITIVE_TYPE_METATABLES:NOT_IMPLEMENTED",
        "METATABLE_NEWINDEX_CALLBACK:NOT_IMPLEMENTED",
        "UPVALUE_PSEUDOINDEX_CONSUMERS:NOT_IMPLEMENTED",
    )
    if any(
        marker in str(row["evidence"])
        for row in rows
        for marker in stale_evidence_markers
    ):
        raise ValueError("P16-2 evidence 仍含已結案或誤導的負向標記")
    a39_row = next(row for row in rows if row["id"] == "lua54:lua.h:function:lua_setcstacklimit:473")
    if "ACTUAL_DEPTH_LIMIT:NOT_IMPLEMENTED" in str(a39_row["evidence"]):
        raise ValueError("P16-2A39 lua_setcstacklimit 不得宣稱 actual depth limit 未實作")
    if len(rows) != 951 or Counter(str(row["implementation_status"]) for row in rows) != {
        "HEADER_ONLY": 538, "IMPLEMENTED": 413
    }:
        raise ValueError("P16-4 B2 全部清單數量回歸")
    p16_2 = [row for row in rows if row["owner_step"] == "P16-2"]
    if Counter(str(row["implementation_status"]) for row in p16_2) != {
        "IMPLEMENTED": 361
    }:
        raise ValueError("P16-2 B11 owner 列數回歸")
    p16_3 = [row for row in rows if row["owner_step"] == "P16-3"]
    if Counter(str(row["implementation_status"]) for row in p16_3) != {"IMPLEMENTED": 32}:
        raise ValueError("P16-3 A6 十六種 API 的兩版列數回歸")
    reserved = [row for row in rows if row["owner_step"] in {"P16-4", "P16-5"}]
    if Counter((str(row["owner_step"]), str(row["implementation_status"])) for row in reserved) != {
        ("P16-4", "IMPLEMENTED"): 2,
        ("P16-5", "IMPLEMENTED"): 18,
    } or {str(row["name"]) for row in reserved if row["owner_step"] == "P16-4"} != {"luaL_requiref"}:
        raise ValueError("P16-4 requiref／P16-5 load 實作列回歸")


def complete_rows() -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    module_probe = (ROOT / "tests" / "p16" / "p17_module_probe.c").read_text()
    for profile in PROFILES:
        for header in HEADERS:
            text = (INCLUDE / profile / header).read_text()
            conditions = condition_by_line(text)
            scan_macros(rows, profile, header, text, conditions)
            scan_functions(rows, profile, header, text, conditions)
            scan_typedefs(rows, profile, header, text, conditions)
            scan_layout(rows, profile, header, text, conditions)
    definitions: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for row in rows:
        key = (str(row["profile"]), str(row["header"]), str(row["kind"]), str(row["name"]))
        definitions[key].add(str(row["definition"]))
    for row in rows:
        profile = str(row["profile"])
        opposite = "lua54" if profile == "lua55" else "lua55"
        current_key = (profile, str(row["header"]), str(row["kind"]), str(row["name"]))
        other_key = (opposite, *current_key[1:])
        row["profile_difference"] = (
            f"only-{profile}" if other_key not in definitions
            else "same" if definitions[current_key] == definitions[other_key]
            else "different"
        )
        row["id"] = f"{profile}:{row['header']}:{row['kind']}:{row['name']}:{row['line']}"
        key = (str(row["kind"]), str(row["name"]))
        row["owner_step"], row["implementation_status"] = classify(row)
        row["implementation_mapping"] = (
            f"rivetlua-capi::{row['name']}" if row["kind"] == "function"
            else f"include/rivetlua/{profile}/{row['header']}::{row['name']}"
        )
        row["evidence"] = f"tests/p16/surface_{profile}.c:COMPILE_ONLY"
        uses_probe = re.search(rf"\b{re.escape(str(row['name']))}\b", module_probe) is not None
        row["p17_use"] = (
            f"tests/p16/surface_{profile}.c:COMPILE_ONLY; "
            + ("tests/p16/p17_module_probe.c:COMPILE_ONLY; " if uses_probe else "")
            + "official-module:NOT_RUN"
        )
        evidence = implemented_p16_2_rows(profile).get((str(row["kind"]), str(row["name"])))
        if row["owner_step"] == "P16-2" and evidence is not None:
            row["implementation_status"] = "IMPLEMENTED"
            coverage = (
                "lua55:PASS" if key in P16_2A2_LUA55_ONLY
                else "lua54:PASS" if key in (P16_2A10_LUA54_ONLY | P16_2A11_LUA54_ONLY)
                else "lua54:PASS" if key in P16_2A39_IMPLEMENTED
                else f"{profile}:PASS" if key == ("macro", "luaL_pushfail")
                else "lua55:PASS" if key in (P16_2A14_IMPLEMENTED | P16_2A46_IMPLEMENTED)
                else "lua55+lua54:NOT_RUN" if key in P16_2A48_IMPLEMENTED
                else "lua55+lua54:PASS"
            )
            row["evidence"] = (
                f"tests/p16/surface_{profile}.c:COMPILE_ONLY"
                if key in P16_2A32_IMPLEMENTED
                else f"tests/p16/{evidence[0]}:HEADER_MACRO_RUNTIME:PASS"
                if key in P16_2A34_IMPLEMENTED
                else f"tests/p16/{evidence[0]}:UPVALUE_INDEX_RUNTIME:PASS"
                if key == ("macro", "lua_upvalueindex")
                else f"crates/rivetlua-capi/tests/{evidence[0]}:{evidence[1]}:{coverage}"
            )
            if row["kind"] == "macro" and (str(row["kind"]), str(row["name"])) in (P16_2A2_IMPLEMENTED | P16_2A3_IMPLEMENTED | P16_2A5_IMPLEMENTED | P16_2A47_IMPLEMENTED | P16_2A48_IMPLEMENTED | P16_2A49_IMPLEMENTED | P16_2B0_IMPLEMENTED):
                row["evidence"] += f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
            if key in P16_2A34_IMPLEMENTED:
                semantic = (
                    "DIRECT_PUBLIC_FIELD_ACCESS"
                    if row["name"] in {"luaL_bufflen", "luaL_buffaddr"}
                    else "DIRECT_N_FIELD_ADD"
                    if row["name"] == "luaL_addsize"
                    else "DIRECT_N_FIELD_SUB"
                )
                row["evidence"] += (
                    f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                    f";include/rivetlua/{profile}/lauxlib.h:{row['name']}:{semantic}"
                    ";RIVETLUA_C_LINK_CALL:NOT_RUN"
                )
            if key in P16_2A35_IMPLEMENTED:
                row["evidence"] += f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                if row["name"] == "lua_upvalueindex":
                    row["evidence"] += (
                        f";include/rivetlua/{profile}/lua.h:lua_upvalueindex:"
                        "DIRECT_REGISTRY_INDEX_SUBTRACTION"
                        ";UPVALUE_PSEUDOINDEX_CONSUMERS:A4B_LOCAL_PASS"
                        ";RIVETLUA_C_LINK_CALL:NOT_RUN"
                    )
                else:
                    row["evidence"] += (
                        f";include/rivetlua/{profile}/lauxlib.h:luaL_newlibtable:"
                        "DIRECT_FORWARD_CREATETABLE_NARR_0_NREC_ARRAY_MINUS_SENTINEL"
                        ";CALLER_ARRAY_WITH_SENTINEL_PRECONDITION"
                        ";C_RUNTIME_CALL:NOT_RUN"
                    )
            if key in P16_2B0_IMPLEMENTED:
                row["evidence"] += (
                    f";include/rivetlua/{profile}/{row['header']}:{row['name']}:"
                    f"{P16_2B0_MACRO_SEQUENCES[row['name']]}"
                    ";tests/p16/register_newlib_b0.c:HEADER_MACRO_RUNTIME:PASS"
                    ";tests/p16/register_newlib_b0.c:C_LINK_RUN:PASS"
                )
            if key in P16_2A36_IMPLEMENTED:
                row["evidence"] += (
                    ";PUBLIC_MAIN_STATE:LUA_OK"
                    ";MAIN_STATE_NOT_YIELDABLE"
                    ";RUST_OVERLAY_NOT_PUBLIC_CHILD"
                    ";STACK_ROOTS_LEDGER_ALLOCATION_GC_TRACE:UNCHANGED"
                    f";{P16_2B3_MAIN_CHILD_EVIDENCE}"
                    ";COROUTINE_CHILD_STATE:B3_PASS"
                    ";CALLBACK_CONTEXT:A5_LOCAL_PASS"
                )
            if key in P16_2A37_IMPLEMENTED:
                row["evidence"] += (
                    ";OPAQUE_NON_DEREFERENCEABLE_RUNTIME_TOKEN"
                    ";FULL_USERDATA_MEMORY_BLOCK"
                    ";LIGHTUSERDATA_VALUE"
                    ";VM_GENERATION_VALIDATED"
                    ";STACK_ROOTS_LEDGER_ALLOCATION_GC_TRACE_UNCHANGED"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";C_LINK_CALL:NOT_RUN"
                )
            if key in P16_2A38_IMPLEMENTED:
                row["evidence"] += (
                    ";PUBLIC_PREFIX_FIELDS:b,size,n,L"
                    ";B_EQUALS_INIT_BUFFER"
                    ";SIZE_LUAL_BUFFERSIZE_1024"
                    ";N_ZERO"
                    ";STATE_POINTER"
                    ";INIT_BYTES_UNCHANGED"
                    ";STACK_LIGHTUSERDATA_PLACEHOLDER"
                    ";GROWTH_ROOTED_USERDATA_BOX"
                    ";RESULT_REPLACES_ANCHOR"
                )
            if key in P16_2A39_IMPLEMENTED:
                row["evidence"] += (
                    ";LUA54_ONLY"
                    ";OFFICIAL_5_4_9_NOOP"
                    ";RETURNS_LUAI_MAXCCALLS_200"
                    ";LIMIT_IGNORED"
                    ";STATE_VALIDATED"
                    ";STACK_ROOTS_LEDGER_ALLOCATION_GC_TRACE_STATUS_UNCHANGED"
                    ";C_LINK_CALL:NOT_RUN"
                )
            if key in P16_2A40_IMPLEMENTED:
                row["evidence"] += (
                    ";ERRNO_CAPTURED_BEFORE_STATE_API"
                    ";STAT_NONZERO_TRUE_ONE_RESULT"
                    ";STAT_ZERO_NIL_MESSAGE_ERRNO_THREE_RESULTS"
                    ";FNAME_RAW_BYTES_PREFIX"
                    ";ERRNO_ZERO_NO_EXTRA_INFO"
                    ";FAILPOINT_ATOMIC"
                    ";ACTIVE_GC_STRING_ROOTED"
                    ";EXECRESULT:A41_PASS"
                    ";C_LINK_CALL:NOT_RUN"
                )
            if key in P16_2A41_IMPLEMENTED:
                row["evidence"] += (
                    ";ERRNO_CAPTURED_BEFORE_STATE_API"
                    ";NONZERO_STAT_ERRNO_TO_FILERESULT"
                    ";POSIX_WAIT_STATUS_DECODE"
                    ";EXIT_ZERO_TRUE_EXIT_ZERO"
                    ";EXIT_NONZERO_NIL_EXIT_CODE"
                    ";SIGNAL_NIL_SIGNAL_NUMBER"
                    ";STOPPED_STATUS_UNCHANGED_EXIT"
                    ";THREE_RESULT_ATOMIC"
                    ";FAILPOINT_ATOMIC"
                    ";ACTIVE_GC_STRING_ROOTED"
                    ";C_LINK_CALL:NOT_RUN"
                )
            if key in P16_2A42_IMPLEMENTED:
                row["evidence"] += f";{P16_2A42_EVIDENCE}"
            if key in P16_2A43_IMPLEMENTED:
                row["evidence"] += (
                    ";crates/rivetlua-capi/tests/c_closure.rs:"
                    "c_closure_a43_active_gc_failed_publish_keeps_trace:lua55+lua54:PASS"
                    ";crates/rivetlua-runtime/tests/capi_c_closure.rs:"
                    "capi_lua_closure_join_shares_closed_cell_and_rejects_invalid:PASS"
                    ";C_CALLBACK_INVOCATION:A4B_LOCAL_PASS"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                    ";C_LINK_CALL:NOT_RUN"
                )
                if row["name"] == "lua_pushcclosure":
                    row["evidence"] += (
                        ";UNPUBLISHED_TRANSACTION_GC_DEFERRED_TO_NEXT_SAFE_ALLOCATION"
                        ";crates/rivetlua-runtime/src/heap.rs:"
                        "gc_running_tests::c_closure_transaction_defers_automatic_gc_to_next_safe_allocation:PASS"
                    )
                if row["name"] in {"lua_getupvalue", "lua_setupvalue"}:
                    row["evidence"] += (
                        ";OPEN_LUA_UPVALUE_ACCESS:A4B_LOCAL_PASS"
                        ";LUA_UPVALUE_NAME:A4B_LOCAL_PASS"
                    )
                if row["kind"] == "macro":
                    row["evidence"] += (
                        f";include/rivetlua/{profile}/{row['header']}:"
                        "lua_pushcfunction:DIRECT_EXPANSION"
                        f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                    )
            if key in P16_2A44_IMPLEMENTED:
                row["evidence"] += (
                    ";NUP_0_TO_255;NULL_FUNC_FALSE;NULL_NAME_SENTINEL;ORDERED_NAMED_WRITES"
                    ";INDEPENDENT_CLOSURE_CELLS;PER_ENTRY_ATOMIC;ORIGINAL_CAPTURES_POP_AFTER_ALL_SUCCESS"
                    ";ACTIVE_INCREMENTAL_AND_GENERATIONAL_GC;UNPUBLISHED_TRANSACTION_GC_DEFERRED_TO_NEXT_SAFE_ALLOCATION"
                    ";ALLOCATION_ORDINAL_AND_NAMED_FAILPOINT_ROLLBACK_RETRY"
                    ";C_CALLBACK_INVOCATION:A4B_LOCAL_PASS;METATABLE_NEWINDEX_CALLBACK:A4A_LOCAL_PASS"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS;ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                    ";C_LINK_CALL:NOT_RUN"
                )
            if key in P16_2A45_IMPLEMENTED:
                row["implementation_mapping"] = "rivetlua-capi::stack::luaL_gsub"
                row["evidence"] += (
                    ";NONEMPTY_PATTERN_CALLER_PRECONDITION;EMPTY_PATTERN_FAIL_CLOSED"
                    ";NULL_STATE_S_P_R_FAIL_CLOSED;STACK_EFFECT=-0,+1,m"
                    ";LEFT_TO_RIGHT_NONOVERLAPPING;REPLACEMENT_NOT_RESCANNED;FIRST_NUL_CSTRING"
                    ";CHECKED_LENGTH_FIRST_PASS;EXACT_ACCOUNTED_STRINGVIEW_SECOND_PASS"
                    ";RETURN_EQUALS_TOP_TOLSTRING;ROOTED_BYTESTRING_SLOT_CLONE_LIFETIME"
                    ";ALLOCATION_ORDINALS:7:Host,Host,Host,LuaHeap,LuaHeap,LuaHeap,Host"
                    ";NAMED_FAILPOINTS:STRING_BYTES,SLOT,OBJECT,OBJECT_INITIALIZE,ROOT,HOST_LEASE"
                    ";ACTIVE_GC:INCREMENTAL_GENERATIONAL_MARK_WORK;COLLECT_EVERY_ALLOCATION:BOTH"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS;C_LINK_CALL:NOT_RUN"
                )
            if key in P16_2A46_IMPLEMENTED:
                row["implementation_mapping"] = "rivetlua-capi::luaL_alloc"
                row["evidence"] += (
                    ";LUA55_ONLY;UD_OSIZE_IGNORED;NSIZE_ZERO_FREE_AND_NULL"
                    ";NULL_PTR_REALLOC_ALLOC;GROW_SHRINK_PREFIX_PRESERVED"
                    ";REALLOC_FAILURE_OLD_BLOCK_REMAINS_VALID"
                    ";C_HEAP_ONLY_NO_VM_STATE_LEDGER_GC"
                    ";VALID_C_ALLOCATOR_POINTER_PRECONDITION;C_LINK_CALL:NOT_RUN"
                )
            if key in P16_2A47_IMPLEMENTED:
                row["evidence"] += f";{P16_2A47_EVIDENCE}"
                if row["kind"] == "function":
                    row["evidence"] += f";tests/p16/surface_{profile}.c:COMPILE_ONLY"
                elif profile == "lua54":
                    row["evidence"] += ";LUA_COMPAT_5_3_ENABLED_FOR_OFFICIAL_HEADER_MACROS"
            if key in P16_2A48_IMPLEMENTED:
                row["evidence"] += f";{P16_2A48_EVIDENCE}"
            if key in P16_2A49_IMPLEMENTED:
                row["evidence"] += f";{P16_2A49_EVIDENCE}"
                if row["kind"] == "macro":
                    row["evidence"] = row["evidence"].replace(
                        f"crates/rivetlua-capi/tests/aux_buffer.rs:C_LINK_RUN:lua55+lua54:PASS",
                        "tests/p16/aux_buffer_a49.c:C_LINK_RUN:lua55+lua54:PASS",
                        1,
                    )
            if key in P16_2A50_IMPLEMENTED:
                row["evidence"] += f";{P16_2A50_EVIDENCE}"
            if key in P16_2B2_IMPLEMENTED:
                row["evidence"] = b2_evidence(profile, str(row["name"]))
            if key in P16_2B3_IMPLEMENTED:
                row["evidence"] = b3_evidence(profile, str(row["name"]))
            if key in P16_2B5_IMPLEMENTED:
                row["evidence"] = b5_evidence(profile, str(row["name"]))
            if key in P16_2B6_IMPLEMENTED:
                row["evidence"] = b6_evidence(profile, str(row["name"]))
            if key in P16_2B7_IMPLEMENTED:
                row["evidence"] = b7_evidence(profile, str(row["name"]))
            if key in P16_2B8_IMPLEMENTED:
                row["evidence"] = b8_evidence(profile)
            if key in P16_2B10_IMPLEMENTED:
                row["evidence"] = b10_evidence(profile, str(row["name"]))
            if str(row["id"]) in P16_2B11_ROW_IDS:
                row["evidence"] = b11_evidence(profile, str(row["name"]))
            if profile == "lua55" and key in P16_2B9_IMPLEMENTED:
                row["evidence"] = b9_evidence()
            if key in {
                ("function", "lua_settop"),
                ("function", "lua_rotate"),
                ("function", "lua_copy"),
                ("function", "lua_xmove"),
            }:
                row["evidence"] += (
                    ";crates/rivetlua-capi/tests/to_close_slots.rs:"
                    "marks_stay_at_positions_across_rotate_copy_and_xmove_b7:lua55+lua54:PASS"
                    ";B7_POSITION_MARK_BOUNDARY_AND_ROOT_PRESERVATION"
                )
            if (str(row["kind"]), str(row["name"])) in {
                ("function", "lua_rawgeti"), ("function", "lua_rawseti")
            }:
                row["evidence"] += f";REGISTRY_PSEUDOINDEX:PASS;{P16_2A5_REGISTRY_EVIDENCE}"
            if (str(row["kind"]), str(row["name"])) in P16_2A4_IMPLEMENTED:
                scope = "REAL_STACK_INDICES_ONLY" if row["name"] == "lua_rawequal" else "REAL_STACK_TABLE_ONLY"
                row["evidence"] += f";A4_STAGE:{scope};REGISTRY_PSEUDOINDEX:PASS;{P16_2A5_REGISTRY_EVIDENCE}"
            if (str(row["kind"]), str(row["name"])) in P16_2A6_IMPLEMENTED:
                row["evidence"] += (
                    ";crates/rivetlua-runtime/tests/capi_table_adapter.rs:"
                    "capi_raw_len_adapter_validates_objects_and_preserves_gc_accounting:PASS"
                    ";FULL_USERDATA:PASS"
                    ";crates/rivetlua-capi/tests/full_userdata.rs:full_userdata_a28_matrix:lua55+lua54:PASS"
                )
                if row["kind"] == "macro":
                    row["evidence"] += f";include/rivetlua/{profile}/{row['header']}:{row['name']}:DIRECT_FORWARD_TO_lua_rawlen"
            if (str(row["kind"]), str(row["name"])) in P16_2A7_IMPLEMENTED:
                row["evidence"] += f";include/rivetlua/{profile}/{row['header']}:{row['name']}:DIRECT_DEFINITION"
            if (str(row["kind"]), str(row["name"])) in P16_2A8_IMPLEMENTED:
                if row["name"] == "lua_isuserdata":
                    row["evidence"] += (
                        ";FULL_USERDATA_CONSTRUCTION:PASS"
                        ";crates/rivetlua-capi/tests/full_userdata.rs:full_userdata_a28_matrix:lua55+lua54:PASS"
                        ";A7_FUNCTION_THREAD_FALSE:"
                        "crates/rivetlua-capi/tests/type_predicates.rs:"
                        "type_predicates_a7_matrix:lua55+lua54:PASS"
                    )
            if (str(row["kind"]), str(row["name"])) in P16_2A9_IMPLEMENTED:
                row["evidence"] += (
                    ";crates/rivetlua-runtime/tests/capi_table_adapter.rs:"
                    "capi_raw_next_adapter_is_pure_content_equal_and_roots_objects:PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                    ";DELETED_CURRENT_KEY:B13_PASS"
                    ";crates/rivetlua-capi/tests/next_stack.rs:next_stack_deleted_current_key_b13:lua55+lua54:PASS"
                    ";crates/rivetlua-runtime/tests/capi_table_adapter.rs:capi_raw_next_deleted_current_key_b13:lua55+lua54:PASS"
                    ";crates/rivetlua-runtime/tests/p13_contracts.rs:p13_basic_next_deleted_current_key_b13:lua55+lua54:PASS"
                    ";tests/p16/deleted_current_next_b13.c:lua55+lua54:COMPILE_LINK_RUN_PASS"
                )
            if key in (P16_2A10_IMPLEMENTED | P16_2A10_LUA54_ONLY):
                row["evidence"] += (
                    ";ERROR_TRAMPOLINE:B7_CLOSE_PATH_ONLY"
                    if key == ("function", "lua_settop")
                    else ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                )
                if row["kind"] == "macro":
                    row["evidence"] += (
                        f";include/rivetlua/{profile}/{row['header']}:"
                        f"{row['name']}:DIRECT_EXPANSION"
                        f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                    )
            if key in (P16_2A11_IMPLEMENTED | P16_2A11_LUA54_ONLY):
                row["evidence"] += ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                if row["name"] == "lua_type":
                    row["evidence"] += ";crates/rivetlua-capi/tests/full_userdata.rs:full_userdata_a28_matrix:lua55+lua54:PASS"
                if row["kind"] == "macro":
                    row["evidence"] += (
                        f";include/rivetlua/{profile}/{row['header']}:"
                        f"{row['name']}:DIRECT_EXPANSION"
                        f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                    )
            if key in P16_2A12_IMPLEMENTED:
                if row["name"] != "lua_pushvalue":
                    row["evidence"] += (
                        ";REGISTRY_DESTINATION:PASS"
                        ";crates/rivetlua-capi/tests/value_copy.rs:registry_destination_b12_matrix:lua55+lua54:PASS"
                        ";tests/p16/registry_destination_b12.c:lua55+lua54:COMPILE_LINK_RUN_PASS"
                    )
                row["evidence"] += (
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                )
                if row["kind"] == "macro":
                    row["evidence"] += (
                        f";include/rivetlua/{profile}/{row['header']}:"
                        f"{row['name']}:DIRECT_EXPANSION"
                        f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                    )
            if key in P16_2A13_IMPLEMENTED:
                row["evidence"] += (
                    ";INVALID_REFERENCE_FAIL_CLOSED"
                    ";VALID_HANDLE_PRECONDITION:SAME_TABLE_ACTIVE_REF"
                    ";REGISTRY_PSEUDOINDEX:PASS"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                    + (
                        f";{P16_2B3_MAIN_CHILD_EVIDENCE};MAINTHREAD_REGISTRY_ENTRY:B3_PASS"
                        if profile == "lua55" else ""
                    )
                )
            if key in P16_2A14_IMPLEMENTED:
                row["evidence"] += (
                    ";TEST_CALLS_HELPER:makeseed_a14_matrix"
                    ";crates/rivetlua-capi/src/lib.rs:"
                    "seed_tests::makeseed_fixed_vectors:lua55:PASS"
                    ";STATE_UNUSED_NULL_VALID_BUSY"
                    ";STATE_PURITY:STACK_ROOTS_LEDGER_GC_TRACE"
                    ";CRYPTOGRAPHIC_ENTROPY:NOT_CLAIMED"
                )
            if key in P16_2A15_IMPLEMENTED:
                row["evidence"] += (
                    ";NORMAL_RESERVATION:PASS"
                    ";FAULT_TRACE:EXPECTED_SINGLE_ATTEMPT"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                    ";MESSAGE_ERROR_PATH:NOT_EXERCISED"
                )
            if key in P16_2A16_IMPLEMENTED:
                if row["kind"] == "function":
                    row["evidence"] += (
                        ";NORMAL_NUMERIC_COERCION:PASS"
                        ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                        ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    )
                    if row["name"] in {"luaL_optnumber", "luaL_optinteger"}:
                        row["evidence"] += ";NONE_NIL_DEFAULT_ONLY:PASS"
                else:
                    row["evidence"] += (
                        f";include/rivetlua/{profile}/{row['header']}:"
                        f"{row['name']}:DIRECT_EXPANSION"
                        f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                    )
                    if row["name"] == "luaL_opt":
                        row["evidence"] += (
                            ";crates/rivetlua-capi/tests/type_predicates.rs:"
                            "type_predicates_a7_matrix:lua55+lua54:PASS"
                            ";GENERIC_FUNCTION_CALLER_PROVIDED"
                            ";C_LINK_CALL:NOT_RUN"
                        )
                    else:
                        row["evidence"] += (
                            ";UNDERLYING_INTEGER_FUNCTIONS:PASS"
                            ";C_CAST_SEMANTICS:HEADER_DEFINED"
                            ";C_RUNTIME_CALL:NOT_RUN"
                        )
            if key in P16_2A18_IMPLEMENTED:
                if row["kind"] == "function":
                    row["evidence"] += (
                        ";NORMAL_STRING_NUMBER_COERCION:PASS"
                        ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                        ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    )
                    if row["name"] == "luaL_optlstring":
                        row["evidence"] += (
                            ";NONE_NIL_DEFAULT_ONLY:PASS"
                            ";DEFAULT_C_STRING_LENGTH:PASS"
                        )
                else:
                    row["evidence"] += (
                        f";include/rivetlua/{profile}/{row['header']}:"
                        f"{row['name']}:DIRECT_EXPANSION"
                        f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                        ";C_RUNTIME_CALL:NOT_RUN"
                    )
            if key in P16_2A19_IMPLEMENTED:
                row["evidence"] += (
                    ";TABLE_METATABLE:PASS"
                    ";REGISTRY_PSEUDOINDEX:PASS"
                    ";GC_BARRIER_FINALIZER_WEAK:PASS"
                    ";PRIMITIVE_TYPE_METATABLES:A4A_LOCAL_PASS"
                    ";FULL_USERDATA_METATABLE:PASS"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";crates/rivetlua-capi/tests/userdata_metatable.rs:userdata_metatable_a30_matrix:lua55+lua54:PASS"
                )
                if row["name"] == "lua_setmetatable":
                    row["evidence"] += ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
            if key in P16_2A20_IMPLEMENTED:
                row["evidence"] += (
                    ";TABLE_METATABLE:PASS"
                    ";REGISTRY_PSEUDOINDEX:PASS"
                    ";PRIMITIVE_TYPE_METATABLES:A4A_LOCAL_PASS"
                    ";FULL_USERDATA_METATABLE:PASS"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                    ";crates/rivetlua-capi/tests/userdata_metatable.rs:userdata_metatable_a30_matrix:lua55+lua54:PASS"
                )
            if key in P16_2A21_IMPLEMENTED:
                if row["kind"] == "function":
                    row["evidence"] += (
                        ";DIRECT_TABLE_PATH:PASS"
                        ";METAMETHOD_CALLBACK:A4A_LOCAL_PASS"
                        ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                    )
                    if row["name"] == "lua_getglobal":
                        row["evidence"] += ";GLOBAL_TABLE:PASS"
                    else:
                        row["evidence"] += (
                            ";REGISTRY_PSEUDOINDEX:PASS"
                            ";PRIMITIVE_TARGET:A4A_LOCAL_PASS"
                            ";FULL_USERDATA_TARGET:A4A_LOCAL_PASS"
                            ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                        )
                else:
                    row["evidence"] += (
                        ";UNDERLYING_GETFIELD:PASS"
                        f";include/rivetlua/{profile}/{row['header']}:"
                        "luaL_getmetatable:DIRECT_EXPANSION"
                        f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                        ";C_RUNTIME_CALL:NOT_RUN"
                    )
            if key in P16_2A22_IMPLEMENTED:
                row["evidence"] += (
                    ";DIRECT_TABLE_PATH:PASS"
                    ";REGISTRY_PSEUDOINDEX:PASS"
                    ";GC_BARRIER_WEAK:PASS"
                    ";METAMETHOD_CALLBACK:A4A_LOCAL_PASS"
                    ";PRIMITIVE_TARGET:A4A_LOCAL_PASS"
                    ";FULL_USERDATA_TARGET:A4A_LOCAL_PASS"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                )
            if key in P16_2A23_IMPLEMENTED:
                row["evidence"] += (
                    ";DIRECT_TABLE_PATH:PASS"
                    ";BYTE_KEY_PUBLICATION_CLEANUP:PASS"
                    ";GC_BARRIER_WEAK:PASS"
                    ";METAMETHOD_CALLBACK:A4A_LOCAL_PASS"
                    ";PRIMITIVE_TARGET:A4A_LOCAL_PASS"
                    ";FULL_USERDATA_TARGET:A4A_LOCAL_PASS"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                )
                row["evidence"] += (
                    ";GLOBALS_TABLE:PASS;REGISTRY_RIDX_GLOBALS:PASS"
                    if row["name"] == "lua_setglobal"
                    else ";REGISTRY_PSEUDOINDEX:PASS"
                )
            if key in P16_2A24_IMPLEMENTED:
                row["evidence"] += (
                    ";DIRECT_TABLE_PATH:PASS"
                    ";REGISTRY_PSEUDOINDEX:PASS"
                    ";GET_OR_CREATE_ATOMIC:PASS"
                    ";BYTE_KEY_PUBLICATION_CLEANUP:PASS"
                    ";GC_BARRIER_WEAK:PASS"
                    ";METAMETHOD_CALLBACK:A4A_LOCAL_PASS"
                    ";PRIMITIVE_TARGET:A4A_LOCAL_PASS"
                    ";FULL_USERDATA_TARGET:A4A_LOCAL_PASS"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                )
            if key in P16_2A25_IMPLEMENTED:
                row["evidence"] += (
                    ";REGISTRY_EXISTING_NONNIL:PASS"
                    ";RAW_NAME_FIELD:PASS"
                    ";ATOMIC_TWO_EDGE_PUBLICATION:PASS"
                    ";GC_ROOT_BARRIER:PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                )
            if key in P16_2A26_IMPLEMENTED:
                row["evidence"] += (
                    ";REGISTRY_TABLE_SET:PASS"
                    ";REGISTRY_NIL_CLEAR:PASS"
                    ";TABLE_TARGET:PASS"
                    ";ROOT_GC_FINALIZER_WEAK:PASS"
                    ";REGISTRY_NON_TABLE_FAIL_CLOSED:PASS"
                    ";ALLOCATION_FAILURE_ATOMIC:PASS"
                    ";FULL_USERDATA_TARGET:PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                    ";crates/rivetlua-capi/tests/userdata_metatable.rs:userdata_metatable_a30_matrix:lua55+lua54:PASS"
                )
            if key in P16_2A28_IMPLEMENTED:
                row["evidence"] += (
                    ";FULL_USERDATA_POINTER_ROOT_GC:PASS"
                    ";ALLOCATION_FAILURE_ATOMIC:PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                )
            if key in P16_2A29_IMPLEMENTED:
                row["evidence"] += (
                    ";USERVALUE_FIXED_SLOTS:PASS"
                    ";STACK_ROOT_GC:PASS"
                    ";ALLOCATION_FAILURE_ATOMIC:PASS"
                    ";GENERATIONAL_REMEMBERED_BARRIER:PASS"
                    ";FILE_ZERO_USERVALUES:IMPLEMENTED_NOT_C_TESTED"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
                )
                if row["kind"] == "macro":
                    row["evidence"] += (
                        f";include/rivetlua/{profile}/lua.h:{row['name']}:DIRECT_FORWARD_USERVALUE_INDEX_1"
                        f";tests/p16/surface_{profile}.c:COMPILE_ONLY"
                        ";C_RUNTIME_CALL:NOT_RUN"
                    )
            if key in P16_2A31_IMPLEMENTED:
                row["evidence"] += (
                    ";RAW_METATABLE_IDENTITY:PASS"
                    ";STACK_BALANCE_TEMP_ROOT_GC:PASS"
                    ";ALLOCATION_FAILURE_ATOMIC:PASS"
                    ";CHECKUDATA_ERROR_TRAMPOLINE:B2_PASS"
                    ";PRIMITIVE_TYPE_METATABLES:A4A_LOCAL_PASS"
                    ";UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS"
                    ";INTERNAL_FILE_PAYLOAD:NOT_C_FULL_USERDATA"
                    ";C_LINK_CALL:NOT_RUN"
                    ";OFFICIAL_MODULES:NOT_RUN"
                )
            if (
                row["kind"] == "macro"
                and macro_expansion_fixture_path(row).name == "surface_lua55_failfalse.c"
            ):
                row["evidence"] = str(row["evidence"]).replace(
                    "tests/p16/surface_lua55.c:MACRO_EXPANSION_COMPILE_ONLY",
                    "tests/p16/surface_lua55_failfalse.c:MACRO_EXPANSION_COMPILE_ONLY",
                    1,
                )
                row["p17_use"] = str(row["p17_use"]).replace(
                    "tests/p16/surface_lua55.c:COMPILE_ONLY",
                    "tests/p16/surface_lua55_failfalse.c:COMPILE_ONLY",
                    1,
                )
            if row["kind"] == "function":
                row["implementation_mapping"] = (
                    f"rivetlua-capi::trampoline.c::{row['name']}"
                    if str(row["id"]) in P16_2B11_ROW_IDS
                    else "rivetlua-capi::luaL_makeseed"
                    if key in P16_2A14_IMPLEMENTED
                    else "rivetlua-capi::luaL_alloc"
                    if key in P16_2A46_IMPLEMENTED
                    else "rivetlua-capi::luaL_checkversion_"
                    if key in P16_2A48_IMPLEMENTED
                    else "rivetlua-capi::luaL_where"
                    if key == ("function", "luaL_where")
                    else f"rivetlua-capi::{row['name']}"
                    if key in (P16_2A49_IMPLEMENTED | P16_2B2_IMPLEMENTED | P16_2B5_IMPLEMENTED | P16_2B6_IMPLEMENTED | P16_2B7_IMPLEMENTED | P16_2B8_IMPLEMENTED | P16_2B9_IMPLEMENTED)
                    or key in P16_2B3_IMPLEMENTED and row["name"] != "lua_tothread"
                    else f"rivetlua-capi::stack::{row['name']}"
                )
            elif row["kind"] == "opaque_type":
                row["implementation_mapping"] = "rivetlua-capi::stack::lua_State"
        if row["owner_step"] == "P16-3" and key in P16_3_IMPLEMENTED:
            row["implementation_status"] = "IMPLEMENTED"
            if row["kind"] == "function":
                row["implementation_mapping"] = (
                    "rivetlua-capi::stack::lua_atpanic"
                    if row["name"] == "lua_atpanic"
                    else f"rivetlua-capi::trampoline.c::{row['name']}"
                )
            else:
                row["evidence"] += (
                    f";tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY"
                    f";include/rivetlua/{profile}/{row['header']}:{row['name']}:DIRECT_DEFINITION"
                )
            if key in P16_3_A2_IMPLEMENTED:
                row["evidence"] += f";tests/p16/public_callback_error_a2.c:C_LINK_RUN:{profile}:PASS"
                if row["name"] in {"lua_atpanic", "lua_callk", "lua_pcallk"}:
                    row["evidence"] += (
                        ";crates/rivetlua-capi/tests/public_callback_error.rs:"
                        "public_sync_call_pcall_and_group_panic_binding:lua55+lua54:PASS"
                    )
            if key in P16_3_A3_IMPLEMENTED:
                row["evidence"] += f";tests/p16/public_aux_error_a3.c:C_LINK_RUN:{profile}:PASS"
                if row["name"] == "luaL_traceback":
                    row["evidence"] += (
                        ";crates/rivetlua-capi/tests/public_aux_error.rs:"
                        "public_traceback_accepts_sibling_and_rejects_foreign_vm_atomically:lua55+lua54:PASS"
                    )
            if key in P16_3_A4A_IMPLEMENTED:
                row["evidence"] += (
                    f";tests/p16/public_sync_metamethod_a4a.c:C_LINK_RUN:{profile}:PASS"
                    ";crates/rivetlua-capi/tests/public_sync_metamethod_a4a.rs:"
                    "public_callmeta_missing_and_one_result_a4a:lua55+lua54:PASS"
                )
            if key in P16_3_A5_IMPLEMENTED or row["name"] in {"lua_callk", "lua_pcallk"}:
                row["evidence"] += f";tests/p16/public_yield_resume_a5.c:C_LINK_RUN:{profile}:PASS"
                if row["name"] == "lua_resume":
                    row["evidence"] += (
                        ";crates/rivetlua-capi/tests/public_yield_resume_a5.rs:"
                        "public_resume_non_yielding_coroutine_a5:lua55+lua54:PASS"
                    )
        if row["owner_step"] == "P16-4" and row["name"] == "luaL_requiref":
            row["implementation_status"] = "IMPLEMENTED"
            row["implementation_mapping"] = "rivetlua-capi::trampoline.c::luaL_requiref"
            row["evidence"] += (
                f";tests/p16/native_requiref_b2.c:C_LINK_RUN:{profile}:PASS"
                ";crates/rivetlua-capi/tests/native_bridge.rs:"
                "protected_requiref_keeps_prefix_and_cached_result:lua55+lua54:PASS"
            )
        if row["owner_step"] == "P16-5" and (
            row["name"] in P16_5_API_FUNCTIONS | P16_5_API_MACROS
        ):
            row["implementation_status"] = "IMPLEMENTED"
            row["evidence"] += f";tests/p16/load_b3.c:C_LINK_RUN:{profile}:PASS"
            if row["kind"] == "function":
                row["implementation_mapping"] = (
                    f"rivetlua-capi::trampoline.c::{row['name']}"
                )
                test = P16_5_LOAD_TESTS.get(str(row["name"]))
                if test:
                    row["evidence"] += (
                        f";crates/rivetlua-capi/tests/load_api.rs:{test}:lua55+lua54:PASS"
                    )
            else:
                row["implementation_mapping"] = (
                    f"include/rivetlua/{profile}/{row['header']}::{row['name']}"
                )
                row["evidence"] += (
                    f";include/rivetlua/{profile}/{row['header']}:{row['name']}:DIRECT_DEFINITION"
                )
                row["evidence"] += ";RUST_NAMED_SCOPE:UNDERLYING_LOAD_PCALL_CONTRACT"
                for rust_file, rust_test in P16_5_MACRO_RUST_TESTS[str(row["name"])]:
                    row["evidence"] += (
                        f";crates/rivetlua-capi/tests/{rust_file}:{rust_test}:lua55+lua54:PASS"
                    )
        if str(row["id"]) in P16_CORE_API_EFFECT_IDS:
            row["evidence"] += f";tests/p16/acceptance/api_effects.c:C_LINK_RUN:{profile}:PASS"
            if str(row["id"]) in P16_CORE_CROSS_CONTRACT:
                target, test = P16_CORE_CROSS_CONTRACT[str(row["id"])]
                row["evidence"] += (
                    f";RustCrossContract:crates/rivetlua-capi/tests/{target}.rs:"
                    f"{test}:{profile}:PASS"
                )
            elif "crates/rivetlua-capi/tests/" not in str(row["evidence"]):
                raise ValueError(f"缺少直接 Rust 具名證據：{row['id']}")
        if row["kind"] == "macro" and row["name"] == "lua_newuserdata":
            row["evidence"] += (
                f";include/rivetlua/{profile}/lua.h:lua_newuserdata:DIRECT_FORWARD_NUVALUE_1"
                ";crates/rivetlua-capi/tests/full_userdata.rs:full_userdata_a28_matrix:lua55+lua54:PASS"
                ";C_RUNTIME_CALL:NOT_RUN"
            )
            if key in P16_2A32_IMPLEMENTED:
                row["evidence"] += ";ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS"
        if row["kind"] == "function" and row["name"] == "luaL_newstate":
            row["evidence"] += (
                ";DEFAULT_C_OWNED_STATE:PASS;EXTRASPACE:PASS;REGISTRY:PASS"
                ";GLOBALS:PASS;VM_ISOLATION:PASS;DROP:PASS"
                ";CUSTOM_ALLOCATOR:A50:PASS"
                ";tests/p16/allocator_state_a50.c:C_LINK_RUN:lua55+lua54:PASS"
                f";{P16_2B3_MAIN_CHILD_EVIDENCE}"
                ";MAINTHREAD_REGISTRY_ENTRY:B3_PASS"
                ";CLOSE_FINALIZER_CALLBACK:B11_PASS"
                f";tests/p16/warning_callback_b6.c:C_LINK_RUN:{profile}:PASS"
                f";AUX_DEFAULT_WARNING_INITIAL:{'ON' if profile == 'lua55' else 'OFF'}:B6_PASS"
                ";AUX_WARNING_ON_OFF_MULTIPART_PREFIX_NEWLINE:B6_PASS"
            )
        if row["owner_step"] == "P16-2":
            evidence = str(row["evidence"])
            a4b = any(tag in evidence for tag in (
                "UPVALUE_PSEUDOINDEX:A4B_LOCAL_PASS",
                "UPVALUE_PSEUDOINDEX_CONSUMERS:A4B_LOCAL_PASS",
                "C_CALLBACK_INVOCATION:A4B_LOCAL_PASS",
                "OPEN_LUA_UPVALUE_ACCESS:A4B_LOCAL_PASS",
                "LUA_UPVALUE_NAME:A4B_LOCAL_PASS",
            ))
            a4a = any(tag in evidence for tag in (
                "METAMETHOD_CALLBACK:A4A_LOCAL_PASS",
                "PRIMITIVE_TARGET:A4A_LOCAL_PASS",
                "FULL_USERDATA_TARGET:A4A_LOCAL_PASS",
                "PRIMITIVE_TYPE_METATABLES:A4A_LOCAL_PASS",
                "METATABLE_NEWINDEX_CALLBACK:A4A_LOCAL_PASS",
            ))
            a5 = any(tag in evidence for tag in (
                "LUA_RESET_CLOSE_RESUME_YIELD:A5_LOCAL_PASS",
                "CALLBACK_CONTEXT:A5_LOCAL_PASS",
            ))
            a3 = (
                "P16_3_PUBLIC_DEBUG_CALLBACK_FRAMES:A3_LOCAL_PASS" in evidence
                or "ERROR_TRAMPOLINE:C_ONLY_CHECKPOINT_LOCAL_PASS" in evidence
                and not (a4a or a4b)
            )
            for selected, fixture in (
                (a3, "public_aux_error_a3.c"),
                (a4a, "public_sync_metamethod_a4a.c"),
                (a4b, "public_upvalue_a4b.c"),
                (a5, "public_yield_resume_a5.c"),
            ):
                if selected and f"tests/p16/{fixture}:C_LINK_RUN:{profile}:PASS" not in str(row["evidence"]):
                    row["evidence"] += f";tests/p16/{fixture}:C_LINK_RUN:{profile}:PASS"
    actual_core_ids = {str(row["id"]) for row in rows if str(row["id"]) in P16_CORE_API_EFFECT_IDS}
    if len(P16_CORE_API_EFFECT_IDS) != 152 or actual_core_ids != P16_CORE_API_EFFECT_IDS:
        raise ValueError("P16 core API effect 逐列 ID 回歸")
    if len(P16_CORE_CROSS_CONTRACT) != 30 or not P16_CORE_CROSS_CONTRACT.keys() <= P16_CORE_API_EFFECT_IDS:
        raise ValueError("P16 core Rust 跨契約白名單回歸")
    ids = [row["id"] for row in rows]
    if len(ids) != len(set(ids)):
        duplicates = [name for name, count in Counter(ids).items() if count > 1]
        raise ValueError(f"重複清單列：{duplicates[:8]}")
    assert_classification(rows)
    return sorted(rows, key=lambda row: (str(row["profile"]), str(row["header"]), int(row["line"]), str(row["kind"]), str(row["name"])))


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_manifest(rows: list[dict[str, object]]) -> bytes:
    lines = [
        '# 由 tests/p16/generate_manifest.py 產生；每列保留來源行與條件。',
        'schema = "rivetlua-p16-abi-manifest-v1"',
        'abi_revision = 1',
        'target_matrix = ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"]',
        'p16_1_module_link = "NOT_RUN"',
        'p16_1_module_load = "NOT_RUN"',
        'p16_1_module_execution = "NOT_RUN"',
    ]
    for profile, spec in PROFILES.items():
        lines.extend(['', '[[profile]]', f'id = {toml_string(profile)}',
                      f'release = {toml_string(str(spec["release"]))}',
                      f'case_profile = {toml_string(str(spec["case_profile"]))}',
                      'numeric_config = "i64f64"',
                      f'source_archive_sha256 = {toml_string(str(spec["archive_sha256"]))}',
                      f'header_set_sha256 = {toml_string(header_set_sha256(profile))}'])
        for header in HEADERS:
            lines.append(f'{header.replace(".", "_")}_sha256 = {toml_string(str(spec["files"][header]))}')
    keys = ("id", "profile", "header", "line", "kind", "name", "definition", "condition",
            "profile_difference", "implementation_mapping", "implementation_status",
            "owner_step", "evidence", "p17_use")
    for row in rows:
        lines.extend(['', '[[item]]'])
        for key in keys:
            value = row[key]
            lines.append(f'{key} = {value if isinstance(value, int) else toml_string(str(value))}')
    return ("\n".join(lines) + "\n").encode()


def rust_array(value: str) -> str:
    return "[" + ", ".join(f"0x{value[i:i + 2]}" for i in range(0, len(value), 2)) + "]"


def render_rust_hashes() -> bytes:
    lines = [
        "// 由 tests/p16/generate_manifest.py 產生；來源為固定 Lua header bytes。",
        "pub const ABI_REVISION: u32 = 1;",
    ]
    for profile in PROFILES:
        lines.extend(rust_const(f"{profile.upper()}_HEADER_SET_SHA256", header_set_sha256(profile)))
        for name in HEADERS:
            label = name.replace(".", "_").upper()
            value = str(PROFILES[profile]["files"][name])
            lines.extend(rust_const(f"{profile.upper()}_{label}_SHA256", value))
    return ("\n".join(lines) + "\n").encode()


def rust_const(name: str, value: str) -> list[str]:
    parts = [f"0x{value[index:index + 2]}" for index in range(0, len(value), 2)]
    return [
        f"pub const {name}: [u8; 32] = [",
        "    " + ", ".join(parts[:16]) + ",",
        "    " + ", ".join(parts[16:]) + ",",
        "];",
    ]


def render_surface(rows: list[dict[str, object]], profile: str) -> bytes:
    selected = [row for row in rows if row["profile"] == profile]
    functions = sorted({str(row["name"]) for row in selected if row["kind"] == "function"})
    macros = sorted({str(row["name"]) for row in selected if row["kind"] in {"macro", "constant"}})
    types = sorted({str(row["name"]) for row in selected if row["kind"] in {"type", "opaque_type"}})
    layouts = sorted({str(row["name"]) for row in selected if row["kind"] == "layout"})
    fields = sorted({str(row["name"]) for row in selected if row["kind"] == "layout_field"})
    lines = [
        "/* 由 tests/p16/generate_manifest.py 產生；只編譯，不連結或執行。 */",
        "/* A16：條件式相容 API 編譯探測，不代表 Lua 5.5 預設啟用。 */",
        "#ifndef LUA_COMPAT_APIINTCASTS",
        "#define LUA_COMPAT_APIINTCASTS",
        "#endif",
        '#include "lua.h"', '#include "lauxlib.h"', '#include "rivetlua_abi.h"',
        "#include <stddef.h>",
        "_Static_assert(sizeof(lua_Integer) == 8, \"i64\");",
        "_Static_assert(sizeof(lua_Number) == 8, \"f64\");",
        "_Static_assert(sizeof(rivetlua_abi_identity) == 248, \"ABI identity size\");",
        "static const char *rivetlua_p16_b2_vf_probe(lua_State *state, const char *fmt, ...) {",
        "  va_list args;",
        "  va_start(args, fmt);",
        "  const char *result = lua_pushvfstring(state, fmt, args);",
        "  va_end(args);",
        "  return result;",
        "}",
        "void rivetlua_p16_surface_probe(void) {",
    ]
    if profile == "lua54":
        lines.insert(2, "#define LUA_COMPAT_5_3")
    for name in functions:
        lines.append(f"  (void)&{name};")
    for name in types:
        lines.append(f"  (void)sizeof({name}{' *' if name == 'lua_State' else ''});")
    for name in layouts:
        lines.extend([f"  (void)sizeof({name});", f"  (void)_Alignof({name});"])
    for name in fields:
        type_name, field = name.split(".", 1)
        lines.append(f"  (void)offsetof({type_name}, {field});")
    # A2／A16 及後續切片的固定 header 巨集都由同一展開表產生。
    lines.extend(
        macro_expansion_probe_lines(
            rows, profile, ROOT / "tests" / "p16" / f"surface_{profile}.c"
        )
    )
    lines.extend([
        "  /* B2：固定 header 的嚴格 auxiliary 與真 va_list 呼叫形狀。 */",
        "  luaL_checktype((lua_State *)0, 1, LUA_TNUMBER);",
        "  luaL_checkany((lua_State *)0, 1);",
        "  (void)luaL_checkudata((lua_State *)0, 1, \"B2Thing\");",
        "  (void)luaL_checkoption((lua_State *)0, 1, \"a\", (const char *const[]){\"a\", NULL});",
        "  (void)lua_pushfstring((lua_State *)0, \"%d\", 1);",
        "  (void)rivetlua_p16_b2_vf_probe((lua_State *)0, \"%d\", 1);",
        "  /* B3：固定 header 的三個 thread 函式真實呼叫形狀。 */",
        "  (void)lua_newthread((lua_State *)0);",
        "  (void)lua_tothread((lua_State *)0, 1);",
        "  (void)lua_pushthread((lua_State *)0);",
        "  /* B12：固定 header 的 registry destination 實際呼叫形狀。 */",
        "  lua_copy((lua_State *)0, 1, LUA_REGISTRYINDEX);",
        "  /* B13：固定 header 的刪除目前鍵後續走呼叫形狀。 */",
        "  lua_createtable((lua_State *)0, 2, 0);",
        "  lua_pushinteger((lua_State *)0, 1);",
        "  lua_pushnil((lua_State *)0);",
        "  lua_rawset((lua_State *)0, -3);",
        "  lua_pushinteger((lua_State *)0, 1);",
        "  (void)lua_next((lua_State *)0, -2);",
        "  /* B6：兩個 warning 符號以固定 header 真實呼叫形狀探測。 */",
        "  lua_setwarnf((lua_State *)0, (lua_WarnFunction)0, (void *)0);",
        "  lua_warning((lua_State *)0, \"warning\", 1);",
        "  /* B7：固定 header to-close 函式真實呼叫形狀。 */",
        "  lua_toclose((lua_State *)0, 1);",
        "  lua_closeslot((lua_State *)0, 1);",
        "  /* B8：固定 header 的 GC varargs 命令與參數型別。 */",
        "  (void)lua_gc((lua_State *)0, LUA_GCCOLLECT);",
        "  (void)lua_gc((lua_State *)0, LUA_GCSTEP, " + ("(size_t)0" if profile == "lua55" else "0") + ");",
        "  /* B11：固定 header 的 close、thread reset 與 from 參數實際呼叫形狀。 */",
        "  (void)lua_closethread((lua_State *)0, (lua_State *)0);",
        "  (void)lua_resetthread((lua_State *)0);",
        "  lua_close((lua_State *)0);",
        "  /* B10：固定 header 的 debug 查詢、local 與 hook 實際呼叫形狀。 */",
        "  (void)lua_getstack((lua_State *)0, 0, (lua_Debug *)0);",
        "  (void)lua_getinfo((lua_State *)0, \"nSlutr\", (lua_Debug *)0);",
        "  (void)lua_getlocal((lua_State *)0, (const lua_Debug *)0, 1);",
        "  (void)lua_setlocal((lua_State *)0, (const lua_Debug *)0, 1);",
        "  lua_sethook((lua_State *)0, (lua_Hook)0, LUA_MASKCALL, 1);",
        "  (void)lua_gethook((lua_State *)0);",
        "  (void)lua_gethookmask((lua_State *)0);",
        "  (void)lua_gethookcount((lua_State *)0);",
        "  luaL_where((lua_State *)0, 0);",
    ])
    if profile == "lua55":
        lines.extend([
            "  /* B9：固定 Lua55 header 的 external string 原指標呼叫形狀。 */",
            "  (void)lua_pushexternalstring((lua_State *)0, (const char *)0, (size_t)0, (lua_Alloc)0, (void *)0);",
        ])
    lines.append("}")
    for name in macros:
        lines.extend([f"#if defined({name})", f"/* 清單巨集：{name} */", "#endif"])
    return ("\n".join(lines) + "\n").encode()


def render_surface_lua55_failfalse(rows: list[dict[str, object]]) -> bytes:
    fixture = ROOT / "tests" / "p16" / "surface_lua55_failfalse.c"
    lines = [
        "/* 由 tests/p16/generate_manifest.py 產生；只編譯，不連結或執行。 */",
        "/* P16 A10：明確啟用 Lua 5.5 LUA_FAILISFALSE 條件分支。 */",
        "#define LUA_FAILISFALSE",
        '#include "lua.h"',
        '#include "lauxlib.h"',
        "void rivetlua_p16_surface_lua55_failfalse_probe(void) {",
    ]
    lines.extend(macro_expansion_probe_lines(rows, "lua55", fixture))
    lines.append("}")
    return ("\n".join(lines) + "\n").encode()


def render_buffer_macro_runtime_fixture(profile: str) -> bytes:
    lines = [
        "/* 由 tests/p16/generate_manifest.py 產生；只測試固定 header 純巨集。 */",
        '#include "lauxlib.h"',
        "#include <assert.h>",
        "#include <string.h>",
        "",
        "static void assert_buffer(",
        "    luaL_Buffer *buffer, char *storage, const char *expected_storage,",
        "    size_t storage_size, size_t expected_length) {",
        "  assert(luaL_buffaddr(buffer) == storage);",
        "  assert(luaL_bufflen(buffer) == expected_length);",
        "  assert(memcmp(storage, expected_storage, storage_size) == 0);",
        "}",
        "",
        "int main(void) {",
        "  char storage[] = {'a', 'b', 'c', 'd'};",
        "  const char expected_storage[] = {'a', 'b', 'c', 'd'};",
        "  luaL_Buffer buffer = {0};",
        "  buffer.b = storage;",
        "  buffer.n = 0;",
        "  buffer.size = sizeof(storage);",
        "",
        "  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 0);",
        "  luaL_addsize(&buffer, 0);",
        "  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 0);",
        "  luaL_addsize(&buffer, 2);",
        "  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 2);",
        "  luaL_addsize(&buffer, 2);",
        "  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), sizeof(storage));",
        "  luaL_buffsub(&buffer, 0);",
        "  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), sizeof(storage));",
        "  luaL_buffsub(&buffer, 3);",
        "  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 1);",
        "  luaL_buffsub(&buffer, 1);",
        "  assert_buffer(&buffer, storage, expected_storage, sizeof(storage), 0);",
        "  return 0;",
        "}",
    ]
    return ("\n".join(lines) + "\n").encode()


def render_upvalue_index_runtime_fixture(profile: str) -> bytes:
    lines = [
        "/* 由 tests/p16/generate_manifest.py 產生；只測試固定 lua.h 巨集。 */",
        '#include "lua.h"',
        "#include <assert.h>",
        "",
        "int main(void) {",
        "  const int registry_index = LUA_REGISTRYINDEX;",
        "  const int upvalue_1 = lua_upvalueindex(1);",
        "  const int upvalue_2 = lua_upvalueindex(2);",
        "  const int upvalue_255 = lua_upvalueindex(255);",
        "  assert(upvalue_1 == registry_index - 1);",
        "  assert(upvalue_2 == registry_index - 2);",
        "  assert(upvalue_255 == registry_index - 255);",
        "  assert(upvalue_1 > upvalue_2);",
        "  assert(upvalue_2 > upvalue_255);",
        "  assert(LUA_REGISTRYINDEX == registry_index);",
        "  return 0;",
        "}",
    ]
    return ("\n".join(lines) + "\n").encode()


def macro_expansion_fixture_path(row: dict[str, object]) -> Path:
    profile, name = str(row["profile"]), str(row["name"])
    fixture = (
        "surface_lua55_failfalse.c"
        if profile == "lua55"
        and name == "luaL_pushfail"
        and "LUA_FAILISFALSE" in str(row["condition"])
        else f"surface_{profile}.c"
    )
    return ROOT / "tests" / "p16" / fixture


def macro_expansion_probe_lines(
    rows: list[dict[str, object]], profile: str, fixture_path: Path
) -> list[str]:
    expected = {
        str(row["name"])
        for row in rows
        if row["profile"] == profile
        and row["kind"] == "macro"
        and row["implementation_status"] == "IMPLEMENTED"
        and "MACRO_EXPANSION_COMPILE_ONLY" in str(row["evidence"])
        and macro_expansion_fixture_path(row) == fixture_path
    }
    unknown = expected - set(P16_SURFACE_MACRO_EXPANSIONS)
    if unknown:
        raise ValueError(f"沒有 compile-only 展開定義：{profile}:{sorted(unknown)}")
    lines: list[str] = []
    for name, (profiles, expression) in P16_SURFACE_MACRO_EXPANSIONS.items():
        if profile in profiles and name in expected:
            lines.extend([
                f"  /* P16 macro expansion: {name} */",
                f"  {expression}",
            ])
    return lines


def assert_surface_macro_expansion_evidence(
    rows: list[dict[str, object]], fixture_sources: dict[Path, bytes]
) -> None:
    expected_by_profile: dict[str, set[str]] = {profile: set() for profile in PROFILES}
    expected_by_fixture: dict[Path, set[str]] = defaultdict(set)
    failures: list[str] = []
    for row in rows:
        if (
            row["implementation_status"] != "IMPLEMENTED"
            or row["kind"] != "macro"
            or "MACRO_EXPANSION_COMPILE_ONLY" not in str(row["evidence"])
        ):
            continue
        profile, name = str(row["profile"]), str(row["name"])
        fixture = macro_expansion_fixture_path(row)
        fixture_name = fixture.relative_to(ROOT).as_posix()
        expected_by_profile[profile].add(name)
        expected_by_fixture[fixture].add(name)
        expansion = P16_SURFACE_MACRO_EXPANSIONS.get(name)
        if expansion is None:
            failures.append(f"{profile}:{name}: expansion table entry missing")
        elif profile not in expansion[0]:
            failures.append(f"{profile}:{name}: expansion table does not cover profile")
        if f"{fixture_name}:MACRO_EXPANSION_COMPILE_ONLY" not in str(row["evidence"]):
            failures.append(f"{profile}:{name}: evidence points to the wrong fixture")
        if f"{fixture_name}:COMPILE_ONLY" not in str(row["p17_use"]):
            failures.append(f"{profile}:{name}: p17_use points to the wrong fixture")

    table_by_profile = {
        profile: {
            name for name, (profiles, _) in P16_SURFACE_MACRO_EXPANSIONS.items()
            if profile in profiles
        }
        for profile in PROFILES
    }
    for profile in PROFILES:
        if expected_by_profile[profile] != table_by_profile[profile]:
            failures.append(
                f"{profile}: evidence/table set differs; "
                f"evidence={sorted(expected_by_profile[profile])}; "
                f"table={sorted(table_by_profile[profile])}"
            )

    for fixture, expected in expected_by_fixture.items():
        source_bytes = fixture_sources.get(fixture)
        fixture_name = fixture.relative_to(ROOT).as_posix()
        if source_bytes is None:
            failures.append(f"{fixture_name}: fixture missing")
            continue
        source = source_bytes.decode("utf-8")
        markers = re.findall(r"/\* P16 macro expansion: ([A-Za-z_][A-Za-z_0-9]*) \*/", source)
        invocations = re.findall(r"(?m)^\s*\(void\)([A-Za-z_][A-Za-z_0-9]*)\s*\(", source)
        marker_counts = Counter(markers)
        invocation_counts = Counter(name for name in invocations if name in P16_SURFACE_MACRO_EXPANSIONS)
        if set(markers) != expected or len(markers) != len(expected):
            failures.append(
                f"{fixture_name}: marker set differs; expected={sorted(expected)}; "
                f"actual={sorted(markers)}"
            )
        actual_expansions = set(invocation_counts)
        if actual_expansions != expected or sum(invocation_counts.values()) != len(expected):
            failures.append(
                f"{fixture_name}: macro invocation set differs; expected={sorted(expected)}; "
                f"actual={sorted(actual_expansions)}"
            )
        for name in expected:
            expansion = P16_SURFACE_MACRO_EXPANSIONS.get(name)
            if expansion is None:
                continue
            expression = expansion[1]
            marker_expression = f"  /* P16 macro expansion: {name} */\n  {expression}"
            if (
                marker_counts[name] != 1
                or invocation_counts[name] != 1
                or marker_expression not in source
            ):
                failures.append(f"{fixture_name}: {name} lacks one marker and exact expansion")
    if failures:
        raise ValueError("compile-only macro evidence mismatch:\n  " + "\n  ".join(failures))


def assert_buffer_macro_runtime_evidence(
    rows: list[dict[str, object]], fixture_sources: dict[Path, bytes]
) -> None:
    expected_names = {name for kind, name in P16_2A34_IMPLEMENTED if kind == "macro"}
    expected_calls = Counter({
        "luaL_buffaddr": 1,
        "luaL_bufflen": 1,
        "luaL_addsize": 3,
        "luaL_buffsub": 3,
    })
    failures: list[str] = []
    for profile in PROFILES:
        profile_rows = [
            row for row in rows
            if row["profile"] == profile
            and (str(row["kind"]), str(row["name"])) in P16_2A34_IMPLEMENTED
        ]
        actual_names = {str(row["name"]) for row in profile_rows}
        if len(profile_rows) != 4 or actual_names != expected_names:
            failures.append(
                f"{profile}: expected exactly four buffer macros; actual={sorted(actual_names)}"
            )
        fixture = ROOT / "tests" / "p16" / f"buffer_macros_{profile}.c"
        source_bytes = fixture_sources.get(fixture)
        if source_bytes is None:
            failures.append(f"{fixture.relative_to(ROOT).as_posix()}: fixture missing")
            continue
        expected_source = render_buffer_macro_runtime_fixture(profile)
        if source_bytes != expected_source:
            failures.append(f"{fixture.relative_to(ROOT).as_posix()}: runtime source differs from generator")
            continue
        source = source_bytes.decode("utf-8")
        calls = Counter(re.findall(r"\b(luaL_[A-Za-z_][A-Za-z_0-9]*)\s*\(", source))
        if calls != expected_calls:
            failures.append(
                f"{fixture.relative_to(ROOT).as_posix()}: macro call matrix differs; "
                f"expected={dict(expected_calls)}; actual={dict(calls)}"
            )
        for row in profile_rows:
            name = str(row["name"])
            semantic = (
                "DIRECT_PUBLIC_FIELD_ACCESS"
                if name in {"luaL_bufflen", "luaL_buffaddr"}
                else "DIRECT_N_FIELD_ADD"
                if name == "luaL_addsize"
                else "DIRECT_N_FIELD_SUB"
            )
            if (
                f"tests/p16/buffer_macros_{profile}.c:HEADER_MACRO_RUNTIME:PASS"
                not in str(row["evidence"])
                or f"include/rivetlua/{profile}/lauxlib.h:{name}:{semantic}"
                not in str(row["evidence"])
                or "RIVETLUA_C_LINK_CALL:NOT_RUN" not in str(row["evidence"])
            ):
                failures.append(f"{profile}:{name}: runtime evidence incomplete")
    if failures:
        raise ValueError("buffer macro runtime evidence mismatch:\n  " + "\n  ".join(failures))


def assert_upvalue_index_runtime_evidence(
    rows: list[dict[str, object]], fixture_sources: dict[Path, bytes]
) -> None:
    expected_calls = Counter({"lua_upvalueindex": 3})
    failures: list[str] = []
    for profile in PROFILES:
        profile_rows = [
            row for row in rows
            if row["profile"] == profile
            and (str(row["kind"]), str(row["name"])) == ("macro", "lua_upvalueindex")
        ]
        if len(profile_rows) != 1:
            failures.append(f"{profile}: expected exactly one lua_upvalueindex row")
        fixture = ROOT / "tests" / "p16" / f"upvalue_index_{profile}.c"
        source_bytes = fixture_sources.get(fixture)
        if source_bytes is None:
            failures.append(f"{fixture.relative_to(ROOT).as_posix()}: fixture missing")
            continue
        if source_bytes != render_upvalue_index_runtime_fixture(profile):
            failures.append(f"{fixture.relative_to(ROOT).as_posix()}: runtime source differs from generator")
            continue
        source = source_bytes.decode("utf-8")
        calls = Counter(re.findall(r"\b(lua[A-Za-z_0-9]*)\s*\(", source))
        if calls != expected_calls:
            failures.append(
                f"{fixture.relative_to(ROOT).as_posix()}: macro call matrix differs; "
                f"expected={dict(expected_calls)}; actual={dict(calls)}"
            )
        if any(
            row["implementation_status"] != "IMPLEMENTED"
            or f"tests/p16/{fixture.name}:UPVALUE_INDEX_RUNTIME:PASS" not in str(row["evidence"])
            or "UPVALUE_PSEUDOINDEX_CONSUMERS:A4B_LOCAL_PASS" not in str(row["evidence"])
            or "RIVETLUA_C_LINK_CALL:NOT_RUN" not in str(row["evidence"])
            for row in profile_rows
        ):
            failures.append(f"{profile}: runtime evidence or API-call limitation incomplete")
    if failures:
        raise ValueError("upvalue index runtime evidence mismatch:\n  " + "\n  ".join(failures))


def assert_header_registration_runtime_evidence(
    rows: list[dict[str, object]], fixture_sources: dict[Path, bytes]
) -> None:
    fixture = ROOT / "tests" / "p16" / "register_newlib_b0.c"
    source_bytes = fixture_sources.get(fixture)
    failures: list[str] = []
    if source_bytes is None:
        failures.append(f"{fixture.relative_to(ROOT).as_posix()}: fixture missing")
    else:
        source = source_bytes.decode("utf-8")
        macro_calls = Counter(
            name for name in ("lua_register", "luaL_newlib")
            for _ in re.finditer(rf"(?m)^\s*{re.escape(name)}\s*\(", source)
        )
        if macro_calls != Counter({"lua_register": 1, "luaL_newlib": 1}):
            failures.append(f"{fixture.relative_to(ROOT).as_posix()}: macro call count differs: {dict(macro_calls)}")
        required_fixture_contract = (
            '#include "lua.h"',
            '#include "lauxlib.h"',
            "lua_register(registration_state(), registration_name(), registration_function());",
            "CHECK(8, registration.events[0] == 1 && registration.events[1] == 2);",
            "CHECK(11, lua_tocfunction(state, -1) == registered_callback);",
            "luaL_newlib(newlib_state(), library);",
            "if (newlib_state_calls == 3 &&",
            "CHECK(12, newlib_state_calls == 3);",
            "CHECK(13, newlib_order_error == 0);",
            'CHECK(16, lua_getfield(state, 1, "first") == LUA_TFUNCTION);',
            'CHECK(18, lua_getfield(state, 1, "second") == LUA_TFUNCTION);',
            'CHECK(20, lua_getfield(state, 1, "after_sentinel") == LUA_TNIL);',
            "{NULL, NULL},",
        )
        if any(token not in source for token in required_fixture_contract):
            failures.append(f"{fixture.relative_to(ROOT).as_posix()}: runtime contract assertions missing")
        if source.count("{NULL, NULL},") != 2:
            failures.append(f"{fixture.relative_to(ROOT).as_posix()}: sentinel/guard records differ")

    rust_test = ROOT / "crates" / "rivetlua-capi" / "tests" / "header_registration.rs"
    if not rust_test.is_file():
        failures.append(f"{rust_test.relative_to(ROOT).as_posix()}: Rust regression missing")
    else:
        rust_source = rust_test.read_text()
        required_rust_contract = (
            "fn header_registration_b0_rust_primitive_contract()",
            "lua_pushcclosure(",
            "lua_setglobal(",
            "luaL_checkversion_(",
            "luaL_setfuncs(",
            'entry(c"after_sentinel"',
        )
        if any(token not in rust_source for token in required_rust_contract):
            failures.append(f"{rust_test.relative_to(ROOT).as_posix()}: primitive regression contract missing")

    b0_rows = [
        row for row in rows
        if (str(row["kind"]), str(row["name"])) in P16_2B0_IMPLEMENTED
    ]
    expected_profiles = {"lua54": 2, "lua55": 2}
    if len(b0_rows) != 4 or Counter(str(row["profile"]) for row in b0_rows) != expected_profiles:
        failures.append("P16-2 B0: expected both fixed macros in each profile")
    for row in b0_rows:
        profile, name = str(row["profile"]), str(row["name"])
        required_evidence = (
            f"tests/p16/register_newlib_b0.c:HEADER_MACRO_RUNTIME:PASS",
            f"tests/p16/register_newlib_b0.c:C_LINK_RUN:PASS",
            f"tests/p16/surface_{profile}.c:MACRO_EXPANSION_COMPILE_ONLY",
            f"include/rivetlua/{profile}/{row['header']}:{name}:{P16_2B0_MACRO_SEQUENCES[name]}",
        )
        if any(token not in str(row["evidence"]) for token in required_evidence):
            failures.append(f"{profile}:{name}: C runtime or fixed macro evidence incomplete")
    if failures:
        raise ValueError("P16-2 B0 header macro evidence mismatch:\n  " + "\n  ".join(failures))


def render_c_abi_header() -> bytes:
    lines = [
        "/* 由 tests/p16/generate_manifest.py 產生；只描述固定 SDK ABI 身分。 */",
        "#ifndef RIVETLUA_ABI_H",
        "#define RIVETLUA_ABI_H",
        "#include <stddef.h>",
        "#include <stdint.h>",
        "#if !defined(LUA_VERSION_RELEASE_NUM)",
        '#error "請先引入指定版本的 lua.h 與 lauxlib.h"',
        "#endif",
        "#if LUA_INT_TYPE != LUA_INT_LONGLONG || LUA_FLOAT_TYPE != LUA_FLOAT_DOUBLE",
        '#error "RivetLua SDK 僅接受 i64f64 設定"',
        "#endif",
        "#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__",
        '#error "P16 SDK 僅支援既定 little-endian target"',
        "#endif",
        "#if !defined(__SIZEOF_POINTER__) || __SIZEOF_POINTER__ != 8",
        '#error "P16 SDK 僅支援既定 64-bit pointer target"',
        "#endif",
        "#if defined(__APPLE__) && defined(__aarch64__)",
        '#define RIVETLUA_TARGET_TRIPLE "aarch64-apple-darwin"',
        "#elif defined(__linux__) && defined(__x86_64__) && defined(__GLIBC__)",
        '#define RIVETLUA_TARGET_TRIPLE "x86_64-unknown-linux-gnu"',
        "#elif defined(__linux__) && defined(__aarch64__) && defined(__GLIBC__)",
        '#define RIVETLUA_TARGET_TRIPLE "aarch64-unknown-linux-gnu"',
        "#else",
        '#error "P16 SDK 不支援此 target"',
        "#endif",
        "#if LUA_VERSION_RELEASE_NUM == 50501",
        "#define RIVETLUA_PROFILE_ID 55",
    ]
    for name, value in [("HEADER_SET", header_set_sha256("lua55")), *[(h.replace(".", "_").upper(), str(PROFILES["lua55"]["files"][h])) for h in HEADERS]]:
        lines.append(f"#define RIVETLUA_{name}_SHA256_BYTES {rust_array(value)}".replace("[", "{").replace("]", "}"))
    lines.extend(["#elif LUA_VERSION_RELEASE_NUM == 50409", "#define RIVETLUA_PROFILE_ID 54"])
    for name, value in [("HEADER_SET", header_set_sha256("lua54")), *[(h.replace(".", "_").upper(), str(PROFILES["lua54"]["files"][h])) for h in HEADERS]]:
        lines.append(f"#define RIVETLUA_{name}_SHA256_BYTES {rust_array(value)}".replace("[", "{").replace("]", "}"))
    lines.extend([
        "#else",
        '#error "P16 SDK 只固定 Lua 5.5.1 與 5.4.9"',
        "#endif",
        "#define RIVETLUA_ABI_REVISION 1",
        "#define RIVETLUA_NUMERIC_CONFIG_I64F64 1",
        "#define RIVETLUA_ENDIAN_LITTLE 1",
        "#define RIVETLUA_LAYOUT_COUNT 37",
        "typedef struct rivetlua_abi_identity {",
        "  uint32_t revision;",
        "  uint16_t profile;",
        "  uint16_t numeric_config;",
        "  uint8_t pointer_width_bits;",
        "  uint8_t endianness;",
        "  uint16_t reserved_zero;",
        "  char target[32];",
        "  uint8_t header_set_sha256[32];",
        "  uint8_t lua_h_sha256[32];",
        "  uint8_t lauxlib_h_sha256[32];",
        "  uint8_t luaconf_h_sha256[32];",
        "  uint16_t layout[RIVETLUA_LAYOUT_COUNT];",
        "} rivetlua_abi_identity;",
        "extern rivetlua_abi_identity rivetlua_abi_identity_v1(void);",
        "static inline rivetlua_abi_identity rivetlua_expected_abi_identity(void) {",
        "  rivetlua_abi_identity identity = {",
        "    RIVETLUA_ABI_REVISION, RIVETLUA_PROFILE_ID, RIVETLUA_NUMERIC_CONFIG_I64F64,",
        "    sizeof(void *) * 8, RIVETLUA_ENDIAN_LITTLE, 0,",
        "    RIVETLUA_TARGET_TRIPLE, RIVETLUA_HEADER_SET_SHA256_BYTES,",
        "    RIVETLUA_LUA_H_SHA256_BYTES, RIVETLUA_LAUXLIB_H_SHA256_BYTES,",
        "    RIVETLUA_LUACONF_H_SHA256_BYTES,",
        "    {",
        "      sizeof(void *), _Alignof(void *), sizeof(int), _Alignof(int),",
        "      sizeof(long), _Alignof(long), sizeof(long long), _Alignof(long long),",
        "      sizeof(double), _Alignof(double), sizeof(long double), _Alignof(long double),",
        "      sizeof(size_t), _Alignof(size_t), sizeof(lua_Integer), _Alignof(lua_Integer),",
        "      sizeof(lua_Number), _Alignof(lua_Number), sizeof(lua_Unsigned), _Alignof(lua_Unsigned),",
        "      sizeof(lua_KContext), _Alignof(lua_KContext),",
        "      sizeof(lua_Debug), _Alignof(lua_Debug), sizeof(luaL_Buffer), _Alignof(luaL_Buffer),",
        "      sizeof(luaL_Reg), _Alignof(luaL_Reg), sizeof(luaL_Stream), _Alignof(luaL_Stream),",
        "      offsetof(lua_Debug, short_src), offsetof(lua_Debug, i_ci),",
        "      offsetof(luaL_Buffer, init), offsetof(luaL_Reg, func),",
        "      offsetof(luaL_Stream, closef), LUA_IDSIZE, LUAL_BUFFERSIZE",
        "    }",
        "  };",
        "  return identity;",
        "}",
        "#endif",
    ])
    return ("\n".join(lines) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("write", "check"))
    args = parser.parse_args()
    validate_inputs()
    rows = complete_rows()
    outputs = {
        OUTPUT: render_manifest(rows),
        RUST_HASHES: render_rust_hashes(),
        C_ABI_HEADER: render_c_abi_header(),
        ROOT / "tests" / "p16" / "surface_lua55.c": render_surface(rows, "lua55"),
        ROOT / "tests" / "p16" / "surface_lua54.c": render_surface(rows, "lua54"),
        ROOT / "tests" / "p16" / "surface_lua55_failfalse.c": render_surface_lua55_failfalse(rows),
        ROOT / "tests" / "p16" / "buffer_macros_lua54.c": render_buffer_macro_runtime_fixture("lua54"),
        ROOT / "tests" / "p16" / "buffer_macros_lua55.c": render_buffer_macro_runtime_fixture("lua55"),
        ROOT / "tests" / "p16" / "upvalue_index_lua54.c": render_upvalue_index_runtime_fixture("lua54"),
        ROOT / "tests" / "p16" / "upvalue_index_lua55.c": render_upvalue_index_runtime_fixture("lua55"),
    }
    fixture_paths = {
        path for path in outputs
        if (
            path.name.startswith("surface_lua")
            or path.name.startswith("buffer_macros_lua")
            or path.name.startswith("upvalue_index_lua")
        ) and path.suffix == ".c"
    }
    fixture_paths.add(ROOT / "tests" / "p16" / "register_newlib_b0.c")
    if args.mode == "write":
        fixture_sources = {
            path: outputs[path] if path in outputs else path.read_bytes()
            for path in fixture_paths
        }
        assert_surface_macro_expansion_evidence(rows, fixture_sources)
        assert_buffer_macro_runtime_evidence(rows, fixture_sources)
        assert_upvalue_index_runtime_evidence(rows, fixture_sources)
        assert_header_registration_runtime_evidence(rows, fixture_sources)
        for path, data in outputs.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    else:
        mismatches: list[str] = []
        for path, expected in outputs.items():
            if not path.is_file():
                mismatches.append(f"{path.relative_to(ROOT).as_posix()}: missing")
                continue
            actual = path.read_bytes()
            if actual != expected:
                mismatches.append(f"{path.relative_to(ROOT).as_posix()}: differs")
        if mismatches:
            raise ValueError("產物與固定來源不同步：\n  " + "\n  ".join(mismatches))
        fixture_sources = {path: path.read_bytes() for path in fixture_paths}
        assert_surface_macro_expansion_evidence(rows, fixture_sources)
        assert_buffer_macro_runtime_evidence(rows, fixture_sources)
        assert_upvalue_index_runtime_evidence(rows, fixture_sources)
        assert_header_registration_runtime_evidence(rows, fixture_sources)
    counts = Counter((row["profile"], row["kind"]) for row in rows)
    print("P16-1 清單 PASS:", len(rows), "rows", sorted(counts.items()))
    for profile in PROFILES:
        print(profile, "header_set_sha256", header_set_sha256(profile))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"P16-1 清單失敗：{error}", file=sys.stderr)
        sys.exit(1)
