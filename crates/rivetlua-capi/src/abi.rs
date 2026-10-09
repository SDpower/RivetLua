//! P16-1 的固定 ABI 身分與純比較器。

use std::ffi::{c_char, c_int, c_long, c_longlong, c_void};
use std::mem::{align_of, offset_of, size_of};

use crate::manifest;

pub const NUMERIC_CONFIG_I64F64: u16 = 1;
pub const LAYOUT_COUNT: usize = 37;

#[cfg(all(target_arch = "aarch64", target_os = "macos"))]
pub const TARGET_TRIPLE: &str = "aarch64-apple-darwin";
#[cfg(all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"))]
pub const TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";
#[cfg(all(target_arch = "aarch64", target_os = "linux", target_env = "gnu"))]
pub const TARGET_TRIPLE: &str = "aarch64-unknown-linux-gnu";

#[cfg(target_os = "macos")]
const LONG_DOUBLE_SIZE: u16 = 8;
#[cfg(target_os = "macos")]
const LONG_DOUBLE_ALIGNMENT: u16 = 8;
#[cfg(target_os = "linux")]
const LONG_DOUBLE_SIZE: u16 = 16;
#[cfg(target_os = "linux")]
const LONG_DOUBLE_ALIGNMENT: u16 = 16;

#[cfg(feature = "lua55")]
pub const PROFILE_ID: u16 = 55;
#[cfg(feature = "lua54")]
pub const PROFILE_ID: u16 = 54;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiIdentity {
    pub revision: u32,
    pub profile: u16,
    pub numeric_config: u16,
    pub pointer_width_bits: u8,
    pub endianness: u8,
    pub reserved_zero: u16,
    pub target: [u8; 32],
    pub header_set_sha256: [u8; 32],
    pub lua_h_sha256: [u8; 32],
    pub lauxlib_h_sha256: [u8; 32],
    pub luaconf_h_sha256: [u8; 32],
    /// 固定順序由 include/rivetlua/rivetlua_abi.h 的 C 初始化式定義。
    pub layout: [u16; LAYOUT_COUNT],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbiMismatch {
    Missing,
    Revision,
    Profile,
    NumericConfig,
    PointerWidth,
    Endianness,
    Reserved,
    Target,
    HeaderSetSha256,
    LuaHSha256,
    LauxlibHSha256,
    LuaconfHSha256,
    Layout(usize),
}

/// 供 P16-5 載入前重用；任何缺少或不符均拒絕。
pub fn compare_identity(
    expected: &AbiIdentity,
    candidate: Option<&AbiIdentity>,
) -> Result<(), AbiMismatch> {
    let candidate = candidate.ok_or(AbiMismatch::Missing)?;
    if candidate.revision != expected.revision {
        return Err(AbiMismatch::Revision);
    }
    if candidate.profile != expected.profile {
        return Err(AbiMismatch::Profile);
    }
    if candidate.numeric_config != expected.numeric_config {
        return Err(AbiMismatch::NumericConfig);
    }
    if candidate.pointer_width_bits != expected.pointer_width_bits {
        return Err(AbiMismatch::PointerWidth);
    }
    if candidate.endianness != expected.endianness {
        return Err(AbiMismatch::Endianness);
    }
    if expected.reserved_zero != 0 || candidate.reserved_zero != expected.reserved_zero {
        return Err(AbiMismatch::Reserved);
    }
    if candidate.target != expected.target {
        return Err(AbiMismatch::Target);
    }
    if candidate.header_set_sha256 != expected.header_set_sha256 {
        return Err(AbiMismatch::HeaderSetSha256);
    }
    if candidate.lua_h_sha256 != expected.lua_h_sha256 {
        return Err(AbiMismatch::LuaHSha256);
    }
    if candidate.lauxlib_h_sha256 != expected.lauxlib_h_sha256 {
        return Err(AbiMismatch::LauxlibHSha256);
    }
    if candidate.luaconf_h_sha256 != expected.luaconf_h_sha256 {
        return Err(AbiMismatch::LuaconfHSha256);
    }
    for (index, (expected, actual)) in expected.layout.iter().zip(candidate.layout).enumerate() {
        if *expected != actual {
            return Err(AbiMismatch::Layout(index));
        }
    }
    Ok(())
}

const fn target_bytes(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    assert!(bytes.len() < 32);
    let mut result = [0_u8; 32];
    let mut index = 0;
    while index < bytes.len() {
        result[index] = bytes[index];
        index += 1;
    }
    result
}

const TARGET_BYTES: [u8; 32] = target_bytes(TARGET_TRIPLE);

#[cfg(feature = "lua55")]
#[repr(C)]
struct LuaDebug55 {
    event: c_int,
    name: *const c_char,
    namewhat: *const c_char,
    what: *const c_char,
    source: *const c_char,
    srclen: usize,
    currentline: c_int,
    linedefined: c_int,
    lastlinedefined: c_int,
    nups: u8,
    nparams: u8,
    isvararg: c_char,
    extraargs: u8,
    istailcall: c_char,
    ftransfer: c_int,
    ntransfer: c_int,
    short_src: [c_char; 60],
    i_ci: *mut c_void,
}

#[cfg(feature = "lua54")]
#[repr(C)]
struct LuaDebug54 {
    event: c_int,
    name: *const c_char,
    namewhat: *const c_char,
    what: *const c_char,
    source: *const c_char,
    srclen: usize,
    currentline: c_int,
    linedefined: c_int,
    lastlinedefined: c_int,
    nups: u8,
    nparams: u8,
    isvararg: c_char,
    istailcall: c_char,
    ftransfer: u16,
    ntransfer: u16,
    short_src: [c_char; 60],
    i_ci: *mut c_void,
}

#[cfg(feature = "lua55")]
type LuaDebug = LuaDebug55;
#[cfg(feature = "lua54")]
type LuaDebug = LuaDebug54;

#[cfg(all(feature = "lua55", target_os = "linux"))]
#[repr(C, align(16))]
struct LuaBufferInit([u8; 1024]);
#[cfg(not(all(feature = "lua55", target_os = "linux")))]
#[repr(C, align(8))]
struct LuaBufferInit([u8; 1024]);

#[repr(C)]
struct LuaBuffer {
    b: *mut c_char,
    size: usize,
    n: usize,
    l: *mut c_void,
    init: LuaBufferInit,
}

#[repr(C)]
struct LuaReg {
    name: *const c_char,
    func: *const c_void,
}

#[repr(C)]
struct LuaStream {
    f: *mut c_void,
    closef: *const c_void,
}

fn layout() -> [u16; LAYOUT_COUNT] {
    [
        size_of::<*const c_void>() as u16,
        align_of::<*const c_void>() as u16,
        size_of::<c_int>() as u16,
        align_of::<c_int>() as u16,
        size_of::<c_long>() as u16,
        align_of::<c_long>() as u16,
        size_of::<c_longlong>() as u16,
        align_of::<c_longlong>() as u16,
        size_of::<f64>() as u16,
        align_of::<f64>() as u16,
        LONG_DOUBLE_SIZE,
        LONG_DOUBLE_ALIGNMENT,
        size_of::<usize>() as u16,
        align_of::<usize>() as u16,
        size_of::<i64>() as u16,
        align_of::<i64>() as u16,
        size_of::<f64>() as u16,
        align_of::<f64>() as u16,
        size_of::<u64>() as u16,
        align_of::<u64>() as u16,
        size_of::<isize>() as u16,
        align_of::<isize>() as u16,
        size_of::<LuaDebug>() as u16,
        align_of::<LuaDebug>() as u16,
        size_of::<LuaBuffer>() as u16,
        align_of::<LuaBuffer>() as u16,
        size_of::<LuaReg>() as u16,
        align_of::<LuaReg>() as u16,
        size_of::<LuaStream>() as u16,
        align_of::<LuaStream>() as u16,
        offset_of!(LuaDebug, short_src) as u16,
        offset_of!(LuaDebug, i_ci) as u16,
        offset_of!(LuaBuffer, init) as u16,
        offset_of!(LuaReg, func) as u16,
        offset_of!(LuaStream, closef) as u16,
        60,
        (16 * size_of::<*const c_void>() * size_of::<f64>()) as u16,
    ]
}

pub fn current_identity() -> AbiIdentity {
    #[cfg(feature = "lua55")]
    let (header_set_sha256, lua_h_sha256, lauxlib_h_sha256, luaconf_h_sha256) = (
        manifest::LUA55_HEADER_SET_SHA256,
        manifest::LUA55_LUA_H_SHA256,
        manifest::LUA55_LAUXLIB_H_SHA256,
        manifest::LUA55_LUACONF_H_SHA256,
    );
    #[cfg(feature = "lua54")]
    let (header_set_sha256, lua_h_sha256, lauxlib_h_sha256, luaconf_h_sha256) = (
        manifest::LUA54_HEADER_SET_SHA256,
        manifest::LUA54_LUA_H_SHA256,
        manifest::LUA54_LAUXLIB_H_SHA256,
        manifest::LUA54_LUACONF_H_SHA256,
    );
    AbiIdentity {
        revision: manifest::ABI_REVISION,
        profile: PROFILE_ID,
        numeric_config: NUMERIC_CONFIG_I64F64,
        pointer_width_bits: (size_of::<*const c_void>() * 8) as u8,
        endianness: 1,
        reserved_zero: 0,
        target: TARGET_BYTES,
        header_set_sha256,
        lua_h_sha256,
        lauxlib_h_sha256,
        luaconf_h_sha256,
        layout: layout(),
    }
}
