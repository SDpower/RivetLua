//! 固定 Lua C SDK 的 ABI 身分；完整 C API 由後續 P16 步驟實作。

#[cfg(all(feature = "lua55", feature = "lua54"))]
compile_error!("P16 C SDK 只能選擇一個 Lua profile");
#[cfg(not(any(feature = "lua55", feature = "lua54")))]
compile_error!("P16 C SDK 必須明確選擇 Lua profile");
#[cfg(not(any(
    all(target_arch = "aarch64", target_os = "macos"),
    all(target_arch = "x86_64", target_os = "linux", target_env = "gnu"),
    all(target_arch = "aarch64", target_os = "linux", target_env = "gnu")
)))]
compile_error!("P16 C SDK 僅支援既定三個 target");
#[cfg(not(target_endian = "little"))]
compile_error!("P16 C SDK 僅支援既定 little-endian target");

pub mod abi;
mod allocator;
#[doc(hidden)]
pub mod error;
mod load;
pub mod manifest;
pub mod native;
pub mod stack;
#[doc(hidden)]
pub mod trampoline;
pub mod worker;

#[cfg(feature = "lua55")]
fn seed_time_seconds() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(-1),
        Err(before_epoch) => {
            let duration = before_epoch.duration();
            let magnitude =
                i128::from(duration.as_secs()) + if duration.subsec_nanos() == 0 { 0 } else { 1 };
            i64::try_from(-magnitude).unwrap_or(-1)
        }
    }
}

#[cfg(feature = "lua55")]
fn seed_mix_into(buff: &mut [u32; 4], address: usize, time_seconds: i64) -> std::ffi::c_uint {
    let pointer_bytes = address.to_ne_bytes();
    let time_bytes = time_seconds.to_ne_bytes();
    *buff = [
        u32::from_ne_bytes([
            pointer_bytes[0],
            pointer_bytes[1],
            pointer_bytes[2],
            pointer_bytes[3],
        ]),
        u32::from_ne_bytes([
            pointer_bytes[4],
            pointer_bytes[5],
            pointer_bytes[6],
            pointer_bytes[7],
        ]),
        u32::from_ne_bytes([time_bytes[0], time_bytes[1], time_bytes[2], time_bytes[3]]),
        u32::from_ne_bytes([time_bytes[4], time_bytes[5], time_bytes[6], time_bytes[7]]),
    ];

    let mut result = buff[0];
    for word in &buff[1..] {
        result ^= result
            .wrapping_shr(3)
            .wrapping_add(result.wrapping_shl(7))
            .wrapping_add(*word);
    }
    result
}

/// 回傳 Lua 5.5 auxiliary library 的 seed；state 依官方實作刻意不使用。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub extern "C" fn luaL_makeseed(_state: *mut stack::lua_State) -> std::ffi::c_uint {
    let mut buff = [0_u32; 4];
    let address = buff.as_ptr() as usize;
    seed_mix_into(&mut buff, address, seed_time_seconds())
}

#[cfg(feature = "lua55")]
unsafe extern "C" {
    #[link_name = "free"]
    fn a46_c_free(ptr: *mut std::ffi::c_void);
    #[link_name = "realloc"]
    fn a46_c_realloc(ptr: *mut std::ffi::c_void, size: usize) -> *mut std::ffi::c_void;
}

/// 依 Lua 5.5 auxiliary library 契約直接委派至 C heap allocator。
///
/// # Safety
/// `ptr` 必須為 NULL，或是由同一 C allocator 回傳且尚未釋放的配置。若 `realloc`
/// 成功，呼叫端不得再使用舊 pointer；若失敗，舊 block 仍有效；每個成功配置恰釋放一次。
/// `ud` 與 `osize` 刻意忽略。本函式不持有 Rust 資源、沒有 panic 路徑，不會讓 unwind 越過 ABI。
#[cfg(feature = "lua55")]
#[unsafe(no_mangle)]
#[allow(non_snake_case)]
pub unsafe extern "C" fn luaL_alloc(
    _ud: *mut std::ffi::c_void,
    ptr: *mut std::ffi::c_void,
    _osize: usize,
    nsize: usize,
) -> *mut std::ffi::c_void {
    if nsize == 0 {
        // SAFETY：函式安全前置條件保證 ptr 為 NULL 或尚未釋放的同一 C allocator block；free(NULL) 亦合法。
        unsafe { a46_c_free(ptr) };
        std::ptr::null_mut()
    } else {
        // SAFETY：函式安全前置條件保證 ptr 為 NULL 或同一 C allocator 的有效 block；失敗時 C realloc 保留舊 block。
        unsafe { a46_c_realloc(ptr, nsize) }
    }
}

/// 固定名稱供 C SDK 對應單一匯出符號；本 crate 只定義此名稱一次，故需 no_mangle。
/// 回傳值是 repr(C)、無指標／borrow／alias 的 POD-by-value ABI 身分；函式本體
/// 不呼叫 callback，也沒有 panic／unwind 路徑。P16-1 只驗證符號，C link／call ABI 尚未驗證。
#[unsafe(no_mangle)]
pub extern "C" fn rivetlua_abi_identity_v1() -> abi::AbiIdentity {
    abi::current_identity()
}

#[cfg(all(test, feature = "lua55"))]
mod seed_tests {
    use super::seed_mix_into;

    fn mix(address: usize, time_seconds: i64) -> u32 {
        let mut buff = [0_u32; 4];
        seed_mix_into(&mut buff, address, time_seconds)
    }

    #[test]
    fn makeseed_fixed_vectors() {
        // 手算向量一：words 為 [2, 1, 3, 0]，折疊結果依序為 0x2、0x103、0x80a0、0x40e0b4。
        assert_eq!(mix(0x0000_0001_0000_0002, 3), 0x0040_e0b4);

        // 手算向量二：words 為 [4, 3, 0xffffffff, 0xfffffffd]，折疊為 0x4、0x207、0x101b8、0x81fd8c；中途有 u32 wrap。
        assert_eq!(
            mix(0x0000_0003_0000_0004, -0x0000_0002_0000_0001),
            0x0081_fd8c
        );
    }
}
