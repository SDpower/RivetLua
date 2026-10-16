#[cfg(all(feature = "lua54", feature = "lua55"))]
compile_error!("請只選擇一個 RivetLua Lua profile feature");

#[cfg(not(any(feature = "lua54", feature = "lua55")))]
compile_error!("請選擇 rivetlua-capi 的 lua54 或 lua55 feature");

fn main() {
    let _ = rivetlua_capi::abi::current_identity();
}
