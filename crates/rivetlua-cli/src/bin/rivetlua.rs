#[cfg(any(feature = "native-lua55", feature = "native-lua54"))]
fn main() -> std::process::ExitCode {
    rivetlua_cli::rivetlua_standalone_main_with_native_attestor(|verified| {
        // SAFETY：此 CLI 的 grant 固定受信任 build provenance 與 process permissions；
        // preflight 驗 bytes/ABI，宿主另承擔 recursive constructor/opener/destructor 的
        // CNoUnwind 與同執行緒契約。所有 opener 只經 C checkpoint 執行。
        unsafe { rivetlua_capi::native::attest_host_native(verified) }
    })
}

#[cfg(not(any(feature = "native-lua55", feature = "native-lua54")))]
fn main() -> std::process::ExitCode {
    rivetlua_cli::rivetlua_standalone_main()
}
