fn main() {
    if std::env::var_os("CARGO_FEATURE_NATIVE_LUA55").is_none()
        && std::env::var_os("CARGO_FEATURE_NATIVE_LUA54").is_none()
    {
        return;
    }
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-arg-bin=rivetlua=-Wl,-export_dynamic");
    } else if cfg!(target_os = "linux") {
        println!("cargo:rustc-link-arg-bin=rivetlua=-Wl,--export-dynamic");
    }
}
