use std::env;
use std::fs;
use std::path::PathBuf;

fn main() {
    let target = env::var("TARGET").expect("Cargo 必須提供 TARGET");
    assert!(
        matches!(
            target.as_str(),
            "aarch64-apple-darwin" | "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
        ),
        "P16 C trampoline 只支援既定 target"
    );
    let codes: &[(&str, i32)] = &[
        ("OK", 0),
        ("OUT_NORMAL", 0),
        ("OUT_RAISED", 1),
        ("OUT_REJECTED", 2),
        ("ACTION_RETURN", 0),
        ("ACTION_RAISE", 1),
        ("ACTION_REJECT", 2),
        ("CANCELLED", 3),
        ("ERROR_LUA", 2),
        ("ERROR_HOST", 3),
        ("ERROR_POLICY", 4),
        ("ERROR_ALLOCATION", 5),
        ("ERROR_ABORTED", 6),
        ("REJECT_NULL", -1),
        ("REJECT_WRONG_THREAD", -2),
        ("REJECT_BUSY", -3),
        ("REJECT_WRONG_STATE", -4),
        ("REJECT_WRONG_GENERATION", -5),
        ("REJECT_STALE", -6),
        ("REJECT_NO_CHECKPOINT", -7),
        ("REJECT_PENDING", -8),
        ("REJECT_INVALID_ACTION", -9),
        ("REJECT_PANIC", -10),
        ("REJECT_NO_PENDING", -11),
        ("REJECT_STACK_CHANGED", -12),
        ("REJECT_CHECKPOINT_ALLOCATION", -13),
        ("BUFFER_INIT", 1),
        ("BUFFER_PREP", 2),
        ("BUFFER_ADDLSTRING", 3),
        ("BUFFER_ADDSTRING", 4),
        ("BUFFER_ADDVALUE", 5),
        ("BUFFER_PUSHRESULT", 6),
        ("BUFFER_PUSHRESULTSIZE", 7),
        ("BUFFER_BUFFINITSIZE", 8),
        ("BUFFER_ADDGSUB", 9),
        ("AUX_CHECKTYPE", 1),
        ("AUX_CHECKANY", 2),
        ("AUX_CHECKUDATA", 3),
        ("AUX_CHECKOPTION", 4),
    ];
    let mut c = String::from("/* 僅供本 crate C trampoline 編譯，與 Rust 常數同源。 */\n");
    let mut rust = String::from("// 由 build.rs 同時產生 C／Rust 私有狀態碼。\n");
    for (name, value) in codes {
        c.push_str(&format!("#define RV_A1_{name} {value}\n"));
        rust.push_str(&format!("pub const {name}: i32 = {value};\n"));
    }
    let out = PathBuf::from(env::var_os("OUT_DIR").expect("Cargo 必須提供 OUT_DIR"));
    fs::write(out.join("trampoline_codes.h"), c).expect("寫入 C 狀態碼");
    fs::write(out.join("trampoline_codes.rs"), rust).expect("寫入 Rust 狀態碼");
    let mut build = cc::Build::new();
    build
        .file("src/trampoline.c")
        .file("src/native/platform.c")
        .include(&out)
        .std("c11")
        .warnings(true)
        .extra_warnings(true)
        .warnings_into_errors(true);
    if env::var_os("CARGO_FEATURE_LUA55").is_some() {
        build
            .include("../../include/rivetlua/lua55")
            .define("RV_LUA55_B2", None);
    } else {
        build.include("../../include/rivetlua/lua54");
    }
    if target == "aarch64-apple-darwin" {
        // Rust 的 Apple arm64 基線為 macOS 11；避免新版 clang 預設較新 deployment target。
        build.flag("-mmacosx-version-min=11.0");
    } else {
        build.define("_GNU_SOURCE", None);
    }
    build.compile("rivetlua_capi_trampoline_a1");
    if target != "aarch64-apple-darwin" {
        println!("cargo:rustc-link-lib=dl");
    }
    let worker_export = if target == "aarch64-apple-darwin" {
        "-Wl,-export_dynamic"
    } else {
        "-Wl,--export-dynamic"
    };
    println!("cargo:rustc-link-arg-bin=rivetlua-native-worker={worker_export}");
    println!("cargo:rerun-if-changed=src/trampoline.c");
    println!("cargo:rerun-if-changed=src/native/platform.c");
    println!("cargo:rerun-if-changed=build.rs");
}
