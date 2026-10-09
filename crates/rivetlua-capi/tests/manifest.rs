use std::io::Write;
use std::mem::{align_of, size_of};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use rivetlua_capi::abi::{
    AbiMismatch, LAYOUT_COUNT, TARGET_TRIPLE, compare_identity, current_identity,
};

const C_LAYOUT: [&str; LAYOUT_COUNT] = [
    "sizeof(void *)",
    "_Alignof(void *)",
    "sizeof(int)",
    "_Alignof(int)",
    "sizeof(long)",
    "_Alignof(long)",
    "sizeof(long long)",
    "_Alignof(long long)",
    "sizeof(double)",
    "_Alignof(double)",
    "sizeof(long double)",
    "_Alignof(long double)",
    "sizeof(size_t)",
    "_Alignof(size_t)",
    "sizeof(lua_Integer)",
    "_Alignof(lua_Integer)",
    "sizeof(lua_Number)",
    "_Alignof(lua_Number)",
    "sizeof(lua_Unsigned)",
    "_Alignof(lua_Unsigned)",
    "sizeof(lua_KContext)",
    "_Alignof(lua_KContext)",
    "sizeof(lua_Debug)",
    "_Alignof(lua_Debug)",
    "sizeof(luaL_Buffer)",
    "_Alignof(luaL_Buffer)",
    "sizeof(luaL_Reg)",
    "_Alignof(luaL_Reg)",
    "sizeof(luaL_Stream)",
    "_Alignof(luaL_Stream)",
    "offsetof(lua_Debug, short_src)",
    "offsetof(lua_Debug, i_ci)",
    "offsetof(luaL_Buffer, init)",
    "offsetof(luaL_Reg, func)",
    "offsetof(luaL_Stream, closef)",
    "LUA_IDSIZE",
    "LUAL_BUFFERSIZE",
];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn profile() -> &'static str {
    if cfg!(feature = "lua55") {
        "lua55"
    } else {
        "lua54"
    }
}

fn include_args(command: &mut Command) {
    command.arg(format!(
        "-I{}",
        root().join("include/rivetlua").join(profile()).display()
    ));
    command.arg(format!("-I{}", root().join("include/rivetlua").display()));
}

#[test]
fn manifest_generator_matches_every_pinned_header_row() {
    let output = Command::new("python3")
        .arg("tests/p16/generate_manifest.py")
        .arg("check")
        .current_dir(root())
        .output()
        .expect("應可執行固定清單核對器");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("951 rows"), "{stdout}");
}

#[test]
fn manifest_identity_matches_build_target_and_export() {
    let expected = current_identity();
    assert_eq!(expected, rivetlua_capi::rivetlua_abi_identity_v1());
    assert_eq!(expected.revision, 1);
    assert_eq!(expected.numeric_config, 1);
    assert_eq!(expected.pointer_width_bits, (size_of::<usize>() * 8) as u8);
    assert_eq!(expected.endianness, 1);
    assert_eq!(expected.reserved_zero, 0);
    assert_eq!(
        expected.profile,
        if cfg!(feature = "lua55") { 55 } else { 54 }
    );
    let target = expected.target.split(|byte| *byte == 0).next().unwrap();
    assert_eq!(target, TARGET_TRIPLE.as_bytes());
    assert_eq!(size_of::<rivetlua_capi::abi::AbiIdentity>(), 248);
    assert_eq!(align_of::<rivetlua_capi::abi::AbiIdentity>(), 4);
    assert!(!std::mem::needs_drop::<rivetlua_capi::abi::AbiIdentity>());
    assert!(compare_identity(&expected, Some(&expected)).is_ok());
}

#[test]
fn manifest_comparator_rejects_every_identity_dimension() {
    let expected = current_identity();
    assert_eq!(compare_identity(&expected, None), Err(AbiMismatch::Missing));
    let mut candidate = expected;
    candidate.revision ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::Revision)
    );
    candidate = expected;
    candidate.profile ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::Profile)
    );
    candidate = expected;
    candidate.numeric_config ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::NumericConfig)
    );
    candidate = expected;
    candidate.pointer_width_bits ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::PointerWidth)
    );
    candidate = expected;
    candidate.endianness ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::Endianness)
    );
    candidate = expected;
    candidate.reserved_zero = 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::Reserved)
    );
    let mut invalid_expected = expected;
    invalid_expected.reserved_zero = 1;
    assert_eq!(
        compare_identity(&invalid_expected, Some(&expected)),
        Err(AbiMismatch::Reserved)
    );
    candidate = expected;
    candidate.target[0] ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::Target)
    );
    candidate = expected;
    candidate.header_set_sha256[0] ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::HeaderSetSha256)
    );
    candidate = expected;
    candidate.lua_h_sha256[0] ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::LuaHSha256)
    );
    candidate = expected;
    candidate.lauxlib_h_sha256[0] ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::LauxlibHSha256)
    );
    candidate = expected;
    candidate.luaconf_h_sha256[0] ^= 1;
    assert_eq!(
        compare_identity(&expected, Some(&candidate)),
        Err(AbiMismatch::LuaconfHSha256)
    );
    for index in 0..LAYOUT_COUNT {
        candidate = expected;
        candidate.layout[index] ^= 1;
        assert_eq!(
            compare_identity(&expected, Some(&candidate)),
            Err(AbiMismatch::Layout(index))
        );
    }
}

#[test]
fn manifest_c_layout_matches_rust_identity_without_linking() {
    let expected = current_identity();
    let mut source = String::from(
        "#include \"lua.h\"\n#include \"lauxlib.h\"\n#include \"rivetlua_abi.h\"\n#include <stddef.h>\n",
    );
    source.push_str(&format!(
        "_Static_assert(sizeof(rivetlua_abi_identity) == {}, \"identity size\");\n",
        size_of::<rivetlua_capi::abi::AbiIdentity>()
    ));
    source.push_str(&format!(
        "_Static_assert(_Alignof(rivetlua_abi_identity) == {}, \"identity align\");\n",
        align_of::<rivetlua_capi::abi::AbiIdentity>()
    ));
    for (index, expression) in C_LAYOUT.iter().enumerate() {
        source.push_str(&format!(
            "_Static_assert(({}) == {}, \"layout {}\");\n",
            expression, expected.layout[index], index
        ));
    }
    let mut command = Command::new("cc");
    command.args([
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fsyntax-only",
        "-x",
        "c",
        "-",
    ]);
    include_args(&mut command);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("應可啟動 C 編譯器");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(source.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn manifest_full_surface_and_module_fixture_compile_only() {
    let mut fixtures = vec![format!("surface_{}.c", profile())];
    if profile() == "lua55" {
        fixtures.push("surface_lua55_failfalse.c".to_owned());
    }
    fixtures.push("p17_module_probe.c".to_owned());
    for fixture in fixtures {
        let mut command = Command::new("cc");
        command.args(["-std=c11", "-Wall", "-Wextra", "-Werror", "-fsyntax-only"]);
        include_args(&mut command);
        let output = command
            .arg(root().join("tests/p16").join(&fixture))
            .output()
            .expect("應可啟動 C 編譯器");
        assert!(
            output.status.success(),
            "{fixture}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
