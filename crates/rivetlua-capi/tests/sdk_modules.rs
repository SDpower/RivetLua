use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn quoted(value: &str) -> String {
    let mut output = String::from("\"");
    for character in value.chars() {
        match character {
            '\"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            value if value.is_control() => output.push_str(&format!("\\u{:04x}", value as u32)),
            value => output.push(value),
        }
    }
    output.push('\"');
    output
}

fn array(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|value| quoted(value))
            .collect::<Vec<_>>()
            .join(",")
    )
}

fn hash(path: &Path) -> String {
    let output = if cfg!(target_os = "macos") {
        Command::new("shasum")
            .args(["-a", "256"])
            .arg(path)
            .output()
    } else {
        Command::new("sha256sum").arg(path).output()
    }
    .expect("SHA-256 指令可用");
    assert!(output.status.success());
    let body = String::from_utf8(output.stdout).unwrap();
    let digest = body.split_whitespace().next().unwrap_or("");
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    digest.to_ascii_lowercase()
}

fn defined_global_function(log: &str, symbol: &str, darwin: bool) -> bool {
    let expected = if darwin {
        format!("_{symbol}")
    } else {
        symbol.to_owned()
    };
    log.lines().any(|line| {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        fields.len() >= 3 && fields[fields.len() - 2] == "T" && fields[fields.len() - 1] == expected
    })
}

#[test]
fn sdk_nm_undefined_symbol_is_not_a_function_export() {
    assert!(defined_global_function(
        "0000 T _luaopen_lib2\n",
        "luaopen_lib2",
        true
    ));
    assert!(defined_global_function(
        "0000 T luaopen_lib2\n",
        "luaopen_lib2",
        false
    ));
    assert!(!defined_global_function(
        "U _luaopen_lib2\n",
        "luaopen_lib2",
        true
    ));
    assert!(!defined_global_function(
        "0000 W luaopen_lib2\n",
        "luaopen_lib2",
        false
    ));
}

fn pair(path: &Path, key: &str) -> String {
    format!(
        "\"{key}_path\":{},\"{key}_sha256\":{}",
        quoted(&path.display().to_string()),
        quoted(&hash(path))
    )
}

fn invoke(root: &Path, command: &[String], log: &Path) -> String {
    let mut process = Command::new(&command[0]);
    let output = process
        .args(&command[1..])
        .current_dir(root)
        .output()
        .unwrap_or_else(|error| panic!("{}: {error}", command.join(" ")));
    let mut body = output.stdout;
    body.extend_from_slice(&output.stderr);
    fs::write(log, &body).unwrap();
    assert!(
        output.status.success(),
        "{} exit={:?}; {}",
        command.join(" "),
        output.status.code(),
        String::from_utf8_lossy(&body)
    );
    String::from_utf8(body).expect("SDK 指令輸出 UTF-8")
}

fn checked_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} 未由 P16 runner 設定"))
}

#[test]
#[ignore = "需由 P16 runner 注入固定 SDK 與 staticlib 證據"]
fn sdk_modules_official_five_load_execute_and_p1() {
    let root = PathBuf::from(checked_env("RIVETLUA_P16_SDK_ROOT"));
    let dir = PathBuf::from(checked_env("RIVETLUA_P16_SDK_EVIDENCE_DIR"));
    let profile = checked_env("RIVETLUA_P16_SDK_PROFILE");
    let target = checked_env("RIVETLUA_P16_SDK_TARGET");
    let host_trust = checked_env("RIVETLUA_P16_SDK_HOST_TRUST");
    let lib = PathBuf::from(checked_env("RIVETLUA_P16_SDK_LIB_PATH"));
    let native = checked_env("RIVETLUA_P16_SDK_NATIVE_LIBS");
    let staticlib_build_log =
        PathBuf::from(checked_env("RIVETLUA_P16_SDK_STATICLIB_BUILD_LOG_PATH"));
    let staticlib_build_log_sha = checked_env("RIVETLUA_P16_SDK_STATICLIB_BUILD_LOG_SHA256");
    assert!(matches!(profile.as_str(), "lua54" | "lua55"));
    assert_eq!(host_trust, "explicit-sdk-host-process-permissions-v1");
    assert!(root.is_absolute() && dir.is_absolute() && lib.is_absolute());
    assert!(dir.is_dir() && lib.is_file());
    assert_eq!(hash(&staticlib_build_log), staticlib_build_log_sha);
    let native_flags = native
        .split('\u{1f}')
        .filter(|item| !item.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let vendor = root.join(match profile.as_str() {
        "lua54" => "vendor/lua54/lua-5.4.9-tests/libs",
        _ => "vendor/lua55/lua-5.5.1-tests/libs",
    });
    let include = root.join(format!("include/rivetlua/{profile}"));
    let common = root.join("include/rivetlua");
    let names = ["lib1.so", "lib11.so", "lib2.so", "lib21.so", "lib2-v2.so"];
    let sources = ["lib1.c", "lib11.c", "lib2.c", "lib21.c", "lib22.c"];
    let symbols = [
        [
            "luaopen_lib1_sub",
            "lib1_export",
            "onefunction",
            "anotherfunc",
        ]
        .as_slice(),
        ["luaopen_lib11"].as_slice(),
        ["luaopen_lib2"].as_slice(),
        ["luaopen_lib21"].as_slice(),
        ["luaopen_lib2"].as_slice(),
    ];
    let mut modules = Vec::new();
    let mut outputs = Vec::new();
    let mut approved_hashes = Vec::new();
    for index in 0..5 {
        let source = vendor.join(sources[index]);
        let module = dir.join(names[index]);
        let build_log = dir.join(format!("{}-build.log", names[index]));
        let mut command = vec![
            "cc".into(),
            "-std=c11".into(),
            "-Wall".into(),
            "-Wextra".into(),
            "-Werror".into(),
            "-fPIC".into(),
        ];
        if profile == "lua55" && index == 4 {
            // 官方 lib22.c 的 t_freestr 保留未使用的 ABI 參數。
            command.push("-Wno-unused-parameter".into());
        }
        if cfg!(target_os = "macos") {
            command.extend([
                "-dynamiclib".into(),
                "-undefined".into(),
                "dynamic_lookup".into(),
            ]);
        } else {
            command.push("-shared".into());
        }
        command.extend([
            "-I".into(),
            include.display().to_string(),
            "-I".into(),
            common.display().to_string(),
            source.display().to_string(),
            "-o".into(),
            module.display().to_string(),
        ]);
        invoke(&root, &command, &build_log);
        let nm_log = dir.join(format!("{}-nm.log", names[index]));
        let nm_command = vec!["nm".into(), "-g".into(), module.display().to_string()];
        let nm = invoke(&root, &nm_command, &nm_log);
        for symbol in symbols[index] {
            assert!(
                defined_global_function(&nm, symbol, cfg!(target_os = "macos")),
                "{symbol} 未作為全域函數匯出"
            );
        }
        outputs.push(module.clone());
        approved_hashes.push(hash(&module));
        modules.push(format!(
            "{{\"name\":{}, {}, {},\"build_command\":{},\"build_exit_code\":0,{},\"nm_command\":{},\"nm_exit_code\":0,{},\"symbols\":{}}}",
            quoted(names[index]), pair(&source, "source"), pair(&module, "module"),
            array(&command), pair(&build_log, "build_log"), array(&nm_command),
            pair(&nm_log, "nm_log"),
            array(&symbols[index].iter().map(|value| (*value).to_owned()).collect::<Vec<_>>())
        ));
    }

    let p1 = dir.join("libs/P1");
    fs::create_dir_all(&p1).unwrap();
    let packages = [("init.lua", 10), ("xuxu.lua", 20)];
    let mut package_records = Vec::new();
    for (name, value) in packages {
        let path = p1.join(name);
        fs::write(&path, format!("_ENV = {{}}\nAA = {value}\nreturn _ENV\n")).unwrap();
        package_records.push(format!(
            "{{\"name\":{}, {},\"aa\":{value},\"global_aa\":0,\"loaded\":true,\"executed\":true}}",
            quoted(name),
            pair(&path, "package")
        ));
    }

    let source = root.join("tests/p16/acceptance/sdk/driver.c");
    let attrib = root.join(match profile.as_str() {
        "lua54" => "vendor/lua54/lua-5.4.9-tests/attrib.lua",
        _ => "vendor/lua55/lua-5.5.1-tests/attrib.lua",
    });
    let attrib_body = fs::read_to_string(&attrib).unwrap();
    assert!(attrib_body.contains("createfiles(files, \"_ENV = {}\\n\", \"\\nreturn _ENV\\n\")"));
    let binary = dir.join("sdk-driver");
    let build_log = dir.join("driver-build.log");
    let mut build = vec![
        "cc".into(),
        "-std=c11".into(),
        "-Wall".into(),
        "-Wextra".into(),
        "-Werror".into(),
        "-I".into(),
        include.display().to_string(),
        "-I".into(),
        common.display().to_string(),
        source.display().to_string(),
    ];
    if cfg!(target_os = "macos") {
        build.push(format!("-Wl,-force_load,{}", lib.display()));
        build.push("-Wl,-export_dynamic".into());
    } else {
        build.extend([
            "-Wl,--whole-archive".into(),
            lib.display().to_string(),
            "-Wl,--no-whole-archive".into(),
            "-rdynamic".into(),
            "-ldl".into(),
        ]);
    }
    build.extend(native_flags.iter().cloned());
    build.extend(["-o".into(), binary.display().to_string()]);
    invoke(&root, &build, &build_log);
    let driver_nm_log = dir.join("driver-nm.log");
    let driver_nm_command = vec!["nm".into(), "-g".into(), binary.display().to_string()];
    let driver_nm = invoke(&root, &driver_nm_command, &driver_nm_log);
    for symbol in [
        "lua_newstate",
        "lua_pcallk",
        "lua_close",
        "luaL_loadstring",
        "rivetlua_capi_configure_load_limits_b3",
    ] {
        assert!(
            defined_global_function(&driver_nm, symbol, cfg!(target_os = "macos")),
            "driver 未匯出 {symbol}"
        );
    }
    let run_log = dir.join("driver-run.log");
    let mut run = vec![binary.display().to_string()];
    run.extend(outputs.iter().map(|path| path.display().to_string()));
    run.extend(
        packages
            .iter()
            .map(|(name, _)| p1.join(name).display().to_string()),
    );
    for (path, approved) in outputs.iter().zip(&approved_hashes) {
        assert_eq!(&hash(path), approved, "module digest 必須先於 dlopen 固定");
    }
    let body = invoke(&root, &run, &run_log);
    for line in [
        "P16_SDK_HOST_LIMITS source=65536 encoded=4194304 module=8388608 temporary=1048576 work=2000000 chunks=256 paths=256 PASS",
        "P16_SDK_LIB11 lib11.so GLOBAL_LINK PASS",
        "P16_SDK_LIB1 FUNCTIONS PASS",
        "P16_SDK_CLOSE ALLOCATOR_RELEASE PASS",
        "P16_SDK_DLCLOSE AFTER_LUA_CLOSE PASS",
        "P16_SDK_RESULT PASS",
    ] {
        assert_eq!(
            body.lines().filter(|actual| *actual == line).count(),
            1,
            "缺失或重複 SDK 效果：{line}"
        );
    }
    for module in &outputs {
        let marker = format!("P16_SDK_DLOPEN {} PASS", module.display());
        assert_eq!(body.lines().filter(|line| *line == marker).count(), 1);
    }
    for (name, symbol) in [
        ("lib1.so", "luaopen_lib1_sub"),
        ("lib2.so", "luaopen_lib2"),
        ("lib21.so", "luaopen_lib21"),
        ("lib2-v2.so", "luaopen_lib2"),
    ] {
        let marker = format!("P16_SDK_MODULE {name} {symbol} TWO_ARG_ID PASS");
        assert_eq!(body.lines().filter(|line| *line == marker).count(), 1);
    }
    for (name, aa) in packages {
        let marker = format!(
            "P16_SDK_P1 {} AA={aa} GLOBAL=0 PASS",
            p1.join(name).display()
        );
        assert_eq!(body.lines().filter(|line| *line == marker).count(), 1);
    }
    let record = dir.join("sdk-record.json");
    let json = format!(
        "{{\"schema\":\"rivetlua-p16-sdk-evidence-v1\",\"profile\":{},\"target\":{},\"host_trust\":{},\"host_load_limits\":{{\"source\":65536,\"encoded\":4194304,\"module\":8388608,\"temporary\":1048576,\"work\":2000000,\"chunks\":256,\"paths\":256,\"configured\":true}}, {},{}, {},\"native_static_libs\":{},\"modules\":[{}],\"driver\":{{{}, {},\"build_command\":{},\"build_exit_code\":0,{},\"nm_command\":{},\"nm_exit_code\":0,{},\"run_command\":{},\"run_exit_code\":0,{},\"close_before_dlclose\":true,\"allocator_released\":true}},\"packages\":[{}]}}\n",
        quoted(&profile),
        quoted(&target),
        quoted(&host_trust),
        pair(&lib, "library"),
        pair(&attrib, "attrib_source"),
        pair(&staticlib_build_log, "staticlib_build_log"),
        array(&native_flags),
        modules.join(","),
        pair(&source, "source"),
        pair(&binary, "binary"),
        array(&build),
        pair(&build_log, "build_log"),
        array(&driver_nm_command),
        pair(&driver_nm_log, "nm_log"),
        array(&run),
        pair(&run_log, "run_log"),
        package_records.join(",")
    );
    fs::write(&record, json).unwrap();
    println!(
        "\nRVP16SDK\tv=1\tprofile={}\tresult=PASS\trecord_path={}\trecord_sha256={}",
        profile,
        record.display(),
        hash(&record)
    );
}
