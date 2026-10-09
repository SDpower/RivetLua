"""P16 NEG006：稽核本輪 staticlib 與 C 薄層來源。"""

import argparse
import collections
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile


THIN_SOURCES = ("src/trampoline.c", "src/native/platform.c")
TARGETS = ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu",
           "aarch64-unknown-linux-gnu")
PRIVATE = re.compile(r"^_?lua[A-KM-Z][A-Za-z0-9_]*$")


def check_build_source(source: str) -> None:
    files = re.findall(r'\.file\(\s*"([^"]+)"\s*\)', source)
    if files != list(THIN_SOURCES):
        raise ValueError(f"C source set {files!r} differs from fixed thin layer")
    for link in re.findall(r"cargo:rustc-link-lib=([^\s\"]+)", source):
        if link != "dl":
            raise ValueError(f"foreign C link {link}")
    if re.search(r'\.object\(|\.objects\(|\.file\(\s*[a-zA-Z_]', source):
        raise ValueError("dynamic C object/source input")


def check_members(members: list[str]) -> None:
    for basename in ("trampoline.o", "platform.o"):
        matches = [member for member in members if member.endswith("-" + basename)]
        if len(matches) != 1:
            raise ValueError(f"thin C object {basename}: {len(matches)}")
    for member in members:
        if re.search(r"(?:^|[-_/])(lvm|ldo|lgc|lstate|lapi|lfunc|lstring|ltable|lparser|llex)\.o$", member):
            raise ValueError(f"Lua engine object {member}")


def check_symbols(symbols: list[str]) -> None:
    forbidden = [symbol for symbol in symbols if PRIVATE.fullmatch(symbol)]
    if forbidden:
        raise ValueError(f"Lua private engine symbol {forbidden[0]}")


def globals_from_nm(text: str) -> list[str]:
    names = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.fullmatch(r"[A-Za-z]", parts[-2]):
            names.append(parts[-1])
    return names


def sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def tool_version(command: list[str]) -> str:
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    value = (result.stdout + result.stderr).strip()
    if not value:
        raise ValueError(f"tool version unavailable: {command[0]}")
    return value


def ar_names(archive: pathlib.Path) -> list[str]:
    result = subprocess.run(["ar", "-t", str(archive)], check=True, capture_output=True, text=True)
    names = [name for name in result.stdout.splitlines() if not name.startswith("__.SYMDEF")]
    if len(names) != len(set(names)) or any(
        not re.fullmatch(r"[A-Za-z0-9_.+-]+", name) for name in names
    ):
        raise ValueError(f"archive has duplicate or unsafe member: {archive}")
    return names


def extract(archive: pathlib.Path, directory: pathlib.Path) -> dict[str, pathlib.Path]:
    names = ar_names(archive)
    directory.mkdir(mode=0o700)
    subprocess.run(["ar", "-x", str(archive)], cwd=directory, check=True, capture_output=True)
    members = {name: directory / name for name in names}
    if any(not path.is_file() or path.is_symlink() for path in members.values()):
        raise ValueError(f"archive extraction missing member: {archive}")
    return members


def thin_receipt_out(builds: list[dict], target: str) -> pathlib.Path:
    if target not in TARGETS:
        raise ValueError("unsupported C thin-layer target")
    if len(builds) != 1:
        raise ValueError("exactly one C thin-layer build-script receipt required")
    expected = ["static=rivetlua_capi_trampoline_a1"]
    if target != "aarch64-apple-darwin":
        expected.append("dl")
    if builds[0].get("linked_libs") != expected:
        raise ValueError("fixed C thin-layer linked_libs mismatch")
    out_dir = builds[0].get("out_dir")
    if not isinstance(out_dir, str) or not out_dir:
        raise ValueError("fixed C thin-layer out_dir missing")
    out = pathlib.Path(out_dir).resolve()
    if builds[0].get("linked_paths") != [f"native={out}"]:
        raise ValueError("fixed C thin-layer linked_paths mismatch")
    return out


def source_archives(root: pathlib.Path, build_log: pathlib.Path,
                    profile: str, target: str) -> dict[pathlib.Path, str]:
    events = []
    for line in build_log.read_text(encoding="utf-8").splitlines():
        if line.startswith("{"):
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                raise ValueError("Cargo build log has malformed JSON") from None
    capi = [event for event in events if event.get("reason") == "compiler-artifact"
            and event.get("target", {}).get("name") == "rivetlua_capi"]
    if len(capi) != 1:
        raise ValueError("exactly one rivetlua_capi Cargo artifact required")
    selected = capi[0]
    features = ["default", "lua55"] if profile == "lua55-i64f64" else ["lua54"]
    if sorted(selected.get("features", [])) != sorted(features) or \
       pathlib.Path(selected["target"]["src_path"]).resolve() != \
       (root / "crates/rivetlua-capi/src/lib.rs").resolve() or \
       not {"rlib", "staticlib"}.issubset(set(selected["target"].get("crate_types", []))):
        raise ValueError("Cargo CAPI source/features/crate types mismatch")
    artifacts = [event for event in events if event.get("reason") == "compiler-artifact"]
    cargo_rlibs = {
        pathlib.Path(file).resolve(): "cargo"
        for event in artifacts for file in event.get("filenames", [])
        if file.endswith(".rlib")
    }
    if not any(path.name == "librivetlua_capi.rlib" for path in cargo_rlibs):
        raise ValueError("CAPI rlib source missing from Cargo artifact")
    builds = [event for event in events if event.get("reason") == "build-script-executed"
              and event.get("package_id", "").endswith("/crates/rivetlua-capi#0.0.0")]
    out = thin_receipt_out(builds, target)
    thin = out / "librivetlua_capi_trampoline_a1.a"
    if not thin.is_file():
        raise ValueError("C thin-layer archive missing")
    libdir = subprocess.run(["rustc", "--print", "target-libdir", "--target", target],
                            check=True, capture_output=True, text=True).stdout.strip()
    sysroot = pathlib.Path(libdir).resolve()
    if sysroot.name != "lib" or sysroot.parent.name != target:
        raise ValueError("rustc sysroot target mismatch")
    archives = dict(cargo_rlibs)
    archives.update({path.resolve(): "sysroot" for path in sysroot.glob("lib*.rlib")})
    archives[thin] = "thin"
    return archives


def provenance(archive: pathlib.Path, build_log: pathlib.Path,
               sources: dict[pathlib.Path, str], directory: pathlib.Path) -> list[dict]:
    manifest = directory / "receipt.json"
    names = set(ar_names(archive))
    candidates = [{"original": str(path), "category": category}
                  for path, category in sorted(sources.items(), key=lambda item: str(item[0]))]
    if not candidates or len(candidates) != len({item["original"] for item in candidates}):
        raise ValueError("provenance candidate source set invalid")
    if not manifest.exists():
        directory.mkdir(mode=0o700)
        selected = []
        for source, category in sorted(sources.items(), key=lambda item: str(item[0])):
            if source.is_file() and (set(ar_names(source)) & names or category == "thin"):
                number = len(selected)
                snapshot = directory / f"source-{number}.a"
                shutil.copyfile(source, snapshot)
                selected.append({"category": category, "original": str(source),
                                 "original_sha256": sha256(source),
                                 "snapshot": str(snapshot), "snapshot_sha256": sha256(snapshot)})
        if not any(item["category"] == "thin" for item in selected):
            raise ValueError("thin C archive not selected")
        receipt = {"schema": "P16-NEG006-PROVENANCE-v1", "library_sha256": sha256(archive),
                   "build_log_sha256": sha256(build_log), "candidates": candidates,
                   "selected_originals": [item["original"] for item in selected],
                   "sources": selected}
        manifest.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
                            encoding="utf-8")
    receipt = json.loads(manifest.read_text(encoding="utf-8"))
    if receipt.get("schema") != "P16-NEG006-PROVENANCE-v1" or \
       receipt.get("library_sha256") != sha256(archive) or \
       receipt.get("build_log_sha256") != sha256(build_log) or \
       receipt.get("candidates") != candidates:
        raise ValueError("provenance receipt does not bind archive/build log")
    selected = receipt.get("sources", [])
    if not isinstance(selected, list) or not selected or \
       receipt.get("selected_originals") != [item.get("original") for item in selected] or \
       len(selected) != len({item.get("original") for item in selected}):
        raise ValueError("provenance source list missing or duplicate")
    for index, item in enumerate(selected):
        original = pathlib.Path(item["original"])
        snapshot = pathlib.Path(item["snapshot"])
        if sources.get(original) != item["category"] or \
           snapshot != directory / f"source-{index}.a" or \
           not snapshot.is_file() or sha256(snapshot) != item["snapshot_sha256"] or \
           item["snapshot_sha256"] != item["original_sha256"]:
            raise ValueError("provenance source path/hash mismatch")
    return selected


def classify(path: pathlib.Path) -> str:
    magic = path.open("rb").read(4)
    if magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\x7fELF"):
        return "native"
    if magic in (b"BC\xc0\xde", b"\xde\xc0\x17\x0b"):
        return "bitcode"
    raise ValueError(f"unrecognized archive member format: {path.name}")


def embedded_llvm_bitcode(path: pathlib.Path, target: str) -> bool:
    if target != "aarch64-apple-darwin" or classify(path) != "native":
        return False
    result = subprocess.run(["otool", "-l", str(path)], capture_output=True, text=True)
    if result.returncode != 0 or result.stderr.strip():
        raise ValueError(f"Mach-O section inspection failed: {path.name}")
    lines = [line.strip() for line in result.stdout.splitlines()]
    return any(lines[index] == "sectname __bitcode" and lines[index + 1] == "segname __LLVM"
               for index in range(len(lines) - 1))


def checked_nm(library: pathlib.Path, formats: dict[str, str],
               paths: dict[str, pathlib.Path], target: str) -> tuple[list[str], set[str]]:
    result = subprocess.run(["nm", "-g", str(library)], capture_output=True, text=True)
    unreadable = set()
    for line in result.stderr.splitlines():
        if not line.strip():
            continue
        found = re.search(r"\.a\(([^()]+)\)", line)
        if found is None and ": no symbols" in line:
            found = re.search(r"\.a:([^:]+): no symbols", line)
        if found is None:
            raise ValueError(f"nm failed outside known archive member: {line}")
        member = found.group(1)
        if member not in formats:
            raise ValueError(f"nm failed on unknown member: {member}")
        if "Unknown attribute kind" in line and \
           "Producer: 'LLVM" in line and "-rust-" in line and \
           member.endswith(".rcgu.o") and \
           (formats[member] == "bitcode" or
            embedded_llvm_bitcode(paths[member], target)):
            unreadable.add(member)
        elif ": no symbols" not in line:
            raise ValueError(f"nm failed on native/unknown member: {member}")
    if (result.returncode != 0) != bool(unreadable):
        raise ValueError("nm exit code differs from inspected bitcode diagnostics")
    names = globals_from_nm(result.stdout)
    if not names:
        raise ValueError("archive has no readable global symbols")
    return names, unreadable


def shim_symbols(path: pathlib.Path, target: str) -> tuple[set[str], set[str]]:
    nm = subprocess.run(["nm", "-g", str(path)], check=True, capture_output=True, text=True)
    if nm.stderr.strip():
        raise ValueError("allocator shim nm emitted diagnostics")
    defined, undefined = set(), set()
    observed = 0
    prefix = "__RNv" if target == "aarch64-apple-darwin" else "_RNv"
    if target not in ("aarch64-apple-darwin", "x86_64-unknown-linux-gnu",
                      "aarch64-unknown-linux-gnu"):
        raise ValueError("unsupported allocator shim target")
    for line in nm.stdout.splitlines():
        parts = line.split()
        if len(parts) < 2 or not re.fullmatch(r"[A-Za-z]", parts[-2]):
            continue
        symbol = parts[-1]
        observed += 1
        match = re.fullmatch(
            re.escape(prefix) + r"Cs[0-9A-Za-z]+_7___rustc\d+___"
            r"(rust|rdl)_(alloc|dealloc|realloc|alloc_zeroed|no_alloc_shim_is_unstable_v2)",
            symbol,
        )
        if match is None:
            raise ValueError(f"unexpected allocator shim global {symbol}")
        family, name = match.groups()
        if parts[-2] == "U":
            undefined.add((family, name))
        elif parts[-2] in ("T", "t"):
            defined.add((family, name))
        else:
            raise ValueError(f"allocator shim symbol type {parts[-2]}")
    expected_defined = {("rust", name) for name in
                        ("alloc", "dealloc", "realloc", "alloc_zeroed",
                         "no_alloc_shim_is_unstable_v2")}
    expected_undefined = {("rdl", name) for name in
                          ("alloc", "dealloc", "realloc", "alloc_zeroed")}
    if observed != 9 or defined != expected_defined or undefined != expected_undefined:
        raise ValueError("allocator shim defined/undefined symbol set mismatch")
    return {f"{family}_{name}" for family, name in defined}, \
           {f"{family}_{name}" for family, name in undefined}


def one_shim(count: int) -> None:
    if count != 1:
        raise ValueError(f"allocator shim count {count}")


def negative_controls(source: str, members: list[str], names: list[str],
                      shim_path: pathlib.Path, target: str) -> int:
    controls = (
        ("source", lambda: check_build_source(source + '\n.file("src/lvm.c")')),
        ("link", lambda: check_build_source(source + '\nprintln!("cargo:rustc-link-lib=lua")')),
        ("object", lambda: check_members(members + ["injected-lvm.o"])),
        ("symbol", lambda: check_symbols(names + ["luaV_execute"])),
        ("shim_private", lambda: check_symbols(names + ["luaK_codegen"])),
        ("shim_extra", lambda: check_shim_probe(shim_path, target, "extra_c_symbol")),
        ("second_shim", lambda: one_shim(2)),
    )
    rejected = 0
    for label, check in controls:
        try:
            check()
        except ValueError as error:
            rejected += 1
            print(f"P16_NEG006_CONTROL {label}=REJECTED reason={error}")
        else:
            raise ValueError(f"negative control {label} unexpectedly passed")
    return rejected


def check_shim_probe(path: pathlib.Path, target: str, injected: str) -> None:
    defined, undefined = shim_symbols(path, target)
    defined.add(injected)
    expected = {"rust_alloc", "rust_dealloc", "rust_realloc", "rust_alloc_zeroed",
                "rust_no_alloc_shim_is_unstable_v2"}
    if defined != expected or undefined != {
        "rdl_alloc", "rdl_dealloc", "rdl_realloc", "rdl_alloc_zeroed"
    }:
        raise ValueError("allocator shim extra global")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, required=True)
    parser.add_argument("--library", type=pathlib.Path, required=True)
    parser.add_argument("--build-log", type=pathlib.Path, required=True)
    parser.add_argument("--profile", choices=("lua55-i64f64", "lua54-i64f64"), required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--provenance", type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    source_path = root / "crates/rivetlua-capi/build.rs"
    source = source_path.read_text(encoding="utf-8")
    check_build_source(source)
    if args.library.name != "librivetlua_capi.a" or not args.library.is_file():
        raise ValueError("staticlib snapshot missing")
    if not args.build_log.is_file():
        raise ValueError("staticlib Cargo build log missing")
    members = ar_names(args.library)
    check_members(members)
    sources = source_archives(root, args.build_log, args.profile, args.target)
    selected = provenance(args.library, args.build_log, sources, args.provenance)
    temp_root = pathlib.Path(os.environ.get("TMPDIR", ""))
    if not temp_root.is_absolute() or not temp_root.is_dir() or temp_root.is_relative_to(root):
        raise ValueError("external absolute TMPDIR required for archive inspection")
    with tempfile.TemporaryDirectory(prefix="p16-neg006-", dir=temp_root) as scratch:
        scratch_path = pathlib.Path(scratch)
        static = extract(args.library, scratch_path / "static")
        referenced = {}
        thin_names = set()
        capi_hash = None
        for index, item in enumerate(selected):
            origin = extract(pathlib.Path(item["snapshot"]), scratch_path / f"origin-{index}")
            if item["category"] == "thin":
                thin_names = set(origin)
            if pathlib.Path(item["original"]).name == "librivetlua_capi.rlib":
                hashes = {match.group(1) for name in origin
                          if (match := re.fullmatch(r"rivetlua_capi-([0-9a-f]+)\..*\.rcgu\.o", name))}
                if len(hashes) != 1:
                    raise ValueError("Cargo CAPI rlib codegen hash not unique")
                capi_hash = hashes.pop()
            for name, path in origin.items():
                referenced.setdefault(name, set()).add((sha256(path), item["category"]))
        if len(thin_names) != 2 or not all(
            any(name.endswith("-" + basename) for name in thin_names)
            for basename in ("trampoline.o", "platform.o")
        ):
            raise ValueError("C thin-layer source archive is not exactly two objects")
        formats = {}
        member_sha256 = {}
        shim = []
        for name, path in static.items():
            fmt = classify(path)
            formats[name] = fmt
            evidence = referenced.get(name, set())
            digest = sha256(path)
            member_sha256[name] = digest
            allowed = {category for source_sha, category in evidence if source_sha == digest}
            if name in thin_names:
                if fmt != "native" or "thin" not in allowed:
                    raise ValueError(f"C thin-layer member bytes mismatch: {name}")
            elif fmt == "bitcode":
                if not name.endswith(".rcgu.o") or not allowed.intersection(("cargo", "sysroot")):
                    raise ValueError(f"unmatched Rust bitcode member: {name}")
            elif not allowed.intersection(("cargo", "sysroot")):
                if capi_hash is None or not re.fullmatch(
                    rf"rivetlua_capi-{capi_hash}\.[A-Za-z0-9.]+\.rcgu\.o", name
                ):
                    raise ValueError(f"unmatched native archive member: {name}")
                shim_symbols(path, args.target)
                shim.append((name, path))
        one_shim(len(shim))
        names, unreadable = checked_nm(args.library, formats, static, args.target)
        check_symbols(names)
        rejected = negative_controls(source, members, names, shim[0][1], args.target)
        shim_name, shim_file = shim[0]
        shim_sha = sha256(shim_file)
    if rejected != 7:
        raise ValueError("negative control count mismatch")
    receipt_path = args.provenance / "receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    observed_shim = {"member": shim_name, "sha256": shim_sha, "capi_hash": capi_hash}
    observed_identity = {
        "shim": observed_shim,
        "member_sha256": member_sha256,
        "llvm_bitcode_unreadable": {name: member_sha256[name] for name in sorted(unreadable)},
        "formats": {name: ("native_with_bitcode" if name in unreadable and fmt == "native"
                            else fmt) for name, fmt in formats.items()},
        "toolchain": {"rustc": tool_version(["rustc", "--version", "--verbose"]),
                      "nm": tool_version(["nm", "--version"]),
                      "otool": tool_version(["otool", "--version"])
                      if args.target == "aarch64-apple-darwin" else None},
    }
    if "shim" not in receipt:
        receipt.update(observed_identity)
        receipt_path.write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n",
                                encoding="utf-8")
    elif any(receipt.get(key) != value for key, value in observed_identity.items()):
        raise ValueError("archive member/provenance receipt changed")
    classes = collections.Counter(observed_identity["formats"].values())
    print(f"P16_NEG006_LIMITATION llvm_bitcode_unreadable={len(unreadable)} native={classes['native']} native_with_bitcode={classes['native_with_bitcode']} bitcode={classes['bitcode']} source_member_sha_verified={len(formats) - 1} shim_member_sha256={shim_sha}")
    print(f"P16_NEG006 profile={args.profile} target={args.target} members={len(members)} globals={len(names)} negative_controls={rejected} PASS")
    print("P16_ASSERT ABI-NEG-006 reject_c_lua_fallback=PASS")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"P16_NEG006 FAIL {error}", file=sys.stderr)
        sys.exit(1)
