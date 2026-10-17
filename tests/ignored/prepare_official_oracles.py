#!/usr/bin/env python3
"""以釘選的 vendor 來源準備官方 Lua oracle 與固定測試輸入。"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import struct
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
VERSIONS = {"54": "5.4.9", "55": "5.5.1"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compiler() -> tuple[Path, Path | None, dict[str, str]]:
    if sys.platform == "darwin":
        cc = Path("/Library/Developer/CommandLineTools/usr/bin/clang")
        ld = Path("/Library/Developer/CommandLineTools/usr/bin/ld")
        sdk = Path("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk").resolve(strict=True)
        if cc.is_symlink() or not cc.is_file() or not ld.is_file() or not sdk.is_dir():
            raise RuntimeError("未確認安全的 macOS 編譯器、連結器與 SDK")
        return cc, sdk, {
            "PATH": "/Library/Developer/CommandLineTools/usr/bin:/usr/bin:/bin",
            "SDKROOT": str(sdk),
            "MACOSX_DEPLOYMENT_TARGET": "11.0",
        }
    if sys.platform.startswith("linux"):
        cc = Path("/usr/bin/gcc").resolve(strict=True)
        gcc_helpers = Path("/usr/lib/gcc")
        if (
            not cc.is_file()
            or not os.access(cc, os.X_OK)
            or "gcc" not in cc.name
            or not Path("/usr/bin/as").is_file()
            or not Path("/usr/bin/ld").is_file()
            or not any(gcc_helpers.glob("*/[0-9]*/cc1"))
            or not any(gcc_helpers.glob("*/[0-9]*/collect2"))
        ):
            raise RuntimeError("未確認具體 GNU C 編譯器")
        return cc, None, {"PATH": "/usr/bin:/bin"}
    raise RuntimeError(f"不支援的 oracle 建置平台：{platform.system()}")


def macos_dependencies(path: Path) -> None:
    data = path.read_bytes()
    magic, cpu, _, kind, commands, _, _, _ = struct.unpack_from("<IIIIIIII", data)
    if (magic, cpu, kind) != (0xFEEDFACF, 0x0100000C, 2):
        raise RuntimeError(f"官方工具不是預期的 arm64 Mach-O：{path}")
    offset = 32
    for _ in range(commands):
        command, size = struct.unpack_from("<II", data, offset)
        if size < 8 or offset + size > len(data):
            raise RuntimeError(f"官方工具的 Mach-O load command 無效：{path}")
        if command & 0x7FFFFFFF in (0xC, 0x18, 0x1F, 0x23):
            name_offset = struct.unpack_from("<I", data, offset + 8)[0]
            name = data[offset + name_offset : offset + size].split(b"\0", 1)[0]
            if not (name.startswith(b"/usr/lib/") or name.startswith(b"/System/Library/")):
                raise RuntimeError(f"官方工具有非系統動態依賴：{path}: {name!r}")
        offset += size


def build_oracles(output: Path) -> dict[str, Path]:
    cc, sdk, child_env = compiler()
    sources: dict[str, tuple[Path, list[Path]]] = {}
    source_hash = hashlib.sha256()
    for profile, release in VERSIONS.items():
        src = ROOT / f"vendor/lua{profile}/lua-{release}/src"
        units = sorted(path for path in src.glob("l*.c") if path.name not in ("lua.c", "luac.c"))
        if len(units) != 32:
            raise RuntimeError(f"官方 Lua {release} 編譯單元數量不符")
        sources[profile] = src, units
        source_hash.update(profile.encode())
        for path in sorted((*src.glob("*.c"), *src.glob("*.h"))):
            source_hash.update(path.name.encode())
            source_hash.update(path.read_bytes())
    cc_stat = cc.stat()
    key = {
        "schema": 2,
        "compiler": str(cc),
        "compiler_size": cc_stat.st_size,
        "compiler_mtime_ns": cc_stat.st_mtime_ns,
        "sdk": str(sdk) if sdk else None,
        "flags": "-std=gnu99 -O2 LUA_USE_MACOSX/POSIX LUA_COMPAT_5_3(54) -lm -lreadline(mac55)",
        "source_sha256": source_hash.hexdigest(),
    }
    binaries = {f"{name}{profile}": output / f"{name}{profile}" for profile in VERSIONS for name in ("lua", "luac")}
    stamp_path = output / "oracle-build.json"
    try:
        stamp = json.loads(stamp_path.read_text()) if stamp_path.is_file() else {}
    except (OSError, ValueError):
        stamp = {}
    reused = stamp.get("key") == key and all(
        path.is_file() and not path.is_symlink() and digest(path.read_bytes()) == stamp.get("binaries", {}).get(name)
        for name, path in binaries.items()
    )
    if not reused:
        for profile, (src, units) in sources.items():
            flags = ["-std=gnu99", "-O2", "-I", str(src)]
            if sdk:
                flags += ["-DLUA_USE_MACOSX", "-isysroot", str(sdk), "-mmacosx-version-min=11.0"]
            else:
                flags += ["-DLUA_USE_POSIX"]
            if profile == "54":
                flags += ["-DLUA_COMPAT_5_3"]
            for name in ("lua", "luac"):
                target = binaries[f"{name}{profile}"]
                building = target.with_name(target.name + ".building")
                command = [str(cc), *flags, "-o", str(building), str(src / f"{name}.c"), *(str(path) for path in units), "-lm"]
                if sdk and profile == "55":
                    command += ["-lreadline"]
                result = subprocess.run(command, capture_output=True, text=True, env=child_env, check=False, timeout=120)
                if result.returncode:
                    building.unlink(missing_ok=True)
                    raise RuntimeError(f"官方 Lua {profile} {name} 編譯失敗：\n{result.stderr}")
                os.replace(building, target)
    version_env = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home())}
    for profile, release in VERSIONS.items():
        for name in ("lua", "luac"):
            path = binaries[f"{name}{profile}"]
            if sdk:
                macos_dependencies(path)
            result = subprocess.run([str(path), "-v"], capture_output=True, text=True, env=version_env, check=False, timeout=5)
            if result.returncode or f"Lua {release}" not in result.stdout + result.stderr:
                raise RuntimeError(f"官方工具版本不符：{path}")
    if not reused:
        stamp_path.write_text(json.dumps({"key": key, "binaries": {name: digest(path.read_bytes()) for name, path in binaries.items()}}, sort_keys=True))
    print("官方 Lua 工具：" + ("重用" if reused else "建置") + "；版本 5.4.9／5.5.1", file=sys.stderr)
    return binaries


def write_exact(path: Path, value: bytes) -> None:
    if path.parent.is_symlink():
        raise RuntimeError(f"拒絕寫入符號連結目錄：{path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise RuntimeError(f"拒絕覆寫符號連結：{path}")
    if not path.is_file() or path.read_bytes() != value:
        path.write_bytes(value)


def fixtures(output: Path) -> dict[str, Path]:
    suite55 = ROOT / "vendor/lua55/lua-5.5.1-tests"
    suite54 = ROOT / "vendor/lua54/lua-5.4.9-tests"
    db = (suite55 / "db.lua").read_bytes()
    if len(db) != 26598 or digest(db) != "82ed710f0aa5ab23eb86fc0ad73705e6d8f8b0cd9c8a3d1b4da31623c3e40f10":
        raise RuntimeError("固定的 Lua 5.5.1 db.lua 輸入不符")
    gc = (suite55 / "gc.lua").read_bytes()
    if len(gc) != 19650 or digest(gc) != "e1768dd5a40921af0e5d24b1d61c9fd4727c45716e28bf167246a45e38735a99":
        raise RuntimeError("固定的 Lua 5.5.1 gc.lua 輸入不符")
    raw = output / "fixtures"
    write_exact(raw / "lua-5.5.1-tests/gc.lua", gc)
    lines = gc.splitlines(keepends=True)
    for count, size, prefix in ((350, 8484, "148c8bf704b70276"), (395, 9478, "5c0cfe51f9253386")):
        value = b"".join(lines[:count])
        if len(value) != size or not digest(value).startswith(prefix):
            raise RuntimeError(f"固定的 gc_prefix_{count}.lua 輸入不符")
        write_exact(raw / f"repro/gc_prefix_{count}.lua", value)
    for count, size, prefix in ((5, 85, "6909155e0fba2610"), (21, 357, "851f0446d85e1796")):
        value = b"do local x=1 end\n" * count
        if len(value) != size or not digest(value).startswith(prefix):
            raise RuntimeError(f"固定的 simple_{count}.lua 輸入不符")
        write_exact(raw / f"repro/simple_{count}.lua", value)
    return {
        "RIVETLUA_HOSTLOAD_MAIN": suite55 / "main.lua",
        "RIVETLUA_HOSTLOAD_DB": suite55 / "db.lua",
        "RIVETLUA_HOSTLOAD_GC55": suite55 / "gc.lua",
        "RIVETLUA_HOSTLOAD_GC54": suite54 / "gc.lua",
        "RIVETLUA_TRACEGC_DIR": suite55,
        "RIVETLUA_RAW_V23_DB": suite55 / "db.lua",
        "RIVETLUA_V24_FIXTURES": suite55,
        "RIVETLUA_RAW_V13_DIR": raw,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--env-file", type=Path)
    parser.add_argument("--p15-db-chunk", type=Path)
    args = parser.parse_args()
    if not args.output_root.is_absolute() or args.output_root.is_symlink():
        raise RuntimeError("輸出根目錄必須是非符號連結的絕對路徑")
    output = args.output_root.resolve()
    if output.is_relative_to(ROOT):
        raise RuntimeError("oracle 暫存輸出不可位於專案內")
    output.mkdir(parents=True, exist_ok=True)
    oracles = output / "oracles"
    if oracles.is_symlink():
        raise RuntimeError("oracle 輸出目錄不可為符號連結")
    oracles.mkdir(exist_ok=True)
    for name in ("tmp", "evidence", "fixtures"):
        folder = output / name
        if folder.is_symlink():
            raise RuntimeError(f"輸出目錄不可為符號連結：{folder}")
        folder.mkdir(exist_ok=True)
    binaries = build_oracles(oracles)
    values = fixtures(output)
    values.update({
        "RIVETLUA_LUA54": binaries["lua54"],
        "RIVETLUA_LUA55": binaries["lua55"],
        "RIVETLUA_LUA54_LUAC": binaries["luac54"],
        "RIVETLUA_LUA55_LUAC": binaries["luac55"],
        "RIVETLUA_OFFICIAL_ORACLE_OUTPUT_DIR": output / "evidence",
        "TMPDIR": output / "tmp",
    })
    if args.p15_db_chunk:
        chunk = args.p15_db_chunk.resolve(strict=True)
        contents = chunk.read_bytes()
        if len(contents) != 64377 or digest(contents) != "148574895de297028b10f5191d147bf531bbfd3c898f0137a5f98c1e2fe01e4c":
            raise RuntimeError("RivetLua Lua 5.5.1 db chunk 與已驗證產物不符")
        values["RIVETLUA_P15_DB_CHUNK"] = chunk
    for name, path in values.items():
        if not path.exists() or "\n" in str(path):
            raise RuntimeError(f"固定輸入不存在或路徑無效：{name}={path}")
    lines = "".join(f"{name}={path}\n" for name, path in sorted(values.items()))
    if args.env_file:
        if args.env_file.is_symlink():
            raise RuntimeError("環境輸出檔不可為符號連結")
        with args.env_file.open("a", encoding="utf-8") as stream:
            stream.write(lines)
    sys.stdout.write(lines)


if __name__ == "__main__":
    main()
