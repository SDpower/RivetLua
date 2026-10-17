"""P24 暫存套件交易的純檔案工具；不執行 Cargo、編譯器或發布命令。"""

from __future__ import annotations

import argparse
import copy
import hashlib
import http.server
import io
import json
import os
import re
import shutil
import stat
import tarfile
import tempfile
import tomllib
from urllib.parse import unquote, urlsplit
from pathlib import Path, PurePosixPath

REGISTRY = "p24-stage"
CRATES_IO_INDEX = "https://github.com/rust-lang/crates.io-index"
PUBLIC = frozenset({
    "rivetlua-core", "rivetlua-compiler", "rivetlua-runtime", "rivetlua-native",
    "rivetlua", "rivetlua-cli", "rivetlua-capi",
})
ASSETS = ("LICENSE-MIT", "LICENSE-APACHE", "THIRD_PARTY_NOTICES.md")
MAX_ARCHIVE = 64 * 1024 * 1024
MAX_UNPACKED = 128 * 1024 * 1024
MAX_MEMBERS = 10000


class ReleaseError(ValueError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _read_regular(path: Path, limit: int) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        raise ReleaseError("E_FILE_POLICY")
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > limit:
                raise ReleaseError("E_FILE_POLICY")
            data = stream.read(limit + 1)
    except OSError as error:
        raise ReleaseError("E_FILE_POLICY") from error
    if len(data) > limit:
        raise ReleaseError("E_FILE_POLICY")
    return data


def _deps(manifest: dict):
    """遍歷一般、build、dev 與 target 條件依賴表。"""
    for section in ("dependencies", "build-dependencies", "dev-dependencies"):
        table = manifest.get(section, {})
        if not isinstance(table, dict):
            raise ReleaseError("E_MANIFEST_DEP")
        yield table
    for target in manifest.get("target", {}).values():
        if not isinstance(target, dict):
            raise ReleaseError("E_MANIFEST_DEP")
        for section in ("dependencies", "build-dependencies", "dev-dependencies"):
            table = target.get(section, {})
            if not isinstance(table, dict):
                raise ReleaseError("E_MANIFEST_DEP")
            yield table


def _internal_path(path: str, package: str) -> bool:
    return isinstance(path, str) and path == "../" + package


def _manifest_paths(manifest: dict) -> None:
    package = manifest.get("package", {})
    if not isinstance(package, dict) or not isinstance(manifest.get("bin", []), list):
        raise ReleaseError("E_MANIFEST_PATH")
    if package.get("readme") not in (None, "README.md") or package.get("build") not in (None, False, "build.rs"):
        raise ReleaseError("E_MANIFEST_PATH")
    if "include" in package or "exclude" in package:
        raise ReleaseError("E_MANIFEST_PATH")
    for target in ([manifest["lib"]] if "lib" in manifest else []) + manifest.get("bin", []):
        if not isinstance(target, dict):
            raise ReleaseError("E_MANIFEST_PATH")
        path = target.get("path")
        if path is None:
            continue
        if not isinstance(path, str) or not path.startswith("src/") or "\\" in path or any(
            segment in ("", ".", "..") for segment in path.split("/")
        ):
            raise ReleaseError("E_MANIFEST_PATH")


def release_graph(manifests: dict[str, dict], workspace_package: dict) -> list[str]:
    if set(manifests) != PUBLIC or not workspace_package:
        raise ReleaseError("E_DAG_PUBLIC")
    edges = {}
    for name, manifest in manifests.items():
        if manifest.get("package", {}).get("name") != name:
            raise ReleaseError("E_DAG_PUBLIC")
        links = set()
        for table in _deps(manifest):
            for alias, dep in table.items():
                if not isinstance(dep, dict):
                    continue
                package = dep.get("package", alias)
                if "path" in dep:
                    if package not in manifests or not _internal_path(dep["path"], package):
                        raise ReleaseError("E_DAG_DEP")
                    links.add(package)
                elif package in manifests:
                    raise ReleaseError("E_DAG_DEP")
        edges[name] = links
    state, ordered = {}, []

    def visit(name: str) -> None:
        if state.get(name) == 1:
            raise ReleaseError("E_DAG_CYCLE")
        if state.get(name) == 2:
            return
        state[name] = 1
        for dep in sorted(edges[name]):
            visit(dep)
        state[name] = 2
        ordered.append(name)

    for name in sorted(manifests):
        visit(name)
    return ordered


def stage_manifest(original: dict, workspace_package: dict, ready: dict[str, str]) -> dict:
    _manifest_paths(original)
    staged = copy.deepcopy(original)
    package = staged.get("package")
    if not isinstance(package, dict) or package.get("name") not in PUBLIC:
        raise ReleaseError("E_MANIFEST_PACKAGE")
    if package.get("publish") is False:
        raise ReleaseError("E_MANIFEST_PACKAGE")
    for key, value in list(package.items()):
        if value == {"workspace": True}:
            if key not in workspace_package:
                raise ReleaseError("E_MANIFEST_WORKSPACE")
            package[key] = copy.deepcopy(workspace_package[key])
    if not isinstance(package.get("version"), str):
        raise ReleaseError("E_MANIFEST_VERSION")
    for table in _deps(staged):
        for alias, dep in table.items():
            if not isinstance(dep, dict) or "path" not in dep:
                continue
            name = dep.get("package", alias)
            version = ready.get(name)
            if name not in PUBLIC or not _internal_path(dep["path"], name):
                raise ReleaseError("E_MANIFEST_DEP")
            if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
                raise ReleaseError("E_STAGE_NOT_READY")
            if "registry" in dep or ("version" in dep and dep["version"] not in (version, "=" + version)):
                raise ReleaseError("E_MANIFEST_DEP")
            del dep["path"]
            dep["version"] = "=" + version
            dep["registry"] = REGISTRY
    return staged


def verify_manifest_allowdiff(original: dict, staged: dict, workspace_package: dict, ready: dict[str, str]) -> None:
    if staged != stage_manifest(original, workspace_package, ready):
        raise ReleaseError("E_MANIFEST_DIFF")


def _manifest_identity(manifest: dict, name: str, version: str) -> None:
    _manifest_paths(manifest)
    package = manifest.get("package", {})
    if package.get("name") != name or package.get("version") != version:
        raise ReleaseError("E_ARCHIVE_MANIFEST")
    if package.get("license") != "MIT OR Apache-2.0":
        raise ReleaseError("E_ARCHIVE_LICENSE")
    for table in _deps(manifest):
        for dep in table.values():
            if isinstance(dep, dict) and "path" in dep:
                raise ReleaseError("E_ARCHIVE_PATH_DEP")


def verify_archive_manifest(staged: dict, archived: dict,
                            staged_files: set[str], archive_files: set[str]) -> None:
    """比較套件語意；只容許目前已知的 Cargo 自動欄位。"""
    def reject() -> None:
        raise ReleaseError("E_ARCHIVE_METADATA")

    if not isinstance(staged, dict) or not isinstance(archived, dict) or not isinstance(staged_files, set) or not isinstance(archive_files, set):
        reject()
    sections = {"package", "lib", "bin", "features", "dependencies", "build-dependencies", "dev-dependencies", "target"}
    if set(staged) - sections or set(archived) - sections:
        reject()
    expected, actual = staged.get("package"), archived.get("package")
    if (not isinstance(expected, dict) or not isinstance(actual, dict)
            or not isinstance(expected.get("name"), str)):
        reject()
    if any(actual.get(key) != value for key, value in expected.items()):
        reject()
    for key in set(actual) - set(expected):
        value = actual[key]
        if key == "authors" and value == []:
            continue
        if key in {"autolib", "autobins", "autoexamples", "autotests", "autobenches"} and value is False:
            continue
        if key == "build" and value == ("build.rs" if "build.rs" in staged_files else False):
            continue
        reject()
    if "build.rs" in staged_files and "build.rs" not in archive_files:
        reject()

    canonical_lib = {"name": expected["name"].replace("-", "_"), "path": "src/lib.rs"}
    expected_lib = staged.get("lib")
    actual_lib = archived.get("lib")
    if expected_lib is not None and not isinstance(expected_lib, dict):
        reject()
    if expected_lib is not None and expected_lib.get("path", "src/lib.rs") != "src/lib.rs":
        reject()
    if ("src/lib.rs" in staged_files) != (actual_lib is not None):
        reject()
    if actual_lib is not None:
        if not isinstance(actual_lib, dict) or "src/lib.rs" not in archive_files:
            reject()
        for key, value in (expected_lib or {}).items():
            if actual_lib.get(key) != value:
                reject()
        for key in set(actual_lib) - set(expected_lib or {}):
            if key not in canonical_lib or actual_lib[key] != canonical_lib[key]:
                reject()
    expected_bins, actual_bins = staged.get("bin", []), archived.get("bin", [])
    if not isinstance(expected_bins, list) or not isinstance(actual_bins, list) or len(expected_bins) != len(actual_bins):
        reject()
    if any(not isinstance(item, dict) or not isinstance(item.get("name"), str)
           or not isinstance(item.get("path"), str) or item["path"] not in staged_files or item["path"] not in archive_files
           for item in expected_bins):
        reject()
    if any(not isinstance(item, dict) or not isinstance(item.get("name"), str) for item in actual_bins):
        reject()
    if sorted(expected_bins, key=lambda item: item["name"]) != sorted(actual_bins, key=lambda item: item.get("name", "")):
        reject()

    def dep_table(value: object) -> dict:
        if not isinstance(value, dict):
            reject()
        result = {}
        for name, spec in value.items():
            if not isinstance(name, str):
                reject()
            spec = {"version": spec} if isinstance(spec, str) else spec
            if not isinstance(spec, dict) or set(spec) - {"version", "registry", "package", "features", "optional", "default-features"}:
                reject()
            if (not isinstance(spec.get("version"), str) or not isinstance(spec.get("features", []), list)
                    or any(not isinstance(feature, str) for feature in spec.get("features", []))
                    or type(spec.get("optional", False)) is not bool or type(spec.get("default-features", True)) is not bool
                    or not isinstance(spec.get("package", name), str)
                    or (spec.get("registry") is not None and not isinstance(spec["registry"], str))):
                reject()
            result[name] = (spec["version"], spec.get("registry"), spec.get("package", name),
                            tuple(sorted(spec.get("features", []))), spec.get("optional", False),
                            spec.get("default-features", True))
        return result

    for section in ("dependencies", "build-dependencies", "dev-dependencies"):
        if dep_table(staged.get(section, {})) != dep_table(archived.get(section, {})):
            reject()
    staged_targets, archived_targets = staged.get("target", {}), archived.get("target", {})
    if not isinstance(staged_targets, dict) or not isinstance(archived_targets, dict) or set(staged_targets) != set(archived_targets):
        reject()
    for target in staged_targets:
        left, right = staged_targets[target], archived_targets[target]
        if (not isinstance(left, dict) or not isinstance(right, dict) or set(left) != set(right)
                or set(left) - {"dependencies", "build-dependencies", "dev-dependencies"}):
            reject()
        if any(dep_table(left[section]) != dep_table(right[section]) for section in left):
            reject()
    left, right = staged.get("features", {}), archived.get("features", {})
    if not isinstance(left, dict) or not isinstance(right, dict) or set(left) != set(right):
        reject()
    if any(not isinstance(left[key], list) or not isinstance(right[key], list)
           or any(not isinstance(feature, str) for feature in left[key] + right[key])
           or sorted(left[key]) != sorted(right[key]) for key in left):
        reject()


def inspect_archive(path: Path, name: str, version: str) -> dict:
    path = Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_ARCHIVE:
        raise ReleaseError("E_ARCHIVE_INPUT")
    if name not in PUBLIC or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ReleaseError("E_ARCHIVE_ID")
    prefix = name + "-" + version
    files, contents, total = {}, {}, 0
    packed = _read_regular(path, MAX_ARCHIVE)
    try:
        with tarfile.open(fileobj=io.BytesIO(packed), mode="r:gz") as archive:
            for count, member in enumerate(archive):
                if count >= MAX_MEMBERS:
                    raise ReleaseError("E_ARCHIVE_LIMIT")
                if member.isdir() and member.name.rstrip("/") == prefix:
                    continue
                raw_parts = member.name.rstrip("/").split("/")
                parts = PurePosixPath(member.name).parts
                if len(parts) < 2 or parts[0] != prefix or any(part in ("", ".", "..") for part in parts):
                    raise ReleaseError("E_ARCHIVE_PATH")
                if raw_parts != list(parts):
                    raise ReleaseError("E_ARCHIVE_PATH")
                relative = "/".join(parts[1:])
                if member.name.startswith("/") or "\\" in member.name or relative.startswith((".git/", "target/", "tmp/")) or relative in (".env", ".cargo/credentials.toml"):
                    raise ReleaseError("E_ARCHIVE_PRIVATE")
                if member.isdir():
                    continue
                if relative not in {"Cargo.toml", "Cargo.toml.orig", "Cargo.lock", "README.md", "build.rs", *ASSETS} and not relative.startswith(("src/", "tests/", "examples/", "benches/", "include/")):
                    raise ReleaseError("E_ARCHIVE_PRIVATE")
                if not member.isfile() or relative in files or member.size < 0:
                    raise ReleaseError("E_ARCHIVE_TYPE")
                total += member.size
                if total > MAX_UNPACKED:
                    raise ReleaseError("E_ARCHIVE_LIMIT")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ReleaseError("E_ARCHIVE_TYPE")
                data = stream.read(member.size + 1)
                if len(data) != member.size:
                    raise ReleaseError("E_ARCHIVE_SIZE")
                files[relative] = _sha(data)
                if relative in ("Cargo.toml", *ASSETS):
                    contents[relative] = data
    except (tarfile.TarError, OSError, OverflowError) as error:
        raise ReleaseError("E_ARCHIVE_FORMAT") from error
    if "Cargo.toml" not in contents or not any(key.startswith("src/") for key in files):
        raise ReleaseError("E_ARCHIVE_FILES")
    if any(not contents.get(asset) for asset in ASSETS):
        raise ReleaseError("E_ARCHIVE_LICENSE")
    try:
        manifest = tomllib.loads(contents["Cargo.toml"].decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise ReleaseError("E_ARCHIVE_MANIFEST") from error
    _manifest_identity(manifest, name, version)
    return {"sha256": _sha(packed), "files": files, "manifest": manifest}


def verify_archive_assets(archive: dict, canonical_hashes: dict[str, str]) -> None:
    if any(archive["files"].get(name) != digest for name, digest in canonical_hashes.items()):
        raise ReleaseError("E_ARCHIVE_ASSET_HASH")


def index_entry(name: str, version: str, archive_sha256: str, manifest: dict) -> dict:
    if not isinstance(archive_sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", archive_sha256):
        raise ReleaseError("E_INDEX_HASH")
    if name not in PUBLIC or not isinstance(version, str):
        raise ReleaseError("E_INDEX_NAME")
    _manifest_identity(manifest, name, version)
    dependencies = []
    for kind, section in (("normal", "dependencies"), ("build", "build-dependencies"), ("dev", "dev-dependencies")):
        for alias, spec in manifest.get(section, {}).items():
            dep = {"name": alias, "req": spec if isinstance(spec, str) else spec.get("version"),
                   "features": [] if isinstance(spec, str) else spec.get("features", []),
                   "optional": False if isinstance(spec, str) else spec.get("optional", False),
                   "default_features": True if isinstance(spec, str) else spec.get("default-features", True),
                   "target": None, "kind": kind,
                   "registry": None if isinstance(spec, dict) and spec.get("registry") == REGISTRY else CRATES_IO_INDEX}
            if isinstance(spec, dict) and spec.get("package", alias) != alias:
                dep["package"] = spec["package"]
            if not isinstance(dep["req"], str):
                raise ReleaseError("E_INDEX_DEP")
            dependencies.append(dep)
    for target, clauses in manifest.get("target", {}).items():
        for kind, section in (("normal", "dependencies"), ("build", "build-dependencies"), ("dev", "dev-dependencies")):
            for alias, spec in clauses.get(section, {}).items():
                dep = {"name": alias, "req": spec if isinstance(spec, str) else spec.get("version"),
                       "features": [] if isinstance(spec, str) else spec.get("features", []),
                       "optional": False if isinstance(spec, str) else spec.get("optional", False),
                       "default_features": True if isinstance(spec, str) else spec.get("default-features", True),
                       "target": target, "kind": kind,
                       "registry": None if isinstance(spec, dict) and spec.get("registry") == REGISTRY else CRATES_IO_INDEX}
                if isinstance(spec, dict) and spec.get("package", alias) != alias:
                    dep["package"] = spec["package"]
                if not isinstance(dep["req"], str):
                    raise ReleaseError("E_INDEX_DEP")
                dependencies.append(dep)
    entry = {"name": name, "vers": version, "deps": dependencies,
             "cksum": archive_sha256, "features": manifest.get("features", {}),
             "yanked": False, "v": 2}
    if "rust-version" in manifest["package"]:
        entry["rust_version"] = manifest["package"]["rust-version"]
    return entry


def verify_index(entry: dict, archive_sha256: str, manifest: dict) -> None:
    if not isinstance(entry, dict):
        raise ReleaseError("E_INDEX_MISMATCH")
    try:
        expected = index_entry(entry.get("name"), entry.get("vers"), archive_sha256, manifest)
    except ReleaseError as error:
        raise ReleaseError("E_INDEX_MISMATCH") from error
    if entry != expected:
        raise ReleaseError("E_INDEX_MISMATCH")


def sparse_path(name: str) -> str:
    if not re.fullmatch(r"[a-z0-9_-]+", name):
        raise ReleaseError("E_INDEX_NAME")
    if len(name) == 1:
        return "1/" + name
    if len(name) == 2:
        return "2/" + name
    if len(name) == 3:
        return "3/" + name[0] + "/" + name
    return name[:2] + "/" + name[2:4] + "/" + name


def load_workspace(root: Path) -> tuple[dict[str, dict], dict]:
    root = Path(root).resolve(strict=True)
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    members = workspace["workspace"]["members"]
    manifests = {}
    for member in members:
        if member == "xtask":
            continue
        manifest_path = (root / member / "Cargo.toml").resolve(strict=True)
        if root not in manifest_path.parents:
            raise ReleaseError("E_WORKSPACE_PATH")
        manifest = tomllib.loads(manifest_path.read_text())
        name = manifest["package"]["name"]
        if name in manifests:
            raise ReleaseError("E_DAG_PUBLIC")
        manifests[name] = manifest
    release_graph(manifests, workspace["workspace"]["package"])
    return manifests, workspace["workspace"]["package"]


def init_session(base: Path) -> Path:
    base = Path(base)
    if base.is_symlink() or not base.is_dir():
        raise ReleaseError("E_SESSION_BASE")
    session = Path(tempfile.mkdtemp(prefix="p24-", dir=base))
    for child in ("registry/index", "registry/mirror-index", "registry/api/v1/crates", "cargo-home", "staging", "consumers"):
        (session / child).mkdir(parents=True)
    (session / ".p24-owned").write_text("P24-B01\n")
    return session


def owned_session(path: Path) -> Path:
    path = Path(path)
    if path.is_symlink() or not path.is_dir() or not path.name.startswith("p24-"):
        raise ReleaseError("E_SESSION_PATH")
    if _read_regular(path / ".p24-owned", 16) != b"P24-B01\n":
        raise ReleaseError("E_SESSION_PATH")
    return path.resolve(strict=True)


def staged_file_names(stage: Path) -> set[str]:
    if stage.is_symlink() or not stage.is_dir():
        raise ReleaseError("E_STAGE_PATH")
    files = set()
    for entry in stage.rglob("*"):
        if entry.is_symlink() or (not entry.is_file() and not entry.is_dir()):
            raise ReleaseError("E_STAGE_PATH")
        if entry.is_file():
            files.add(entry.relative_to(stage).as_posix())
            if len(files) > MAX_MEMBERS:
                raise ReleaseError("E_STAGE_PATH")
    return files


def copy_canonical_assets(root: Path, package_dir: Path, capi: bool) -> dict[str, str]:
    hashes = {}
    for asset in ASSETS:
        source = Path(root) / asset
        if source.is_symlink() or not source.is_file():
            raise ReleaseError("E_ASSET_SOURCE")
        data = _read_regular(source, MAX_ARCHIVE)
        if not data:
            raise ReleaseError("E_ASSET_SOURCE")
        target = Path(package_dir) / asset
        target.write_bytes(data)
        hashes[asset] = _sha(data)
    if capi:
        for relative in ("rivetlua_abi.h", "lua54/lua.h", "lua54/lauxlib.h", "lua54/luaconf.h", "lua54/lualib.h",
                         "lua55/lua.h", "lua55/lauxlib.h", "lua55/luaconf.h", "lua55/lualib.h"):
            source = Path(root) / "include/rivetlua" / relative
            if source.is_symlink() or not source.is_file():
                raise ReleaseError("E_HEADER_SOURCE")
            data = _read_regular(source, MAX_ARCHIVE)
            target = Path(package_dir) / "include/rivetlua" / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            hashes["include/rivetlua/" + relative] = _sha(data)
    return hashes


def _toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, int):
        return str(value)
    if isinstance(value, list):
        return "[" + ", ".join(_toml_value(item) for item in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join(f"{key} = {_toml_value(item)}" for key, item in value.items()) + " }"
    raise ReleaseError("E_TOML_VALUE")


def render_manifest(manifest: dict) -> str:
    """只輸出目前公開 crate 實際使用的 Cargo manifest 表。"""
    allowed = {"package", "lib", "bin", "features", "dependencies", "build-dependencies",
               "dev-dependencies", "target"}
    if set(manifest) - allowed:
        raise ReleaseError("E_TOML_SCOPE")
    lines = []

    def table(header: str, values: dict) -> None:
        if not isinstance(values, dict):
            raise ReleaseError("E_TOML_VALUE")
        lines.append("[" + header + "]")
        for key, value in values.items():
            lines.append(f"{json.dumps(key) if '.' in key else key} = {_toml_value(value)}")
        lines.append("")

    for section in ("package", "lib", "features", "dependencies", "build-dependencies", "dev-dependencies"):
        if section in manifest:
            table(section, manifest[section])
    for binary in manifest.get("bin", []):
        if not isinstance(binary, dict):
            raise ReleaseError("E_TOML_VALUE")
        lines.append("[[bin]]")
        for key, value in binary.items():
            lines.append(f"{key} = {_toml_value(value)}")
        lines.append("")
    for target, sections in manifest.get("target", {}).items():
        if not isinstance(sections, dict) or set(sections) - {"dependencies", "build-dependencies", "dev-dependencies"}:
            raise ReleaseError("E_TOML_SCOPE")
        for section, values in sections.items():
            table("target." + json.dumps(target) + "." + section, values)
    output = "\n".join(lines)
    if tomllib.loads(output) != manifest:
        raise ReleaseError("E_TOML_ROUNDTRIP")
    return output


def stage_package(root: Path, session: Path, name: str, original: dict,
                  workspace_package: dict, ready: dict[str, str]) -> dict:
    """複製本 crate 明列檔案；不讀母專案私檔，不產生虛構 lock。"""
    if name not in PUBLIC or original.get("package", {}).get("name") != name:
        raise ReleaseError("E_STAGE_PACKAGE")
    root, session = Path(root).resolve(strict=True), owned_session(session)
    source = root / "crates" / name
    if source.is_symlink() or not source.is_dir() or (session / "staging" / name).exists():
        raise ReleaseError("E_STAGE_PATH")
    staged_manifest = stage_manifest(original, workspace_package, ready)
    destination = session / "staging" / name
    destination.mkdir()
    try:
        for item in ("src", "tests", "examples", "benches", "README.md", "build.rs"):
            entry = source / item
            if not entry.exists():
                continue
            if entry.is_symlink():
                raise ReleaseError("E_STAGE_SYMLINK")
            if entry.is_file():
                (destination / item).write_bytes(_read_regular(entry, MAX_ARCHIVE))
                continue
            if not entry.is_dir():
                raise ReleaseError("E_STAGE_PATH")
            for file in entry.rglob("*"):
                if file.is_symlink() or (not file.is_file() and not file.is_dir()):
                    raise ReleaseError("E_STAGE_SYMLINK")
                if file.is_file():
                    target = destination / file.relative_to(source)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(_read_regular(file, MAX_ARCHIVE))
        (destination / "Cargo.toml").write_text(render_manifest(staged_manifest))
        assets = copy_canonical_assets(root, destination, name == "rivetlua-capi")
    except Exception:
        # 只回收本次剛建立的暫存 crate，不留下貌似可封裝的半成品。
        shutil.rmtree(destination)
        raise
    return {"manifest": staged_manifest, "assets": assets, "path": str(destination)}


def mirror_locked(lock_path: Path, archive_dir: Path, index_dir: Path, session: Path) -> int:
    """只接受使用者明確給定的離線 archives/index snapshot。"""
    lock = tomllib.loads(Path(lock_path).read_text())
    registry = owned_session(session) / "registry"
    mirror = registry / "mirror-index"
    downloads = registry / "api/v1/crates"
    if any(path.is_symlink() or (not path.is_dir() and path.relative_to(mirror) != Path("config.json"))
           for path in mirror.rglob("*")) or any(downloads.iterdir()):
        raise ReleaseError("E_MIRROR_EXISTS")
    pending = []
    indexed = {}
    for package in lock.get("package", []):
        source = package.get("source", "")
        if not source:
            if package["name"] not in PUBLIC | {"rivetlua-xtask"}:
                raise ReleaseError("E_MIRROR_SOURCE")
            continue
        if source != "registry+" + CRATES_IO_INDEX:
            raise ReleaseError("E_MIRROR_SOURCE")
        name, version, checksum = package["name"], package["version"], package.get("checksum")
        if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][a-zA-Z0-9.-]+)?", version):
            raise ReleaseError("E_MIRROR_LOCK")
        if not isinstance(checksum, str) or not re.fullmatch(r"[0-9a-f]{64}", checksum):
            raise ReleaseError("E_MIRROR_LOCK")
        archive = Path(archive_dir) / f"{name}-{version}.crate"
        index = Path(index_dir) / sparse_path(name)
        if archive.is_symlink() or index.is_symlink() or not archive.is_file() or not index.is_file():
            raise ReleaseError("E_MIRROR_MISSING")
        archive_bytes = _read_regular(archive, MAX_ARCHIVE)
        if _sha(archive_bytes) != checksum:
            raise ReleaseError("E_MIRROR_HASH")
        try:
            records = [json.loads(line) for line in _read_regular(index, 16 * 1024 * 1024).decode("utf-8").splitlines() if line]
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ReleaseError("E_MIRROR_INDEX") from error
        matches = [record for record in records if record.get("name") == name and record.get("vers") == version]
        if len(matches) != 1 or matches[0].get("cksum") != checksum:
            raise ReleaseError("E_MIRROR_INDEX")
        if not isinstance(matches[0].get("deps"), list) or any(
            not isinstance(dep, dict) or dep.get("registry") not in (None, CRATES_IO_INDEX)
            for dep in matches[0]["deps"]
        ):
            raise ReleaseError("E_MIRROR_INDEX")
        if any(previous[1] == version for previous in indexed.get(name, [])):
            raise ReleaseError("E_MIRROR_INDEX")
        indexed.setdefault(name, []).append((matches[0], version))
        pending.append((name, version, archive, checksum))
    created = []
    try:
        for name, version, archive, checksum in pending:
            target_archive = downloads / name / version / "download"
            target_archive.parent.mkdir(parents=True, exist_ok=True)
            packed = _read_regular(archive, MAX_ARCHIVE)
            if _sha(packed) != checksum:
                raise ReleaseError("E_MIRROR_CHANGED")
            created.append(target_archive)
            target_archive.write_bytes(packed)
        for name, records in indexed.items():
            target_index = mirror / sparse_path(name)
            target_index.parent.mkdir(parents=True, exist_ok=True)
            created.append(target_index)
            target_index.write_text("".join(json.dumps(record, separators=(",", ":")) + "\n"
                                            for record, _ in records))
    except Exception:
        for path in created:
            path.unlink(missing_ok=True)
        for path in reversed(created):
            parent = path.parent
            while parent not in (mirror, downloads):
                try:
                    parent.rmdir()
                except OSError:
                    break
                parent = parent.parent
        raise
    return len(pending)


def verify_stage_lock(lock_path: Path, public_archives: dict[str, dict],
                      third_party_lock: Path, registry_url: str,
                      unpublished_root: str | None = None) -> None:
    """檢查外部 resolver 真正產生的 staging lock；絕不手造 checksum。"""
    staged = tomllib.loads(_read_regular(Path(lock_path), 16 * 1024 * 1024).decode("utf-8"))
    original = tomllib.loads(_read_regular(Path(third_party_lock), 16 * 1024 * 1024).decode("utf-8"))
    expected_external = {(p["name"], p["version"]): (p.get("checksum"), p["source"])
                         for p in original["package"] if p.get("source")}
    found_public = set()
    for package in staged.get("package", []):
        name, version = package["name"], package["version"]
        if name in PUBLIC:
            if name == unpublished_root and not package.get("source") and not package.get("checksum"):
                found_public.add(name)
                continue
            archive = public_archives.get(name)
            if not archive or archive["version"] != version or package.get("checksum") != archive["sha256"]:
                raise ReleaseError("E_STAGE_LOCK")
            if package.get("source") != "registry+sparse+" + registry_url:
                raise ReleaseError("E_STAGE_LOCK")
            found_public.add(name)
        else:
            if (name, version) not in expected_external or expected_external[(name, version)] != (package.get("checksum"), package.get("source")):
                raise ReleaseError("E_STAGE_LOCK")
    expected_public = set(public_archives) | ({unpublished_root} if unpublished_root else set())
    if found_public != expected_public:
        raise ReleaseError("E_STAGE_LOCK")


def write_index(registry: Path, entry: dict, archive_path: Path, manifest: dict,
                staged_files: set[str]) -> None:
    archive = inspect_archive(archive_path, entry["name"], entry["vers"])
    verify_archive_manifest(manifest, archive["manifest"], staged_files, set(archive["files"]))
    verify_index(entry, archive["sha256"], manifest)
    verify_index(entry, archive["sha256"], archive["manifest"])
    destination = Path(registry) / "index" / sparse_path(entry["name"])
    payload = Path(registry) / "api/v1/crates" / entry["name"] / entry["vers"] / "download"
    if destination.is_symlink() or payload.is_symlink() or destination.exists() or payload.exists():
        raise ReleaseError("E_INDEX_EXISTS")
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload.parent.mkdir(parents=True, exist_ok=True)
    try:
        packed = _read_regular(archive_path, MAX_ARCHIVE)
        if _sha(packed) != archive["sha256"]:
            raise ReleaseError("E_ARCHIVE_CHANGED")
        payload.write_bytes(packed)
        destination.write_text(json.dumps(entry, separators=(",", ":")) + "\n")
    except (OSError, ReleaseError):
        destination.unlink(missing_ok=True)
        payload.unlink(missing_ok=True)
        raise


def configure_registry(session: Path, port: int) -> str:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ReleaseError("E_REGISTRY_PORT")
    session = owned_session(session)
    registry = session / "registry"
    if not registry.is_dir() or registry.is_symlink():
        raise ReleaseError("E_REGISTRY_PATH")
    base = f"http://127.0.0.1:{port}/"
    config_path = session / "staging/.cargo/config.toml"
    if config_path.exists() or config_path.is_symlink():
        current = tomllib.loads(_read_regular(config_path, 16 * 1024).decode("utf-8"))
        if current.get("registries", {}).get(REGISTRY, {}).get("index") != "sparse+" + base + "index/":
            raise ReleaseError("E_REGISTRY_CHANGED")
    for index in ("index", "mirror-index"):
        (registry / index / "config.json").write_text(json.dumps({
            "dl": base + "api/v1/crates", "auth-required": False,
        }, separators=(",", ":")))
    # 外部 crates.io 依賴仍保留 production manifest 欄位，只在此隔離 session 取 locked mirror。
    config = ("[registries.p24-stage]\nindex = \"sparse+" + base + "index/\"\n"
              "[source.crates-io]\nreplace-with = \"p24-mirror\"\n"
              "[source.p24-mirror]\nregistry = \"sparse+" + base + "mirror-index/\"\n")
    for base_dir in (session / "staging", session / "consumers"):
        (base_dir / ".cargo").mkdir(exist_ok=True)
        (base_dir / ".cargo/config.toml").write_text(config)
    return base


def stage_registry_index(session: Path) -> str:
    config = tomllib.loads(_read_regular(owned_session(session) / "staging/.cargo/config.toml", 16 * 1024).decode("utf-8"))
    value = config.get("registries", {}).get(REGISTRY, {}).get("index", "")
    if not isinstance(value, str) or not re.fullmatch(r"sparse\+http://127\.0\.0\.1:[0-9]+/index/", value):
        raise ReleaseError("E_REGISTRY_CONFIG")
    return value[len("sparse+"):]


def serve_registry(session: Path, port: int) -> None:
    """僅 loopback、唯讀 index/archive GET；不得對外或提供目錄列舉。"""
    registry = (owned_session(session) / "registry").resolve(strict=True)
    if registry.is_symlink() or not registry.is_dir():
        raise ReleaseError("E_REGISTRY_PATH")

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self._serve(False)

        def do_HEAD(self):
            self._serve(True)

        def _serve(self, head_only: bool):
            url = urlsplit(self.path)
            raw = unquote(url.path)
            parts = raw.lstrip("/").split("/")
            if url.query or raw != "/" + "/".join(parts) or any(part in ("", ".", "..") for part in parts):
                self.send_error(404)
                return
            if parts[0] not in ("index", "mirror-index") and parts[:3] != ["api", "v1", "crates"]:
                self.send_error(404)
                return
            path = registry.joinpath(*parts)
            if path.is_symlink() or not path.is_file() or registry not in path.resolve().parents:
                self.send_error(404)
                return
            size = path.stat().st_size
            if size > MAX_ARCHIVE:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Length", str(size))
            self.end_headers()
            if not head_only:
                with path.open("rb") as stream:
                    shutil.copyfileobj(stream, self.wfile)

    # 只有明確手動啟動此函式才會 bind；本工具沒有自動背景 server。
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()


def validate_consumer_manifest(manifest: dict, sealed_versions: dict[str, str]) -> None:
    """乾淨 consumer 僅可依賴已封存的具名暫存套件。"""
    if not isinstance(manifest, dict) or set(manifest) != {"package", "dependencies"}:
        raise ReleaseError("E_CONSUMER_MANIFEST")
    package, dependencies = manifest["package"], manifest["dependencies"]
    if not isinstance(package, dict) or not isinstance(dependencies, dict) or not dependencies:
        raise ReleaseError("E_CONSUMER_MANIFEST")
    if package.get("version") != "0.0.0" or package.get("edition") != "2024" or package.get("publish") is not False:
        raise ReleaseError("E_CONSUMER_MANIFEST")
    if not isinstance(package.get("name"), str) or not re.fullmatch(r"[a-z0-9_-]+", package["name"]):
        raise ReleaseError("E_CONSUMER_MANIFEST")
    if set(package) != {"name", "version", "edition", "publish"}:
        raise ReleaseError("E_CONSUMER_MANIFEST")
    for name, spec in dependencies.items():
        if name not in PUBLIC or name not in sealed_versions or not isinstance(spec, dict):
            raise ReleaseError("E_CONSUMER_DEP")
        if set(spec) != {"version", "registry"} or spec["version"] != "=" + sealed_versions[name] or spec["registry"] != REGISTRY:
            raise ReleaseError("E_CONSUMER_DEP")


def prepare_consumer(session: Path, name: str, version: str) -> Path:
    if name not in PUBLIC or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ReleaseError("E_CONSUMER_ID")
    session = owned_session(session)
    manifest = {"package": {"name": "p24-clean-" + name, "version": "0.0.0", "edition": "2024", "publish": False},
                "dependencies": {name: {"version": "=" + version, "registry": REGISTRY}}}
    validate_consumer_manifest(manifest, indexed_ready(session))
    consumer = session / "consumers" / name
    if consumer.exists() or consumer.is_symlink():
        raise ReleaseError("E_CONSUMER_EXISTS")
    try:
        (consumer / "src").mkdir(parents=True)
        (consumer / "Cargo.toml").write_text(render_manifest(manifest))
        (consumer / "src/main.rs").write_text("fn main() {}\n")
        (consumer / ".cargo").mkdir()
        (consumer / "cargo-home").mkdir()
        shutil.copyfile(session / "consumers/.cargo/config.toml", consumer / ".cargo/config.toml")
    except Exception:
        if consumer.exists():
            shutil.rmtree(consumer)
        raise
    return consumer


def static_closure(session: Path, manifests: dict[str, dict], workspace_package: dict,
                   archives: dict[str, Path], canonical: dict[str, dict[str, str]]) -> dict:
    """只驗 sealed package/index 的靜態閉包；不宣稱 clean consumer 已執行。"""
    ordered = release_graph(manifests, workspace_package)
    session = owned_session(session)
    if set(archives) != PUBLIC or set(canonical) != PUBLIC:
        raise ReleaseError("E_CLOSURE_INCOMPLETE")
    checked = {}
    for name in ordered:
        staged = stage_manifest(manifests[name], workspace_package,
                                {dep: checked[dep]["version"] for dep in checked})
        stage_dir = session / "staging" / name
        actual_staged = tomllib.loads(_read_regular(stage_dir / "Cargo.toml", 64 * 1024).decode("utf-8"))
        if actual_staged != staged:
            raise ReleaseError("E_MANIFEST_DIFF")
        version = staged["package"]["version"]
        archive = inspect_archive(archives[name], name, version)
        verify_archive_manifest(staged, archive["manifest"], staged_file_names(stage_dir), set(archive["files"]))
        verify_archive_assets(archive, canonical[name])
        index_path = Path(session) / "registry/index" / sparse_path(name)
        if index_path.is_symlink() or not index_path.is_file():
            raise ReleaseError("E_CLOSURE_INDEX")
        try:
            lines = [json.loads(line) for line in index_path.read_text().splitlines() if line]
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ReleaseError("E_CLOSURE_INDEX") from error
        if len(lines) != 1:
            raise ReleaseError("E_CLOSURE_INDEX")
        verify_index(lines[0], archive["sha256"], staged)
        verify_index(lines[0], archive["sha256"], archive["manifest"])
        payload = Path(session) / "registry/api/v1/crates" / name / version / "download"
        if _sha(_read_regular(payload, MAX_ARCHIVE)) != archive["sha256"]:
            raise ReleaseError("E_CLOSURE_ARCHIVE")
        checked[name] = {"version": version, "sha256": archive["sha256"]}
    return {"status": "STATIC_ONLY", "packages": checked, "consumer_status": "BLOCKED_CHAIN"}


def inert_recipe(session: Path, name: str, version: str) -> dict:
    """資料而非執行器；沒有完整轉遞啟動鏈證據時固定 BLOCKED。"""
    if name not in PUBLIC or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ReleaseError("E_RECIPE_ID")
    session = owned_session(session)
    stage = session / "staging" / name
    consumer = session / "consumers" / name
    return {"status": "BLOCKED_CHAIN", "cargo_executable": None,
            "required_chain": ["cargo", "rustc", "linker", "C compiler", "archiver", "SDK discovery", "build.rs", "transitive subprocesses"],
            "environment": {"CARGO_HOME": str(Path(session) / "cargo-home"),
                            "CARGO_TARGET_DIR": "<P24_SHARED_EXTERNAL_TARGET>",
                            "PATH": "<VERIFIED_CONCRETE_EXECUTABLES_ONLY>"},
            "steps": [
                {"cwd": str(stage), "argv": ["<VERIFIED_CARGO>", "generate-lockfile"]},
                {"cwd": str(stage), "argv": ["<VERIFIED_CARGO>", "package", "--locked", "--registry", REGISTRY]},
                {"cwd": str(consumer), "environment": {"CARGO_HOME": str(consumer / "cargo-home")},
                 "argv": ["<VERIFIED_CARGO>", "check", "--locked"]},
            ], "version": version}


def canonical_hashes(root: Path, capi: bool) -> dict[str, str]:
    root = Path(root).resolve(strict=True)
    names = list(ASSETS)
    if capi:
        names += ["include/rivetlua/" + relative for relative in (
            "rivetlua_abi.h", "lua54/lua.h", "lua54/lauxlib.h", "lua54/luaconf.h", "lua54/lualib.h",
            "lua55/lua.h", "lua55/lauxlib.h", "lua55/luaconf.h", "lua55/lualib.h")]
    return {name: _sha(_read_regular(root / name, MAX_ARCHIVE)) for name in names}


def indexed_ready(session: Path) -> dict[str, str]:
    registry = owned_session(session) / "registry"
    ready = {}
    for name in PUBLIC:
        index_path = registry / "index" / sparse_path(name)
        if not index_path.exists():
            continue
        try:
            records = [json.loads(line) for line in _read_regular(index_path, 64 * 1024).decode("utf-8").splitlines() if line]
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ReleaseError("E_INDEX_READY") from error
        if len(records) != 1 or records[0].get("name") != name:
            raise ReleaseError("E_INDEX_READY")
        record = records[0]
        archive = registry / "api/v1/crates" / name / record["vers"] / "download"
        if _sha(_read_regular(archive, MAX_ARCHIVE)) != record.get("cksum"):
            raise ReleaseError("E_INDEX_READY")
        ready[name] = record["vers"]
    return ready


def package_version(manifest: dict, workspace_package: dict) -> str:
    version = manifest["package"]["version"]
    if version == {"workspace": True}:
        version = workspace_package.get("version")
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ReleaseError("E_MANIFEST_VERSION")
    return version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="P24 離線暫存封裝；不啟動 Cargo 或發布")
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("topology", "init", "mirror", "stage", "inspect", "index", "consumer", "closure", "recipe", "serve"):
        item = sub.add_parser(command)
        if command in ("topology", "stage", "index", "closure"):
            item.add_argument("--root", required=True, type=Path)
        if command in ("mirror", "stage", "index", "consumer", "closure", "recipe", "serve"):
            item.add_argument("--session", required=True, type=Path)
        if command in ("stage", "index", "consumer", "recipe"):
            item.add_argument("--name", required=True)
        if command in ("consumer", "recipe", "inspect"):
            item.add_argument("--version", required=True)
        if command in ("inspect", "index"):
            item.add_argument("--archive", required=True, type=Path)
        if command == "inspect":
            item.add_argument("--name", required=True)
        if command == "init":
            item.add_argument("--base", required=True, type=Path)
            item.add_argument("--port", required=True, type=int)
        if command == "mirror":
            item.add_argument("--lock", required=True, type=Path)
            item.add_argument("--archives", required=True, type=Path)
            item.add_argument("--index", required=True, type=Path)
        if command == "closure":
            item.add_argument("--archives", required=True, type=Path)
        if command == "serve":
            item.add_argument("--port", required=True, type=int)
    args = parser.parse_args(argv)
    try:
        if args.command == "topology":
            manifests, workspace = load_workspace(args.root)
            result = {"order": release_graph(manifests, workspace)}
        elif args.command == "init":
            session = init_session(args.base)
            configure_registry(session, args.port)
            result = {"session": str(session), "status": "EMPTY"}
        elif args.command == "mirror":
            result = {"mirrored": mirror_locked(args.lock, args.archives, args.index, args.session)}
        elif args.command == "stage":
            manifests, workspace = load_workspace(args.root)
            ready = indexed_ready(args.session)
            staged = stage_package(args.root, args.session, args.name, manifests[args.name], workspace, ready)
            result = {"name": args.name, "version": staged["manifest"]["package"]["version"],
                      "status": "STAGED_NOT_PACKAGED", "recipe": inert_recipe(args.session, args.name, staged["manifest"]["package"]["version"])}
        elif args.command == "inspect":
            archive = inspect_archive(args.archive, args.name, args.version)
            result = {"sha256": archive["sha256"], "files": archive["files"]}
        elif args.command == "index":
            manifests, workspace = load_workspace(args.root)
            stage = owned_session(args.session) / "staging" / args.name
            staged = tomllib.loads(_read_regular(stage / "Cargo.toml", 64 * 1024).decode("utf-8"))
            ready = indexed_ready(args.session)
            verify_manifest_allowdiff(manifests[args.name], staged, workspace, ready)
            staged_lock = stage / "Cargo.lock"
            lock = tomllib.loads(_read_regular(staged_lock, 16 * 1024 * 1024).decode("utf-8"))
            public_archives = {}
            for package in lock.get("package", []):
                name = package["name"]
                if name not in PUBLIC or name == args.name:
                    continue
                if name not in ready or ready[name] != package["version"]:
                    raise ReleaseError("E_STAGE_LOCK")
                index_path = owned_session(args.session) / "registry/index" / sparse_path(name)
                record = json.loads(_read_regular(index_path, 64 * 1024).decode("utf-8"))
                public_archives[name] = {"version": ready[name], "sha256": record["cksum"]}
            direct = {spec.get("package", alias) for table in _deps(staged)
                      for alias, spec in table.items() if isinstance(spec, dict) and spec.get("registry") == REGISTRY}
            if not direct <= set(public_archives):
                raise ReleaseError("E_STAGE_LOCK")
            verify_stage_lock(staged_lock, public_archives, args.root / "Cargo.lock",
                              stage_registry_index(args.session), args.name)
            archive = inspect_archive(args.archive, args.name, staged["package"]["version"])
            verify_archive_assets(archive, canonical_hashes(args.root, args.name == "rivetlua-capi"))
            entry = index_entry(args.name, staged["package"]["version"], archive["sha256"], staged)
            write_index(owned_session(args.session) / "registry", entry, args.archive, staged,
                        staged_file_names(stage))
            result = {"name": args.name, "sha256": archive["sha256"], "status": "INDEXED_NOT_CONSUMED"}
        elif args.command == "consumer":
            prepare_consumer(args.session, args.name, args.version)
            result = inert_recipe(args.session, args.name, args.version)
            result["consumer_kind"] = "COMPILE_SMOKE"
        elif args.command == "closure":
            manifests, workspace = load_workspace(args.root)
            archives = {name: args.archives / f"{name}-{package_version(manifest, workspace)}.crate"
                        for name, manifest in manifests.items()}
            canonical = {name: canonical_hashes(args.root, name == "rivetlua-capi") for name in PUBLIC}
            result = static_closure(args.session, manifests, workspace, archives, canonical)
        elif args.command == "recipe":
            result = inert_recipe(args.session, args.name, args.version)
        else:
            serve_registry(args.session, args.port)
            return 0
        print(json.dumps({"version": 1, **result}, sort_keys=True))
        return 0
    except (ReleaseError, KeyError, ValueError, OSError, UnicodeError, tomllib.TOMLDecodeError) as error:
        code = error.code if isinstance(error, ReleaseError) else "E_RELEASE_INPUT"
        print(json.dumps({"version": 1, "status": "BLOCKED", "code": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
