import copy
import io
import sys
import tarfile
import tempfile
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from release import (
    ReleaseError,
    index_entry,
    inspect_archive,
    release_graph,
    stage_manifest,
    verify_archive_assets,
    verify_archive_manifest,
    verify_index,
    verify_manifest_allowdiff,
)


PUBLIC = (
    "rivetlua-core",
    "rivetlua-compiler",
    "rivetlua-runtime",
    "rivetlua-native",
    "rivetlua",
    "rivetlua-cli",
    "rivetlua-capi",
)
WORKSPACE_PACKAGE = {
    "version": "0.0.0",
    "edition": "2024",
    "rust-version": "1.94.1",
    "license": "MIT OR Apache-2.0",
    "repository": "https://example.invalid/r",
}
ARCHIVE_ROOT = "rivetlua-core-0.0.0"
ARCHIVE_FILES = {
    "Cargo.toml": (
        b'[package]\nname = "rivetlua-core"\nversion = "0.0.0"\n'
        b'license = "MIT OR Apache-2.0"\nedition = "2024"\n'
        b'[lib]\npath = "src/lib.rs"\n'
    ),
    "src/lib.rs": b"pub fn core() {}\n",
    "LICENSE-MIT": b"MIT license\n",
    "LICENSE-APACHE": b"Apache license\n",
    "THIRD_PARTY_NOTICES.md": b"Notices\n",
}


def public_manifests():
    manifests = {
        name: {"package": {"name": name}, "dependencies": {}}
        for name in PUBLIC
    }
    manifests["rivetlua"]["dependencies"]["rivetlua-core"] = {
        "path": "../rivetlua-core"
    }
    return manifests


class ReleaseFixtures(unittest.TestCase):
    def assert_release_error(self, code, function, *args):
        with self.assertRaises(ReleaseError) as caught:
            function(*args)
        self.assertEqual(caught.exception.code, code)

    def test_archive_manifest_allows_supported_cargo_normalization(self):
        staged = tomllib.loads(ARCHIVE_FILES["Cargo.toml"].decode("utf-8"))
        staged["dependencies"] = {"libm": "0.2.16"}
        staged["features"] = {"default": ["std", "embed"]}
        archived = copy.deepcopy(staged)
        archived["package"].update(
            {
                "authors": [],
                "autolib": False,
                "autobins": False,
                "autoexamples": False,
                "autotests": False,
                "autobenches": False,
                "build": False,
            }
        )
        archived["lib"]["name"] = "rivetlua_core"
        archived["dependencies"]["libm"] = {"version": "0.2.16"}
        archived["features"]["default"].reverse()

        verify_archive_manifest(
            staged,
            archived,
            {"src/lib.rs"},
            {"Cargo.toml", "src/lib.rs"},
        )

    def test_archive_manifest_rejects_metadata_bin_dependency_and_feature_drift(self):
        staged = tomllib.loads(ARCHIVE_FILES["Cargo.toml"].decode("utf-8"))
        staged_files = {"src/lib.rs"}
        archive_files = {"Cargo.toml", "src/lib.rs"}
        mutations = (
            ("edition", lambda manifest: manifest["package"].update(edition="2021")),
            ("license", lambda manifest: manifest["package"].update(license="MIT")),
            ("description", lambda manifest: manifest["package"].update(description="Drift")),
            ("lib path", lambda manifest: manifest["lib"].update(path="src/other.rs")),
            ("unknown normalization", lambda manifest: manifest["package"].update(unrecognized_field=True)),
        )
        for label, mutate in mutations:
            with self.subTest(metadata_drift=label):
                archived = copy.deepcopy(staged)
                mutate(archived)
                self.assert_release_error(
                    "E_ARCHIVE_METADATA",
                    verify_archive_manifest,
                    staged,
                    archived,
                    staged_files,
                    archive_files,
                )

        staged_bin = copy.deepcopy(staged)
        staged_bin["bin"] = [{"name": "rivetlua", "path": "src/bin/rivetlua.rs"}]
        archived_bin = copy.deepcopy(staged_bin)
        del archived_bin["bin"]
        self.assert_release_error(
            "E_ARCHIVE_METADATA",
            verify_archive_manifest,
            staged_bin,
            archived_bin,
            staged_files | {"src/bin/rivetlua.rs"},
            archive_files | {"src/bin/rivetlua.rs"},
        )

        staged_dependency = copy.deepcopy(staged)
        staged_dependency["dependencies"] = {"libm": "0.2.16"}
        archived_dependency = copy.deepcopy(staged_dependency)
        archived_dependency["dependencies"]["libm"] = {"version": "0.2.15"}
        self.assert_release_error(
            "E_ARCHIVE_METADATA",
            verify_archive_manifest,
            staged_dependency,
            archived_dependency,
            staged_files,
            archive_files,
        )

        staged_feature = copy.deepcopy(staged)
        staged_feature["features"] = {"default": ["std"]}
        archived_feature = copy.deepcopy(staged_feature)
        archived_feature["features"]["default"] = ["embed"]
        self.assert_release_error(
            "E_ARCHIVE_METADATA",
            verify_archive_manifest,
            staged_feature,
            archived_feature,
            staged_files,
            archive_files,
        )

    def test_release_graph_is_leaf_first_and_rejects_cycles_and_external_paths(self):
        manifests = public_manifests()
        self.assertEqual(
            release_graph(manifests, WORKSPACE_PACKAGE),
            [
                "rivetlua-core",
                "rivetlua",
                "rivetlua-capi",
                "rivetlua-cli",
                "rivetlua-compiler",
                "rivetlua-native",
                "rivetlua-runtime",
            ],
        )

        cyclic = public_manifests()
        cyclic["rivetlua-core"]["dependencies"]["rivetlua"] = {
            "path": "../rivetlua"
        }
        self.assert_release_error(
            "E_DAG_CYCLE", release_graph, cyclic, WORKSPACE_PACKAGE
        )

        for path, package in (
            ("../not-public", "not-public"),
            ("../../rivetlua-core", "rivetlua-core"),
        ):
            with self.subTest(path=path):
                invalid = public_manifests()
                invalid["rivetlua"]["dependencies"][package] = {"path": path}
                self.assert_release_error(
                    "E_DAG_DEP", release_graph, invalid, WORKSPACE_PACKAGE
                )

    def test_stage_manifest_changes_only_ready_internal_dependency_and_workspace_fields(self):
        original = {
            "package": {
                "name": "rivetlua-runtime",
                "version": {"workspace": True},
                "edition": {"workspace": True},
                "rust-version": {"workspace": True},
                "license": {"workspace": True},
                "repository": {"workspace": True},
                "description": "Keep this metadata",
            },
            "dependencies": {
                "rivetlua-core": {
                    "path": "../rivetlua-core",
                    "features": ["vm"],
                    "optional": True,
                    "default-features": False,
                }
            },
            "features": {"default": ["embed"]},
        }
        before = copy.deepcopy(original)
        ready = {"rivetlua-core": "0.0.0"}
        staged = stage_manifest(original, WORKSPACE_PACKAGE, ready)

        self.assertEqual(original, before)
        self.assertEqual(
            staged["package"],
            {
                "name": "rivetlua-runtime",
                "version": "0.0.0",
                "edition": "2024",
                "rust-version": "1.94.1",
                "license": "MIT OR Apache-2.0",
                "repository": "https://example.invalid/r",
                "description": "Keep this metadata",
            },
        )
        self.assertEqual(
            staged["dependencies"]["rivetlua-core"],
            {
                "features": ["vm"],
                "optional": True,
                "default-features": False,
                "version": "=0.0.0",
                "registry": "p24-stage",
            },
        )
        self.assertEqual(staged["features"], original["features"])
        verify_manifest_allowdiff(original, staged, WORKSPACE_PACKAGE, ready)

        changed = copy.deepcopy(staged)
        changed["package"]["description"] = "Unexpected drift"
        self.assert_release_error(
            "E_MANIFEST_DIFF",
            verify_manifest_allowdiff,
            original,
            changed,
            WORKSPACE_PACKAGE,
            ready,
        )

        external = copy.deepcopy(original)
        external["dependencies"]["rivetlua-core"]["path"] = "../../rivetlua-core"
        self.assert_release_error(
            "E_MANIFEST_DEP", stage_manifest, external, WORKSPACE_PACKAGE, ready
        )

    def write_archive(self, path, files, extra_members=()):
        with tarfile.open(path, "w:gz") as archive:
            for relative, data in files.items():
                member = tarfile.TarInfo(f"{ARCHIVE_ROOT}/{relative}")
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            for member, data in extra_members:
                if data is None:
                    archive.addfile(member)
                else:
                    member.size = len(data)
                    archive.addfile(member, io.BytesIO(data))

    def archive_path(self, files=None, extra_members=()):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        path = Path(temporary.name) / f"{ARCHIVE_ROOT}.crate"
        self.write_archive(path, ARCHIVE_FILES if files is None else files, extra_members)
        return path

    def test_archive_hash_and_index_are_bound_to_the_inspected_manifest(self):
        archive = inspect_archive(self.archive_path(), "rivetlua-core", "0.0.0")
        self.assertIn("Cargo.toml", archive["files"])
        self.assertEqual(len(archive["sha256"]), 64)
        manifest = archive["manifest"]

        entry = index_entry("rivetlua-core", "0.0.0", archive["sha256"], manifest)
        verify_index(entry, archive["sha256"], manifest)

        wrong_hash = "0" * 64 if archive["sha256"] != "0" * 64 else "1" * 64
        self.assert_release_error(
            "E_INDEX_MISMATCH", verify_index, entry, wrong_hash, manifest
        )
        wrong_entry = copy.deepcopy(entry)
        wrong_entry["cksum"] = wrong_hash
        self.assert_release_error(
            "E_INDEX_MISMATCH", verify_index, wrong_entry, archive["sha256"], manifest
        )
        self.assert_release_error(
            "E_ARCHIVE_ASSET_HASH",
            verify_archive_assets,
            archive,
            {"LICENSE-MIT": wrong_hash},
        )

    def test_archive_rejects_traversal_symlinks_private_files_and_path_dependencies(self):
        traversal = tarfile.TarInfo(f"{ARCHIVE_ROOT}/../escape.txt")
        traversal.size = 0
        self.assert_release_error(
            "E_ARCHIVE_PATH",
            inspect_archive,
            self.archive_path(extra_members=((traversal, b""),)),
            "rivetlua-core",
            "0.0.0",
        )

        symlink = tarfile.TarInfo(f"{ARCHIVE_ROOT}/src/link.rs")
        symlink.type = tarfile.SYMTYPE
        symlink.linkname = "../lib.rs"
        self.assert_release_error(
            "E_ARCHIVE_TYPE",
            inspect_archive,
            self.archive_path(extra_members=((symlink, None),)),
            "rivetlua-core",
            "0.0.0",
        )

        private = tarfile.TarInfo(f"{ARCHIVE_ROOT}/.env")
        private.size = 0
        self.assert_release_error(
            "E_ARCHIVE_PRIVATE",
            inspect_archive,
            self.archive_path(extra_members=((private, b""),)),
            "rivetlua-core",
            "0.0.0",
        )

        path_dependency = copy.deepcopy(ARCHIVE_FILES)
        path_dependency["Cargo.toml"] += (
            b"\n[dependencies]\nrivetlua-runtime = { path = \"../rivetlua-runtime\" }\n"
        )
        self.assert_release_error(
            "E_ARCHIVE_PATH_DEP",
            inspect_archive,
            self.archive_path(path_dependency),
            "rivetlua-core",
            "0.0.0",
        )

    def test_archive_requires_nonempty_license_and_notice_assets(self):
        missing_license = dict(ARCHIVE_FILES)
        del missing_license["LICENSE-MIT"]
        self.assert_release_error(
            "E_ARCHIVE_LICENSE",
            inspect_archive,
            self.archive_path(missing_license),
            "rivetlua-core",
            "0.0.0",
        )

        missing_notice = dict(ARCHIVE_FILES)
        del missing_notice["THIRD_PARTY_NOTICES.md"]
        self.assert_release_error(
            "E_ARCHIVE_LICENSE",
            inspect_archive,
            self.archive_path(missing_notice),
            "rivetlua-core",
            "0.0.0",
        )


if __name__ == "__main__":
    unittest.main()
