"""NEG006 來源與符號拒絕路徑的獨立負向測試。"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import abi_neg006


class NegativeAuditTests(unittest.TestCase):
    def test_fixed_build_script_receipts_for_three_targets(self):
        out = pathlib.Path(os.environ["TMPDIR"]) / "p16-thin-mock-out"
        for target in abi_neg006.TARGETS:
            expected = ["static=rivetlua_capi_trampoline_a1"]
            if target != "aarch64-apple-darwin":
                expected.append("dl")
            event = {"reason": "build-script-executed", "out_dir": str(out),
                     "linked_paths": [f"native={out}"], "linked_libs": expected}
            self.assertEqual(abi_neg006.thin_receipt_out([event], target), out)
            bad_lists = [[], expected + ["lua"]]
            if len(expected) > 1:
                bad_lists.extend((expected[:1], list(reversed(expected))))
            else:
                bad_lists.append(expected + ["dl"])
            for bad in bad_lists:
                with self.assertRaisesRegex(ValueError, "linked_libs"):
                    abi_neg006.thin_receipt_out([{**event, "linked_libs": bad}], target)
            with self.assertRaisesRegex(ValueError, "linked_paths"):
                abi_neg006.thin_receipt_out([{**event, "linked_paths": []}], target)
            with self.assertRaisesRegex(ValueError, "exactly one"):
                abi_neg006.thin_receipt_out([event, event], target)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            abi_neg006.thin_receipt_out([event], "not-a-fixed-target")

    def test_receipt_replay_keeps_snapshot_and_rejects_source_list_changes(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as name:
            root = pathlib.Path(name)
            archive, cargo, thin = (root / part for part in ("static.a", "cargo.rlib", "thin.a"))
            archive.write_bytes(b"static")
            cargo.write_bytes(b"initial cargo alias")
            thin.write_bytes(b"thin")
            build_log = root / "build.log"
            build_log.write_text("fixed build log", encoding="utf-8")
            sources = {cargo: "cargo", thin: "thin"}
            receipt_dir = root / "provenance"
            with mock.patch.object(abi_neg006, "ar_names", return_value=["member.o"]):
                selected = abi_neg006.provenance(archive, build_log, sources, receipt_dir)
                self.assertEqual(len(selected), 2)
                receipt_path = receipt_dir / "receipt.json"
                first = abi_neg006.sha256(receipt_path)
                cargo.write_bytes(b"later profile alias")
                self.assertEqual(
                    abi_neg006.provenance(archive, build_log, sources, receipt_dir), selected)
                self.assertEqual(abi_neg006.sha256(receipt_path), first)
                original = receipt_path.read_text(encoding="utf-8")
                for change in (lambda record: record["sources"].pop(),
                               lambda record: record["candidates"].pop()):
                    record = json.loads(original)
                    change(record)
                    receipt_path.write_text(json.dumps(record), encoding="utf-8")
                    with self.assertRaisesRegex(ValueError, "provenance"):
                        abi_neg006.provenance(archive, build_log, sources, receipt_dir)
                receipt_path.write_text(original, encoding="utf-8")

    def test_fixed_thin_sources_and_private_symbols(self):
        source = '.file("src/trampoline.c")\n.file("src/native/platform.c")\n'
        abi_neg006.check_build_source(source)
        with self.assertRaisesRegex(ValueError, "source set"):
            abi_neg006.check_build_source(source + '.file("src/lvm.c")\n')
        with self.assertRaisesRegex(ValueError, "foreign C link"):
            abi_neg006.check_build_source(source + 'println!("cargo:rustc-link-lib=lua")\n')
        abi_neg006.check_symbols(["_lua_pushinteger", "_luaL_ref", "_luaopen_lib2"])
        for symbol in ("luaV_execute", "luaD_call", "luaK_code", "luaP_opnames"):
            with self.assertRaisesRegex(ValueError, "private engine"):
                abi_neg006.check_symbols([symbol])

    def test_archive_and_shim_negative_controls(self):
        members = ["abc-trampoline.o", "def-platform.o"]
        abi_neg006.check_members(members)
        with self.assertRaisesRegex(ValueError, "engine object"):
            abi_neg006.check_members(members + ["evil-lvm.o"])
        abi_neg006.one_shim(1)
        for count in (0, 2):
            with self.assertRaisesRegex(ValueError, "shim count"):
                abi_neg006.one_shim(count)

    def test_main_poisoned_source_exits_nonzero(self):
        with tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as name:
            root = pathlib.Path(name)
            source = root / "crates/rivetlua-capi/build.rs"
            source.parent.mkdir(parents=True)
            source.write_text('.file("src/trampoline.c")\n.file("src/native/platform.c")\n'
                              '.file("src/lvm.c")\n', encoding="utf-8")
            run = subprocess.run(
                [sys.executable, str(pathlib.Path(abi_neg006.__file__)),
                 "--root", str(root), "--library", str(root / "none.a"),
                 "--build-log", str(root / "none.log"),
                 "--profile", "lua55-i64f64", "--target", "aarch64-apple-darwin",
                 "--provenance", str(root / "provenance")],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(run.returncode, 1)
            self.assertIn("C source set", run.stderr)
            self.assertNotIn("P16_ASSERT", run.stdout)


if __name__ == "__main__":
    unittest.main()
