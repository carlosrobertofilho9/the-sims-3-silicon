import hashlib
import json
import struct
import tempfile
import unittest
from pathlib import Path

from tools.static_map import (
    BIN_RELATIVE,
    EXECUTABLES,
    PEFormatError,
    ToolInvocationError,
    collect_app,
    parse_pe_headers,
    render_markdown,
)


def make_pe32(*, tls=True, relocations=True):
    """Small synthetic PE32 fixture; no original game bytes are included."""
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, 0x014C, 1, 0, 0, 0, 224, 0x0102)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x010B)
    struct.pack_into("<I", data, optional + 16, 0x1010)  # entry RVA
    struct.pack_into("<I", data, optional + 28, 0x400000)  # ImageBase
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<I", data, optional + 92, 16)
    directory = optional + 96
    if relocations:
        struct.pack_into("<II", data, directory + 5 * 8, 0x1080, 8)
    if tls:
        struct.pack_into("<II", data, directory + 9 * 8, 0x1000, 24)
    section = optional + 224
    data[section : section + 8] = b".text\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x180, 0x1000, 0x200, 0x200)
    struct.pack_into("<I", data, section + 36, 0x60000020)  # read + execute + code
    return bytes(data)


def make_pe64():
    data = bytearray(make_pe32(tls=False, relocations=False))
    struct.pack_into("<H", data, 0x84, 0x8664)
    optional = 0x98
    struct.pack_into("<H", data, optional, 0x020B)
    struct.pack_into("<Q", data, optional + 24, 0x140000000)
    struct.pack_into("<I", data, optional + 108, 16)
    return bytes(data)


def response(operation, path, *, tls_present=True, status="complete"):
    data = path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    evidence_id = f"ev_test_{Path(path).stem}_{operation}"
    if operation == "inspect_pe_imports":
        normalized = {
            "artifact": {"path": str(path), "sha256": digest, "bytes": len(data)},
            "coverage": {"status": status, "imports": 2, "delay_imports": 1},
            "imports": [
                {"name": "KERNEL32.dll", "functions": [
                    {"name": "CreateFileW", "ordinal": None},
                    {"name": None, "ordinal": 7},
                ]},
                {"name": "d3d9.dll", "functions": [{"name": "Direct3DCreate9", "ordinal": None}]},
            ],
            "delay_imports": [
                {"name": "WS2_32.dll", "functions": [
                    {"name": "connect", "ordinal": None},
                    {"name": None, "ordinal": 12},
                ]}
            ],
            "issues": [],
            "limitations": ["Synthetic controlled response."],
        }
    else:
        normalized = {
            "artifact": {"path": str(path), "sha256": digest, "bytes": len(data)},
            "tls": {
                "directory": {"rva": 0x1000, "size": 24},
                "callbacks": ["0x401100"],
                "raw_data_size": 8,
                "size_of_zero_fill": 0,
            } if tls_present else None,
            "load_config": {
                "directory": {"rva": 0x1100, "size": 64},
                "size": 72,
                "se_handler_count": 1,
                "guard_flags": None,
                "inferences": [],
            },
            "examined_callbacks": 1 if tls_present else 0,
            "limitations": ["Synthetic controlled response."],
        }
    return {"ok": True, "data": {"evidence_id": evidence_id, "normalized_result": normalized, "limitations": []}}


def make_app(root, *, tls_by_file=None):
    app = Path(root) / "Private Sims 3.app"
    binary_dir = app / BIN_RELATIVE
    binary_dir.mkdir(parents=True)
    tls_by_file = tls_by_file or {}
    for filename in EXECUTABLES:
        (binary_dir / filename).write_bytes(make_pe32(tls=tls_by_file.get(filename, True)))
    return app, binary_dir


class PEHeaderTests(unittest.TestCase):
    def test_pe32_headers_entry_sections_permissions_and_relocations(self):
        result = parse_pe_headers(make_pe32())
        self.assertEqual(result["architecture"], "x86")
        self.assertEqual(result["bits"], 32)
        self.assertEqual(result["entry_point"], {"rva": 0x1010, "virtual_address": 0x401010})
        self.assertEqual(result["image_base"], 0x400000)
        self.assertEqual(result["section_alignment"], 0x1000)
        self.assertEqual(result["file_alignment"], 0x200)
        self.assertTrue(result["sections"][0]["permissions"]["execute"])
        self.assertFalse(result["sections"][0]["permissions"]["write"])
        self.assertTrue(result["relocations"]["present"])
        self.assertTrue(result["tls_directory"]["present"])

    def test_pe64_image_base_uses_64_bit_optional_header_field(self):
        result = parse_pe_headers(make_pe64())
        self.assertEqual(result["format"], "pe32_plus")
        self.assertEqual(result["architecture"], "x86_64")
        self.assertEqual(result["bits"], 64)
        self.assertEqual(result["image_base"], 0x140000000)
        self.assertFalse(result["tls_directory"]["present"])
        self.assertFalse(result["relocations"]["present"])

    def test_truncated_file_is_explicit(self):
        with self.assertRaises(PEFormatError) as caught:
            parse_pe_headers(b"MZ\x00")
        self.assertEqual(caught.exception.code, "truncated")


class StaticMapTests(unittest.TestCase):
    def test_normal_delay_named_and_ordinal_imports_and_tls_presence_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, _ = make_app(tmp, tls_by_file={"TS3.exe": False, "Sims3Launcher.exe": False})
            report = collect_app(
                app,
                lambda operation, path: response(
                    operation,
                    path,
                    tls_present=path.name == "TS3W.exe",
                ),
                Path(tmp) / "raw",
                rea_version="6.8.0",
                node_version="24.22.1",
            )
        self.assertEqual(report["status"], "complete")
        runtime = next(item for item in report["binaries"] if item["file"] == "TS3W.exe")
        coverage = runtime["imports"]["coverage"]
        self.assertEqual(coverage["normal_functions"], 3)
        self.assertEqual(coverage["delay_functions"], 2)
        self.assertEqual(coverage["ordinal_functions"], 2)
        self.assertEqual(runtime["imports"]["delay_imports"][0]["functions"][1]["ordinal"], 12)
        self.assertEqual(runtime["loader"]["tls"]["callback_count"], 1)
        launcher = next(item for item in report["binaries"] if item["file"] == "Sims3Launcher.exe")
        self.assertFalse(launcher["loader"]["tls"]["present"])
        self.assertEqual(runtime["imports"]["dependency_categories"]["graphics"]["import_count"], 1)

    def test_truncated_input_reports_header_failure_without_exposing_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, binary_dir = make_app(tmp)
            (binary_dir / "TS3.exe").write_bytes(b"MZ\x00")
            report = collect_app(app, response, Path(tmp) / "raw")
            rendered = json.dumps(report, ensure_ascii=False) + render_markdown(report)
        item = next(item for item in report["binaries"] if item["file"] == "TS3.exe")
        self.assertEqual(item["pe_headers"]["error_code"], "truncated")
        self.assertEqual(item["status"], "partial")
        self.assertNotIn(str(app), rendered)
        self.assertNotIn("Private Sims 3.app", rendered)

    def test_tool_unavailable_is_reported_without_raw_error_text(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, _ = make_app(tmp)

            def unavailable(operation, path):
                raise ToolInvocationError("rea_cli_unavailable")

            report = collect_app(app, unavailable, Path(tmp) / "raw")
        self.assertEqual(report["status"], "partial")
        self.assertTrue(all(item["imports"]["error_code"] == "rea_cli_unavailable" for item in report["binaries"]))

    def test_changed_file_aborts_consolidation(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, binary_dir = make_app(tmp)

            def mutate_after_import(operation, path):
                result = response(operation, path)
                if path.name == "TS3W.exe" and operation == "inspect_pe_load_config":
                    path.write_bytes(path.read_bytes() + b"changed")
                    result = response(operation, path)
                return result

            report = collect_app(app, mutate_after_import, Path(tmp) / "raw")
        runtime = next(item for item in report["binaries"] if item["file"] == "TS3W.exe")
        self.assertEqual(runtime["status"], "inconsistent")
        self.assertEqual(runtime["identity_stability"]["status"], "aborted_file_changed")
        self.assertEqual(runtime["imports"]["status"], "aborted")
        self.assertEqual(report["status"], "inconsistent")

    def test_incomplete_import_coverage_is_not_reported_complete(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, _ = make_app(tmp)

            def partial(operation, path):
                return response(operation, path, status="partial") if operation == "inspect_pe_imports" else response(operation, path)

            report = collect_app(app, partial, Path(tmp) / "raw")
        self.assertEqual(report["status"], "partial")
        self.assertTrue(all(item["imports"]["status"] == "partial" for item in report["binaries"]))

    def test_every_successful_query_has_a_matching_source_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            app, _ = make_app(tmp)
            report = collect_app(app, response, Path(tmp) / "raw")
        for item in report["binaries"]:
            identity = item["identity"]["sha256"]
            self.assertEqual(item["identity_stability"]["rea_query_sha256"], [identity, identity])
            self.assertEqual(item["identity_stability"]["status"], "stable")


if __name__ == "__main__":
    unittest.main()
