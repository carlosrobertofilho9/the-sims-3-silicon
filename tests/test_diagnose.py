import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.diagnose import PEFormatError, diagnose_app, parse_pe


def make_pe32(machine=0x014C, imported_dll=b"D3D9.DLL"):
    """Small original PE fixture with one import and no proprietary content."""
    data = bytearray(0x400)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    coff = 0x84
    struct.pack_into("<HHIIIHH", data, coff, machine, 1, 0, 0, 0, 224, 0)
    optional = coff + 20
    struct.pack_into("<H", data, optional, 0x10B)
    struct.pack_into("<I", data, optional + 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<I", data, optional + 92, 16)  # NumberOfRvaAndSizes
    struct.pack_into("<II", data, optional + 104, 0x1000, 40)  # import directory
    section = optional + 224
    data[section : section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x200, 0x1000, 0x200, 0x200)
    # One IMAGE_IMPORT_DESCRIPTOR, followed by the null descriptor.
    struct.pack_into("<IIIII", data, 0x200, 0, 0, 0, 0x103C, 0)
    name = imported_dll + b"\0"
    data[0x23C : 0x23C + len(name)] = name
    return bytes(data)


class ParsePETests(unittest.TestCase):
    def test_valid_x86_pe_reads_direct_import(self):
        self.assertEqual(
            parse_pe(make_pe32()),
            {"architecture": "x86", "direct_imports": ["d3d9.dll"]},
        )

    def test_truncated_pe_is_classified(self):
        with self.assertRaises(PEFormatError) as error:
            parse_pe(b"MZ\0\0")
        self.assertEqual(error.exception.category, "truncated")

    def test_unknown_machine_is_classified_without_exposing_machine_value(self):
        with self.assertRaises(PEFormatError) as error:
            parse_pe(make_pe32(machine=0x9999))
        self.assertEqual(error.exception.category, "unknown_architecture")
        self.assertNotIn("9999", str(error.exception))

    def test_absent_file_is_not_pe(self):
        with self.assertRaises(PEFormatError) as error:
            parse_pe(b"")
        self.assertEqual(error.exception.category, "not_pe")


class AppDiagnosticTests(unittest.TestCase):
    def test_missing_app_emits_sanitized_not_found_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            absent = Path(tmp) / "private-install-name.app"
            with patch("tools.diagnose._matching_failure_records", return_value={}):
                report = diagnose_app(absent)
        serialized = json.dumps(report)
        self.assertEqual(report["status"], "not_found")
        self.assertNotIn(str(absent), serialized)
        self.assertNotIn("CFBundleIdentifier", serialized)

    def test_app_bundle_detects_key_x86_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            app = Path(tmp) / "Sample.app"
            contents = app / "Contents"
            game_bin = contents / "Resources/drive_c/Program Files (x86)/Electronic Arts/The Sims 3/Game/Bin"
            game_bin.mkdir(parents=True)
            with (contents / "Info.plist").open("wb") as f:
                import plistlib

                plistlib.dump(
                    {"CFBundleShortVersionString": "1.67.2", "CFBundleVersion": "Wineskin 2.9.0.6"},
                    f,
                )
            (game_bin / "TS3W.exe").write_bytes(make_pe32())
            with (
                patch("tools.diagnose._signature_status", return_value={"status": "unavailable", "findings": []}),
                patch("tools.diagnose._matching_failure_records", return_value={"matching_record_count": 0, "scan_available": True, "summary_categories": {}, "raw_contents_included": False, "source_scope": "test fixture"}),
                patch("tools.diagnose._find_wine_version", return_value=None),
            ):
                report = diagnose_app(app)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["subject"]["version"], "1.67.2")
        self.assertEqual(report["pe_inventory"]["key_binaries"][0]["architecture"], "x86")
        self.assertEqual(report["dependencies"]["directx9_imports"], ["d3d9.dll"])
        self.assertNotIn(str(app), json.dumps(report))


if __name__ == "__main__":
    unittest.main()
