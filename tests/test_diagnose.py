import json
import struct
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.diagnose import PEFormatError, _json_documents, _matching_failure_records, diagnose_app, parse_pe, render_markdown


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
                patch("tools.diagnose._matching_failure_records", return_value={"matching_record_count": 2, "unreadable_matching_record_count": 0, "scan_available": True, "summary_categories": {"signature_or_seal_failure": 2}, "raw_contents_included": False, "source_scope": "test fixture"}),
                patch("tools.diagnose._find_wine_version", return_value=None),
            ):
                report = diagnose_app(app)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["subject"]["version"], "1.67.2")
        self.assertEqual(report["pe_inventory"]["key_binaries"][0]["architecture"], "x86")
        self.assertEqual(report["dependencies"]["directx9_imports"], ["d3d9.dll"])
        self.assertNotIn(str(app), json.dumps(report))
        markdown = render_markdown(report)
        self.assertIn("signature_or_seal_failure: 2", markdown)
        self.assertNotIn(str(app), markdown)


class FailureRecordTests(unittest.TestCase):
    def test_single_json_ips_uses_structured_exception_fields(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "single.ips").write_text(
                json.dumps({
                    "app_name": "TS3W",
                    "procPath": "/Users/private-person/Library/Game/TS3W",
                    "bundleID": "PRIVATE_BUNDLE_ID_123",
                    "exception": {"type": "EXC_BAD_ACCESS", "signal": "SIGSEGV"},
                    "termination": {"namespace": "SIGNAL", "code": 11},
                }),
                encoding="utf-8",
            )
            report = _matching_failure_records("PRIVATE_BUNDLE_ID_123", [root])
        self.assertEqual(report["matching_record_count"], 1)
        self.assertEqual(report["summary_categories"], {"memory_access_failure": 1})
        serialized = json.dumps(report)
        self.assertNotIn("/Users/private-person", serialized)
        self.assertNotIn("PRIVATE_BUNDLE_ID_123", serialized)
        self.assertNotIn("TS3W", serialized)

    def test_header_and_multiline_body_ips_match_by_private_bundle_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            header = {"app_name": "unknown-wrapper", "bundleID": "PRIVATE_BUNDLE_ID_456"}
            body = {
                "procName": "unrecognized-process",
                "procPath": "/Users/private-person/Applications/Wrapper",
                "exception": {"type": "EXC_CRASH", "signal": "SIGABRT"},
                "termination": {"namespace": "SIGNAL", "code": 6, "byPid": 12345},
            }
            (root / "split.ips").write_text(
                json.dumps(header) + "\n" + json.dumps(body, indent=2), encoding="utf-8"
            )
            report = _matching_failure_records("PRIVATE_BUNDLE_ID_456", [root])
        self.assertEqual(report["matching_record_count"], 1)
        self.assertEqual(report["summary_categories"], {"aborted_process": 1})
        serialized = json.dumps(report)
        for private_value in ("PRIVATE_BUNDLE_ID_456", "/Users/private-person", "unrecognized-process", "12345"):
            self.assertNotIn(private_value, serialized)

    def test_unreadable_matching_ips_is_counted_without_echoing_contents(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "TS3W_unreadable.ips").write_text(
                "secret path /Users/private-person and private token", encoding="utf-8"
            )
            (root / "corrupt-body.ips").write_text(
                json.dumps({"bundleID": "PRIVATE_BUNDLE_ID_789"}) + "\nnot-json", encoding="utf-8"
            )
            (root / "other_unreadable.ips").write_text("not json", encoding="utf-8")
            report = _matching_failure_records("PRIVATE_BUNDLE_ID_789", [root])
        self.assertEqual(report["matching_record_count"], 2)
        self.assertEqual(report["unreadable_matching_record_count"], 2)
        self.assertEqual(report["summary_categories"], {"unreadable_record": 2})
        self.assertNotIn("private-person", json.dumps(report))
        self.assertNotIn("private token", json.dumps(report))

    def test_ips_json_decoder_accepts_single_and_separated_objects(self):
        one = {"app_name": "TS3W"}
        header = {"bundleID": "PRIVATE_BUNDLE_ID_ABC"}
        body = {"exception": {"type": "EXC_BAD_ACCESS"}}
        self.assertEqual(_json_documents(json.dumps(one)), [one])
        self.assertEqual(_json_documents(json.dumps(header) + "\n" + json.dumps(body, indent=2)), [header, body])
        self.assertIsNone(_json_documents("corrupt"))


if __name__ == "__main__":
    unittest.main()
