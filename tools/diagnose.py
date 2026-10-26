#!/usr/bin/env python3
"""Read-only, privacy-conscious inventory for a Sims 3 macOS bundle."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import plistlib
import re
import shutil
import struct
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
SAFE_DLL_RE = re.compile(r"^[A-Za-z0-9_.+\-]{1,128}$")
WINE_VERSION_RE = re.compile(rb"(?:wine[- ]|wine version\s+)([0-9]+\.[0-9]+(?:\.[0-9]+)?)", re.IGNORECASE)
PROCESS_NAMES = {"wineskinlauncher", "ts3", "ts3w", "sims3launcher", "thesims3"}


class PEFormatError(ValueError):
    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise PEFormatError("truncated")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise PEFormatError("truncated")
    return struct.unpack_from("<I", data, offset)[0]


def _read_c_string(data: bytes, offset: int, limit: int = 256) -> str | None:
    if offset < 0 or offset >= len(data):
        return None
    end = data.find(b"\0", offset, min(len(data), offset + limit))
    if end < 0:
        return None
    try:
        name = data[offset:end].decode("ascii")
    except UnicodeDecodeError:
        return None
    if not SAFE_DLL_RE.fullmatch(name):
        return None
    return name.lower()


def parse_pe(data: bytes) -> dict[str, Any]:
    """Parse PE architecture and normal import-table DLL names, without executing it."""
    if len(data) < 2 or data[:2] != b"MZ":
        raise PEFormatError("not_pe")
    pe_offset = _u32(data, 0x3C)
    if pe_offset + 4 > len(data):
        raise PEFormatError("truncated")
    if data[pe_offset : pe_offset + 4] != b"PE\0\0":
        raise PEFormatError("invalid_pe")

    coff = pe_offset + 4
    machine = _u16(data, coff)
    section_count = _u16(data, coff + 2)
    optional_size = _u16(data, coff + 16)
    optional = coff + 20
    if optional + optional_size > len(data):
        raise PEFormatError("truncated")
    magic = _u16(data, optional)

    machine_arch = {
        0x014C: "x86",
        0x8664: "x86_64",
        0x01C0: "arm",
        0x01C4: "arm",
        0xAA64: "arm64",
    }.get(machine)
    if machine_arch is None:
        raise PEFormatError("unknown_architecture")
    if magic == 0x010B:
        directory_base, number_dirs_offset = optional + 96, optional + 92
    elif magic == 0x020B:
        directory_base, number_dirs_offset = optional + 112, optional + 108
    else:
        raise PEFormatError("invalid_pe")
    if machine_arch in {"x86", "arm"} and magic != 0x010B:
        raise PEFormatError("invalid_pe")
    if machine_arch in {"x86_64", "arm64"} and magic != 0x020B:
        raise PEFormatError("invalid_pe")

    directories_count = _u32(data, number_dirs_offset)
    import_rva = import_size = 0
    if directories_count > 1 and directory_base + 16 <= optional + optional_size:
        import_rva = _u32(data, directory_base + 8)
        import_size = _u32(data, directory_base + 12)

    sections_offset = optional + optional_size
    sections: list[tuple[int, int, int, int]] = []
    for i in range(section_count):
        section = sections_offset + i * 40
        if section + 40 > len(data):
            raise PEFormatError("truncated")
        virtual_size = _u32(data, section + 8)
        virtual_address = _u32(data, section + 12)
        raw_size = _u32(data, section + 16)
        raw_offset = _u32(data, section + 20)
        sections.append((virtual_address, max(virtual_size, raw_size), raw_size, raw_offset))

    headers_size = _u32(data, optional + 60)

    def rva_to_offset(rva: int) -> int | None:
        if rva < headers_size and rva < len(data):
            return rva
        for va, span, raw_size, raw_offset in sections:
            if va <= rva < va + span:
                delta = rva - va
                if delta >= raw_size:
                    return None
                mapped = raw_offset + delta
                if mapped >= len(data):
                    return None
                return mapped
        return None

    imports: set[str] = set()
    if import_rva:
        import_offset = rva_to_offset(import_rva)
        if import_offset is None:
            raise PEFormatError("truncated")
        descriptor_limit = min(import_size or (len(data) - import_offset), len(data) - import_offset)
        descriptor_count = descriptor_limit // 20
        terminated = False
        for i in range(descriptor_count):
            desc = import_offset + i * 20
            values = struct.unpack_from("<IIIII", data, desc)
            if not any(values):
                terminated = True
                break
            name_offset = rva_to_offset(values[3])
            if name_offset is None:
                raise PEFormatError("truncated")
            dll = _read_c_string(data, name_offset)
            if dll:
                imports.add(dll)
        if not terminated:
            raise PEFormatError("truncated")

    return {"architecture": machine_arch, "direct_imports": sorted(imports)}


def parse_macho_architectures(data: bytes) -> list[str]:
    """Return CPU architectures from common 32/64-bit thin or universal Mach-O headers."""
    names = {0x01000007: "x86_64", 0x0100000C: "arm64", 7: "x86", 12: "arm"}
    if len(data) < 8:
        return []
    magic = data[:4]
    if magic in (b"\xCF\xFA\xED\xFE", b"\xCE\xFA\xED\xFE"):
        cpu = struct.unpack_from("<I", data, 4)[0]
        return [names[cpu]] if cpu in names else []
    if magic in (b"\xFE\xED\xFA\xCF", b"\xFE\xED\xFA\xCE"):
        cpu = struct.unpack_from(">I", data, 4)[0]
        return [names[cpu]] if cpu in names else []
    if magic == b"\xCA\xFE\xBA\xBE" and len(data) >= 8:
        count = struct.unpack_from(">I", data, 4)[0]
        if count > 32 or 8 + count * 20 > len(data):
            return []
        result = set()
        for i in range(count):
            cpu = struct.unpack_from(">I", data, 8 + i * 20)[0]
            if cpu in names:
                result.add(names[cpu])
        return sorted(result)
    return []


def _safe_plist_version(plist_path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    subject: dict[str, Any] = {"product": "The Sims 3", "version": None}
    wrapper: dict[str, Any] = {"name": "Wineskin", "version": None}
    try:
        with plist_path.open("rb") as f:
            info = plistlib.load(f)
        version = info.get("CFBundleShortVersionString")
        if isinstance(version, (str, int, float)):
            subject["version"] = str(version)[:64]
        wrapper_version = info.get("CFBundleVersion")
        if isinstance(wrapper_version, str):
            match = re.search(r"Wineskin\s+([0-9]+(?:\.[0-9]+){1,3})", wrapper_version, re.IGNORECASE)
            if match:
                wrapper["version"] = match.group(1)
    except (OSError, plistlib.InvalidFileException, ValueError, TypeError):
        pass
    return subject, wrapper


def _find_wine_version(contents: Path) -> str | None:
    candidates = [
        contents / "Frameworks" / "wswine.bundle" / "bin" / "wine",
        contents / "Resources" / "bin" / "wine",
        contents / "Frameworks" / "wswine.bundle" / "lib" / "libwine.1.0.dylib",
        contents / "Frameworks" / "wswine.bundle" / "lib64" / "libwine.1.0.dylib",
    ]
    for path in candidates:
        try:
            with path.open("rb") as f:
                data = f.read(16 * 1024 * 1024)
            match = WINE_VERSION_RE.search(data)
            if match:
                return match.group(1).decode("ascii")
        except OSError:
            continue
    return None


def _find_wine_architectures(contents: Path) -> list[str]:
    root = contents / "Frameworks" / "wswine.bundle" / "bin"
    architectures: set[str] = set()
    for name in ("wine", "wine64"):
        try:
            architectures.update(parse_macho_architectures((root / name).read_bytes()))
        except OSError:
            continue
    return sorted(architectures)


def _signature_status(app: Path) -> dict[str, Any]:
    result = {"status": "unavailable", "assessment": "unavailable", "findings": []}
    tool = shutil.which("codesign")
    if sys.platform != "darwin" or not tool:
        return result
    try:
        proc = subprocess.run(
            [tool, "--verify", "--deep", "--strict", os.fspath(app)],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return result
    result["status"] = "valid" if proc.returncode == 0 else "invalid"
    diagnostic = (proc.stderr + "\n" + proc.stdout).lower()
    findings = []
    if "invalid info.plist" in diagnostic:
        findings.append("sealed_info_plist_mismatch")
    if "invalid resource directory" in diagnostic:
        findings.append("sealed_resources_mismatch")
    if "code object is not signed" in diagnostic or "not signed at all" in diagnostic:
        findings.append("unsigned_code_object")
    if proc.returncode != 0 and not findings:
        findings.append("verification_failed_reason_unclassified")

    assessment_tool = shutil.which("spctl")
    if assessment_tool:
        try:
            assessment = subprocess.run(
                [assessment_tool, "--assess", "--type", "execute", "-vv", os.fspath(app)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assessment_diagnostic = (assessment.stderr + "\n" + assessment.stdout).lower()
            if assessment.returncode == 0:
                result["assessment"] = "accepted"
            else:
                result["assessment"] = "rejected"
                if "invalid resource directory" in assessment_diagnostic:
                    findings.append("sealed_resources_mismatch")
                elif "rejected" in assessment_diagnostic:
                    findings.append("execution_assessment_rejected")
        except (OSError, subprocess.TimeoutExpired):
            pass
    result["findings"] = sorted(set(findings))
    return result


def _decode_json_documents(raw: str) -> tuple[list[dict[str, Any]], bool]:
    """Decode .ips JSON objects and retain a valid header if the body is damaged."""
    try:
        value = json.loads(raw)
        return ([value], True) if isinstance(value, dict) else ([], False)
    except (json.JSONDecodeError, ValueError):
        pass
    documents = []
    decoder = json.JSONDecoder()
    position = 0
    while position < len(raw):
        while position < len(raw) and raw[position].isspace():
            position += 1
        if position == len(raw):
            break
        try:
            value, position = decoder.raw_decode(raw, position)
        except (json.JSONDecodeError, ValueError):
            return documents, False
        if not isinstance(value, dict):
            return documents, False
        documents.append(value)
    return documents, bool(documents)


def _json_documents(raw: str) -> list[dict[str, Any]] | None:
    """Read either one JSON object or separated header/body JSON objects."""
    documents, complete = _decode_json_documents(raw)
    return documents if complete else None


def _walk_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_dicts(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_dicts(child)


def _normalized_process(value: str) -> str:
    basename = value.replace("\\", "/").rsplit("/", 1)[-1]
    if "." in basename:
        basename = basename.rsplit(".", 1)[0]
    return re.sub(r"[^a-z0-9]", "", basename.lower())


def _is_known_process(value: str) -> bool:
    normalized = _normalized_process(value)
    return normalized in PROCESS_NAMES or normalized.startswith("thesims3")


def _filename_matches_process(filename: str) -> bool:
    basename = filename.replace("\\", "/").rsplit("/", 1)[-1]
    stem = basename.rsplit(".", 1)[0]
    candidate = re.split(r"[_\-.]", stem, maxsplit=1)[0]
    return _is_known_process(candidate)


def _matches_failure_record(documents: list[dict[str, Any]], filename: str, bundle_identifier: str | None) -> bool:
    if bundle_identifier:
        for document in documents:
            for item in _walk_dicts(document):
                for key in ("bundleID", "bundle_id", "CFBundleIdentifier", "identifier"):
                    value = item.get(key)
                    if isinstance(value, str) and value == bundle_identifier:
                        return True
    candidates = []
    for document in documents:
        for item in _walk_dicts(document):
            for key in ("app_name", "procName", "processName", "process", "name", "Process", "CFBundleName"):
                value = item.get(key)
                if isinstance(value, str):
                    candidates.append(value)
    if any(_is_known_process(value) for value in candidates):
        return True
    return _filename_matches_process(filename)


def _structured_failure_category(documents: list[dict[str, Any]]) -> str:
    exceptions = []
    terminations = []
    for document in documents:
        for item in _walk_dicts(document):
            if isinstance(item.get("exception"), dict):
                exceptions.append(item["exception"])
            if isinstance(item.get("termination"), dict):
                terminations.append(item["termination"])
    exception_types = {str(item.get("type", "")).upper() for item in exceptions}
    signals = {str(item.get("signal", "")).upper() for item in exceptions}
    namespaces = {str(item.get("namespace", "")).upper() for item in terminations}
    details = " ".join(
        str(item.get(key, ""))
        for item in terminations
        for key in ("indicator", "reason", "code", "description")
    ).lower()
    if "CODESIGNING" in namespaces or "code signature invalid" in details or "invalid signature" in details:
        return "signature_or_seal_failure"
    if "EXC_BAD_ACCESS" in exception_types or signals.intersection({"SIGSEGV", "SIGBUS"}):
        return "memory_access_failure"
    if "SIGABRT" in signals:
        return "aborted_process"
    if exceptions:
        return "other_exception"
    if terminations:
        return "other_termination"
    return "structured_failure_unclassified"


def _crash_document(raw: str) -> list[dict[str, Any]]:
    """Extract only stable exception/termination fields from legacy .crash text."""
    process = re.search(r"(?im)^Process:\s*(.*?)\s+\[\d+\]", raw)
    exception = re.search(r"(?im)^Exception Type:\s*([^\r\n]+)", raw)
    termination = re.search(r"(?im)^Termination Reason:\s*([^\r\n]+)", raw)
    document: dict[str, Any] = {}
    if process:
        document["procName"] = process.group(1).strip()
    if exception:
        document["exception"] = {"type": exception.group(1).strip()}
    if termination:
        document["termination"] = {"reason": termination.group(1).strip()}
    return [document] if document else []


def _bundle_identifier(plist_path: Path) -> str | None:
    """Read an identifier solely for local record matching; never return it in reports."""
    try:
        with plist_path.open("rb") as f:
            value = plistlib.load(f).get("CFBundleIdentifier")
        return value if isinstance(value, str) else None
    except (OSError, plistlib.InvalidFileException, ValueError, TypeError):
        return None


def _matching_failure_records(
    bundle_identifier: str | None = None,
    roots: list[Path] | None = None,
) -> dict[str, Any]:
    """Summarize local failure records without returning source text, IDs, or paths."""
    roots = roots or [Path.home() / "Library" / "Logs" / "DiagnosticReports", Path("/Library/Logs/DiagnosticReports")]
    categories: Counter[str] = Counter()
    count = unreadable_count = 0
    scanned = False
    for root in roots:
        try:
            records = list(root.glob("*.ips")) + list(root.glob("*.crash"))
            scanned = scanned or root.exists()
        except OSError:
            continue
        for path in records:
            try:
                if path.stat().st_size > 5 * 1024 * 1024:
                    continue
                raw = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if path.suffix == ".ips":
                documents, readable = _decode_json_documents(raw)
            else:
                documents = _crash_document(raw)
                readable = bool(documents)
            if not readable:
                # Match a valid header or filename, but never share any damaged content.
                if _matches_failure_record(documents, path.stem, bundle_identifier):
                    count += 1
                    unreadable_count += 1
                    categories["unreadable_record"] += 1
                continue
            if not _matches_failure_record(documents, path.stem, bundle_identifier):
                continue
            count += 1
            categories[_structured_failure_category(documents)] += 1
    return {
        "source_scope": "local macOS DiagnosticReports only",
        "matching_record_count": count,
        "unreadable_matching_record_count": unreadable_count,
        "summary_categories": dict(sorted(categories.items())),
        "raw_contents_included": False,
        "scan_available": scanned,
    }


def _main_game_folder(contents: Path) -> Path | None:
    root = contents / "Resources" / "drive_c" / "Program Files (x86)" / "Electronic Arts" / "The Sims 3" / "Game" / "Bin"
    return root if root.is_dir() else None


def _inspect_key_binaries(contents: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    game_bin = _main_game_folder(contents)
    if game_bin is None:
        return [], {"pe_files_scanned": 0, "pe_architecture_counts": {}, "status": "not_found"}

    key_roles = {
        "TS3W.exe": "game_runtime_executable",
        "TS3.exe": "alternate_game_executable",
        "Sims3Launcher.exe": "game_launcher_executable",
    }
    key_entries: list[dict[str, Any]] = []
    pe_count = 0
    architecture_counts: Counter[str] = Counter()
    for path in sorted(game_bin.iterdir(), key=lambda p: p.name.lower()):
        if not path.is_file() or path.suffix.lower() not in {".exe", ".dll"}:
            continue
        try:
            data = path.read_bytes()
            parsed = parse_pe(data)
        except (OSError, PEFormatError):
            continue
        pe_count += 1
        architecture_counts[parsed["architecture"]] += 1
        role = key_roles.get(path.name)
        if role:
            key_entries.append({
                "role": role,
                "format": "PE",
                "architecture": parsed["architecture"],
                "direct_imports": parsed["direct_imports"],
            })
    return key_entries, {
        "pe_files_scanned": pe_count,
        "pe_architecture_counts": dict(sorted(architecture_counts.items())),
        "status": "scanned",
    }


def diagnose_app(app: Path) -> dict[str, Any]:
    app = app.expanduser()
    contents = app / "Contents"
    bundle_found = app.is_dir() and contents.is_dir()
    plist_path = contents / "Info.plist"
    subject, wrapper = _safe_plist_version(plist_path) if bundle_found else ({"product": "The Sims 3", "version": None}, {"name": "Wineskin", "version": None})

    launcher_arches: list[str] = []
    launcher_path = contents / "MacOS" / "WineskinLauncher"
    try:
        launcher_arches = parse_macho_architectures(launcher_path.read_bytes())
    except OSError:
        pass

    key_binaries, pe_summary = _inspect_key_binaries(contents) if bundle_found else ([], {"pe_files_scanned": 0, "pe_architecture_counts": {}, "status": "not_found"})
    observed_imports = sorted({dll for item in key_binaries for dll in item["direct_imports"]})
    dx9_names = [name for name in observed_imports if name == "d3d9.dll" or name.startswith("d3dx9_") or name in {"dinput.dll", "dinput8.dll"}]

    signature = _signature_status(app) if bundle_found else {"status": "unavailable", "findings": []}
    failures = _matching_failure_records(_bundle_identifier(plist_path)) if bundle_found and sys.platform == "darwin" else {
        "source_scope": "local macOS DiagnosticReports only",
        "matching_record_count": 0,
        "unreadable_matching_record_count": 0,
        "summary_categories": {},
        "raw_contents_included": False,
        "scan_available": False,
    }

    facts = []
    hypotheses = []
    pending = []
    if bundle_found:
        facts.append("The supplied application bundle was found and inspected without launching it.")
    else:
        facts.append("The supplied application path does not contain a readable macOS application bundle.")
    if subject["version"]:
        facts.append(f"The bundle metadata reports game version {subject['version']}.")
    host_arch = platform.machine().lower() or "unknown"
    if host_arch in {"aarch64", "arm64"} and "x86_64" in launcher_arches:
        facts.append("The host reports ARM64 while the bundle launcher is x86_64.")
        hypotheses.append("Launching this Intel-only wrapper on Apple silicon may require Rosetta 2; availability and a real launch were not tested.")
        pending.append("Check whether Rosetta 2 is available and whether the bundled x86/x86_64 Wine components can run the 32-bit Windows executable on this macOS release.")
    elif launcher_arches:
        facts.append("The launcher Mach-O architecture was read from its binary header.")
    else:
        pending.append("The launcher architecture could not be read from its Mach-O header.")
    if wrapper["version"]:
        facts.append(f"Bundle metadata identifies Wineskin {wrapper['version']}.")
    wine_version = _find_wine_version(contents) if bundle_found else None
    wine_architectures = _find_wine_architectures(contents) if bundle_found else []
    if wine_version:
        facts.append(f"The bundled Wine support library identifies itself as Wine {wine_version}; Wine executables were not run.")
    else:
        pending.append("The Wine version was not recovered from embedded version text without executing Wine.")
    if wine_architectures:
        facts.append(f"Bundled Wine host executable architectures are {', '.join(wine_architectures)}.")
    if key_binaries:
        for item in key_binaries:
            if item["architecture"] == "x86":
                facts.append(f"The {item['role'].replace('_', ' ')} is a 32-bit x86 PE executable.")
        if dx9_names:
            facts.append("DirectX 9 DLLs appear in the normal PE import table of inspected game executables.")
        else:
            pending.append("DirectX dependencies were not found in the normal imports of the inspected key binaries; runtime and delay-loaded modules remain unknown.")
    else:
        pending.append("Key game PE executables were not found at the expected bundle-relative location.")
    if signature["status"] == "invalid":
        facts.append("Strict macOS code-signature verification failed for the application bundle.")
        for item in signature["findings"]:
            if item == "sealed_info_plist_mismatch":
                facts.append("The verifier reported that the sealed Info.plist does not match the signed bundle state.")
            elif item == "sealed_resources_mismatch":
                facts.append("The verifier reported that the sealed resource directory does not match the signed bundle state.")
        hypotheses.append("The signature/seal failure may prevent macOS from launching the wrapper; the denial path was not exercised in this read-only scan.")
        pending.append("Correlate the signature failure with a fresh, sanitized launch-services or diagnostic record during a separately authorized execution test.")
    elif signature["status"] == "valid":
        facts.append("Strict macOS code-signature verification passed.")
    else:
        pending.append("Strict macOS code-signature verification was unavailable.")
    if signature.get("assessment") == "rejected":
        facts.append("macOS execution policy assessment rejected the application bundle.")
    if failures["matching_record_count"]:
        facts.append(f"{failures['matching_record_count']} matching local DiagnosticReports records were summarized by category only.")
    elif failures["scan_available"]:
        facts.append("No matching local DiagnosticReports records were found for the recognized launcher/game processes.")
    else:
        pending.append("Local DiagnosticReports could not be scanned on this host.")

    return {
        "schema_version": SCHEMA_VERSION,
        "generated_on": datetime.date.today().isoformat(),
        "status": "ok" if bundle_found else "not_found",
        "subject": subject,
        "host": {"mac_architecture": host_arch, "macos_version": platform.mac_ver()[0] or None},
        "launcher": {"format": "Mach-O" if launcher_arches else "unknown", "architectures": launcher_arches},
        "compatibility_layer": {**wrapper, "wine_version": wine_version, "host_executable_architectures": wine_architectures},
        "pe_inventory": {"summary": pe_summary, "key_binaries": key_binaries},
        "dependencies": {
            "directly_observed_normal_imports": observed_imports,
            "directx9_imports": dx9_names,
            "runtime_dynamic_or_delay_loaded_modules": "unknown; static normal-import inspection cannot determine runtime loads",
        },
        "signature": signature,
        "failure_records": failures,
        "evidence": {"facts": facts, "hypotheses": hypotheses, "pending_checks": pending},
        "privacy": {"absolute_paths_included": False, "identifiers_included": False, "raw_failure_records_included": False, "game_content_included": False},
    }


def render_markdown(report: dict[str, Any]) -> str:
    subject = report["subject"]
    host = report["host"]
    launcher = report["launcher"]
    wrapper = report["compatibility_layer"]
    imports = report["dependencies"]
    records = report["failure_records"]
    lines = [
        "# Diagnóstico local do The Sims 3",
        "",
        f"- Versão do jogo: {subject['version'] or 'não identificada'}",
        f"- Arquitetura do Mac: {host['mac_architecture']}",
        f"- macOS: {host['macos_version'] or 'não identificado'}",
        f"- Iniciador: {', '.join(launcher['architectures']) or 'não identificado'} Mach-O",
        f"- Wineskin: {wrapper['version'] or 'não identificada'}; Wine: {wrapper['wine_version'] or 'não identificado'}",
        f"- Assinatura: {report['signature']['status']}",
        f"- Registros locais correspondentes: {records['matching_record_count']} (DiagnosticReports; conteúdo bruto omitido)",
        f"- Categorias de falha: {', '.join(f'{name}: {count}' for name, count in records['summary_categories'].items()) or 'nenhuma'}",
        f"- Registros correspondentes ilegíveis: {records.get('unreadable_matching_record_count', 0)}",
        "",
        "## Executáveis PE",
        "",
    ]
    for item in report["pe_inventory"]["key_binaries"]:
        lines.append(f"- {item['role']}: {item['architecture']} PE; imports diretos: {', '.join(item['direct_imports']) or 'nenhum encontrado'}.")
    if not report["pe_inventory"]["key_binaries"]:
        lines.append("- Executáveis principais não encontrados.")
    lines.extend(["", "## Dependências", ""])
    lines.append(f"- Imports diretamente observados: {', '.join(imports['directly_observed_normal_imports']) or 'nenhum encontrado'}.")
    lines.append(f"- Imports de DirectX 9 observados: {', '.join(imports['directx9_imports']) or 'nenhum encontrado'}.")
    lines.append(f"- Carregamentos dinâmicos ou adiados: {imports['runtime_dynamic_or_delay_loaded_modules']}.")
    for title, key in (("Fatos", "facts"), ("Hipóteses", "hypotheses"), ("Verificações pendentes", "pending_checks")):
        lines.extend(["", f"## {title}", ""])
        items = report["evidence"][key] or ["Nenhum item."]
        lines.extend(f"- {item}" for item in items)
    lines.extend(["", "## Privacidade", "", "O relatório não inclui caminhos absolutos, identificadores, registros brutos nem conteúdo do jogo.", ""])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gera um diagnóstico sanitizado e somente de leitura de um app do The Sims 3.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    diagnose = subparsers.add_parser("diagnose", help="Inspeciona metadados, iniciador, PE, assinatura e resumos de falha locais.")
    diagnose.add_argument("--app", required=True, help="Caminho local para o pacote .app")
    diagnose.add_argument("--format", choices=("json", "markdown"), default="json")
    diagnose.add_argument("--output", help="Arquivo opcional para salvar o relatório; por padrão imprime no terminal.")
    args = parser.parse_args(argv)

    report = diagnose_app(Path(args.app))
    output = json.dumps(report, ensure_ascii=False, indent=2) + "\n" if args.format == "json" else render_markdown(report)
    if args.output:
        try:
            Path(args.output).expanduser().write_text(output, encoding="utf-8")
        except OSError:
            print("Não foi possível gravar o relatório no destino informado.", file=sys.stderr)
            return 2
    else:
        sys.stdout.write(output)
    return 0 if report["status"] == "ok" else 2


if __name__ == "__main__":
    raise SystemExit(main())
