#!/usr/bin/env python3
"""Create a sanitized, static map of the three Sims 3 PE executables.

REA supplies PE import, delay-import, TLS, and load-configuration records.
This module independently reads PE headers and never executes a target.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable


SCHEMA_VERSION = 1
REA_VERSION = "6.8.0"
BIN_RELATIVE = Path(
    "Contents/Resources/drive_c/Program Files (x86)/Electronic Arts/"
    "The Sims 3/Game/Bin"
)
EXECUTABLES = ("TS3.exe", "TS3W.exe", "Sims3Launcher.exe")
ROOT = Path(__file__).resolve().parents[1]
REA_COMMANDS = {
    "inspect_pe_imports": "inspect-pe-imports",
    "inspect_pe_load_config": "inspect-pe-load-config",
}


class PEFormatError(ValueError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ToolInvocationError(RuntimeError):
    def __init__(self, code: str, raw: dict[str, Any] | None = None):
        super().__init__(code)
        self.code = code
        self.raw = raw or {"error_code": code}


def _require(data: bytes, offset: int, size: int) -> None:
    if offset < 0 or size < 0 or offset + size > len(data):
        raise PEFormatError("truncated")


def _u16(data: bytes, offset: int) -> int:
    _require(data, offset, 2)
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    _require(data, offset, 4)
    return struct.unpack_from("<I", data, offset)[0]


def _u64(data: bytes, offset: int) -> int:
    _require(data, offset, 8)
    return struct.unpack_from("<Q", data, offset)[0]


def _machine_name(machine: int) -> str:
    return {
        0x014C: "x86",
        0x8664: "x86_64",
        0x01C0: "arm",
        0x01C4: "armv7",
        0xAA64: "arm64",
    }.get(machine, "unknown")


def parse_pe_headers(data: bytes) -> dict[str, Any]:
    """Read bounded PE identity, sections, permissions, alignments and directories."""
    if len(data) < 2 or data[:2] != b"MZ":
        raise PEFormatError("not_pe")
    _require(data, 0x3C, 4)
    nt_offset = _u32(data, 0x3C)
    _require(data, nt_offset, 24)
    if data[nt_offset : nt_offset + 4] != b"PE\0\0":
        raise PEFormatError("not_pe")

    coff = nt_offset + 4
    machine, section_count = struct.unpack_from("<HH", data, coff)
    characteristics = _u16(data, coff + 18)
    optional_size = _u16(data, coff + 16)
    optional = coff + 20
    _require(data, optional, optional_size)
    magic = _u16(data, optional)
    if magic == 0x10B:
        pe_format, bits, image_base_offset, count_offset, directory_offset, ptr_size = (
            "pe32", 32, 28, 92, 96, 4
        )
    elif magic == 0x20B:
        pe_format, bits, image_base_offset, count_offset, directory_offset, ptr_size = (
            "pe32_plus", 64, 24, 108, 112, 8
        )
    else:
        raise PEFormatError("unsupported_optional_header")

    if optional_size < directory_offset:
        raise PEFormatError("truncated")
    entry_rva = _u32(data, optional + 16)
    image_base = _u32(data, optional + image_base_offset) if bits == 32 else _u64(data, optional + image_base_offset)
    section_alignment = _u32(data, optional + 32)
    file_alignment = _u32(data, optional + 36)
    size_of_image = _u32(data, optional + 56)
    size_of_headers = _u32(data, optional + 60)
    directory_count = _u32(data, optional + count_offset)
    available_directories = (optional_size - directory_offset) // 8
    directories_to_read = min(directory_count, available_directories)
    directories: list[tuple[int, int]] = []
    for index in range(directories_to_read):
        directories.append(struct.unpack_from("<II", data, optional + directory_offset + index * 8))

    section_table = optional + optional_size
    _require(data, section_table, section_count * 40)
    if section_count > 96:
        raise PEFormatError("section_count_out_of_bounds")

    sections: list[dict[str, Any]] = []
    for index in range(section_count):
        offset = section_table + index * 40
        raw_name, virtual_size, virtual_address, raw_size, raw_offset = struct.unpack_from(
            "<8sIIII", data, offset
        )
        section_flags = _u32(data, offset + 36)
        name = raw_name.split(b"\0", 1)[0].decode("ascii", errors="replace")
        if raw_size:
            _require(data, raw_offset, raw_size)
        sections.append(
            {
                "name": name,
                "virtual_address": virtual_address,
                "virtual_size": virtual_size,
                "file_offset": raw_offset,
                "raw_size": raw_size,
                "characteristics": section_flags,
                "permissions": {
                    "read": bool(section_flags & 0x40000000),
                    "write": bool(section_flags & 0x80000000),
                    "execute": bool(section_flags & 0x20000000),
                },
            }
        )

    def rva_to_file_offset(rva: int, size: int = 1) -> int | None:
        if rva < size_of_headers and rva + size <= min(size_of_headers, len(data)):
            return rva
        for section in sections:
            span = max(section["virtual_size"], section["raw_size"])
            delta = rva - section["virtual_address"]
            if 0 <= delta < span:
                if delta + size <= section["raw_size"]:
                    candidate = section["file_offset"] + delta
                    return candidate if candidate + size <= len(data) else None
                return None
        return None

    def directory(index: int) -> dict[str, Any]:
        if index >= len(directories):
            return {"present": False, "rva": 0, "size": 0, "file_offset": None}
        rva, size = directories[index]
        return {
            "present": bool(rva and size),
            "rva": rva,
            "size": size,
            "file_offset": rva_to_file_offset(rva, min(size, 1)) if rva and size else None,
        }

    relocation = directory(5)
    relocations_stripped = bool(characteristics & 0x0001)
    if relocation["present"] and relocations_stripped:
        relocation_status = "directory_present_with_relocations_stripped_flag"
    elif relocation["present"]:
        relocation_status = "directory_present"
    elif relocations_stripped:
        relocation_status = "stripped_or_absent"
    else:
        relocation_status = "directory_absent"

    return {
        "format": pe_format,
        "architecture": _machine_name(machine),
        "bits": bits,
        "machine": machine,
        "entry_point": {
            "rva": entry_rva,
            "virtual_address": image_base + entry_rva,
        },
        "image_base": image_base,
        "section_alignment": section_alignment,
        "file_alignment": file_alignment,
        "size_of_image": size_of_image,
        "size_of_headers": size_of_headers,
        "sections": sections,
        "relocations": {
            **relocation,
            "stripped_flag": relocations_stripped,
            "status": relocation_status,
        },
        "tls_directory": directory(9),
        "header_coverage": "complete",
    }


def _jsonable(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _save_raw(raw_dir: Path, stem: str, operation: str, value: Any) -> None:
    safe_name = re.sub(r"[^A-Za-z0-9_.-]", "_", stem)
    (raw_dir / f"{safe_name}.{operation}.json").write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _response_data(response: Any) -> dict[str, Any]:
    if isinstance(response, str):
        try:
            response = json.loads(response)
        except json.JSONDecodeError as exc:
            raise ToolInvocationError("invalid_json") from exc
    if not isinstance(response, dict):
        raise ToolInvocationError("invalid_response")
    if response.get("ok") is False or response.get("isError") is True:
        code = response.get("error_code") or response.get("error", {}).get("code") or "tool_failed"
        raise ToolInvocationError(str(code), response)
    if isinstance(response.get("data"), dict):
        return response["data"]
    if isinstance(response.get("structuredContent"), dict):
        return response["structuredContent"]
    if "normalized_result" in response:
        return response
    raise ToolInvocationError("missing_evidence_record")


def _function_record(function: dict[str, Any]) -> dict[str, Any]:
    name = function.get("name")
    ordinal = function.get("ordinal")
    result: dict[str, Any] = {"name": name, "ordinal": ordinal}
    if name is None and ordinal is None:
        result["identity_status"] = "unresolved"
    return result


def _module_records(imports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records = []
    for module in imports:
        functions = [_function_record(item) for item in module.get("functions", [])]
        records.append({"module": module.get("name"), "functions": functions})
    return records


def _all_functions(imports: list[dict[str, Any]]) -> list[tuple[str, dict[str, Any]]]:
    return [
        (str(module.get("name") or "").lower(), function)
        for module in imports
        for function in module.get("functions", [])
    ]


def _category(module: str, function: dict[str, Any]) -> str:
    name = str(function.get("name") or "").lower()
    if module in {"msvcr80.dll", "msvcp80.dll", "msvcr90.dll", "msvcp90.dll", "msvcrt.dll"}:
        return "c_cpp_runtime"
    if module in {"d3d9.dll", "d3dx9_31.dll", "ddraw.dll", "gdi32.dll", "opengl32.dll"}:
        return "graphics"
    if module in {"dsound.dll", "dsound", "dsound3d.dll"}:
        return "audio"
    if module in {"ws2_32.dll", "wsock32.dll", "wininet.dll", "iphlpapi.dll", "netapi32.dll", "dnsapi.dll"}:
        return "network"
    if module in {"user32.dll", "imm32.dll", "usp10.dll"}:
        return "interface"
    if module == "winmm.dll":
        if name.startswith(("time", "mmtime", "joy")):
            return "concurrency_timing"
        return "audio"
    if module in {"advapi32.dll", "shell32.dll", "version.dll", "setupapi.dll"}:
        return "files_configuration"
    if re.match(r"^(virtual|heap|globalalloc|globalfree|localalloc|localfree|malloc|calloc|realloc|free|memcpy|memmove|memset|new|delete)", name):
        return "memory"
    if re.match(r"^(createthread|openthread|exitthread|getcurrentthread|wait|sleep|criticalsection|interlocked|tlsalloc|tlsfree|tlsgetvalue|tlssetvalue|createevent|setevent|resetevent|createmutex|releasemutex|beginthread|endthread|queueuserworkitem)", name):
        return "concurrency_timing"
    if re.match(r"^(createfile|readfile|writefile|deletefile|findfirst|findnext|findclose|movefile|copyfile|getfile|setfile|flushfile|lockfile|unlockfile|createdirectory|removedirectory|setcurrentdirectory|getcurrentdirectory)", name):
        return "files_configuration"
    if name.startswith(("socket", "connect", "bind", "listen", "accept", "send", "recv", "getaddrinfo", "inet_", "wsasocket", "wsa")):
        return "network"
    return "other_system"


CATEGORY_LABELS = {
    "graphics": "Gráficos",
    "audio": "Áudio",
    "interface": "Interface e entrada de texto",
    "memory": "Memória",
    "files_configuration": "Arquivos e configuração",
    "network": "Rede",
    "concurrency_timing": "Concorrência e temporização",
    "c_cpp_runtime": "Biblioteca C/C++",
    "other_system": "Outras APIs de sistema",
}


def _dependency_categories(imports: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[tuple[str, dict[str, Any]]]] = {key: [] for key in CATEGORY_LABELS}
    for module, function in _all_functions(imports):
        grouped[_category(module, function)].append((module, function))
    output: dict[str, Any] = {}
    for key, records in grouped.items():
        modules = sorted({module for module, _ in records})
        examples = []
        for module, function in records:
            identity = function.get("name")
            if identity is None and function.get("ordinal") is not None:
                identity = f"ordinal:{function['ordinal']}"
            if identity is not None and len(examples) < 8 and identity not in [item["import"] for item in examples]:
                examples.append({"module": module, "import": identity})
        output[key] = {
            "label": CATEGORY_LABELS[key],
            "import_count": len(records),
            "modules": modules,
            "examples": examples,
            "basis": "classificação estática por módulo e nome de API importado",
        }
    return output


def _compact_import_evidence(record: dict[str, Any]) -> dict[str, Any]:
    result = record.get("normalized_result")
    if not isinstance(result, dict):
        raise ToolInvocationError("missing_import_result")
    coverage = result.get("coverage") or {}
    normal = result.get("imports") or []
    delayed = result.get("delay_imports") or []
    issues = result.get("issues") or []
    all_imports = normal + delayed
    functions = [function for _, function in _all_functions(all_imports)]
    named_count = sum(function.get("name") is not None for function in functions)
    ordinal_count = sum(function.get("ordinal") is not None for function in functions)
    complete = coverage.get("status") == "complete" and not issues
    return {
        "evidence_id": record.get("evidence_id"),
        "status": "complete" if complete else "partial",
        "coverage": {
            "status": coverage.get("status", "unknown"),
            "normal_modules": len(normal),
            "normal_functions": sum(len(module.get("functions", [])) for module in normal),
            "delay_modules": len(delayed),
            "delay_functions": sum(len(module.get("functions", [])) for module in delayed),
            "named_functions": named_count,
            "ordinal_functions": ordinal_count,
            "issue_count": len(issues),
        },
        "normal_imports": _module_records(normal),
        "delay_imports": _module_records(delayed),
        "dependency_categories": _dependency_categories(all_imports),
        "limitations": list(result.get("limitations") or record.get("limitations") or []),
    }


def _compact_load_evidence(record: dict[str, Any]) -> dict[str, Any]:
    result = record.get("normalized_result")
    if not isinstance(result, dict):
        raise ToolInvocationError("missing_load_config_result")
    tls = result.get("tls")
    load_config = result.get("load_config")
    callbacks = list((tls or {}).get("callbacks") or [])
    return {
        "evidence_id": record.get("evidence_id"),
        "status": "complete" if record.get("evidence_id") else "partial",
        "tls": {
            "present": tls is not None,
            "directory_rva": (tls or {}).get("directory", {}).get("rva") if tls else None,
            "directory_size": (tls or {}).get("directory", {}).get("size") if tls else None,
            "callback_count": len(callbacks),
            "callbacks": callbacks,
            "raw_data_size": (tls or {}).get("raw_data_size") if tls else None,
            "zero_fill_size": (tls or {}).get("size_of_zero_fill") if tls else None,
        },
        "load_configuration": {
            "present": load_config is not None,
            "directory_rva": (load_config or {}).get("directory", {}).get("rva") if load_config else None,
            "directory_size": (load_config or {}).get("directory", {}).get("size") if load_config else None,
            "structure_size": (load_config or {}).get("size") if load_config else None,
            "guard_flags": (load_config or {}).get("guard_flags") if load_config else None,
            "safe_seh_handler_count": (load_config or {}).get("se_handler_count") if load_config else None,
            "inferences": (load_config or {}).get("inferences", []) if load_config else [],
        },
        "examined_callbacks": result.get("examined_callbacks"),
        "limitations": list(result.get("limitations") or record.get("limitations") or []),
    }


def _query_failure(code: str, evidence_id: str | None = None) -> dict[str, Any]:
    return {"status": "unavailable" if code in {"rea_cli_unavailable", "node_unavailable", "rea_version_mismatch"} else "failed", "error_code": code, "evidence_id": evidence_id}


def collect_app(
    app_path: str | Path,
    query_runner: Callable[[str, Path], Any],
    raw_dir: str | Path,
    *,
    rea_version: str | None = None,
    node_version: str | None = None,
) -> dict[str, Any]:
    """Collect REA evidence plus independent PE-header observations.

    query_runner receives the REA operation name and exact executable path.
    Tests inject controlled responses here; production uses the local REA CLI.
    """
    app = Path(app_path).expanduser()
    app_contents = app / "Contents"
    binary_dir = app / BIN_RELATIVE
    raw_root = Path(raw_dir)
    raw_root.mkdir(parents=True, exist_ok=True)
    binaries: list[dict[str, Any]] = []

    for filename in EXECUTABLES:
        stem = Path(filename).stem
        path = binary_dir / filename
        item: dict[str, Any] = {
            "file": filename,
            "status": "unavailable",
            "source": "local app bundle, Game/Bin",
            "identity": {"bytes": None, "sha256": None, "architecture": None},
            "identity_stability": {"status": "not_checked", "before_sha256": None, "after_sha256": None, "rea_query_sha256": []},
            "pe_headers": {"status": "unavailable", "source": "independent Python PE header parser", "error_code": "file_not_found"},
            "imports": _query_failure("not_queried"),
            "loader": _query_failure("not_queried"),
            "limitations": [],
        }
        if not app_contents.is_dir():
            item["status"] = "unavailable"
            item["limitations"].append("The selected path does not contain an app bundle Contents directory.")
            binaries.append(item)
            continue
        if not path.is_file():
            item["limitations"].append("The expected executable was not found in the app bundle's Game/Bin directory.")
            binaries.append(item)
            continue

        try:
            before_bytes = path.read_bytes()
            before_sha = hashlib.sha256(before_bytes).hexdigest()
            parsed_headers = parse_pe_headers(before_bytes)
            item["pe_headers"] = {"status": "complete", "source": "independent Python PE header parser", **parsed_headers}
            item["identity"].update(
                {
                    "bytes": len(before_bytes),
                    "sha256": before_sha,
                    "architecture": parsed_headers["architecture"],
                }
            )
        except OSError:
            item["pe_headers"] = {"status": "unavailable", "source": "independent Python PE header parser", "error_code": "file_read_failed"}
            binaries.append(item)
            continue
        except PEFormatError as exc:
            item["identity"].update({"bytes": len(before_bytes), "sha256": before_sha})
            item["pe_headers"] = {"status": "failed", "source": "independent Python PE header parser", "error_code": exc.code}
            item["limitations"].append("PE header parsing did not complete; REA queries are still recorded independently.")

        imported_record: dict[str, Any] | None = None
        load_record: dict[str, Any] | None = None
        query_hashes: list[str] = []
        for operation in ("inspect_pe_imports", "inspect_pe_load_config"):
            try:
                response = query_runner(operation, path)
                _save_raw(raw_root, stem, operation, response)
                record = _response_data(response)
                normalized = record.get("normalized_result")
                artifact = normalized.get("artifact") if isinstance(normalized, dict) else None
                if isinstance(artifact, dict) and artifact.get("sha256"):
                    query_hashes.append(str(artifact["sha256"]))
                if operation == "inspect_pe_imports":
                    imported_record = record
                    item["imports"] = _compact_import_evidence(record)
                else:
                    load_record = record
                    item["loader"] = _compact_load_evidence(record)
            except ToolInvocationError as exc:
                _save_raw(raw_root, stem, operation, exc.raw)
                destination = "imports" if operation == "inspect_pe_imports" else "loader"
                item[destination] = _query_failure(exc.code)
            except (OSError, ValueError, TypeError):
                destination = "imports" if operation == "inspect_pe_imports" else "loader"
                item[destination] = _query_failure("invalid_tool_response")

        try:
            after_sha = hashlib.sha256(path.read_bytes()).hexdigest()
        except OSError:
            after_sha = None
        tool_shas = [
            imported_record.get("normalized_result", {}).get("artifact", {}).get("sha256") if imported_record else None,
            load_record.get("normalized_result", {}).get("artifact", {}).get("sha256") if load_record else None,
        ]
        tool_shas = [str(value) for value in tool_shas if value]
        file_changed = after_sha != before_sha
        query_mismatch = any(value not in {before_sha, after_sha} for value in tool_shas)
        query_incomplete = len(tool_shas) != 2
        stable = not file_changed and not query_mismatch and not query_incomplete
        if stable:
            identity_status = "stable"
        elif file_changed:
            identity_status = "aborted_file_changed"
        elif query_mismatch:
            identity_status = "aborted_rea_identity_mismatch"
        else:
            identity_status = "query_incomplete"
        item["identity_stability"] = {
            "status": identity_status,
            "before_sha256": before_sha,
            "after_sha256": after_sha,
            "rea_query_sha256": tool_shas,
        }
        if file_changed or query_mismatch:
            item["imports"] = {"status": "aborted", "evidence_id": item.get("imports", {}).get("evidence_id"), "reason": "The source digest changed or one REA query did not bind to the same artifact; imports were withheld from consolidation."}
            item["loader"] = {"status": "aborted", "evidence_id": item.get("loader", {}).get("evidence_id"), "reason": "The source digest changed or one REA query did not bind to the same artifact; loader observations were withheld from consolidation."}
            item["status"] = "inconsistent"
            reason = "the file changed during collection" if file_changed else "REA reported a different artifact digest"
            item["limitations"].append(f"Consolidation stopped because {reason}.")
        elif query_incomplete:
            item["status"] = "partial"
            item["limitations"].append("Identity verification is incomplete because one or more REA queries did not return an artifact digest.")
        elif item["pe_headers"]["status"] != "complete" or item["imports"].get("status") != "complete" or item["loader"].get("status") != "complete":
            item["status"] = "partial"
        else:
            item["status"] = "complete"
        if item["pe_headers"].get("status") == "complete" and item["imports"].get("status") == "complete":
            rea_identity = imported_record.get("normalized_result", {}).get("artifact", {}) if imported_record else {}
            if rea_identity.get("bytes") != item["identity"]["bytes"] or rea_identity.get("sha256") != before_sha:
                item["status"] = "inconsistent"
                item["identity_stability"]["status"] = "aborted_rea_identity_mismatch"
                item["imports"] = {"status": "aborted", "evidence_id": item["imports"].get("evidence_id"), "reason": "REA and the independent file read reported different artifact identity."}
                item["loader"] = {"status": "aborted", "evidence_id": item["loader"].get("evidence_id"), "reason": "REA and the independent file read reported different artifact identity."}
                item["limitations"].append("Consolidation stopped because the independent byte count or SHA-256 disagreed with REA.")
        binaries.append(item)

    statuses = [item["status"] for item in binaries]
    if all(status == "complete" for status in statuses):
        overall = "complete"
    elif any(status == "inconsistent" for status in statuses):
        overall = "inconsistent"
    else:
        overall = "partial"

    return {
        "schema_version": SCHEMA_VERSION,
        "report": "Marco 2 — mapa estático dos executáveis",
        "generated_on": dt.date.today().isoformat(),
        "status": overall,
        "scope": {
            "application": "The Sims 3 local macOS app bundle",
            "relative_directory": str(BIN_RELATIVE).replace("\\", "/"),
            "executables": list(EXECUTABLES),
            "target_executed": False,
            "resources_extracted": False,
            "disassembly_or_decompilation_collected": False,
        },
        "toolchain": {"rea_version": rea_version, "node_version": node_version},
        "binaries": binaries,
        "lab_comparison": _lab_comparison(),
        "limitations": [
            "Static import declarations do not prove that an API is called, reachable, resolved, or used at runtime.",
            "Static loading metadata does not observe callback execution, dynamic LoadLibrary calls, bound imports, forwarded exports, or the loaded import address table.",
            "This milestone does not execute game bytes, decode game instructions, or measure instruction coverage; coverage of instructions used by the game remains unknown.",
            "Dependency categories are analyst classifications from imported DLL and API names; they are not runtime behavior claims.",
            "Raw REA records are local-only files under diagnostics/raw/ and are excluded from Git.",
        ],
        "next_milestone": {
            "priority": "Implement a minimal PE32 loader and process-memory model against synthetic fixtures before expanding instruction support.",
            "basis": "All three targets are PE32 x86, while the lab currently accepts byte vectors only; it has no section mapping, relocation, import resolution, TLS setup, page permissions, or API boundary model. The runtime's large declared import surface makes those loader/API boundaries a prerequisite for representative experiments.",
            "small_experiment": "Build one synthetic PE32 fixture with .text and .data sections, one HIGHLOW relocation, one named import and one ordinal import; map it into simulated memory at a different base and assert the entry RVA, relocated value, IAT entries, and read/write/execute permissions without running its code.",
        },
    }


def _lab_comparison() -> list[dict[str, str]]:
    return [
        {"capability": "PE loader", "observed_target_declarations": "PE32 headers, sections, normal imports, TLS and load-config metadata", "lab_today": "No PE image input or section mapping", "gap": "Image layout, entry initialization, imports, delay imports, relocations, TLS and load configuration are not implemented", "source": "lab/src/x86_subset.cpp; lab/src/x86_subset_lab.cpp"},
        {"capability": "Memory", "observed_target_declarations": "Imports include memory and allocation related API declarations", "lab_today": "A separate fixed-size synthetic byte vector with checked 32-bit little-endian reads and writes", "gap": "No 32-bit virtual address space, heap, stack, page permissions, or OS allocation behavior", "source": "lab/include/synthetic_memory.hpp; lab/src/x86_subset.cpp"},
        {"capability": "Graphics", "observed_target_declarations": "DirectX 9 and GDI imports in the runtime executable", "lab_today": "No graphics or DirectX API model", "gap": "No COM interfaces, device state, resources, or presentation calls", "source": "lab/src/x86_subset.cpp"},
        {"capability": "Audio", "observed_target_declarations": "DirectSound and multimedia imports in the runtime executable", "lab_today": "No audio API model", "gap": "No device, buffer, mixer, or timing side effects", "source": "lab/src/x86_subset.cpp"},
        {"capability": "Interface", "observed_target_declarations": "Window, input-method, and text-shaping imports", "lab_today": "No window, message queue, input, or UI API model", "gap": "No platform interface boundary or event loop", "source": "lab/src/x86_subset.cpp"},
        {"capability": "Files and configuration", "observed_target_declarations": "File, registry, shell, and version API imports", "lab_today": "Only synthetic code/data buffers and CLI output", "gap": "No filesystem, registry, or resource-resolution model", "source": "lab/src/x86_subset.cpp; lab/src/x86_subset_lab.cpp"},
        {"capability": "Network", "observed_target_declarations": "Internet, sockets, adapter, and network-management imports", "lab_today": "No network API model", "gap": "No sockets, DNS, HTTP, or network lifecycle model", "source": "lab/src/x86_subset.cpp"},
        {"capability": "Concurrency", "observed_target_declarations": "Thread, wait, synchronization, and timer API declarations are inventoried where present", "lab_today": "One sequential interpreter loop", "gap": "No threads, processes, synchronization objects, or scheduling", "source": "lab/src/x86_subset.cpp; lab/src/x86_subset_lab.cpp"},
        {"capability": "C/C++ libraries", "observed_target_declarations": "MSVC 8 runtime DLL imports in all three executables", "lab_today": "C++17 is the host implementation language", "gap": "No emulation of the 32-bit Visual C++ ABI or target runtime behavior", "source": "lab/CMakeLists.txt; lab/src/x86_subset.cpp"},
        {"capability": "Instruction semantics", "observed_target_declarations": "Instruction use is not measured in this static-import milestone", "lab_today": "A bounded hand-written subset of x86 forms and ZF", "gap": "No evidence yet establishes which forms the game executes or how much code the subset covers", "source": "lab/include/x86_subset.hpp; docs/marco-1-x86-subset.md"},
    ]


def render_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# Marco 2 — mapa estático dos executáveis",
        "",
        f"- Estado da coleta: **{report['status']}**.",
        f"- REA: {report['toolchain'].get('rea_version') or 'indisponível'}; Node.js: {report['toolchain'].get('node_version') or 'indisponível'}.",
        "- Escopo: três executáveis PE na pasta Game/Bin; nenhum foi executado e nenhum recurso foi extraído.",
        "- Método: REA 6.8.0 para imports, TLS e load config; parser Python independente para cabeçalhos PE.",
        "",
        "## Identidade e estabilidade",
        "",
        "| Executável | Bytes | Arquitetura | SHA-256 | Identidade estável | Estado |",
        "|---|---:|---|---|---|---|",
    ]
    for item in report["binaries"]:
        identity = item["identity"]
        stable = item["identity_stability"].get("status")
        lines.append(
            f"| {item['file']} | {identity.get('bytes') if identity.get('bytes') is not None else '—'} | "
            f"{identity.get('architecture') or '—'} | {identity.get('sha256') or '—'} | {stable} | {item['status']} |"
        )

    lines.extend(["", "## Cabeçalhos PE — leitura independente", ""])
    for item in report["binaries"]:
        headers = item.get("pe_headers", {})
        lines.extend([f"### {item['file']}", ""])
        if headers.get("status") != "complete":
            lines.append(f"- Cabeçalho não completo: `{headers.get('error_code', headers.get('status'))}`.")
            lines.append("")
            continue
        entry = headers["entry_point"]
        reloc = headers["relocations"]
        tls = headers["tls_directory"]
        lines.extend(
            [
                f"- Ponto de entrada: RVA `0x{entry['rva']:x}` (endereço preferido `0x{entry['virtual_address']:x}`).",
                f"- Base da imagem: `0x{headers['image_base']:x}`; formato {headers['format']} / {headers['bits']} bits / {headers['architecture']}.",
                f"- Alinhamento: seção `{headers['section_alignment']}`, arquivo `{headers['file_alignment']}`; tamanho de imagem declarado `{headers['size_of_image']}` bytes.",
                f"- Relocações: `{reloc['status']}`; diretório presente={str(reloc['present']).lower()}, RVA `0x{reloc['rva']:x}`, tamanho `{reloc['size']}`, COFF flag stripped={str(reloc['stripped_flag']).lower()}. A presença do diretório não valida nem aplica as entradas.",
                f"- Diretório TLS nos cabeçalhos: presente={str(tls['present']).lower()}, RVA `0x{tls['rva']:x}`, tamanho `{tls['size']}`.",
                "",
                "| Seção | RVA | Virtual bytes | File offset | Raw bytes | R | W | X |",
                "|---|---:|---:|---:|---:|:---:|:---:|:---:|",
            ]
        )
        for section in headers["sections"]:
            perms = section["permissions"]
            lines.append(
                f"| {section['name']} | `0x{section['virtual_address']:x}` | {section['virtual_size']} | "
                f"`0x{section['file_offset']:x}` | {section['raw_size']} | "
                f"{'✓' if perms['read'] else '—'} | {'✓' if perms['write'] else '—'} | {'✓' if perms['execute'] else '—'} |"
            )
        lines.append("")

    lines.extend(["## Imports estáticos e dependências", ""])
    lines.append("Os nomes abaixo são declarações nas tabelas PE. Eles não demonstram execução nem chamadas alcançáveis.")
    lines.append("")
    for item in report["binaries"]:
        imports = item.get("imports", {})
        lines.extend([f"### {item['file']}", ""])
        if imports.get("status") != "complete":
            lines.append(f"- Imports: `{imports.get('status')}`; motivo: `{imports.get('error_code', imports.get('reason', 'cobertura incompleta'))}`.")
            lines.append("")
            continue
        coverage = imports["coverage"]
        lines.append(
            f"- Tabela normal: {coverage['normal_modules']} DLLs, {coverage['normal_functions']} funções; "
            f"{coverage['named_functions']} por nome e {coverage['ordinal_functions']} por ordinal."
        )
        lines.append(
            f"- Tabela adiada: {coverage['delay_modules']} DLLs e {coverage['delay_functions']} funções; "
            f"cobertura REA `{coverage['status']}`, problemas `{coverage['issue_count']}`."
        )
        lines.append("")
        lines.append("| Grupo funcional | Imports | Módulos declarados | Exemplos |")
        lines.append("|---|---:|---|---|")
        for key, category in imports["dependency_categories"].items():
            examples = ", ".join(f"`{example['import']}`" for example in category["examples"][:4]) or "—"
            modules = ", ".join(f"`{module}`" for module in category["modules"]) or "—"
            lines.append(f"| {category['label']} | {category['import_count']} | {modules} | {examples} |")
        lines.append("")
        lines.append("DLLs e funções completas por nome/ordinal estão no JSON sanitizado; a captura REA completa permanece em `diagnostics/raw/`.")
        lines.append("")

    lines.extend(["## TLS e configuração de carregamento — REA", ""])
    lines.append("| Executável | TLS | Callbacks encontrados | Load config | SafeSEH count | Evidence IDs |")
    lines.append("|---|---|---:|---|---:|---|")
    for item in report["binaries"]:
        loader = item.get("loader", {})
        if loader.get("status") != "complete":
            lines.append(f"| {item['file']} | `{loader.get('status')}` | — | — | — | — |")
            continue
        tls = loader["tls"]
        config = loader["load_configuration"]
        lines.append(
            f"| {item['file']} | {'presente' if tls['present'] else 'ausente'} | {tls['callback_count']} | "
            f"{'presente' if config['present'] else 'ausente'} | "
            f"{config['safe_seh_handler_count'] if config['safe_seh_handler_count'] is not None else '—'} | "
            f"`{loader['evidence_id']}` |"
        )
    lines.append("")
    lines.append("TLS/load-config descrevem estruturas estáticas; não provam que callbacks executem ou que mitigações sejam aplicadas pelo loader.")

    lines.extend(["", "## Comparação com o laboratório", "", "| Capacidade | Evidência estática | Laboratório atual | Lacuna |", "|---|---|---|---|"])
    for row in report["lab_comparison"]:
        lines.append(f"| {row['capability']} | {row['observed_target_declarations']} | {row['lab_today']} | {row['gap']} |")

    lines.extend(["", "## Evidências REA", ""])
    for item in report["binaries"]:
        lines.append(f"- **{item['file']}** — SHA-256 `{item['identity'].get('sha256') or 'indisponível'}`.")
        for field, label in (("imports", "imports"), ("loader", "TLS/load config")):
            evidence_id = item.get(field, {}).get("evidence_id")
            if evidence_id:
                lines.append(f"  - {label}: `{evidence_id}`.")
    lines.extend(["", "## Limitações", ""])
    lines.extend(f"- {text}" for text in report["limitations"])
    for item in report["binaries"]:
        for limitation in item.get("limitations", []):
            lines.append(f"- {item['file']}: {limitation}")
        for group in (item.get("imports", {}), item.get("loader", {})):
            lines.extend(f"- {item['file']}: REA — {limitation}" for limitation in group.get("limitations", []))
    next_step = report["next_milestone"]
    lines.extend(
        [
            "",
            "## Prioridade para o marco 3",
            "",
            f"**Prioridade:** {next_step['priority']}",
            "",
            next_step["basis"],
            "",
            f"**Experimento pequeno:** {next_step['small_experiment']}",
            "",
        ]
    )
    return "\n".join(lines)


def _resolve_executable(value: str, search_path: str | None = None) -> str | None:
    candidate = Path(value).expanduser()
    if candidate.is_file():
        return str(candidate.resolve())
    return shutil.which(value, path=search_path)


def _preflight(node_value: str, rea_value: str) -> tuple[str | None, str | None, str | None, str | None, str | None]:
    node = _resolve_executable(node_value)
    if not node:
        return None, None, None, None, "node_unavailable"
    environment = os.environ.copy()
    environment["PATH"] = str(Path(node).parent) + os.pathsep + environment.get("PATH", "")
    rea = _resolve_executable(rea_value, environment["PATH"])
    if not rea:
        return node, None, None, None, "rea_cli_unavailable"
    try:
        node_result = subprocess.run([node, "--version"], capture_output=True, text=True, timeout=10, env=environment, check=False)
        rea_result = subprocess.run([rea, "--version"], capture_output=True, text=True, timeout=15, env=environment, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return node, rea, None, None, "toolchain_preflight_failed"
    node_version = node_result.stdout.strip().removeprefix("v") if node_result.returncode == 0 else None
    rea_match = re.search(r"\b(\d+\.\d+\.\d+)\b", rea_result.stdout)
    rea_version = rea_match.group(1) if rea_match and rea_result.returncode == 0 else None
    if rea_version != REA_VERSION:
        return node, rea, node_version, rea_version, "rea_version_mismatch"
    if node_result.returncode != 0 or not node_version:
        return node, rea, node_version, rea_version, "node_version_unavailable"
    return node, rea, node_version, rea_version, None


def _rea_runner(rea_executable: str, node_executable: str) -> Callable[[str, Path], Any]:
    environment = os.environ.copy()
    environment["PATH"] = str(Path(node_executable).parent) + os.pathsep + environment.get("PATH", "")

    def run(operation: str, path: Path) -> Any:
        command = REA_COMMANDS[operation]
        try:
            completed = subprocess.run(
                [rea_executable, command, str(path), "--format", "json", "--full-output"],
                capture_output=True,
                text=True,
                timeout=180,
                env=environment,
                check=False,
            )
        except FileNotFoundError as exc:
            raise ToolInvocationError("rea_cli_unavailable") from exc
        except subprocess.TimeoutExpired as exc:
            raise ToolInvocationError("rea_query_timeout") from exc
        raw: Any
        try:
            raw = json.loads(completed.stdout)
        except json.JSONDecodeError:
            raw = {"exit_code": completed.returncode, "stdout": completed.stdout, "stderr": completed.stderr}
            raise ToolInvocationError("invalid_json", raw)
        if completed.returncode != 0 or raw.get("ok") is False:
            raise ToolInvocationError("tool_failed", raw)
        return raw

    return run


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Gera um mapa estático sanitizado dos executáveis PE do The Sims 3.")
    parser.add_argument("--app", required=True, help="Caminho local para o pacote .app; nenhum binário será executado.")
    parser.add_argument("--rea-cli", default="rea", help="Executável rea local (padrão: rea no PATH).")
    parser.add_argument("--node", default="node", help="Executável Node.js usado pelo CLI REA (padrão: node no PATH).")
    parser.add_argument("--json-output", default=str(ROOT / "docs/marco-2-mapa-estatico.json"))
    parser.add_argument("--markdown-output", default=str(ROOT / "docs/marco-2-mapa-estatico.md"))
    parser.add_argument("--raw-dir", default=str(ROOT / "diagnostics/raw"))
    args = parser.parse_args(argv)

    node, rea, node_version, rea_version, preflight_error = _preflight(args.node, args.rea_cli)
    if preflight_error:
        def unavailable_runner(operation: str, path: Path) -> Any:
            raise ToolInvocationError(preflight_error)
        runner = unavailable_runner
        rea_version = None
    else:
        runner = _rea_runner(rea or "rea", node or "node")

    report = collect_app(
        args.app,
        runner,
        args.raw_dir,
        rea_version=rea_version,
        node_version=node_version,
    )
    if preflight_error:
        report["toolchain"]["rea_status"] = preflight_error
        report["status"] = "partial"
    json_path = Path(args.json_output).expanduser()
    markdown_path = Path(args.markdown_output).expanduser()
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    print(json.dumps({"status": report["status"], "json": json_path.name, "markdown": markdown_path.name, "rea_version": rea_version, "node_version": node_version}, ensure_ascii=False))
    return 0 if report["status"] == "complete" else 2


if __name__ == "__main__":
    raise SystemExit(main())
