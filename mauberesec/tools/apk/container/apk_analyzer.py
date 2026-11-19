#!/usr/bin/env python3
"""APK static analyzer — runs INSIDE a restricted container (v0.6).

Self-contained (stdlib only). The APK is mounted read-only at a path given
as argv[1]; output is a JSON document on stdout. Rules:

- The APK is data only: nothing from it is executed or imported.
- ZIP limits (entries, per-entry size, total uncompressed, compression
  ratio) prevent archive bombs; violations abort with a JSON error.
- Embedded secret indicators never include the matched value — only the
  rule name, artifact path, and offset are reported (safe redaction).
"""

from __future__ import annotations

import json
import re
import sys
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
from axml import AxmlError, parse_axml

MAX_ENTRIES = 20_000
MAX_TOTAL_UNCOMPRESSED = 2 * 1024 * 1024 * 1024
MAX_ENTRY_UNCOMPRESSED = 200 * 1024 * 1024
MAX_RATIO = 200
RATIO_MIN_UNCOMPRESSED = 1024 * 1024
MAX_SCAN_BYTES_PER_ENTRY = 8 * 1024 * 1024
MAX_DEX_STRINGS = 200_000

DANGEROUS_PERMISSIONS = {
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_PHONE_STATE",
    "android.permission.RECORD_VIDEO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.BODY_SENSORS",
    "android.permission.GET_ACCOUNTS",
}

# Fixed indicator patterns (rule_name, compiled regex). Matched values are
# never reported.
SECRET_INDICATORS: list[tuple[str, re.Pattern[str]]] = [
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\b")),
    (
        "password-assignment",
        re.compile(r"(?i)\b(password|passwd|api[_-]?key|secret)\b\s*[:=]\s*['\"]?[^\s'\"]{8,}"),
    ),
    (
        "private-key-marker",
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    ),
]

TEXT_SUFFIXES = {
    ".json",
    ".xml",
    ".properties",
    ".txt",
    ".cfg",
    ".conf",
    ".ini",
    ".yml",
    ".yaml",
    ".js",
    ".ts",
    ".py",
    ".sh",
    ".md",
    ".html",
    ".csv",
}


class ApkAnalysisError(Exception):
    """Analysis could not proceed (malformed or bomb-like APK)."""


# --- zip safety -----------------------------------------------------------------


def open_safe_zip(path: str) -> zipfile.ZipFile:
    try:
        zf = zipfile.ZipFile(path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise ApkAnalysisError(f"Malformed APK/ZIP: {exc}") from exc
    infos = zf.infolist()
    if len(infos) > MAX_ENTRIES:
        raise ApkAnalysisError(f"Too many entries ({len(infos)} > {MAX_ENTRIES}).")
    total = 0
    for info in infos:
        if info.file_size > MAX_ENTRY_UNCOMPRESSED:
            raise ApkAnalysisError(
                f"Entry '{info.filename}' exceeds per-entry cap "
                f"({info.file_size} > {MAX_ENTRY_UNCOMPRESSED})."
            )
        if (
            info.compress_size > 0
            and info.file_size > RATIO_MIN_UNCOMPRESSED
            and info.file_size / info.compress_size > MAX_RATIO
        ):
            raise ApkAnalysisError(
                f"Entry '{info.filename}' has a suspicious compression ratio "
                f"({info.file_size}/{info.compress_size}); possible zip bomb."
            )
        total += info.file_size
        if total > MAX_TOTAL_UNCOMPRESSED:
            raise ApkAnalysisError("Total uncompressed size exceeds the cap.")
    return zf


# --- manifest analysis ------------------------------------------------------------


def _is_true(value: Any) -> bool:
    return value is True or value == "true"


def manifest_findings(manifest: Any) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    app_elems = manifest.find_all("application")
    app = app_elems[0] if app_elems else None

    if app is not None:
        if _is_true(app.get_attr("debuggable")):
            findings.append(
                {
                    "rule": "manifest.debuggable",
                    "severity": "high",
                    "confidence": "high",
                    "artifact": "AndroidManifest.xml",
                    "title": "Application is debuggable (android:debuggable=true)",
                    "evidence": "application@android:debuggable=true in AndroidManifest.xml",
                    "remediation": "Set android:debuggable=false (or omit) for release builds.",
                }
            )
        if _is_true(app.get_attr("usesCleartextTraffic")):
            findings.append(
                {
                    "rule": "manifest.cleartext",
                    "severity": "medium",
                    "confidence": "high",
                    "artifact": "AndroidManifest.xml",
                    "title": "Cleartext traffic globally permitted",
                    "evidence": "application@android:usesCleartextTraffic=true",
                    "remediation": "Disable cleartext traffic or use a network security config.",
                }
            )
        if _is_true(app.get_attr("allowBackup")):
            findings.append(
                {
                    "rule": "manifest.allow_backup",
                    "severity": "low",
                    "confidence": "medium",
                    "artifact": "AndroidManifest.xml",
                    "title": "Full-data backup enabled (android:allowBackup=true)",
                    "evidence": "application@android:allowBackup=true",
                    "remediation": "Disable backups or exclude sensitive data via rules.",
                }
            )

    for perm in manifest.find_all("uses-permission"):
        name = str(perm.get_attr("name") or "")
        if name in DANGEROUS_PERMISSIONS:
            findings.append(
                {
                    "rule": "manifest.dangerous_permission",
                    "severity": "medium",
                    "confidence": "high",
                    "artifact": "AndroidManifest.xml",
                    "title": f"Dangerous permission requested: {name}",
                    "evidence": f"uses-permission@android:name={name}",
                    "remediation": "Justify the permission or use a narrower alternative.",
                }
            )

    component_tags = ("activity", "activity-alias", "service", "receiver", "provider")
    for tag in component_tags:
        for comp in manifest.find_all(tag):
            if not _is_true(comp.get_attr("exported")):
                continue
            protected = bool(comp.get_attr("permission"))
            severity = "low" if protected else ("high" if tag == "provider" else "medium")
            comp_name = str(comp.get_attr("name") or "?")
            findings.append(
                {
                    "rule": "manifest.exported_component",
                    "severity": severity,
                    "confidence": "medium" if protected else "high",
                    "artifact": "AndroidManifest.xml",
                    "title": (
                        f"Exported {tag}: {comp_name}"
                        + (" (permission-protected)" if protected else " (unprotected)")
                    ),
                    "evidence": f"{tag}@android:exported=true name={comp_name}",
                    "remediation": "Set exported=false or protect with a permission.",
                }
            )

    for sdk in manifest.find_all("uses-sdk"):
        target = sdk.get_attr("targetSdkVersion")
        if isinstance(target, int) and target < 24:
            findings.append(
                {
                    "rule": "manifest.outdated_target_sdk",
                    "severity": "low",
                    "confidence": "high",
                    "artifact": "AndroidManifest.xml",
                    "title": f"Outdated targetSdkVersion: {target}",
                    "evidence": f"uses-sdk@android:targetSdkVersion={target}",
                    "remediation": "Target a recent Android API level.",
                }
            )
    return findings


def manifest_summary(manifest: Any) -> dict[str, Any]:
    app = next(iter(manifest.find_all("application") or []), None)
    return {
        "package": manifest.get_attr("package"),
        "versionName": manifest.get_attr("versionName"),
        "versionCode": manifest.get_attr("versionCode"),
        "debuggable": _is_true(app.get_attr("debuggable")) if app else None,
        "permissions": [str(p.get_attr("name")) for p in manifest.find_all("uses-permission")],
        "exported_components": sum(
            1
            for tag in ("activity", "activity-alias", "service", "receiver", "provider")
            for c in manifest.find_all(tag)
            if _is_true(c.get_attr("exported"))
        ),
    }


# --- network security config ---------------------------------------------------------


def nsc_findings(zf: zipfile.ZipFile, app: Any) -> list[dict[str, Any]]:
    if app is None:
        return []
    ref = app.get_attr("networkSecurityConfig")
    if not isinstance(ref, str) or not ref.startswith("@"):
        return []
    # Resource ID -> res/xml file: brute-force scan res/xml/*.xml (small set).
    findings: list[dict[str, Any]] = []
    for info in zf.infolist():
        name = info.filename
        if not name.startswith("res/xml/") or not name.endswith(".xml"):
            continue
        try:
            root = parse_axml(zf.read(info))
        except (AxmlError, OSError, zipfile.BadZipFile):
            continue
        for elem in [root, *root.find_all("base-config"), *root.find_all("domain-config")]:
            if _is_true(elem.get_attr("cleartextTrafficPermitted")):
                findings.append(
                    {
                        "rule": "nsc.cleartext_permitted",
                        "severity": "medium",
                        "confidence": "high",
                        "artifact": name,
                        "title": f"Network security config permits cleartext ({elem['name']})",
                        "evidence": f"{name}: {elem['name']}@cleartextTrafficPermitted=true",
                        "remediation": "Set cleartextTrafficPermitted=false.",
                    }
                )
    return findings


# --- secret indicators -------------------------------------------------------------------


def _iter_candidate_entries(zf: zipfile.ZipFile) -> Iterator[zipfile.ZipInfo]:
    for info in zf.infolist():
        name = info.filename
        base = name.rsplit("/", 1)[-1]
        suffix = ("." + base.rsplit(".", 1)[-1].lower()) if "." in base else ""
        if (
            name.startswith(("assets/", "res/raw/"))
            or suffix in TEXT_SUFFIXES
            or re.fullmatch(r"classes\d*\.dex", base)
        ):
            yield info


def _printable_runs(data: bytes, min_len: int = 6) -> Iterator[tuple[int, str]]:
    pattern = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for match in pattern.finditer(data):
        yield match.start(), match.group().decode("ascii", "replace")


def secret_findings(zf: zipfile.ZipFile) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for info in _iter_candidate_entries(zf):
        if info.file_size > MAX_SCAN_BYTES_PER_ENTRY:
            continue
        try:
            data = zf.read(info)
        except (OSError, zipfile.BadZipFile, RuntimeError):
            continue
        data = data[:MAX_SCAN_BYTES_PER_ENTRY]
        if info.filename.endswith(".dex"):
            candidates = _printable_runs(data, 6)
        else:
            candidates = _printable_runs(data, 4)
        for offset, text in candidates:
            if len(text) > 4096:
                text = text[:4096]
            for rule, pattern in SECRET_INDICATORS:
                match = pattern.search(text)
                if match:
                    findings.append(
                        {
                            "rule": f"secret.{rule}",
                            "severity": "high",
                            "confidence": "medium",
                            "artifact": f"{info.filename}@{offset}",
                            "title": f"Possible embedded secret: {rule}",
                            "evidence": (
                                f"Indicator '{rule}' found in {info.filename} "
                                f"at offset {offset + match.start()}; value withheld."
                            ),
                            "remediation": "Remove the secret and rotate the credential.",
                        }
                    )
                    if len(findings) > 500:
                        return findings
    return findings


# --- entry point ---------------------------------------------------------------------------


def analyze_apk(apk_path: str, sha256: str = "") -> dict[str, Any]:
    zf = open_safe_zip(apk_path)
    with zf:
        names = set(zf.namelist())
        if "AndroidManifest.xml" not in names:
            raise ApkAnalysisError("AndroidManifest.xml missing — not an APK.")
        try:
            manifest = parse_axml(zf.read("AndroidManifest.xml"))
        except (AxmlError, zipfile.BadZipFile) as exc:
            raise ApkAnalysisError(f"Malformed AndroidManifest.xml: {exc}") from exc

        app = next(iter(manifest.find_all("application") or []), None)
        findings = [
            *manifest_findings(manifest),
            *nsc_findings(zf, app),
            *secret_findings(zf),
        ]
        return {
            "apk": {"path": Path(apk_path).name, "sha256": sha256},
            "manifest": manifest_summary(manifest),
            "findings": findings,
        }


def main() -> int:
    if len(sys.argv) < 2:
        print(json.dumps({"error": "usage: apk_analyzer.py <apk> [sha256]"}))
        return 2
    try:
        result = analyze_apk(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
    except ApkAnalysisError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
