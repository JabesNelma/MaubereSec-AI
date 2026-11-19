"""Unit tests for scanner output parsers and deduplication."""

import json

from mauberesec.tools.source_audit.adapters import (
    dedup_findings,
    parse_gitleaks,
    parse_osv,
    parse_semgrep,
)

SEMGREP_SAMPLE = json.dumps(
    {
        "results": [
            {
                "check_id": "python.sqlalchemy.security.audit",
                "path": "app/db.py",
                "start": {"line": 42},
                "extra": {
                    "severity": "ERROR",
                    "message": "Unsafe SQL query built from user input.",
                },
            },
            {
                "check_id": "generic.weak-hash",
                "path": "app/hash.py",
                "start": {"line": 7},
                "extra": {"severity": "WARNING", "message": "MD5 used."},
            },
        ]
    }
)

GITLEAKS_SAMPLE = json.dumps(
    [
        {
            "RuleID": "openai-api-key",
            "File": "config/prod.py",
            "StartLine": 12,
            "Secret": "sk-supersecretvalue123",
            "Fingerprint": "config/prod.py:openai-api-key:12",
        }
    ]
)

OSV_SAMPLE = json.dumps(
    {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.19.0"},
                        "advisories": [{"id": "GHSA-x9j5", "summary": "CVE in urllib3"}],
                    }
                ],
            }
        ]
    }
)


def test_parse_semgrep():
    findings = parse_semgrep(SEMGREP_SAMPLE)
    assert len(findings) == 2
    f = findings[0]
    assert f.tool_name == "static.semgrep"
    assert f.severity.value == "high"
    assert "app/db.py:42" in f.evidence
    assert "Unsafe SQL" in f.evidence


def test_parse_gitleaks_never_keeps_secret():
    findings = parse_gitleaks(GITLEAKS_SAMPLE)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity.value == "high"
    assert "sk-supersecretvalue123" not in f.evidence
    assert "sk-supersecretvalue123" not in f.model_dump_json()
    assert "config/prod.py:12" in f.evidence


def test_parse_osv():
    findings = parse_osv(OSV_SAMPLE)
    assert len(findings) == 1
    assert "requests 2.19.0" in findings[0].title
    assert "GHSA-x9j5" in findings[0].evidence


def test_parse_empty_outputs():
    assert parse_semgrep("") == []
    assert parse_gitleaks("") == []
    assert parse_osv("") == []


def test_dedup_findings():
    base = parse_semgrep(SEMGREP_SAMPLE)
    dup = parse_semgrep(SEMGREP_SAMPLE)
    combined = [*base, *dup, base[0]]
    result = dedup_findings(combined)
    assert len(result) == len(base)
    keys = [(f.tool_name, f.title) for f in result]
    assert len(set(keys)) == len(keys)
