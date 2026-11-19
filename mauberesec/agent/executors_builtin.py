"""Built-in executors wiring registered tools to real v0.4-v0.6 capabilities."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import httpx

from ..docker.client import DockerClient
from ..scope.urlcheck import (
    DestinationError,
    normalize_url,
    validate_lab_destination,
    validate_live_destination,
)
from ..tools.apk.analysis import ApkAnalyzerAdapter
from ..tools.source_audit.adapters import ScannerUnavailable, default_adapters
from ..tools.website.passive import Budget, PassiveHttpChecker
from .executor import Executor, ExecutorRegistry, StepResult


def _httpx_error_detail(exc: Exception) -> str:
    return f"cannot reach target: {exc}"[:300]


def make_http_executor(lab_subnets: list[str]) -> Executor:
    def executor(assessment: Any, step: Any) -> StepResult:
        try:
            normalized = normalize_url(step.target)
        except Exception as exc:  # UrlError
            return StepResult(detail=f"invalid URL: {exc}")
        if assessment.mode.value == "local_lab":
            validator = lambda u: validate_lab_destination(u, lab_subnets)  # noqa: E731
        else:
            validator = validate_live_destination
        checker = PassiveHttpChecker(
            budget=Budget(min_interval_seconds=0.5),
            validate_destination=validator,
        )
        try:
            evidence, findings = checker.check(str(normalized))
        except httpx.HTTPError as exc:
            return StepResult(detail=_httpx_error_detail(exc))
        except DestinationError as exc:
            return StepResult(detail=f"destination rejected: {exc}")
        finally:
            checker.close()
        return StepResult(detail=evidence.summary()[:900], findings=findings)

    return executor


def make_source_executors(client: DockerClient) -> dict[str, Executor]:
    executors: dict[str, Executor] = {}
    for adapter in default_adapters(client):

        def make_executor(adapter: Any = adapter) -> Executor:
            def executor(assessment: Any, step: Any) -> StepResult:
                try:
                    findings = adapter.run(step.target)
                except ScannerUnavailable as exc:
                    return StepResult(detail=f"scanner unavailable: {exc}")
                return StepResult(
                    detail=f"{adapter.name}: {len(findings)} findings",
                    findings=findings,
                )

            return executor

        executors[adapter.name] = make_executor()
    return executors


def make_apk_executor(client: DockerClient) -> Executor:
    def executor(assessment: Any, step: Any) -> StepResult:
        apk_path = Path(step.target)
        digest = hashlib.sha256()
        with open(apk_path, "rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
        try:
            _report, findings = ApkAnalyzerAdapter(client).run(step.target, digest.hexdigest())
        except ScannerUnavailable as exc:
            return StepResult(detail=f"analyzer unavailable: {exc}")
        return StepResult(detail=f"apk.static_review: {len(findings)} findings", findings=findings)

    return executor


def default_executor_registry(
    client: DockerClient | None, lab_subnets: list[str] | None = None
) -> ExecutorRegistry:
    registry = ExecutorRegistry()
    registry.register("passive.http_headers", make_http_executor(lab_subnets or []))
    if client is not None and client.available:
        for name, executor in make_source_executors(client).items():
            registry.register(name, executor)
        registry.register("apk.static_review", make_apk_executor(client))
    # lab.recon / lab.controlled_validation have no executor yet (v0.3+ scope):
    # attempting them fails safely with UnknownExecutorError and an audit event.
    return registry
