# SPDX-License-Identifier: AGPL-3.0-or-later
from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import httpx

from pkgsentry.adapter import Finding
from pkgsentry.logging_setup import get_logger

log = get_logger("detonate.client")

_DETONATE_TIMEOUT = 180.0
_HEALTH_TIMEOUT = 5.0


@dataclass
class PhaseResult:
    exit_code: int
    duration_ms: int
    timed_out: bool


@dataclass
class DetonationResult:
    detonation_id: str
    status: str
    install_phase: Optional[PhaseResult]
    import_phase: Optional[PhaseResult]
    findings_json: list[dict]
    trace_events_json: list[dict]
    total_trace_events: int
    filtered_trace_events: int

    def to_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for f in self.findings_json:
            out.append(Finding(
                rule_id=f["rule_id"],
                category=f.get("category", "dynamic"),
                severity=f.get("severity", "medium"),
                confidence=f.get("confidence", "medium"),
                file=f.get("file", ""),
                line=f.get("line"),
                evidence=f.get("evidence", ""),
            ))
        return out


def _default_socket() -> Optional[str]:
    return os.environ.get("DETONATION_SOCKET")


def _default_url() -> Optional[str]:
    return os.environ.get("DETONATION_URL")


class DetonationClient:
    def __init__(
        self,
        socket_path: Optional[str] = None,
        base_url: Optional[str] = None,
    ) -> None:
        self._socket = socket_path if socket_path is not None else _default_socket()
        self._url = base_url if base_url is not None else _default_url()

    def is_enabled(self) -> bool:
        return self._socket is not None or self._url is not None

    def _make_client(self) -> httpx.AsyncClient:
        if self._socket:
            transport = httpx.AsyncHTTPTransport(uds=self._socket)
            return httpx.AsyncClient(transport=transport, base_url="http://detonation")
        return httpx.AsyncClient(base_url=self._url or "")

    async def health(self) -> bool:
        if not self.is_enabled():
            return False
        try:
            async with self._make_client() as client:
                resp = await client.get("/api/v1/health", timeout=_HEALTH_TIMEOUT)
                return resp.status_code == 200
        except Exception:
            return False

    def _make_sync_client(self) -> httpx.Client:
        if self._socket:
            transport = httpx.HTTPTransport(uds=self._socket)
            return httpx.Client(transport=transport, base_url="http://detonation")
        return httpx.Client(base_url=self._url or "")

    def detonate_sync(
        self,
        *,
        ecosystem: str,
        name: str,
        version: str,
        archive_path: str,
        archive_kind: str,
        timeout_seconds: int = 120,
    ) -> Optional[DetonationResult]:
        if not self.is_enabled():
            return None
        payload = {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "archive_path": archive_path,
            "archive_kind": archive_kind,
            "timeout_seconds": timeout_seconds,
        }
        try:
            with self._make_sync_client() as client:
                resp = client.post(
                    "/api/v1/detonate",
                    json=payload,
                    timeout=_DETONATE_TIMEOUT,
                )
                if resp.status_code != 200:
                    log.warning("detonation_http_error", status=resp.status_code, name=name, version=version)
                    return None
                data = resp.json()
        except Exception as e:
            log.warning("detonation_request_failed", name=name, version=version, error=str(e))
            return None
        return self._parse_result(data, name, version)

    async def detonate(
        self,
        *,
        ecosystem: str,
        name: str,
        version: str,
        archive_path: str,
        archive_kind: str,
        timeout_seconds: int = 120,
    ) -> Optional[DetonationResult]:
        if not self.is_enabled():
            return None
        payload = {
            "ecosystem": ecosystem,
            "name": name,
            "version": version,
            "archive_path": archive_path,
            "archive_kind": archive_kind,
            "timeout_seconds": timeout_seconds,
        }
        try:
            async with self._make_client() as client:
                resp = await client.post(
                    "/api/v1/detonate",
                    json=payload,
                    timeout=_DETONATE_TIMEOUT,
                )
                if resp.status_code != 200:
                    log.warning("detonation_http_error", status=resp.status_code, name=name, version=version)
                    return None
                data = resp.json()
        except Exception as e:
            log.warning("detonation_request_failed", name=name, version=version, error=str(e))
            return None
        return self._parse_result(data, name, version)

    def _parse_result(self, data: dict, name: str, version: str) -> DetonationResult:
        install = None
        if data.get("install_phase"):
            ip = data["install_phase"]
            install = PhaseResult(exit_code=ip.get("exit_code", -1), duration_ms=ip.get("duration_ms", 0), timed_out=ip.get("timed_out", False))
        imp = None
        if data.get("import_phase"):
            ipd = data["import_phase"]
            imp = PhaseResult(exit_code=ipd.get("exit_code", -1), duration_ms=ipd.get("duration_ms", 0), timed_out=ipd.get("timed_out", False))

        trace_events = data.get("trace_events") or []
        return DetonationResult(
            detonation_id=data.get("id", ""),
            status=data.get("status", "error"),
            install_phase=install,
            import_phase=imp,
            findings_json=data.get("findings", []),
            trace_events_json=trace_events,
            total_trace_events=data.get("trace_summary", {}).get("total_events", 0),
            filtered_trace_events=len(trace_events),
        )


_client: Optional[DetonationClient] = None


def get_client() -> DetonationClient:
    global _client
    if _client is None:
        _client = DetonationClient()
    return _client
