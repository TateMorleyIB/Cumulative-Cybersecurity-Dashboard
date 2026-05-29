import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
import urllib3
from requests.exceptions import SSLError
from urllib3.exceptions import InsecureRequestWarning

from app.config import (
    ABNORMAL_ALLOW_INSECURE_SSL_FALLBACK,
    ABNORMAL_API_KEY,
    ABNORMAL_BASE_URL,
    ABNORMAL_CA_BUNDLE,
    ABNORMAL_VERIFY_SSL,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]
CACHE_FILE = PROJECT_ROOT / "data" / "raw" / "abnormal" / "abnormal_snapshot.json"
CACHE_TTL = timedelta(minutes=15)
DEFAULT_BASE_URL = "https://api.abnormalplatform.com"
ABUSE_REASON_LABELS = {
    "COULD_NOT_EXTRACT": "Needs manual review",
    "INVALID_SUBMISSION": "Invalid submission",
    "INVALID_MAILBOX": "Invalid mailbox",
    "PHISHING_SIMULATION": "Phishing simulation",
}
DEFAULT_LIMITS = {
    "threats": 25,
    "cases": 25,
    "iocs": 25,
    "users": 25,
}

HIGH_LEVEL_ENDPOINTS = {
    "dashboard_summary": ("GET", "/v1/aggregations/dashboard_summary"),
    "attack_stopped": ("GET", "/v1/aggregations/attack_stopped"),
    "trending_attacks": ("GET", "/v1/aggregations/trending_attacks"),
    "attack_vector_breakdown": ("GET", "/v1/aggregations/attack_vector_breakdown"),
    "attack_strategy_breakdown": ("GET", "/v1/aggregations/attack_strategy_breakdown"),
    "sender_impersonation_breakdown": (
        "GET",
        "/v1/aggregations/sender_impersonation_breakdown",
    ),
    "attacker_origin": ("GET", "/v1/aggregations/attacker_origin"),
    "most_impersonated_employee": (
        "GET",
        "/v1/aggregations/most_impersonated_employee",
    ),
    "most_impersonated_vendor": ("GET", "/v1/aggregations/most_impersonated_vendor"),
    "abuse_not_analyzed": ("GET", "/v1/abuse_mailbox/not_analyzed"),
    "recipient_employees": ("GET", "/v1/aggregations/recipient_employees"),
    "threats": ("GET", "/v1/threats"),
    "cases": ("GET", "/v1/cases"),
    "iocs": ("GET", "/v1/iocs"),
}

ACCESSIBLE_ENDPOINTS = {
    "threat_detail": ("GET", "/v1/threats/{id}"),
    "threat_messages": ("GET", "/v1/threat-messages"),
    "threat_intel": ("GET", "/v1/threat-intel"),
    "most_impersonated_employee_non_vip": (
        "GET",
        "/v1/aggregations/most_impersonated_employee_non_vip",
    ),
    "detection360_reports": ("GET", "/v1/detection360/reports"),
    "soar_tokens": ("GET", "/v1/soar/tokens"),
    "security_settings": ("GET", "/v1/security-settings"),
    "abuse_not_analyzed": ("GET", "/v1/abuse_mailbox/not_analyzed"),
    "recipient_employees": ("GET", "/v1/aggregations/recipient_employees"),
    "posture_timeline": ("GET", "/v1/spm-v2/postures/{id}/timeline"),
    "message_download": ("GET", "/v1/messages/{id}/download"),
    "attack_vector_breakdown": ("GET", "/v1/aggregations/attack_vector_breakdown"),
    "recipient_employees_non_vip": (
        "GET",
        "/v1/aggregations/recipient_employees_non_vip",
    ),
    "case_analysis": ("GET", "/v1/cases/{id}/analysis"),
    "clicked_events": ("GET", "/v1/url-rewrite/clicked-events"),
    "attacker_origin": ("GET", "/v1/aggregations/attacker_origin"),
    "dashboard_summary": ("GET", "/v1/aggregations/dashboard_summary"),
    "vendors": ("GET", "/v1/vendors"),
    "vendor_details": ("GET", "/v1/vendors/{id}/details"),
    "iocs": ("GET", "/v1/iocs"),
    "users": ("GET", "/v1/users"),
    "threats_export_csv": ("GET", "/v1/threats_export/csv"),
    "most_impersonated_employee_vip": (
        "GET",
        "/v1/aggregations/most_impersonated_employee_vip",
    ),
    "case_action": ("GET", "/v1/cases/{id}/actions/{action_id}"),
    "posture_catalog": ("GET", "/v1/spm-v2/posture-catalog"),
    "postures_query": ("POST", "/v1/spm-v2/postures/query"),
    "activity_status": ("GET", "/v1/search/activities/{activity_log_id}/status"),
    "ioc_detail": ("GET", "/v1/iocs/{id}"),
    "threats": ("GET", "/v1/threats"),
    "attack_strategy_breakdown": ("GET", "/v1/aggregations/attack_strategy_breakdown"),
    "recipient_employees_vip": ("GET", "/v1/aggregations/recipient_employees_vip"),
    "message_attachment": ("GET", "/v1/messages/{id}/attachment/{name}"),
    "threat_message_detail": ("GET", "/v1/threats/messages/{id}"),
    "case_detail": ("GET", "/v1/cases/{id}"),
    "employee": ("GET", "/v1/employee/{id}"),
    "employee_identity": ("GET", "/v1/employee/{id}/identity"),
    "spm_summary": ("GET", "/v1/spm-v2/reports/summary"),
    "threat_action": ("GET", "/v1/threats/{id}/actions/{action_id}"),
    "employee_logins": ("GET", "/v1/employee/{id}/logins"),
    "threat_attachments": ("GET", "/v1/threats/{id}/attachments"),
    "vendor_cases": ("GET", "/v1/vendor-cases"),
    "search": ("POST", "/v1/search"),
    "sender_impersonation_breakdown": (
        "GET",
        "/v1/aggregations/sender_impersonation_breakdown",
    ),
    "attack_frequency": ("GET", "/v1/aggregations/attack_frequency"),
    "vendor_activity": ("GET", "/v1/vendors/{id}/activity"),
    "auditlogs": ("GET", "/v1/auditlogs"),
    "search_activities": ("GET", "/v1/search/activities"),
    "abusecampaigns": ("GET", "/v1/abusecampaigns"),
    "message_attachment_download": (
        "GET",
        "/v1/messages/{id}/attachment/{name}/download",
    ),
    "most_impersonated_employee": (
        "GET",
        "/v1/aggregations/most_impersonated_employee",
    ),
    "cases": ("GET", "/v1/cases"),
    "posture_detail": ("GET", "/v1/spm-v2/postures/{id}"),
    "trending_attacks": ("GET", "/v1/aggregations/trending_attacks"),
    "most_impersonated_vendor": ("GET", "/v1/aggregations/most_impersonated_vendor"),
    "vendor_case_detail": ("GET", "/v1/vendor-cases/{id}"),
    "abusecampaign_detail": ("GET", "/v1/abusecampaigns/{id}"),
    "message_remediation_history": ("GET", "/v1/messages/{id}/remediation_history"),
    "threat_links": ("GET", "/v1/threats/{id}/links"),
    "attack_stopped": ("GET", "/v1/aggregations/attack_stopped"),
    "search_attachment_download": ("GET", "/v1/search/messages/attachments/download"),
    "workflow_raw_json": ("GET", "/v1/spm-v2/workflow-logs/{id}/raw-json"),
    "search_message_eml": ("GET", "/v1/search/messages/{message_id}/eml"),
    "roles": ("GET", "/v1/roles"),
}


class AbnormalConnector:
    """Collects high-level Abnormal Security telemetry for the dashboard."""

    def __init__(self, cache_ttl: timedelta = CACHE_TTL):
        """
        Initialize the Abnormal API connector session and cache settings.

        Args:
            cache_ttl: Maximum age for the local snapshot cache before the connector refreshes API data.

        Raises:
            ValueError: Raised when ``ABNORMAL_API_KEY`` is not configured.
        """
        if not ABNORMAL_API_KEY:
            raise ValueError("ABNORMAL_API_KEY is missing from .env")

        self.base_url = (ABNORMAL_BASE_URL or DEFAULT_BASE_URL).rstrip("/")
        self.cache_ttl = cache_ttl
        self.verify: bool | str = self._resolve_verify_setting()
        self.allow_insecure_ssl_fallback = self._env_flag(
            ABNORMAL_ALLOW_INSECURE_SSL_FALLBACK, default=True
        )
        self.ssl_warnings: list[str] = []
        if self.verify is False:
            urllib3.disable_warnings(InsecureRequestWarning)
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Authorization": f"Bearer {ABNORMAL_API_KEY}",
            }
        )

    def _request(self, method: str, path: str, **kwargs) -> Any:
        """
        Send an Abnormal API request and decode the JSON response.

        Args:
            method: HTTP method such as ``GET`` or ``POST``.
            path: Upstream path relative to the configured Abnormal base URL.
            **kwargs: Additional ``requests`` options such as params or JSON payload.

        Returns:
            Any: Decoded JSON payload, or an empty dictionary when the response body is empty.

        Raises:
            requests.HTTPError: Propagated when the upstream API returns an error status.
        """
        response = self._send_request(method, path, **kwargs)
        response.raise_for_status()
        if not response.content:
            return {}
        content_type = response.headers.get("content-type", "")
        if "json" not in content_type:
            return {"content": response.text}
        return response.json()

    def _send_request(self, method: str, path: str, **kwargs) -> requests.Response:
        """
        Send a prepared HTTP request with optional TLS fallback behavior.

        Args:
            method: HTTP method for the Abnormal request.
            path: Upstream path relative to the connector base URL.
            **kwargs: Additional ``requests`` options forwarded to the session.

        Returns:
            requests.Response: Raw response object after a successful request.

        Raises:
            SSLError: Re-raised when certificate verification fails and insecure fallback is disabled.
        """
        kwargs.setdefault("verify", self.verify)
        try:
            return self.session.request(
                method, f"{self.base_url}{path}", timeout=30, **kwargs
            )
        except SSLError:
            if not self._can_retry_without_ssl_verification(kwargs.get("verify")):
                raise

            self.verify = False
            kwargs["verify"] = False
            urllib3.disable_warnings(InsecureRequestWarning)
            warning = (
                "TLS certificate verification failed; retried Abnormal API requests "
                "with certificate verification disabled. Configure ABNORMAL_CA_BUNDLE "
                "with your corporate CA certificate or set "
                "ABNORMAL_ALLOW_INSECURE_SSL_FALLBACK=false to fail closed."
            )
            if warning not in self.ssl_warnings:
                self.ssl_warnings.append(warning)
            return self.session.request(
                method, f"{self.base_url}{path}", timeout=30, **kwargs
            )

    def _can_retry_without_ssl_verification(self, current_verify: bool | str) -> bool:
        """
        Determine whether an SSL failure may be retried without certificate verification.

        Args:
            current_verify: Current requests ``verify`` value.

        Returns:
            bool: True when policy permits a fallback retry with ``verify=False``.
        """
        return bool(self.allow_insecure_ssl_fallback and current_verify is not False)

    def _resolve_verify_setting(self) -> bool | str:
        """
        Resolve the configured certificate verification setting for Abnormal requests.

        Returns:
            bool | str: Either a boolean verification flag or a custom CA bundle path.
        """
        if ABNORMAL_CA_BUNDLE:
            return ABNORMAL_CA_BUNDLE
        return self._env_flag(ABNORMAL_VERIFY_SSL, default=True)

    @staticmethod
    def _env_flag(value: str | None, default: bool) -> bool:
        """
        Parse a boolean-like environment value.

        Args:
            value: Raw environment string, if present.
            default: Fallback value used when the string is unset.

        Returns:
            bool: Parsed boolean value.
        """
        if value is None or value == "":
            return default
        return value.strip().lower() not in {"0", "false", "no", "off"}

    def get_endpoint(
        self,
        endpoint_key: str,
        path_params: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> Any:
        """
        Call any endpoint listed in ``ACCESSIBLE_ENDPOINTS``.

        Args:
            endpoint_key: Friendly endpoint key configured in the connector map.
            params: Optional query string parameters, including path parameter replacements.
            payload: Optional JSON body for POST endpoints.

        Returns:
            Any: Decoded JSON response from the selected Abnormal endpoint.

        Raises:
            ValueError: Raised for unknown endpoints or missing path parameters.
        """
        if endpoint_key not in ACCESSIBLE_ENDPOINTS:
            raise ValueError(f"Unknown Abnormal endpoint: {endpoint_key}")
        method, path_template = ACCESSIBLE_ENDPOINTS[endpoint_key]
        path_values = dict(path_params or {})
        if params:
            path_values.update(params)
        try:
            path = path_template.format(**path_values)
        except KeyError as error:
            missing = error.args[0]
            raise ValueError(
                f"Abnormal endpoint '{endpoint_key}' requires path parameter '{missing}'"
            ) from error
        query_params = {
            key: value
            for key, value in (params or {}).items()
            if f"{{{key}}}" not in path_template
        }
        kwargs: dict[str, Any] = {}
        if query_params:
            kwargs["params"] = query_params
        if payload and method == "POST":
            kwargs["json"] = payload
        return self._request(method, path, **kwargs)

    def get_snapshot(self, use_cache: bool = True) -> dict[str, Any]:
        """
        Collect or read the multi-endpoint Abnormal snapshot.

        Args:
            use_cache: When true, use a fresh local cache if available and valid.

        Returns:
            dict[str, Any]: Snapshot containing raw endpoint payloads, normalized dashboard data, and any endpoint issues.
        """
        if use_cache:
            cached = self._read_cache()
            if cached:
                return cached

        raw: dict[str, Any] = {}
        errors: dict[str, str] = {}
        notices: dict[str, str] = {}
        for key, (method, path) in HIGH_LEVEL_ENDPOINTS.items():
            try:
                kwargs = self._default_kwargs(key)
                raw[key] = self._request(method, path, **kwargs)
            except requests.HTTPError as error:
                message = self._format_http_error(error)
                if self._is_optional_feature_unavailable(key, message):
                    notices[key] = message
                else:
                    errors[key] = message
            except Exception as error:
                errors[key] = str(error)

        snapshot = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "base_url": self.base_url,
            "raw": raw,
            "normalized": self.normalize(raw),
            "errors": errors,
            "notices": notices,
            "warnings": self.ssl_warnings,
        }
        self._write_cache(snapshot)
        return snapshot

    def _default_kwargs(self, key: str) -> dict[str, Any]:
        """
        Return default request options for a high-level Abnormal endpoint.

        Args:
            key: Endpoint key from ``HIGH_LEVEL_ENDPOINTS``.

        Returns:
            dict[str, Any]: Request keyword arguments such as default limits.
        """
        if key in {"threats", "cases", "iocs"}:
            return {"params": {"limit": DEFAULT_LIMITS[key]}}
        return {}

    def _read_cache(self) -> dict[str, Any] | None:
        """
        Read a valid Abnormal snapshot from disk when available.

        Returns:
            dict[str, Any] | None: Cached snapshot when fresh and usable; otherwise ``None``.
        """
        try:
            if not CACHE_FILE.exists():
                return None
            modified_at = datetime.fromtimestamp(
                CACHE_FILE.stat().st_mtime, timezone.utc
            )
            if datetime.now(timezone.utc) - modified_at > self.cache_ttl:
                return None
            snapshot = json.loads(CACHE_FILE.read_text())
            if self._is_unusable_error_snapshot(snapshot):
                return None
            snapshot["normalized"] = self.normalize(snapshot.get("raw", {}))
            errors, notices = self._split_endpoint_issues(snapshot.get("errors", {}))
            existing_notices = snapshot.get("notices", {})
            if isinstance(existing_notices, dict):
                notices = {**existing_notices, **notices}
            snapshot["errors"] = errors
            snapshot["notices"] = notices
            snapshot.setdefault("warnings", [])
            return snapshot
        except (OSError, json.JSONDecodeError):
            return None

    def _is_unusable_error_snapshot(self, snapshot: dict[str, Any]) -> bool:
        """
        Detect cache payloads that contain only endpoint failures.

        Args:
            snapshot: Cached snapshot dictionary to inspect.

        Returns:
            bool: True when all endpoint collections failed and cache reuse should be avoided.
        """
        return not snapshot.get("raw") and bool(snapshot.get("errors"))

    def _split_endpoint_issues(
        self, errors: dict[str, str]
    ) -> tuple[dict[str, str], dict[str, str]]:
        """
        Separate hard endpoint errors from optional-feature notices.

        Args:
            errors: Mapping of endpoint key to formatted error message.

        Returns:
            tuple[dict[str, str], dict[str, str]]: Hard errors first, optional notices second.
        """
        blocking_errors: dict[str, str] = {}
        notices: dict[str, str] = {}
        for key, message in errors.items():
            if self._is_optional_feature_unavailable(key, message):
                notices[key] = message
            else:
                blocking_errors[key] = message
        return blocking_errors, notices

    def _is_optional_feature_unavailable(self, key: str, message: str) -> bool:
        """
        Classify whether an endpoint failure represents a disabled optional feature.

        Args:
            key: Endpoint key that failed.
            message: Formatted upstream error message.

        Returns:
            bool: True when the failure should be shown as a notice rather than a collection error.
        """
        normalized = str(message).lower()
        return key == "iocs" and "403" in normalized and "not enabled" in normalized

    def _write_cache(self, snapshot: dict[str, Any]) -> None:
        """
        Persist a usable Abnormal snapshot to disk.

        Args:
            snapshot: Snapshot payload to write as formatted JSON.

        Returns:
            None: This method performs filesystem side effects only.
        """
        if self._is_unusable_error_snapshot(snapshot):
            return
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        CACHE_FILE.write_text(json.dumps(snapshot, indent=2, default=str))

    def normalize(self, raw: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize raw Abnormal endpoint payloads for dashboard rendering.

        Args:
            raw: Mapping of endpoint keys to raw decoded API payloads.

        Returns:
            dict[str, Any]: Summary metrics, normalized records, aggregation buckets, and display status.
        """
        dashboard_summary = raw.get("dashboard_summary", {})
        threats = self._extract_records(raw.get("threats", {}))
        cases = self._extract_records(raw.get("cases", {}))
        iocs = self._extract_records(raw.get("iocs", {}))
        abuse_items = self._extract_records(raw.get("abuse_not_analyzed", {}))

        total_threats = self._first_number(
            raw.get("threats", {}),
            "total_threats",
            "totalthreats",
            "threats_total",
            "threat_count",
            "total",
        )
        if total_threats is None:
            total_threats = self._first_number(
                dashboard_summary,
                "total_threats",
                "totalthreats",
                "threats_total",
                "threat_count",
            )
        stopped_attacks = self._first_number(
            raw.get("attack_stopped", {}),
            "attack_stopped",
            "attacks_stopped",
            "stopped_attacks",
            "stopped",
            "attack_count",
            "total",
        )
        open_cases = self._first_number(
            raw.get("cases", {}), "open_cases", "opencases", "case_count", "total"
        )
        not_analyzed = self._first_number(
            raw.get("abuse_not_analyzed", {}),
            "not_analyzed",
            "notanalyzed",
            "untriaged",
            "total",
        )
        ioc_count = self._first_number(raw.get("iocs", {}), "ioc_count", "total")

        summary = {
            "total_threats": (
                total_threats if total_threats is not None else len(threats)
            ),
            "stopped_attacks": stopped_attacks if stopped_attacks is not None else 0,
            "open_cases": open_cases if open_cases is not None else len(cases),
            "not_analyzed": (
                not_analyzed if not_analyzed is not None else len(abuse_items)
            ),
            "ioc_count": ioc_count if ioc_count is not None else len(iocs),
        }
        summary["risk_level"] = self._risk_level(summary)
        summary["status"] = self._status(summary)

        return {
            "summary": summary,
            "trending_attacks": self._top_buckets(
                self._payload_for_key(raw, "trending_attacks")
            ),
            "attack_vectors": self._top_buckets(
                self._payload_for_key(raw, "attack_vector_breakdown")
            ),
            "attack_strategies": self._top_buckets(
                self._payload_for_key(raw, "attack_strategy_breakdown")
            ),
            "sender_impersonation": self._top_buckets(
                self._payload_for_key(raw, "sender_impersonation_breakdown")
            ),
            "attacker_origins": self._top_buckets(
                self._payload_for_key(raw, "attacker_origin")
            ),
            "impersonated_employees": self._top_buckets(
                self._payload_for_key(raw, "most_impersonated_employee")
            ),
            "impersonated_vendors": self._top_buckets(
                self._payload_for_key(raw, "most_impersonated_vendor")
            ),
            "recipient_employees": self._top_buckets(
                self._payload_for_key(raw, "recipient_employees")
            ),
            "attack_frequency": self._attack_frequency(
                self._payload_for_key(raw, "attack_frequency")
            ),
            "recent_abuse_reports": [
                self._normalize_abuse_report(item) for item in abuse_items[:6]
            ],
            "recent_threats": [self._normalize_threat(item) for item in threats[:6]],
        }

    def _risk_level(self, summary: dict[str, int]) -> str:
        """
        Derive an Abnormal dashboard risk level from summary counters.

        Args:
            summary: Normalized Abnormal summary counters.

        Returns:
            str: One of ``High``, ``Moderate``, or ``Low``.
        """
        if summary.get("not_analyzed", 0) > 0 or summary.get("open_cases", 0) >= 10:
            return "High"
        if summary.get("total_threats", 0) > 0 or summary.get("open_cases", 0) > 0:
            return "Moderate"
        return "Low"

    def _status(self, summary: dict[str, int]) -> str:
        """
        Build a human-readable Abnormal status line from summary counters.

        Args:
            summary: Normalized Abnormal summary counters.

        Returns:
            str: Concise operational status suitable for dashboard display.
        """
        if summary.get("not_analyzed", 0) > 0:
            return f"{summary['not_analyzed']} abuse mailbox item(s) awaiting analysis"
        if summary.get("open_cases", 0) > 0:
            return f"{summary['open_cases']} case(s) require analyst review"
        if summary.get("total_threats", 0) > 0:
            return "Threat activity observed; no untriaged abuse items returned"
        return "No active Abnormal email security signal in the current snapshot"

    def _normalize_threat(self, threat: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize one Abnormal threat record.

        Args:
            threat: Raw threat object from the Abnormal API.

        Returns:
            dict[str, Any]: Stable threat fields used by dashboard templates.
        """
        return {
            "id": self._first(threat, "threatId", "threat_id", "id"),
            "subject": self._first(threat, "subject", "summary", "attackType", "type")
            or "Threat",
            "severity": self._first(threat, "severity", "riskLevel", "threatLevel")
            or "Unknown",
            "status": self._first(threat, "status", "remediationStatus", "state"),
            "received_at": self._first(
                threat, "receivedTime", "received_at", "createdAt", "created_at"
            ),
        }

    def _attack_frequency(self, payload: Any, limit: int = 14) -> list[dict[str, Any]]:
        """
        Normalize Abnormal attack frequency buckets.

        Args:
            payload: Raw aggregation payload from Abnormal.
            limit: Maximum number of buckets to return.

        Returns:
            list[dict[str, Any]]: Date or label buckets with counts.
        """
        return self._top_buckets(payload, limit=limit, record_key="attack_frequency")

    def _normalize_abuse_report(self, item: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize one abuse mailbox item.

        Args:
            item: Raw abuse mailbox record from Abnormal.

        Returns:
            dict[str, Any]: Stable subject, reporter, timestamp, and reason fields.
        """
        reporter = (
            item.get("reporter") if isinstance(item.get("reporter"), dict) else {}
        )
        raw_reason = self._first(item, "not_analyzed_reason", "reason") or "Unknown"
        return {
            "id": self._first(item, "abx_message_id", "id"),
            "subject": self._first(item, "subject") or "Reported message",
            "reason": self._format_abuse_reason(raw_reason),
            "raw_reason": raw_reason,
            "reported_at": self._first(item, "reported_datetime", "reported_at"),
            "reporter": self._first(reporter, "email", "name") if reporter else None,
        }

    def _payload_for_key(self, raw: dict[str, Any], key: str) -> Any:
        """
        Find the most relevant payload for a normalized endpoint key.

        Args:
            raw: Mapping of endpoint keys to raw payloads.
            key: Preferred endpoint key.

        Returns:
            Any: Direct payload, nested named payload, or an empty dictionary.
        """
        payload = raw.get(key)
        if payload not in (None, {}, []):
            return payload
        return self._find_named_payload(raw.get("dashboard_summary", {}), key)

    def _find_named_payload(self, payload: Any, key: str) -> Any:
        """
        Recursively search a payload for a non-empty value under a specific key.

        Args:
            payload: JSON-compatible object to search.
            key: Dictionary key to locate.

        Returns:
            Any: Matching non-empty value, or an empty dictionary when not found.
        """
        if isinstance(payload, dict):
            if key in payload:
                return {key: payload[key]}
            for value in payload.values():
                found = self._find_named_payload(value, key)
                if found not in (None, {}, []):
                    return found
        elif isinstance(payload, list):
            for item in payload:
                found = self._find_named_payload(item, key)
                if found not in (None, {}, []):
                    return found
        return {}

    def _format_abuse_reason(self, reason: Any) -> str:
        """
        Format an Abnormal abuse mailbox reason code for users.

        Args:
            reason: Raw reason code or missing value.

        Returns:
            str: Friendly reason label.
        """
        reason_text = str(reason or "Unknown")
        return ABUSE_REASON_LABELS.get(
            reason_text, reason_text.replace("_", " ").strip().title() or "Unknown"
        )

    def _top_buckets(
        self, payload: Any, limit: int = 5, record_key: str | None = None
    ) -> list[dict[str, Any]]:
        """
        Extract top aggregation buckets from flexible Abnormal payload shapes.

        Args:
            payload: Raw aggregation payload that may contain lists, nested objects, or numeric counters.
            limit: Maximum number of buckets to return.
            record_key: Optional preferred nested record key to inspect first.

        Returns:
            list[dict[str, Any]]: Label/count dictionaries sorted in source order or by numeric counter frequency.
        """
        records = self._extract_records(payload, record_key=record_key)
        buckets: list[dict[str, Any]] = []
        for record in records:
            if not isinstance(record, dict):
                continue
            label = self._first(
                record,
                "name",
                "label",
                "key",
                "attackType",
                "attack_type",
                "attack_vector_group",
                "attack_strategy",
                "impersonated_party_name",
                "impersonated_brand_name",
                "display_name",
                "employee",
                "vendor",
                "country",
                "region_name",
                "origin",
                "strategy",
                "vector",
                "value",
            )
            count = self._first(
                record, "attack_count", "count", "total", "value", "occurrences"
            )
            if label is None:
                continue
            buckets.append(
                {"label": str(label), "count": count if count is not None else "—"}
            )

        if buckets:
            return buckets[:limit]

        if isinstance(payload, dict):
            counters = Counter(
                {
                    key: value
                    for key, value in payload.items()
                    if isinstance(value, int | float)
                }
            )
            return [
                {"label": label, "count": count}
                for label, count in counters.most_common(limit)
            ]
        return []

    def _extract_records(
        self, payload: Any, record_key: str | None = None
    ) -> list[Any]:
        """
        Extract a list of records from common Abnormal response wrappers.

        Args:
            payload: Raw JSON-compatible payload to inspect.
            record_key: Optional preferred nested key containing records.

        Returns:
            list[Any]: Extracted list of records, or an empty list when no records are present.
        """
        if isinstance(payload, list):
            if record_key:
                for item in payload:
                    if isinstance(item, dict) and record_key in item:
                        return self._extract_records(item[record_key])
            return payload
        if not isinstance(payload, dict):
            return []

        preferred_keys = [record_key] if record_key else []
        preferred_keys.extend(
            [
                "resources",
                "data",
                "results",
                "items",
                "threats",
                "cases",
                "iocs",
                "attack_stopped",
                "attack_frequency",
                "trending_attacks",
                "attack_vector_breakdown",
                "attack_strategy_breakdown",
                "sender_impersonation_breakdown",
                "attacker_origin",
                "most_impersonated_employee",
                "most_impersonated_vendor",
                "recipient_employees",
                "recipient_employees_vip",
                "recipient_employees_non_vip",
            ]
        )
        for key in preferred_keys:
            if not key:
                continue
            value = payload.get(key)
            if isinstance(value, list):
                return value
            if isinstance(value, dict):
                nested = self._extract_records(value, record_key=record_key)
                if nested:
                    return nested

        for value in payload.values():
            if isinstance(value, list) and all(
                isinstance(item, dict) for item in value
            ):
                return value
        return []

    def _first_number(self, payload: Any, *keys: str) -> int | None:
        """
        Find the first numeric value matching any candidate key.

        Args:
            payload: JSON-compatible payload to search recursively.
            *keys: Candidate field names that may contain a number.

        Returns:
            int | None: First matching integer value, or ``None`` when no numeric value is found.
        """
        keyset = {key.lower() for key in keys}
        value = self._find_value(payload, keyset)
        if isinstance(value, bool):
            return None
        if isinstance(value, int | float):
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
        return None

    def _find_value(self, payload: Any, keyset: set[str]) -> Any:
        """
        Recursively find the first scalar value whose key matches a normalized key set.

        Args:
            payload: JSON-compatible payload to traverse.
            keyset: Lowercase normalized key names to match.

        Returns:
            Any: First scalar matching value, or ``None`` when no match exists.
        """
        if isinstance(payload, dict):
            for key, value in payload.items():
                normalized = key.replace("-", "_").lower()
                compact = normalized.replace("_", "")
                if normalized in keyset or compact in keyset:
                    if not isinstance(value, dict | list):
                        return value
                    found = self._find_value(value, keyset)
                    if found is not None:
                        return found
            for value in payload.values():
                found = self._find_value(value, keyset)
                if found is not None:
                    return found
        elif isinstance(payload, list):
            for item in payload:
                found = self._find_value(item, keyset)
                if found is not None:
                    return found
        return None

    def _first(self, payload: dict[str, Any], *keys: str) -> Any:
        """
        Return the first non-empty value for a set of candidate keys.

        Args:
            payload: Dictionary to inspect.
            *keys: Candidate keys in priority order.

        Returns:
            Any: First non-empty value, or ``None`` if all candidates are missing.
        """
        for key in keys:
            value = payload.get(key)
            if value not in (None, ""):
                return value
        return None

    def _format_http_error(self, error: requests.HTTPError) -> str:
        """
        Format a requests HTTPError into a concise endpoint error message.

        Args:
            error: HTTPError raised by the Abnormal request layer.

        Returns:
            str: Status code and JSON or text error details.
        """
        response = error.response
        if response is None:
            return str(error)
        try:
            payload = response.json()
            errors = payload.get("errors") or payload.get("error") or payload
            return f"{response.status_code}: {errors}"
        except ValueError:
            return f"{response.status_code}: {response.text[:500]}"
