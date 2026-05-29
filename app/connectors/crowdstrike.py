import json
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from app.config import (
    CROWDSTRIKE_BASE_URL,
    CROWDSTRIKE_CLIENT_ID,
    CROWDSTRIKE_SECRET,
    CROWDSTRIKE_VULNERABILITY_FILTER,
)

# Constants for caching, limits, and severity mapping are defined here for easy configuration and maintenance.
PROJECT_ROOT = Path(__file__).resolve().parents[2]
CACHE_FILE = PROJECT_ROOT / "data" / "raw" / "crowdstrike" / "crowdstrike_snapshot.json"
CACHE_TTL = timedelta(minutes=15)
DEFAULT_BASE_URL = "https://api.crowdstrike.com"
DEFAULT_LIMITS = {
    "hosts": 500,
    "detections": 250,
    "alerts": 250,
    "identity_alerts": 250,
    "incidents": 250,
    "vulnerabilities": 400,
}
DEFAULT_VULNERABILITY_FILTER = "last_seen_within:'90'"
VULNERABILITY_FALLBACK_FILTERS = [
    DEFAULT_VULNERABILITY_FILTER,
    "last_seen_within:'45'",
    "last_seen_within:'30'",
    "status:['open','reopen']",
]
SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "informational": 1,
    "unknown": 0,
}


class CrowdStrikeConnector:
    """Pulls, normalizes, and summarizes data available to the configured Falcon API client."""

    def __init__(self, cache_ttl: timedelta = CACHE_TTL):
        """Sets up the caching infrastructure and checks for proper CrowdStrike credentials

        Args:
            cache_ttl (timedelta, optional): RPO for cached data. Defaults to CACHE_TTL.

        Raises:
            ValueError: warns if the client id is not in the .env
            ValueError: warns if the CrowdStrike secret is not in the .env
        """
        if not CROWDSTRIKE_CLIENT_ID:
            raise ValueError("CROWDSTRIKE_CLIENT_ID is missing from .env")
        if not CROWDSTRIKE_SECRET:
            raise ValueError("CROWDSTRIKE_SECRET is missing from .env")

        self.base_url = (CROWDSTRIKE_BASE_URL or DEFAULT_BASE_URL).rstrip("/")
        self.cache_ttl = cache_ttl
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})
        self._token: str | None = None

    def _authenticate(self) -> str:
        """Authenticates CrowdStrike requests by generating and storing a validation token

        Raises:
            ValueError: Detects if CrowdStrike does not supply the user with a token

        Returns:
            str: the token
        """
        if self._token:
            return self._token

        # Request an OAuth2 token using CrowdStrike Credentials
        response = self.session.post(
            f"{self.base_url}/oauth2/token",
            data={
                "client_id": CROWDSTRIKE_CLIENT_ID,
                "client_secret": CROWDSTRIKE_SECRET,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        response.raise_for_status()
        token = response.json().get("access_token")
        if not token:
            raise ValueError(
                "CrowdStrike authentication response did not include an access token"
            )
        self._token = token
        self.session.headers.update({"Authorization": f"Bearer {token}"})
        return token

    def _request(self, method: str, path: str, **kwargs) -> dict[str, Any]:
        """Request wrapper that authenticates and checks that content is being returned

        Args:
            method (str): The HTTP method for the request (i.e. "GET", "POST", etc.)
            path (str): The endpoint for the API to pull from

        Returns:
            dict[str, Any]: The data fetched
        """
        self._authenticate()
        response = self.session.request(
            method, f"{self.base_url}{path}", timeout=30, **kwargs
        )
        response.raise_for_status()
        if not response.content:
            return {}
        return response.json()

    def _query_ids(
        self,
        path: str,
        limit: int,
        sort: str | None = None,
        filter_query: str | None = None,
    ) -> list[str]:
        """Queries a CrowdStrike endpoint that returns only IDs for the requested data, with optional sorting and filtering

        Args:
            path (str): The endpoint the API pulls from
            limit (int): The number of results to return
            sort (str | None, optional): The field to sort by. Defaults to None.
            filter_query (str | None, optional): The filter query. Defaults to None.

        Returns:
            list[str]: The list of IDs
        """
        data = self._query(path, limit, sort=sort, filter_query=filter_query)
        resources = data.get("resources", [])
        return [resource for resource in resources if isinstance(resource, str)]

    def _query(
        self,
        path: str,
        limit: int,
        sort: str | None = None,
        filter_query: str | None = None,
    ) -> dict[str, Any]:
        """General query method for CrowdStrike endpoints that support filtering and sorting, used as a building block for more specific query methods

        Args:
            path (str): The endpoint the API pulls from
            limit (int): The number of results to return
            sort (str | None, optional): The field to sort by. Defaults to None.
            filter_query (str | None, optional): The filter query. Defaults to None.

        Returns:
            dict[str, Any]: The data fetched
        """
        params: dict[str, Any] = {"limit": limit}
        if sort:
            params["sort"] = sort
        if filter_query:
            params["filter"] = filter_query
        return self._request("GET", path, params=params)

    def _query_ids_with_fallbacks(
        self,
        path: str,
        limit: int,
        sorts: list[str | None],
        filter_query: str | None = None,
    ) -> list[str]:
        """Another wrapper to checks for ids with sorting fallbacks

        Args:
            path (str): The endpoint the API pulls from
            limit (int): The number of results to return
            sorts (list[str  |  None]): The fields to sort by
            filter_query (str | None, optional): The filter query. Defaults to None.

        Raises:
            last_error: The last HTTP error that occurred

        Returns:
            list[str]: The list of ids
        """
        last_error: requests.HTTPError | None = None
        for sort in sorts:
            try:
                return self._query_ids(
                    path, limit, sort=sort, filter_query=filter_query
                )
            except requests.HTTPError as error:
                last_error = error
                if error.response is None or error.response.status_code not in {
                    400,
                    404,
                    500,
                }:
                    raise
        if last_error:
            raise last_error
        return []

    def _fetch_entities_get(
        self, path: str, ids: list[str], id_param: str = "ids"
    ) -> list[dict[str, Any]]:
        """Returns the entities from a GET endpoint using a list of entity ids.

        They are sent in batches of up to 100 per request. Results are gathered from
        the API's response's "resources" field and compiled into a single list.

        Args:
            path (str): API endpoint to query
            ids (list[str]): Entity IDs to fetch
            id_param (str, optional): Name of the query parameter used for entity IDs.
                                      Defaults to "ids".

        Returns:
            list[dict[str, Any]]: An organized list of key pairs of ids
        """
        if not ids:
            return []
        entities: list[dict[str, Any]] = []
        for chunk in self._chunks(ids, 100):
            params = [(id_param, entity_id) for entity_id in chunk]
            data = self._request("GET", path, params=params)
            entities.extend(
                [item for item in data.get("resources", []) if isinstance(item, dict)]
            )
        return entities

    def _fetch_entities_post(
        self, path: str, ids: list[str], id_key: str = "ids"
    ) -> list[dict[str, Any]]:
        """Returns the entities from a POST endpoint using a list of entity ids.

        Args:
            path (str): API endpoint to query
            ids (list[str]): Entity IDs to fetch
            id_key (str, optional): Name of the key in the JSON payload for entity IDs.
                                      Defaults to "ids".

        Returns:
            list[dict[str, Any]]: An organized list of key pairs of ids
        """
        if not ids:
            return []
        entities: list[dict[str, Any]] = []
        for chunk in self._chunks(ids, 100):
            data = self._request("POST", path, json={id_key: chunk})
            entities.extend(
                [item for item in data.get("resources", []) if isinstance(item, dict)]
            )
        return entities

    @staticmethod
    def _chunks(values: list[str], size: int) -> list[list[str]]:
        """
        Split a list into fixed-size chunks for batch API calls.

        Args:
            values: Source values to split.
            size: Maximum number of values in each chunk.

        Returns:
            list[list[str]]: Ordered chunks preserving the source order.
        """
        return [values[index : index + size] for index in range(0, len(values), size)]

    def get_hosts(self, limit: int = DEFAULT_LIMITS["hosts"]) -> list[dict[str, Any]]:
        """
        Fetch and hydrate CrowdStrike host details.

        Args:
            limit: Maximum number of host IDs to query before hydration.

        Returns:
            list[dict[str, Any]]: Host entity records returned by CrowdStrike.
        """
        ids = self._query_ids(
            "/devices/queries/devices/v1", limit, sort="last_seen.desc"
        )
        return self._fetch_entities_get("/devices/entities/devices/v2", ids)

    def get_detections(
        self, limit: int = DEFAULT_LIMITS["detections"]
    ) -> list[dict[str, Any]]:
        """
        Fetch CrowdStrike detection details with endpoint-alert fallback behavior.

        Args:
            limit: Maximum number of detection or alert records to retrieve.

        Returns:
            list[dict[str, Any]]: Detection-like security event records.

        Raises:
            requests.HTTPError: Re-raised when both primary and fallback APIs fail.
        """
        try:
            ids = self._query_ids_with_fallbacks(
                "/detects/queries/detects/v1",
                limit,
                sorts=["first_behavior.desc", "updated_timestamp|desc", None],
            )
            return self._fetch_entities_get("/detects/entities/summaries/GET/v1", ids)
        except requests.HTTPError as error:
            if error.response is None or error.response.status_code != 404:
                raise

        # CrowdStrike has migrated endpoint detections into Unified Alerts in many
        # tenants. If the legacy Detects API is absent, use endpoint-scoped alerts
        # so the dashboard still shows detection signal instead of a 404 banner.
        return self._get_alerts_by_filter(
            limit=limit,
            filter_query="data_domains:'Endpoint'",
            fallback_filter="product:'epp'",
        )

    def get_incidents(
        self, limit: int = DEFAULT_LIMITS["incidents"]
    ) -> list[dict[str, Any]]:
        """
        Fetch CrowdStrike incident details.

        Args:
            limit: Maximum number of incident IDs to query before hydration.

        Returns:
            list[dict[str, Any]]: Incident entity records returned by CrowdStrike.
        """
        try:
            ids = self._query_ids_with_fallbacks(
                "/incidents/queries/incidents/v1",
                limit,
                sorts=["start.desc", "modified_timestamp.desc", None],
            )
            return self._fetch_entities_get("/incidents/entities/incidents/GET/v1", ids)
        except requests.HTTPError as error:
            if error.response is None or error.response.status_code not in {404, 500}:
                raise

        # The legacy Incidents API is being retired in favor of Unified Alerts for
        # some tenants. Fall back to incident-like alerts without surfacing a hard
        # dashboard error for retired endpoints.
        return self._get_alerts_by_filter(
            limit=limit,
            filter_query="type:'IncidentSummaryEvent'",
            fallback_filter="product:'incident'",
        )

    def get_alerts(self, limit: int = DEFAULT_LIMITS["alerts"]) -> list[dict[str, Any]]:
        """
        Fetch unified CrowdStrike alert records.

        Args:
            limit: Maximum number of alert records to retrieve.

        Returns:
            list[dict[str, Any]]: Unified alert records ordered by most recent activity.
        """
        return self._get_alerts_by_filter(limit=limit)

    def _get_alerts_by_filter(
        self,
        limit: int,
        filter_query: str | None = None,
        fallback_filter: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Fetch unified alerts with an optional fallback filter.

        Args:
            limit: Maximum number of alert records to retrieve.
            filter_query: Primary Falcon Query Language filter to apply.
            fallback_filter: Secondary filter used if the primary query fails.

        Returns:
            list[dict[str, Any]]: Alert records returned by the first successful filter.

        Raises:
            requests.HTTPError: Re-raised when the primary query fails and no fallback succeeds.
        """
        filters = [filter_query]
        if fallback_filter and fallback_filter not in filters:
            filters.append(fallback_filter)
        if filter_query is not None:
            filters.append(None)

        last_error: requests.HTTPError | None = None
        for current_filter in filters:
            try:
                ids = self._query_ids_with_fallbacks(
                    "/alerts/queries/alerts/v2",
                    limit,
                    sorts=["created_timestamp|desc", "updated_timestamp|desc", None],
                    filter_query=current_filter,
                )
                return self._fetch_entities_post(
                    "/alerts/entities/alerts/v2", ids, id_key="composite_ids"
                )
            except requests.HTTPError as error:
                last_error = error
                if error.response is None or error.response.status_code != 400:
                    raise

        if last_error:
            raise last_error
        return []

    def get_identity_alerts(
        self, limit: int = DEFAULT_LIMITS["identity_alerts"]
    ) -> list[dict[str, Any]]:
        # Identity alert records are exposed through Unified Alerts in current
        # Falcon tenants. The old identity-protection alerts route can return 404
        # even when the client has Identity Protection Alerts read access.
        """
        Fetch identity-focused CrowdStrike alerts.

        Args:
            limit: Maximum number of identity alert records to retrieve.

        Returns:
            list[dict[str, Any]]: Alert records filtered to identity-domain detections when supported.
        """
        return self._get_alerts_by_filter(
            limit=limit,
            filter_query="data_domains:'Identity'",
            fallback_filter="product:'idp'",
        )

    def get_vulnerabilities(
        self, limit: int = DEFAULT_LIMITS["vulnerabilities"]
    ) -> list[dict[str, Any]]:
        # Spotlight rejects unfiltered vulnerability searches in some tenants. Use
        # the combined endpoint first so the dashboard gets meaningful vulnerability
        # details in one call, then fall back to ID query + entity hydration.
        """
        Fetch CrowdStrike Spotlight vulnerability records.

        Args:
            limit: Maximum number of vulnerabilities to retrieve.

        Returns:
            list[dict[str, Any]]: Vulnerability records from combined or hydrated Spotlight endpoints.
        """
        safe_limit = min(limit, 400)
        filters = self._vulnerability_filters()
        last_error: requests.HTTPError | None = None

        for filter_query in filters:
            try:
                combined = self._query_combined_vulnerabilities(
                    safe_limit, filter_query=filter_query
                )
                if combined:
                    return combined
            except requests.HTTPError as error:
                last_error = error
                if error.response is None or error.response.status_code != 400:
                    raise

        for filter_query in filters:
            try:
                ids = self._query_ids_with_fallbacks(
                    "/spotlight/queries/vulnerabilities/v1",
                    safe_limit,
                    sorts=["updated_timestamp|desc", "created_timestamp|desc", None],
                    filter_query=filter_query,
                )
                return self._fetch_entities_post(
                    "/spotlight/entities/vulnerabilities/v2", ids
                )
            except requests.HTTPError as error:
                last_error = error
                if error.response is None or error.response.status_code != 400:
                    raise

        if last_error:
            raise last_error
        return []

    def _query_combined_vulnerabilities(
        self, limit: int, filter_query: str
    ) -> list[dict[str, Any]]:
        """
        Query the combined Spotlight vulnerability endpoint.

        Args:
            limit: Maximum number of vulnerability records to request.
            filter_query: Spotlight vulnerability filter expression.

        Returns:
            list[dict[str, Any]]: Combined vulnerability resources.
        """
        data = self._query(
            "/spotlight/combined/vulnerabilities/v1",
            limit,
            filter_query=filter_query,
        )
        return [item for item in data.get("resources", []) if isinstance(item, dict)]

    @staticmethod
    def _vulnerability_filters() -> list[str]:
        """
        Build ordered Spotlight vulnerability filters to try.

        Returns:
            list[str]: Configured filter followed by safe fallback filters without duplicates.
        """
        filters = []
        if CROWDSTRIKE_VULNERABILITY_FILTER:
            filters.append(CROWDSTRIKE_VULNERABILITY_FILTER)
        for filter_query in VULNERABILITY_FALLBACK_FILTERS:
            if filter_query not in filters:
                filters.append(filter_query)
        return filters

    def get_snapshot(
        self, use_cache: bool = True, limits: dict[str, int] | None = None
    ) -> dict[str, Any]:
        """
        Collect or read a complete CrowdStrike dashboard snapshot.

        Args:
            use_cache: When true, use a fresh local cache if available.

        Returns:
            dict[str, Any]: Snapshot metadata, raw collections, normalized data, collection errors, and limits.
        """
        if use_cache:
            cached = self._read_cache()
            if cached:
                return cached

        fetch_limits = DEFAULT_LIMITS | (limits or {})
        errors: dict[str, str] = {}
        raw: dict[str, list[dict[str, Any]]] = {}
        fetchers = {
            "hosts": self.get_hosts,
            "detections": self.get_detections,
            "alerts": self.get_alerts,
            "identity_alerts": self.get_identity_alerts,
            "incidents": self.get_incidents,
            "vulnerabilities": self.get_vulnerabilities,
        }

        for name, fetcher in fetchers.items():
            try:
                raw[name] = fetcher(fetch_limits[name])
            except requests.HTTPError as error:
                details = self._response_detail(error.response)
                errors[name] = (
                    f"{error.response.status_code}: {details}"
                    if error.response
                    else str(error)
                )
                raw[name] = []
            except Exception as error:
                errors[name] = str(error)
                raw[name] = []

        snapshot = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "base_url": self.base_url,
            "limits": fetch_limits,
            "errors": errors,
            "raw": raw,
            "normalized": self.normalize(raw),
        }
        self._write_cache(snapshot)
        return snapshot

    def _read_cache(self) -> dict[str, Any] | None:
        """
        Read a fresh CrowdStrike snapshot from disk.

        Returns:
            dict[str, Any] | None: Cached snapshot when it exists and is still fresh; otherwise ``None``.
        """
        if not CACHE_FILE.exists():
            return None
        modified_time = datetime.fromtimestamp(
            CACHE_FILE.stat().st_mtime, tz=timezone.utc
        )
        if datetime.now(timezone.utc) - modified_time >= self.cache_ttl:
            return None
        with open(CACHE_FILE, "r", encoding="utf-8") as file:
            return json.load(file)

    def _write_cache(self, snapshot: dict[str, Any]) -> None:
        """
        Persist a CrowdStrike snapshot to disk.

        Args:
            snapshot: Snapshot payload to serialize as formatted JSON.

        Returns:
            None: This method performs filesystem side effects only.
        """
        CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(CACHE_FILE, "w", encoding="utf-8") as file:
            json.dump(snapshot, file, indent=2, default=str)

    @staticmethod
    def _response_detail(response: requests.Response | None) -> str:
        """
        Extract concise diagnostic details from an HTTP response.

        Args:
            response: Optional requests response associated with an exception.

        Returns:
            str: JSON error payload, response text, or a fallback message.
        """
        if response is None:
            return "No response returned"
        try:
            payload = response.json()
            errors = payload.get("errors")
            if errors:
                return "; ".join(str(error.get("message", error)) for error in errors)
            return json.dumps(payload)[:500]
        except ValueError:
            return response.text[:500]

    def normalize(self, raw: dict[str, list[dict[str, Any]]]) -> dict[str, Any]:
        """
        Normalize raw CrowdStrike collections for dashboard rendering.

        Args:
            raw: Mapping of collection names to raw CrowdStrike records.

        Returns:
            dict[str, Any]: Summary counters, groupings, and normalized host, event, incident, and vulnerability records.
        """
        hosts = [self._normalize_host(host) for host in raw.get("hosts", [])]
        detections = [
            self._normalize_detection(item) for item in raw.get("detections", [])
        ]
        alerts = [
            self._normalize_alert(item, "falcon_alert")
            for item in raw.get("alerts", [])
        ]
        identity_alerts = [
            self._normalize_alert(item, "identity_alert")
            for item in raw.get("identity_alerts", [])
        ]
        incidents = [
            self._normalize_incident(item) for item in raw.get("incidents", [])
        ]
        vulnerabilities = [
            self._normalize_vulnerability(item)
            for item in raw.get("vulnerabilities", [])
        ]
        security_events = sorted(
            detections + alerts + identity_alerts + incidents + vulnerabilities,
            key=lambda event: event.get("timestamp") or "",
            reverse=True,
        )
        return {
            "summary": self._build_summary(hosts, security_events, vulnerabilities),
            "hosts": hosts,
            "security_events": security_events,
            "detections": detections,
            "alerts": alerts,
            "identity_alerts": identity_alerts,
            "incidents": incidents,
            "vulnerabilities": vulnerabilities,
            "groupings": self._build_groupings(hosts, security_events, vulnerabilities),
        }

    def _normalize_host(self, host: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize one CrowdStrike host record.

        Args:
            host: Raw host entity from CrowdStrike.

        Returns:
            dict[str, Any]: Stable host fields including hostname, platform, status, and stale flag.
        """
        return {
            "id": self._first(host, "device_id", "id", "aid"),
            "hostname": self._first(host, "hostname", "device_name", "computer_name")
            or "Unknown host",
            "platform": self._first(
                host, "platform_name", "platform", "os_product_name"
            ),
            "os_version": self._first(host, "os_version", "os_build"),
            "status": self._first(host, "status", "reduced_functionality_mode"),
            "last_seen": self._first(host, "last_seen", "modified_timestamp"),
            "first_seen": self._first(host, "first_seen"),
            "local_ip": self._first(host, "local_ip", "connection_ip"),
            "external_ip": self._first(host, "external_ip"),
            "mac_address": self._first(host, "mac_address"),
            "agent_version": self._first(host, "agent_version"),
            "groups": host.get("groups") or host.get("group_hash") or [],
            "tags": host.get("tags") or [],
            "raw": host,
        }

    def _normalize_detection(self, detection: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize one CrowdStrike detection record.

        Args:
            detection: Raw detection entity from CrowdStrike.

        Returns:
            dict[str, Any]: Stable security event fields used by the dashboard.
        """
        behaviors = detection.get("behaviors") or []
        primary_behavior = behaviors[0] if behaviors else {}
        severity = self._severity_from_any(
            self._first(detection, "max_severity_displayname", "severity_name")
            or primary_behavior.get("severity")
        )
        return {
            "id": self._first(detection, "detection_id", "id"),
            "type": "detection",
            "title": self._first(detection, "display_name", "name")
            or primary_behavior.get("display_name")
            or "Detection",
            "severity": severity,
            "status": self._first(detection, "status", "show_in_ui"),
            "timestamp": self._first(
                detection, "first_behavior", "created_timestamp", "updated_timestamp"
            ),
            "source": self._first(detection, "hostname", "device", "device_name")
            or primary_behavior.get("device_name"),
            "user": self._first(detection, "user_name", "username")
            or primary_behavior.get("user_name"),
            "tactic": primary_behavior.get("tactic"),
            "technique": primary_behavior.get("technique"),
            "objective": detection.get("objective"),
            "description": primary_behavior.get("description")
            or detection.get("description"),
            "raw": detection,
        }

    def _normalize_alert(
        self, alert: dict[str, Any], event_type: str
    ) -> dict[str, Any]:
        """
        Normalize one CrowdStrike unified alert record.

        Args:
            alert: Raw alert entity from CrowdStrike.
            source: Collection label used to distinguish alert families.

        Returns:
            dict[str, Any]: Stable alert fields mapped into the dashboard security event shape.
        """
        return {
            "id": self._first(alert, "id", "composite_id", "alert_id"),
            "type": event_type,
            "title": self._first(
                alert, "name", "display_name", "rule_name", "description"
            )
            or event_type.replace("_", " ").title(),
            "severity": self._severity_from_any(
                self._first(alert, "severity", "severity_name", "severity_name_display")
            ),
            "status": self._first(alert, "status", "state", "workflow_status"),
            "timestamp": self._first(
                alert,
                "created_timestamp",
                "timestamp",
                "updated_timestamp",
                "start_time",
            ),
            "source": self._first(
                alert,
                "device_name",
                "hostname",
                "source_endpoint_name",
                "endpoint_name",
            ),
            "user": self._first(
                alert, "user_name", "username", "source_user_name", "account_name"
            ),
            "tactic": self._first(alert, "tactic", "mitre_tactic"),
            "technique": self._first(alert, "technique", "mitre_technique"),
            "objective": self._first(alert, "objective", "category"),
            "description": self._first(
                alert, "description", "scenario", "pattern_disposition_description"
            ),
            "raw": alert,
        }

    def _normalize_incident(self, incident: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize one CrowdStrike incident record.

        Args:
            incident: Raw incident entity from CrowdStrike.

        Returns:
            dict[str, Any]: Stable incident fields including severity, status, source, and timestamps.
        """
        return {
            "id": self._first(incident, "incident_id", "id", "composite_id"),
            "type": "incident",
            "title": self._first(incident, "name", "display_name", "description")
            or "Incident",
            "severity": self._severity_from_any(
                self._first(incident, "severity", "severity_name", "state")
            ),
            "status": self._first(incident, "status", "state", "workflow_status"),
            "timestamp": self._first(
                incident,
                "start",
                "created",
                "created_timestamp",
                "modified_timestamp",
                "updated_timestamp",
                "end",
            ),
            "source": self._incident_source(incident),
            "user": self._first(incident, "user_name", "username", "account_name"),
            "tactic": self._first(incident, "tactic", "mitre_tactic"),
            "technique": self._first(incident, "technique", "mitre_technique"),
            "objective": self._first(incident, "objective", "type", "category"),
            "description": self._first(incident, "description", "scenario"),
            "raw": incident,
        }

    @staticmethod
    def _incident_source(incident: dict[str, Any]) -> str | None:
        """
        Infer a display source for a CrowdStrike incident.

        Args:
            incident: Raw incident entity that may include multiple source fields.

        Returns:
            str | None: First available source value, or ``None`` when no source is present.
        """
        hosts = incident.get("hosts")
        if isinstance(hosts, list):
            return ", ".join(str(host) for host in hosts[:3])
        for key in ("device_name", "hostname", "source_endpoint_name", "endpoint_name"):
            if incident.get(key):
                return incident[key]
        return None

    def _normalize_vulnerability(self, vulnerability: dict[str, Any]) -> dict[str, Any]:
        """
        Normalize one CrowdStrike Spotlight vulnerability record.

        Args:
            vulnerability: Raw vulnerability entity from CrowdStrike.

        Returns:
            dict[str, Any]: Stable vulnerability fields including CVE, severity, host, status, and exploit context.
        """
        cve = vulnerability.get("cve") or {}
        app = vulnerability.get("apps") or vulnerability.get("app") or []
        app_names = (
            [
                item.get("product_name") or item.get("name")
                for item in app
                if isinstance(item, dict)
            ]
            if isinstance(app, list)
            else []
        )
        title = (
            cve.get("id")
            or self._first(vulnerability, "cve_id", "id")
            or "Vulnerability"
        )
        return {
            "id": self._first(vulnerability, "id", "vulnerability_id") or title,
            "type": "vulnerability",
            "title": title,
            "severity": self._severity_from_any(
                cve.get("severity") or vulnerability.get("severity")
            ),
            "status": self._first(vulnerability, "status", "suppression_status"),
            "timestamp": self._first(
                vulnerability,
                "updated_timestamp",
                "created_timestamp",
                "published_date",
            ),
            "source": self._first(
                vulnerability, "hostname", "host_info.hostname", "device.hostname"
            ),
            "user": None,
            "tactic": None,
            "technique": None,
            "objective": "Exposure management",
            "description": cve.get("description") or vulnerability.get("description"),
            "cve": cve.get("id") or vulnerability.get("cve_id"),
            "cvss_score": cve.get("base_score")
            or cve.get("cvss_score")
            or vulnerability.get("cvss_score"),
            "exploit_status": vulnerability.get("exploit_status")
            or cve.get("exploit_status"),
            "remediation": vulnerability.get("remediation") or cve.get("remediation"),
            "applications": [name for name in app_names if name],
            "raw": vulnerability,
        }

    def _build_summary(
        self,
        hosts: list[dict[str, Any]],
        events: list[dict[str, Any]],
        vulnerabilities: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Build aggregate CrowdStrike dashboard counters.

        Args:
            hosts: Normalized host records.
            events: Normalized security event records.
            incidents: Normalized incident records.
            vulnerabilities: Normalized vulnerability records.

        Returns:
            dict[str, Any]: Counts for hosts, events, severity bands, incidents, stale hosts, and vulnerabilities.
        """
        severity_counts = Counter(
            self._display_value(event.get("severity"), "unknown") for event in events
        )
        event_type_counts = Counter(
            self._display_value(event.get("type"), "unknown") for event in events
        )
        status_counts = Counter(
            self._display_value(event.get("status"), "unknown") for event in events
        )
        stale_hosts = [host for host in hosts if self._is_stale(host.get("last_seen"))]
        return {
            "total_hosts": len(hosts),
            "stale_hosts": len(stale_hosts),
            "total_security_events": len(events),
            "total_vulnerabilities": len(vulnerabilities),
            "critical_or_high_events": sum(
                severity_counts[severity] for severity in ("critical", "high")
            ),
            "severity_counts": dict(severity_counts),
            "event_type_counts": dict(event_type_counts),
            "status_counts": dict(status_counts),
            "top_sources": Counter(
                self._display_value(event.get("source"), "Unknown") for event in events
            ).most_common(10),
            "top_users": Counter(
                self._display_value(event.get("user"), "Unknown")
                for event in events
                if event.get("user")
            ).most_common(10),
        }

    def _build_groupings(
        self,
        hosts: list[dict[str, Any]],
        events: list[dict[str, Any]],
        vulnerabilities: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Build grouping counters for CrowdStrike dashboard charts and lists.

        Args:
            hosts: Normalized host records.
            events: Normalized security event records.
            incidents: Normalized incident records.
            vulnerabilities: Normalized vulnerability records.

        Returns:
            dict[str, list[dict[str, Any]]]: Top operating systems, event severities, tactics, techniques, statuses, and vulnerability severities.
        """
        hosts_by_platform = defaultdict(list)
        for host in hosts:
            hosts_by_platform[
                self._display_value(host.get("platform"), "Unknown")
            ].append(host)
        events_by_severity = defaultdict(list)
        for event in events:
            events_by_severity[
                self._display_value(event.get("severity"), "unknown")
            ].append(event)
        vulnerabilities_by_severity = defaultdict(list)
        for vulnerability in vulnerabilities:
            vulnerabilities_by_severity[
                self._display_value(vulnerability.get("severity"), "unknown")
            ].append(vulnerability)
        return {
            "hosts_by_platform": {
                key: len(value) for key, value in hosts_by_platform.items()
            },
            "events_by_severity": {
                key: len(value) for key, value in events_by_severity.items()
            },
            "vulnerabilities_by_severity": {
                key: len(value) for key, value in vulnerabilities_by_severity.items()
            },
        }

    @staticmethod
    def _severity_from_any(value: Any) -> str:
        """
        Normalize heterogeneous severity values into dashboard severity labels.

        Args:
            value: Numeric or string severity value from CrowdStrike.

        Returns:
            str: Canonical severity label such as ``Critical``, ``High``, ``Medium``, ``Low``, ``Informational``, or ``Unknown``.
        """
        if value is None:
            return "unknown"
        if isinstance(value, (dict, list)):
            value = CrowdStrikeConnector._display_value(value, "unknown")
        if isinstance(value, (int, float)):
            if value > 10:
                if value >= 90:
                    return "critical"
                if value >= 70:
                    return "high"
                if value >= 40:
                    return "medium"
                if value > 0:
                    return "low"
                return "informational"
            if value >= 9:
                return "critical"
            if value >= 7:
                return "high"
            if value >= 4:
                return "medium"
            if value > 0:
                return "low"
            return "informational"
        normalized = str(value).lower().strip()
        for severity in ("critical", "high", "medium", "low", "informational"):
            if severity in normalized:
                return severity
        return normalized or "unknown"

    @staticmethod
    def _is_stale(value: str | None, days: int = 14) -> bool:
        """
        Determine whether a timestamp is older than the allowed freshness window.

        Args:
            value: Timestamp string to evaluate.
            days: Number of days before a record is considered stale.

        Returns:
            bool: True when the timestamp is missing, unparsable, or older than the threshold.
        """
        if not value:
            return True
        timestamp = CrowdStrikeConnector._parse_timestamp(value)
        if not timestamp:
            return False
        return datetime.now(timezone.utc) - timestamp > timedelta(days=days)

    @staticmethod
    def _parse_timestamp(value: str) -> datetime | None:
        """
        Parse a CrowdStrike timestamp into a timezone-aware datetime.

        Args:
            value: Timestamp string that may end with ``Z`` or include an offset.

        Returns:
            datetime | None: Parsed datetime, or ``None`` when parsing fails.
        """
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError):
            return None

    @staticmethod
    def _display_value(value: Any, fallback: str | None = None) -> str:
        """
        Select the first useful display value from a raw field.

        Args:
            value: Raw value that may be a scalar, list, or missing value.
            fallback: Optional value returned when the input is empty.

        Returns:
            str: Human-readable display value.
        """
        if value in (None, "", []):
            return fallback or ""
        if isinstance(value, dict):
            for key in (
                "hostname",
                "device_name",
                "computer_name",
                "name",
                "display_name",
                "username",
                "user_name",
                "id",
                "device_id",
                "aid",
            ):
                nested_value = value.get(key)
                if nested_value not in (None, "", []):
                    return CrowdStrikeConnector._display_value(nested_value, fallback)
            return json.dumps(value, sort_keys=True, default=str)[:200]
        if isinstance(value, list):
            labels = [
                CrowdStrikeConnector._display_value(item)
                for item in value[:3]
                if item not in (None, "", [])
            ]
            return ", ".join(label for label in labels if label) or (fallback or "")
        return str(value)

    @staticmethod
    def _first(data: dict[str, Any], *keys: str) -> Any:
        """
        Return the first non-empty value for a list of candidate keys.

        Args:
            data: Dictionary to inspect.
            *keys: Candidate keys in priority order.

        Returns:
            Any: First non-empty value, or ``None`` if every candidate is missing.
        """
        for key in keys:
            current: Any = data
            for part in key.split("."):
                if not isinstance(current, dict) or part not in current:
                    current = None
                    break
                current = current[part]
            if current not in (None, "", []):
                if isinstance(current, (dict, list)):
                    return CrowdStrikeConnector._display_value(current)
                return current
        return None
