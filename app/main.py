import json
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from app.connectors.abnormal import ACCESSIBLE_ENDPOINTS, AbnormalConnector
from app.connectors.bitsight import BitSightConnector
from app.connectors.crowdstrike import CrowdStrikeConnector

app = FastAPI(title="Cumulative Cybersecurity Dashboard", version="1.0.0")

templates = Jinja2Templates(directory="app/templates")
app.mount("/assets", StaticFiles(directory="app/templates/assets"), name="assets")


def build_bitsight_overview():
    """
    Build the compact BitSight summary used by the master dashboard.

    Reads the configured BitSight company summary, derives the display risk level from the numeric rating, and converts connector failures into a safe fallback dictionary so the dashboard can still render.

    Returns:
        dict[str, object]: Dashboard-ready BitSight fields including company name, score, rating date, risk level, status text, and an error message when collection fails.
    """
    try:
        connector = BitSightConnector()
        summary = connector.get_company_summary()
        if not summary:
            raise ValueError("No BitSight company summary returned")

        score = summary.get("score")
        if score is None:
            risk_level = "Unknown"
            status = "BitSight score unavailable"
        elif score >= 740:
            risk_level = "Low"
            status = "Strong security posture"
        elif score >= 640:
            risk_level = "Moderate"
            status = "Acceptable security posture, some risk"
        else:
            risk_level = "High"
            status = "Needs attention"

        return {
            "company_name": summary.get("name") or "BitSight",
            "score": score or "N/A",
            "risk_level": risk_level,
            "status": status,
            "rating_date": summary.get("rating_date") or "Unknown",
        }
    except Exception as error:
        return {
            "company_name": "BitSight",
            "score": "N/A",
            "risk_level": "Unknown",
            "status": "Unavailable",
            "rating_date": "Unknown",
            "error": str(error),
        }


def build_crowdstrike_overview(use_cache: bool = True):
    """
    Build the CrowdStrike summary used by the master dashboard.

    Args:
        use_cache: When true, allow the connector to reuse a fresh local snapshot instead of contacting CrowdStrike.

    Returns:
        dict[str, object]: Dashboard-ready endpoint counts, risk level, status text, and collection warnings or errors.
    """
    try:
        connector = CrowdStrikeConnector()
        snapshot = connector.get_snapshot(use_cache=use_cache)
        normalized = snapshot.get("normalized", {})
        summary = normalized.get("summary", {})
        critical_or_high = summary.get("critical_or_high_events", 0)
        total_events = summary.get("total_security_events", 0)
        errors = snapshot.get("errors", {})

        if critical_or_high:
            risk_level = "High"
            status = f"{critical_or_high} critical/high events need review"
        elif total_events:
            risk_level = "Moderate"
            status = "Events present, no critical/high events observed"
        else:
            risk_level = "Low"
            status = "No active security events in the current snapshot"

        if errors:
            status = f"{status}; {len(errors)} collection warning(s)"

        return {
            "total_hosts": summary.get("total_hosts", 0),
            "total_security_events": total_events,
            "critical_or_high_events": critical_or_high,
            "total_vulnerabilities": summary.get("total_vulnerabilities", 0),
            "risk_level": risk_level,
            "status": status,
            "errors": errors,
        }
    except Exception as error:
        return {
            "total_hosts": 0,
            "total_security_events": 0,
            "critical_or_high_events": 0,
            "total_vulnerabilities": 0,
            "risk_level": "Unknown",
            "status": "Unavailable",
            "error": str(error),
        }


def build_abnormal_overview(use_cache: bool = True):
    """
    Build the Abnormal Security summary used by the master dashboard.

    Args:
        use_cache: When true, allow the connector to reuse a fresh local snapshot instead of contacting Abnormal.

    Returns:
        dict[str, object]: Dashboard-ready Abnormal metrics, normalized insight lists, warning flags, and fallback error details.
    """
    try:
        connector = AbnormalConnector()
        snapshot = connector.get_snapshot(use_cache=use_cache)
        normalized = snapshot.get("normalized", {})
        summary = normalized.get("summary", {})
        errors = snapshot.get("errors", {})
        notices = snapshot.get("notices", {})
        warnings = snapshot.get("warnings", [])
        status = summary.get("status", "Available")
        if errors:
            status = f"{status}; {len(errors)} collection warning(s)"
        elif warnings:
            status = f"{status}; TLS warning: API requests used fallback certificate handling"

        return {
            "total_threats": summary.get("total_threats", 0),
            "stopped_attacks": summary.get("stopped_attacks", 0),
            "open_cases": summary.get("open_cases", 0),
            "not_analyzed": summary.get("not_analyzed", 0),
            "ioc_count": summary.get("ioc_count", 0),
            "risk_level": summary.get("risk_level", "Unknown"),
            "status": status,
            "trending_attacks": normalized.get("trending_attacks", []),
            "attack_vectors": normalized.get("attack_vectors", []),
            "attack_strategies": normalized.get("attack_strategies", []),
            "sender_impersonation": normalized.get("sender_impersonation", []),
            "attacker_origins": normalized.get("attacker_origins", []),
            "recipient_employees": normalized.get("recipient_employees", []),
            "impersonated_vendors": normalized.get("impersonated_vendors", []),
            "recent_abuse_reports": normalized.get("recent_abuse_reports", []),
            "recent_threats": normalized.get("recent_threats", []),
            "errors": errors,
            "notices": notices,
            "warnings": warnings,
            "collection_warning_count": len(errors),
            "ioc_unavailable": "iocs" in notices,
            "has_trending_error": "trending_attacks" in errors,
            "has_vector_error": "attack_vector_breakdown" in errors,
        }
    except Exception as error:
        return {
            "total_threats": 0,
            "stopped_attacks": 0,
            "open_cases": 0,
            "not_analyzed": 0,
            "ioc_count": 0,
            "risk_level": "Unknown",
            "status": "Unavailable",
            "trending_attacks": [],
            "attack_vectors": [],
            "attack_strategies": [],
            "sender_impersonation": [],
            "attacker_origins": [],
            "recipient_employees": [],
            "impersonated_vendors": [],
            "recent_abuse_reports": [],
            "recent_threats": [],
            "notices": {},
            "ioc_unavailable": False,
            "error": str(error),
        }


def _path_param_names(path: str) -> list[str]:
    """
    Extract FastAPI-style path parameter names from an endpoint template.

    Args:
        path: Endpoint path that may contain placeholders such as ``/v1/threats/{id}``.

    Returns:
        list[str]: Parameter names in the order they appear in the path.
    """
    return [segment.split("}", 1)[0] for segment in path.split("{")[1:]]


def summarize_endpoint_result(payload):
    """
    Summarize an arbitrary Abnormal endpoint payload for HTML presentation.

    Args:
        payload: JSON-compatible response object returned by an Abnormal endpoint.

    Returns:
        dict[str, object]: A title, record count, preview records, and table columns for the endpoint result page.
    """
    if isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(value, list):
                return {
                    "title": key.replace("_", " ").title(),
                    "count": len(value),
                    "records": value[:25],
                    "columns": _record_columns(value),
                }
        return {
            "title": "Response object",
            "count": len(payload),
            "records": [payload],
            "columns": _record_columns([payload]),
        }
    if isinstance(payload, list):
        return {
            "title": "Response list",
            "count": len(payload),
            "records": payload[:25],
            "columns": _record_columns(payload),
        }
    return {
        "title": "Response",
        "count": 1 if payload else 0,
        "records": [],
        "columns": [],
    }


def _record_columns(records) -> list[str]:
    """
    Determine a compact set of table columns from preview records.

    Args:
        records: Iterable of response records, usually dictionaries from an API response.

    Returns:
        list[str]: Up to six unique dictionary keys suitable for a readable browser table.
    """
    columns: list[str] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        for key in record:
            if key not in columns:
                columns.append(key)
            if len(columns) >= 6:
                return columns
    return columns


def _display_value(value) -> str:
    """
    Format a nested JSON value for display in a compact HTML table cell.

    Args:
        value: Any JSON-compatible value from an endpoint response.

    Returns:
        str: Human-readable text that avoids dumping large nested objects into the table.
    """
    if isinstance(value, dict):
        return ", ".join(f"{key}: {val}" for key, val in list(value.items())[:3])
    if isinstance(value, list):
        return f"{len(value)} item(s)"
    if value is None:
        return "—"
    return str(value)


def build_abnormal_endpoint_catalog():
    """
    Build grouped metadata for the Abnormal endpoint browser.

    Returns:
        list[dict[str, object]]: Endpoint groups containing display labels, HTTP methods, paths, parameter requirements, and local browser URLs.
    """
    groups = {
        "Threats & messages": [],
        "Aggregations & dashboard": [],
        "Cases & investigations": [],
        "Employees & identity": [],
        "Vendors": [],
        "Search & audit": [],
        "SPM & settings": [],
        "Other": [],
    }
    for key, (method, path) in ACCESSIBLE_ENDPOINTS.items():
        param_names = _path_param_names(path)
        endpoint = {
            "key": key,
            "label": key.replace("_", " ").title(),
            "method": method,
            "path": path,
            "requires_params": bool(param_names),
            "param_names": param_names,
            "url": f"/abnormal/{key}",
        }
        if any(token in key for token in ("threat", "message", "ioc", "abusecampaign")):
            group = "Threats & messages"
        elif "aggregation" in path or key in {
            "dashboard_summary",
            "attack_stopped",
            "trending_attacks",
            "attack_frequency",
            "attacker_origin",
        }:
            group = "Aggregations & dashboard"
        elif "case" in key:
            group = "Cases & investigations"
        elif any(token in key for token in ("employee", "recipient", "user", "role")):
            group = "Employees & identity"
        elif "vendor" in key:
            group = "Vendors"
        elif any(token in key for token in ("search", "audit")):
            group = "Search & audit"
        elif any(
            token in key
            for token in ("spm", "posture", "security", "soar", "detection360")
        ):
            group = "SPM & settings"
        else:
            group = "Other"
        groups[group].append(endpoint)

    return [
        {"name": name, "endpoints": sorted(endpoints, key=lambda item: item["key"])}
        for name, endpoints in groups.items()
        if endpoints
    ]


@app.get("/dashboard", response_class=HTMLResponse)
def get_master_dashboard(request: Request, use_cache: bool = True):
    """
    Render the unified dashboard HTML page.

    Args:
        request: FastAPI request object required by the Jinja template renderer.
        use_cache: When true, permits connector-level cache reuse for supported tools.

    Returns:
        TemplateResponse: Rendered master dashboard populated with BitSight, CrowdStrike, and Abnormal summaries.
    """
    return templates.TemplateResponse(
        request=request,
        name="master_dashboard.html",
        context={
            "bitsight": build_bitsight_overview(),
            "crowdstrike": build_crowdstrike_overview(use_cache=use_cache),
            "abnormal": build_abnormal_overview(use_cache=use_cache),
        },
    )


@app.get("/")
def root():
    """
    Return basic API health and navigation metadata.

    Returns:
        dict[str, str]: Status message and the primary dashboard route.
    """
    return {
        "status": "running",
        "message": "Cybersecurity Dashboard API Online",
        "dashboard": "/dashboard",
    }


###
# ==============================
# ABNORMAL
# ==============================
###
@app.get("/abnormal/snapshot")
def get_abnormal_snapshot(use_cache: bool = True):
    """
    Return the raw Abnormal snapshot payload used by dashboard widgets.

    Args:
        use_cache: When true, permits reuse of a fresh Abnormal snapshot cache.

    Returns:
        dict[str, object]: Snapshot metadata, raw endpoint payloads, normalized data, and collection issues.

    Raises:
        HTTPException: Raised with status 500 when the connector cannot collect a snapshot.
    """
    try:
        connector = AbnormalConnector()
        return connector.get_snapshot(use_cache=use_cache)
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.get("/abnormal/endpoints", response_class=HTMLResponse)
def get_abnormal_endpoints(request: Request):
    """
    Render the Abnormal endpoint browser.

    Args:
        request: FastAPI request object required by the Jinja template renderer.

    Returns:
        TemplateResponse: HTML endpoint catalog grouped by functional area.
    """
    return templates.TemplateResponse(
        request=request,
        name="abnormal/endpoints.html",
        context={"endpoint_groups": build_abnormal_endpoint_catalog()},
    )


@app.get("/abnormal/endpoints.json")
def get_abnormal_endpoints_json():
    """
    Return machine-readable Abnormal endpoint metadata.

    Returns:
        dict[str, dict[str, str]]: Mapping of endpoint keys to HTTP methods and upstream paths.
    """
    return {
        key: {"method": method, "path": path}
        for key, (method, path) in ACCESSIBLE_ENDPOINTS.items()
    }


@app.get("/abnormal/{endpoint_key}")
def get_abnormal_endpoint(
    endpoint_key: str, request: Request, format: str | None = None
):
    """
    Proxy a configured Abnormal endpoint and optionally render an HTML preview.

    Args:
        endpoint_key: Key from ``ACCESSIBLE_ENDPOINTS`` identifying the upstream endpoint.
        request: FastAPI request carrying query parameters and accept headers.
        format: Optional output override; ``json`` forces a raw JSON response.

    Returns:
        dict[str, object] | list[object] | TemplateResponse: Raw endpoint payload for API clients or an HTML summary for browsers.

    Raises:
        HTTPException: Raised with status 404 for unknown endpoints or 500 for connector failures.
    """
    try:
        connector = AbnormalConnector()
        query_params = dict(request.query_params)
        query_params.pop("format", None)
        result = connector.get_endpoint(endpoint_key, params=query_params or None)
        if format == "json" or "text/html" not in request.headers.get("accept", ""):
            return result

        method, path = ACCESSIBLE_ENDPOINTS[endpoint_key]
        return templates.TemplateResponse(
            request=request,
            name="abnormal/endpoint_result.html",
            context={
                "endpoint": {
                    "key": endpoint_key,
                    "label": endpoint_key.replace("_", " ").title(),
                    "method": method,
                    "path": path,
                },
                "summary": summarize_endpoint_result(result),
                "result_json": json.dumps(result, indent=2, default=str),
                "display_value": _display_value,
            },
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.post("/abnormal/{endpoint_key}")
async def post_abnormal_endpoint(endpoint_key: str, request: Request):
    """
    Proxy POST requests to a configured Abnormal endpoint.

    Args:
        endpoint_key: Key from ``ACCESSIBLE_ENDPOINTS`` identifying the upstream POST endpoint.
        request: FastAPI request containing JSON body and optional query parameters.

    Returns:
        Any: JSON-compatible Abnormal response payload.

    Raises:
        HTTPException: Raised with status 404 for unknown endpoints or 500 for connector failures.
    """
    try:
        connector = AbnormalConnector()
        payload = await request.json()
        return connector.get_endpoint(
            endpoint_key, params=dict(request.query_params) or None, payload=payload
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


###
# ==============================
# BITSIGHT
# ==============================
###
@app.get("/bitsight/logo")
def get_bitsight_logo():
    """
    Return the cached or freshly fetched BitSight company logo image.

    Returns:
        Response: Binary image response using the upstream content type.

    Raises:
        HTTPException: Raised with status 404 when no logo is available or 500 for connector errors.
    """
    try:
        connector = BitSightConnector()
        image, content_type = connector.get_company_logo_image()

        if not image:
            raise HTTPException(status_code=404, detail="Logo not found")

        return Response(content=image, media_type=content_type)

    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.get("/bitsight/sparkline")
def get_bitsight_sparkline():
    """
    Return the cached or freshly fetched BitSight sparkline image.

    Returns:
        Response: Binary image response used by dashboard ``img`` elements sized to 60x20 pixels.

    Raises:
        HTTPException: Raised with status 404 when no sparkline is available or 500 for connector errors.
    """
    try:
        connector = BitSightConnector()
        image, content_type = connector.get_company_sparkline_image()

        if not image:
            raise HTTPException(status_code=404, detail="Sparkline not found")

        return Response(content=image, media_type=content_type)

    except HTTPException:
        raise
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.get("/bitsight/summary", response_class=HTMLResponse)
def get_bitsight_summary(request: Request):
    """
    Render the BitSight summary dashboard.

    Args:
        request: FastAPI request object required by the Jinja template renderer.

    Returns:
        TemplateResponse: HTML summary page containing rating, risk, date, logo, and sparkline context.

    Raises:
        HTTPException: Raised with status 404 when summary data is missing or 500 for connector failures.
    """
    try:
        connector = BitSightConnector()
        summary = connector.get_company_summary()

        if not summary:
            raise HTTPException(status_code=404, detail="Error fetching summary")

        score = summary.get("score")

        if score >= 740:
            risk_level = "Low"
            status = "Strong security posture"

        elif score >= 640:
            risk_level = "Moderate"
            status = "Acceptable security posture, some risk"

        else:
            risk_level = "High"
            status = "Needs attention"

        return templates.TemplateResponse(
            request=request,
            name="bitsight/summary.html",
            context={
                "company_name": summary.get("name"),
                "score": score,
                "risk_level": risk_level,
                "status": status,
                "rating_date": summary.get("rating_date"),
                "rating_since": summary.get("rating_since"),
                "company_url": summary.get("company_url"),
            },
        )

    except HTTPException:
        raise

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


###
# ==============================
# CROWDSTRIKE
# ==============================
###
@app.get("/crowdstrike/summary")
def get_crowdstrike_summary(use_cache: bool = True):
    """
    Return a compact JSON CrowdStrike summary.

    Args:
        use_cache: When true, permits reuse of a fresh CrowdStrike snapshot cache.

    Returns:
        dict[str, object]: Snapshot metadata, limits, errors, and normalized CrowdStrike data.

    Raises:
        HTTPException: Raised with status 500 when snapshot collection fails.
    """
    try:
        connector = CrowdStrikeConnector()
        snapshot = connector.get_snapshot(use_cache=use_cache)
        return {
            "generated_at": snapshot.get("generated_at"),
            "base_url": snapshot.get("base_url"),
            "limits": snapshot.get("limits"),
            "errors": snapshot.get("errors"),
            "normalized": snapshot.get("normalized"),
        }

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.get("/crowdstrike/raw")
def get_crowdstrike_raw(use_cache: bool = True):
    """
    Return the full CrowdStrike snapshot payload.

    Args:
        use_cache: When true, permits reuse of a fresh CrowdStrike snapshot cache.

    Returns:
        dict[str, object]: Raw and normalized CrowdStrike snapshot data.

    Raises:
        HTTPException: Raised with status 500 when snapshot collection fails.
    """
    try:
        connector = CrowdStrikeConnector()
        return connector.get_snapshot(use_cache=use_cache)

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.get("/crowdstrike/dashboard", response_class=HTMLResponse)
def get_crowdstrike_dashboard(request: Request, use_cache: bool = True):
    """
    Render the CrowdStrike detail dashboard.

    Args:
        request: FastAPI request object required by the Jinja template renderer.
        use_cache: When true, permits reuse of a fresh CrowdStrike snapshot cache.

    Returns:
        TemplateResponse: HTML page with host, event, incident, vulnerability, and grouping details.

    Raises:
        HTTPException: Raised with status 500 when snapshot collection or rendering context preparation fails.
    """
    try:
        connector = CrowdStrikeConnector()
        snapshot = connector.get_snapshot(use_cache=use_cache)
        normalized = snapshot.get("normalized", {})

        return templates.TemplateResponse(
            request=request,
            name="crowdstrike/dashboard.html",
            context={
                "generated_at": snapshot.get("generated_at"),
                "base_url": snapshot.get("base_url"),
                "errors": snapshot.get("errors", {}),
                "summary": normalized.get("summary", {}),
                "groupings": normalized.get("groupings", {}),
                "events": normalized.get("security_events", []),
                "hosts": normalized.get("hosts", []),
            },
        )

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))
