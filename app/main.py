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
    try:
        connector = AbnormalConnector()
        snapshot = connector.get_snapshot(use_cache=use_cache)
        normalized = snapshot.get("normalized", {})
        summary = normalized.get("summary", {})
        errors = snapshot.get("errors", {})
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
            "recent_threats": normalized.get("recent_threats", []),
            "errors": errors,
            "warnings": warnings,
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
            "recent_threats": [],
            "error": str(error),
        }


@app.get("/dashboard", response_class=HTMLResponse)
def get_master_dashboard(request: Request, use_cache: bool = True):
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
    try:
        connector = AbnormalConnector()
        return connector.get_snapshot(use_cache=use_cache)
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.get("/abnormal/endpoints")
def get_abnormal_endpoints():
    return {
        key: {"method": method, "path": path}
        for key, (method, path) in ACCESSIBLE_ENDPOINTS.items()
    }


@app.get("/abnormal/{endpoint_key}")
def get_abnormal_endpoint(endpoint_key: str, request: Request):
    try:
        connector = AbnormalConnector()
        return connector.get_endpoint(
            endpoint_key, params=dict(request.query_params) or None
        )
    except ValueError as error:
        raise HTTPException(status_code=404, detail=str(error))
    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.post("/abnormal/{endpoint_key}")
async def post_abnormal_endpoint(endpoint_key: str, request: Request):
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
    try:
        connector = CrowdStrikeConnector()
        return connector.get_snapshot(use_cache=use_cache)

    except Exception as error:
        raise HTTPException(status_code=500, detail=str(error))


@app.get("/crowdstrike/dashboard", response_class=HTMLResponse)
def get_crowdstrike_dashboard(request: Request, use_cache: bool = True):
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
