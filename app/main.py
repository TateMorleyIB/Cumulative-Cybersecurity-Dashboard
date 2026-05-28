from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from app.connectors.bitsight import BitSightConnector
from app.connectors.crowdstrike import CrowdStrikeConnector

app = FastAPI(title="Cumulative Cybersecurity Dashboard", version="1.0.0")

templates = Jinja2Templates(directory="app/templates")
app.mount("/assets", StaticFiles(directory="app/templates/assets"), name="assets")


@app.get("/")
def root():
    return {"status": "running", "message": "Cybersecurity Dashboard API Online"}


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
