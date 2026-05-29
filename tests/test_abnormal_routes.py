from pathlib import Path

from starlette.requests import Request

from app import main


class FakeAbnormalConnector:
    def get_endpoint(self, endpoint_key, params=None, payload=None):
        assert endpoint_key == "abusecampaigns"
        return {
            "campaigns": [
                {"campaignId": "campaign-1", "status": "open"},
                {"campaignId": "campaign-2", "status": "closed"},
            ]
        }


def request_with_accept(accept: str) -> Request:
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/abnormal/abusecampaigns",
            "query_string": b"",
            "headers": [(b"accept", accept.encode())],
            "app": main.app,
            "router": main.app.router,
        }
    )


def test_endpoint_catalog_includes_param_names_for_id_toggle():
    groups = main.build_abnormal_endpoint_catalog()
    endpoints = {
        endpoint["key"]: endpoint
        for group in groups
        for endpoint in group["endpoints"]
    }

    assert endpoints["threat_detail"]["requires_params"] is True
    assert endpoints["threat_detail"]["param_names"] == ["id"]
    assert endpoints["abusecampaigns"]["requires_params"] is False


def test_abnormal_endpoint_browser_has_hide_needs_id_switch():
    template = Path("app/templates/abnormal/endpoints.html").read_text()

    assert "hide-needs-id" in template
    assert "TODO: Add forms for endpoints with path parameters" in template
    assert 'data-needs-id="{{' in template
    assert "needs-id-endpoint is-hidden" in template
    assert "updateGroupVisibility" in template


def test_abnormal_get_endpoint_prepares_html_result_for_browser(monkeypatch):
    monkeypatch.setattr(main, "AbnormalConnector", lambda: FakeAbnormalConnector())

    response = main.get_abnormal_endpoint(
        "abusecampaigns", request_with_accept("text/html")
    )

    assert response.template.name == "abnormal/endpoint_result.html"
    assert response.context["endpoint"]["label"] == "Abusecampaigns"
    assert response.context["summary"]["title"] == "Campaigns"
    assert response.context["summary"]["count"] == 2
    assert "campaign-1" in response.context["result_json"]


def test_abnormal_get_endpoint_still_returns_json_when_requested(monkeypatch):
    monkeypatch.setattr(main, "AbnormalConnector", lambda: FakeAbnormalConnector())

    response = main.get_abnormal_endpoint(
        "abusecampaigns", request_with_accept("application/json"), format="json"
    )

    assert response["campaigns"][0]["campaignId"] == "campaign-1"
