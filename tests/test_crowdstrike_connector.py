from datetime import timedelta

import requests

from app.connectors.crowdstrike import CACHE_TTL, CrowdStrikeConnector, DEFAULT_LIMITS


class DummyResponse:
    def __init__(self, status_code=400):
        self.status_code = status_code
        self.text = ""

    def json(self):
        return {"errors": [{"message": "mock error"}]}


def http_error(status_code):
    response = DummyResponse(status_code)
    return requests.HTTPError(f"{status_code} error", response=response)


def connector():
    return CrowdStrikeConnector.__new__(CrowdStrikeConnector)


def test_alert_entities_are_requested_with_post_composite_ids(monkeypatch):
    crowdstrike = connector()
    calls = []

    def fake_query_ids_with_fallbacks(path, limit, sorts, filter_query=None):
        assert path == "/alerts/queries/alerts/v2"
        assert limit == 2
        assert sorts[0] == "created_timestamp|desc"
        assert filter_query is None
        return ["composite-1", "composite-2"]

    def fake_request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return {"resources": [{"id": "alert-1"}]}

    monkeypatch.setattr(crowdstrike, "_query_ids_with_fallbacks", fake_query_ids_with_fallbacks)
    monkeypatch.setattr(crowdstrike, "_request", fake_request)

    assert crowdstrike.get_alerts(limit=2) == [{"id": "alert-1"}]
    assert calls == [
        (
            "POST",
            "/alerts/entities/alerts/v2",
            {"json": {"composite_ids": ["composite-1", "composite-2"]}},
        )
    ]


def test_legacy_detection_404_falls_back_to_endpoint_alerts(monkeypatch):
    crowdstrike = connector()
    attempted_legacy = False

    def fake_query_ids_with_fallbacks(path, limit, sorts, filter_query=None):
        nonlocal attempted_legacy
        if path == "/detects/queries/detects/v1":
            attempted_legacy = True
            raise http_error(404)
        assert path == "/alerts/queries/alerts/v2"
        assert filter_query == "data_domains:'Endpoint'"
        return ["endpoint-alert"]

    def fake_fetch_entities_post(path, ids, id_key="ids"):
        assert path == "/alerts/entities/alerts/v2"
        assert ids == ["endpoint-alert"]
        assert id_key == "composite_ids"
        return [{"id": "endpoint-alert"}]

    monkeypatch.setattr(crowdstrike, "_query_ids_with_fallbacks", fake_query_ids_with_fallbacks)
    monkeypatch.setattr(crowdstrike, "_fetch_entities_post", fake_fetch_entities_post)

    assert crowdstrike.get_detections(limit=1) == [{"id": "endpoint-alert"}]
    assert attempted_legacy is True


def test_identity_alerts_use_unified_alerts_api(monkeypatch):
    crowdstrike = connector()

    def fake_get_alerts_by_filter(limit, filter_query=None, fallback_filter=None):
        assert limit == DEFAULT_LIMITS["identity_alerts"]
        assert filter_query == "data_domains:'Identity'"
        assert fallback_filter == "product:'idp'"
        return [{"id": "identity-alert"}]

    monkeypatch.setattr(crowdstrike, "_get_alerts_by_filter", fake_get_alerts_by_filter)

    assert crowdstrike.get_identity_alerts() == [{"id": "identity-alert"}]


def test_vulnerability_query_uses_filtered_combined_spotlight_endpoint(monkeypatch):
    crowdstrike = connector()
    calls = []

    def fake_query(path, limit, sort=None, filter_query=None):
        calls.append((path, limit, sort, filter_query))
        return {"resources": [{"id": "vulnerability-1"}]}

    monkeypatch.setattr(crowdstrike, "_query", fake_query)

    assert crowdstrike.get_vulnerabilities(limit=500) == [{"id": "vulnerability-1"}]
    assert calls == [
        (
            "/spotlight/combined/vulnerabilities/v1",
            400,
            None,
            "last_seen_within:'90'",
        )
    ]


def test_vulnerability_query_falls_back_to_filtered_id_lookup(monkeypatch):
    crowdstrike = connector()

    def fake_query_combined_vulnerabilities(limit, filter_query):
        raise http_error(400)

    def fake_query_ids_with_fallbacks(path, limit, sorts, filter_query=None):
        assert path == "/spotlight/queries/vulnerabilities/v1"
        assert limit == 400
        assert sorts[0] == "updated_timestamp|desc"
        assert filter_query == "last_seen_within:'90'"
        return ["vulnerability-1"]

    def fake_fetch_entities_post(path, ids, id_key="ids"):
        assert path == "/spotlight/entities/vulnerabilities/v2"
        assert ids == ["vulnerability-1"]
        assert id_key == "ids"
        return [{"id": "vulnerability-1"}]

    monkeypatch.setattr(
        crowdstrike,
        "_query_combined_vulnerabilities",
        fake_query_combined_vulnerabilities,
    )
    monkeypatch.setattr(crowdstrike, "_query_ids_with_fallbacks", fake_query_ids_with_fallbacks)
    monkeypatch.setattr(crowdstrike, "_fetch_entities_post", fake_fetch_entities_post)

    assert crowdstrike.get_vulnerabilities(limit=500) == [{"id": "vulnerability-1"}]


def test_normalization_handles_nested_dict_values_without_unhashable_errors():
    crowdstrike = connector()
    normalized = crowdstrike.normalize(
        {
            "hosts": [
                {
                    "device_id": "host-1",
                    "hostname": {"name": "nested-hostname"},
                    "platform_name": {"name": "Windows"},
                    "last_seen": {"unexpected": "timestamp-shape"},
                }
            ],
            "detections": [
                {
                    "detection_id": "ldt:1",
                    "display_name": "Nested detection",
                    "status": {"name": "new"},
                    "device": {"hostname": "detected-host"},
                    "user_name": {"username": "analyst"},
                    "behaviors": [{"severity": "High"}],
                }
            ],
            "alerts": [],
            "identity_alerts": [],
            "incidents": [],
            "vulnerabilities": [],
        }
    )

    assert normalized["summary"]["total_hosts"] == 1
    assert normalized["summary"]["critical_or_high_events"] == 1
    assert normalized["summary"]["top_sources"] == [("detected-host", 1)]
    assert normalized["summary"]["top_users"] == [("analyst", 1)]
    assert normalized["groupings"]["hosts_by_platform"] == {"Windows": 1}


def test_crowdstrike_cache_ttl_is_fifteen_minutes():
    assert CACHE_TTL == timedelta(minutes=15)
