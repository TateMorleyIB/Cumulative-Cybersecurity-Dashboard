import json
from app.connectors.abnormal import AbnormalConnector
import app.connectors.abnormal as abnormal_module


def connector(monkeypatch):
    monkeypatch.setattr(abnormal_module, "ABNORMAL_API_KEY", "test-key")
    return AbnormalConnector.__new__(AbnormalConnector)


def test_abnormal_endpoint_resolves_path_params_and_query(monkeypatch):
    abnormal = connector(monkeypatch)
    calls = []

    def fake_request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return {"ok": True}

    monkeypatch.setattr(abnormal, "_request", fake_request)

    result = abnormal.get_endpoint(
        "threat_detail", params={"id": "threat-1", "includeMessages": "true"}
    )

    assert result == {"ok": True}
    assert calls == [
        (
            "GET",
            "/v1/threats/threat-1",
            {"params": {"includeMessages": "true"}},
        )
    ]


def test_abnormal_normalize_builds_overview_from_mixed_payloads(monkeypatch):
    abnormal = connector(monkeypatch)

    normalized = abnormal.normalize(
        {
            "dashboard_summary": {"totalThreats": 8},
            "attack_stopped": {"stopped": 6},
            "cases": {"total": 2, "data": [{"id": "case-1"}]},
            "abuse_not_analyzed": {"resources": [{"id": "abuse-1"}]},
            "iocs": {"resources": [{"id": "ioc-1"}, {"id": "ioc-2"}]},
            "trending_attacks": {"resources": [{"attackType": "BEC", "count": 4}]},
            "attack_vector_breakdown": {"resources": [{"vector": "Link", "count": 3}]},
            "threats": {
                "resources": [
                    {
                        "threatId": "threat-1",
                        "subject": "Invoice lure",
                        "severity": "High",
                    }
                ]
            },
        }
    )

    assert normalized["summary"]["total_threats"] == 8
    assert normalized["summary"]["stopped_attacks"] == 6
    assert normalized["summary"]["open_cases"] == 2
    assert normalized["summary"]["not_analyzed"] == 1
    assert normalized["summary"]["ioc_count"] == 2
    assert normalized["summary"]["risk_level"] == "High"
    assert normalized["trending_attacks"] == [{"label": "BEC", "count": 4}]
    assert normalized["attack_vectors"] == [{"label": "Link", "count": 3}]
    assert normalized["recent_threats"][0]["subject"] == "Invoice lure"


class DummyAbnormalResponse:
    status_code = 200
    content = b'{"resources": []}'
    headers = {"content-type": "application/json"}

    def raise_for_status(self):
        return None

    def json(self):
        return {"resources": []}


def test_abnormal_retries_ssl_certificate_failures_without_verification():
    import requests

    abnormal = AbnormalConnector.__new__(AbnormalConnector)
    abnormal.base_url = "https://api.abnormalplatform.com"
    abnormal.verify = True
    abnormal.allow_insecure_ssl_fallback = True
    abnormal.ssl_warnings = []
    calls = []

    class FakeSession:
        def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            if len(calls) == 1:
                raise requests.exceptions.SSLError("certificate verify failed")
            return DummyAbnormalResponse()

    abnormal.session = FakeSession()

    assert abnormal._request("GET", "/v1/threats") == {"resources": []}
    assert calls[0][2]["verify"] is True
    assert calls[1][2]["verify"] is False
    assert abnormal.verify is False
    assert "TLS certificate verification failed" in abnormal.ssl_warnings[0]


def test_abnormal_does_not_reuse_all_error_cache(tmp_path, monkeypatch):
    cache_file = tmp_path / "abnormal_snapshot.json"
    cache_file.write_text(
        '{"raw": {}, "errors": {"threats": "certificate verify failed"}}'
    )
    monkeypatch.setattr(abnormal_module, "CACHE_FILE", cache_file)

    abnormal = AbnormalConnector.__new__(AbnormalConnector)
    abnormal.cache_ttl = abnormal_module.CACHE_TTL

    assert abnormal._read_cache() is None


def test_abnormal_does_not_write_all_error_cache(tmp_path, monkeypatch):
    cache_file = tmp_path / "abnormal_snapshot.json"
    monkeypatch.setattr(abnormal_module, "CACHE_FILE", cache_file)

    abnormal = AbnormalConnector.__new__(AbnormalConnector)
    abnormal._write_cache(
        {"raw": {}, "errors": {"threats": "certificate verify failed"}}
    )

    assert not cache_file.exists()


def test_abnormal_normalize_does_not_treat_generic_dashboard_total_as_threats(
    monkeypatch,
):
    abnormal = connector(monkeypatch)

    normalized = abnormal.normalize(
        {
            "dashboard_summary": {"total": 100},
            "abuse_not_analyzed": {"total": 100},
            "threats": {"resources": []},
        }
    )

    assert normalized["summary"]["total_threats"] == 0
    assert normalized["summary"]["not_analyzed"] == 100


def test_abnormal_refreshes_cached_normalized_payload_with_current_rules(
    tmp_path, monkeypatch
):
    cache_file = tmp_path / "abnormal_snapshot.json"
    cache_file.write_text(
        json.dumps(
            {
                "raw": {
                    "dashboard_summary": {"total": 100},
                    "abuse_not_analyzed": {"total": 100},
                    "threats": {"resources": []},
                },
                "normalized": {"summary": {"total_threats": 100}},
                "errors": {},
            }
        )
    )
    monkeypatch.setattr(abnormal_module, "CACHE_FILE", cache_file)

    abnormal = AbnormalConnector.__new__(AbnormalConnector)
    abnormal.cache_ttl = abnormal_module.CACHE_TTL

    cached = abnormal._read_cache()

    assert cached["normalized"]["summary"]["total_threats"] == 0
    assert cached["normalized"]["summary"]["not_analyzed"] == 100


def test_abnormal_normalize_extracts_abnormal_named_payloads(monkeypatch):
    abnormal = connector(monkeypatch)

    normalized = abnormal.normalize(
        {
            "attack_stopped": {
                "attack_stopped": [{"attack_count": 234, "prev_attack_count": 195}]
            },
            "trending_attacks": {
                "trending_attacks": [
                    {"attack_type": "Phishing: Credential", "attack_count": 144},
                    {"attack_type": "Spam", "attack_count": 83},
                ]
            },
            "attack_vector_breakdown": {
                "attack_vector_breakdown": [
                    {"attack_vector_group": "Link", "attack_count": 128}
                ]
            },
            "attack_strategy_breakdown": {
                "attack_strategy_breakdown": [
                    {"attack_strategy": "Unknown Sender", "attack_count": 180}
                ]
            },
            "sender_impersonation_breakdown": {
                "sender_impersonation_breakdown": [
                    {"impersonated_party_name": "Unknown Partner", "attack_count": 88}
                ]
            },
            "attacker_origin": {
                "attacker_origin": [{"region_name": "Americas", "attack_count": 190}]
            },
            "most_impersonated_vendor": {
                "most_impersonated_vendor": [
                    {"impersonated_brand_name": "docusign", "attack_count": 2}
                ]
            },
            "recipient_employees": {
                "recipient_employees": [
                    {"display_name": "Executive User", "attack_count": 11}
                ]
            },
            "abuse_not_analyzed": {
                "results": [
                    {
                        "abx_message_id": 1,
                        "subject": "Suspicious report",
                        "not_analyzed_reason": "COULD_NOT_EXTRACT",
                        "reporter": {"email": "reporter@example.com"},
                    }
                ]
            },
            "threats": {"total": 1463, "threats": [{"threatId": "threat-1"}]},
        }
    )

    assert normalized["summary"]["total_threats"] == 1463
    assert normalized["summary"]["stopped_attacks"] == 234
    assert normalized["summary"]["not_analyzed"] == 1
    assert normalized["trending_attacks"] == [
        {"label": "Phishing: Credential", "count": 144},
        {"label": "Spam", "count": 83},
    ]
    assert normalized["attack_vectors"] == [{"label": "Link", "count": 128}]
    assert normalized["attack_strategies"] == [
        {"label": "Unknown Sender", "count": 180}
    ]
    assert normalized["sender_impersonation"] == [
        {"label": "Unknown Partner", "count": 88}
    ]
    assert normalized["attacker_origins"] == [{"label": "Americas", "count": 190}]
    assert normalized["impersonated_vendors"] == [{"label": "docusign", "count": 2}]
    assert normalized["recipient_employees"] == [
        {"label": "Executive User", "count": 11}
    ]
    assert normalized["recent_abuse_reports"][0]["subject"] == "Suspicious report"
