"""API tests: upload -> pipeline -> storage -> incident browsing, plus
the report stub, health flag, and CORS for the frontend dev server.

Uses FastAPI's TestClient with a per-test temp SQLite file; fixture data
is the synthetic sample logs in data/ (AGENTS.md rule 7).
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.ingest import load_csv
from app import main as api
from app.main import DEV_ORIGINS, app

DATA_DIR = Path(__file__).resolve().parents[2] / "data"
ATTACKS = DATA_DIR / "sample_attacks.csv"
BENIGN = DATA_DIR / "sample_benign.csv"


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """TestClient wired to a fresh temp database per test."""
    monkeypatch.setenv("CYBERSENTRY_DB_PATH", str(tmp_path / "api-test.db"))
    monkeypatch.delenv("CYBERSENTRY_REPORT_MODE", raising=False)
    if hasattr(app.state, "database"):
        del app.state.database
    return TestClient(app)


def upload_csv(client: TestClient, path: Path) -> dict:
    response = client.post(
        "/upload",
        files={"file": (path.name, path.read_bytes(), "text/csv")},
    )
    assert response.status_code == 200, response.text
    return response.json()


def upload_text(client: TestClient, name: str, text: str) -> dict:
    response = client.post(
        "/upload",
        files={"file": (name, text.encode("utf-8"), "text/csv")},
    )
    return response.json() if response.status_code == 200 else {"status_code": response.status_code, "detail": response.json().get("detail")}


class TestHealth:
    def test_health_reports_ok_without_llm(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in (
            "LLM_PROVIDER",
            "LLM_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ):
            monkeypatch.delenv(var, raising=False)
        body = client.get("/health").json()
        assert body["status"] == "ok"
        assert body["service"] == "cybersentry-ai"
        assert body["llm_available"] is False

    def test_health_reports_llm_available_with_key(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-key-not-real")
        assert client.get("/health").json()["llm_available"] is True


class TestUpload:
    @pytest.mark.skipif(not ATTACKS.exists(), reason="generated fixtures not present")
    def test_upload_sample_attacks_counts(self, client: TestClient) -> None:
        events, rejected = load_csv(ATTACKS)
        assert rejected == []
        body = upload_csv(client, ATTACKS)
        assert body["filename"] == "sample_attacks.csv"
        assert body["events"] == len(events)
        assert body["rejected"] == 0
        assert body["incidents"] == 4  # brute, spray, offhours-priv, extvpn

    @pytest.mark.skipif(not BENIGN.exists(), reason="generated fixtures not present")
    def test_upload_sample_benign_yields_no_incidents(self, client: TestClient) -> None:
        body = upload_csv(client, BENIGN)
        assert body["events"] > 0
        assert body["rejected"] == 0
        assert body["incidents"] == 0

    def test_malformed_rows_are_rejected_not_dropped(self, client: TestClient) -> None:
        body = upload_text(
            client,
            "mixed.csv",
            "event_id,timestamp,event_type,user,host,src_ip,severity,message,privileged\n"
            "e1,2024-06-11T10:00:00Z,login_failed,alice,ws-01.lab.local,10.0.0.1,4,fail,false\n"
            "e2,2024-06-11T10:00:01Z,too,many,fields,here,now,right\n",
        )
        assert body["events"] == 1
        assert body["rejected"] == 1

    def test_unsupported_extension_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/upload", files={"file": ("log.exe", b"MZ", "application/octet-stream")}
        )
        assert response.status_code == 400
        assert "unsupported" in response.json()["detail"]

    def test_empty_file_rejected(self, client: TestClient) -> None:
        response = client.post(
            "/upload", files={"file": ("empty.csv", b"", "text/csv")}
        )
        assert response.status_code == 400


@pytest.mark.skipif(not ATTACKS.exists(), reason="generated fixtures not present")
class TestIncidentEndpoints:
    @pytest.fixture()
    def uploaded(self, client: TestClient) -> TestClient:
        upload_csv(client, ATTACKS)
        return client

    def test_list_summaries_have_requested_fields(self, uploaded: TestClient) -> None:
        body = uploaded.get("/incidents").json()
        assert len(body) == 4
        for summary in body:
            assert set(summary) >= {
                "incident_id", "score", "band", "rules", "entities", "event_count",
            }
            assert summary["incident_id"].startswith("inc-")
            assert 0 <= summary["score"] <= 100
            assert summary["rules"]  # every incident traces to rules
            assert summary["event_count"] >= 1
        # Highest score first; brute force (79, High) leads the sample.
        scores = [summary["score"] for summary in body]
        assert scores == sorted(scores, reverse=True)
        brute = next(s for s in body if s["rules"] == ["R1", "R2"])
        assert brute["score"] == 79
        assert brute["band"] == "High"
        assert brute["entities"]["users"] == ["erin"]
        assert brute["event_count"] == 10

    def test_detail_returns_evidence_package_and_timeline(
        self, uploaded: TestClient
    ) -> None:
        brute = next(
            s for s in uploaded.get("/incidents").json() if s["rules"] == ["R1", "R2"]
        )
        detail = uploaded.get(f"/incidents/{brute['incident_id']}").json()
        assert detail["incident_id"] == brute["incident_id"]
        assert detail["score"]["score"] == 79
        assert detail["score"]["rule_component"] == 40  # components exposed
        assert {f["rule_id"] for f in detail["findings"]} == {"R1", "R2"}
        for finding in detail["findings"]:
            assert finding["reasons"]
            assert finding["matched_event_ids"]
        assert len(detail["supporting_records"]) == 10
        assert detail["timeline"]
        stamps = [entry["timestamp"] for entry in detail["timeline"]]
        assert stamps == sorted(stamps)
        assert all("untrusted_text" in entry for entry in detail["timeline"])

    def test_detail_unknown_incident_404(self, uploaded: TestClient) -> None:
        response = uploaded.get("/incidents/inc-doesnotexist")
        assert response.status_code == 404

    def test_reupload_does_not_duplicate_incidents(self, uploaded: TestClient) -> None:
        before = uploaded.get("/incidents").json()
        upload_csv(uploaded, ATTACKS)
        after = uploaded.get("/incidents").json()
        assert len(after) == len(before) == 4


@pytest.mark.skipif(not ATTACKS.exists(), reason="generated fixtures not present")
class TestReport:
    def test_report_falls_back_to_rules_template_without_llm(
        self, client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for var in (
            "LLM_PROVIDER",
            "LLM_API_KEY",
            "OPENAI_API_KEY",
            "ANTHROPIC_API_KEY",
        ):
            monkeypatch.delenv(var, raising=False)
        upload_csv(client, ATTACKS)
        brute = next(
            s for s in client.get("/incidents").json() if s["rules"] == ["R1", "R2"]
        )
        response = client.post(f"/incidents/{brute['incident_id']}/report")
        assert response.status_code == 200
        report = response.json()
        # One schema for both paths; fallback marks the template.
        assert set(report) == {
            "incident_id",
            "summary",
            "observed_facts",
            "hypotheses",
            "alternative_explanations",
            "unknowns",
            "recommended_checks",
            "evidence_sufficient",
            "fallback",
        }
        assert report["incident_id"] == brute["incident_id"]
        assert report["fallback"] is True
        assert report["summary"]
        assert report["evidence_sufficient"] is True
        assert client.get(
            f"/incidents/{brute['incident_id']}"
        ).status_code == 200
        brute_ids = {f"atk-brute-{i:02d}" for i in range(1, 11)}
        facts = report["observed_facts"]
        assert len(facts) == 2  # one per rule finding (R1, R2)
        for fact in facts:
            assert fact["text"]
            assert fact["evidence_ids"]  # every fact cites event IDs
            assert set(fact["evidence_ids"]) <= brute_ids
        cited = {eid for fact in facts for eid in fact["evidence_ids"]}
        assert cited == brute_ids  # every claim traces to real event IDs

        assert report["hypotheses"]
        for hypothesis in report["hypotheses"]:
            assert hypothesis["confidence"] in {"low", "medium", "high"}
            assert set(hypothesis["evidence_ids"]) <= brute_ids

        assert report["alternative_explanations"]
        assert report["unknowns"]
        assert report["recommended_checks"]
        assert all(
            "analyst review" in check.lower()
            for check in report["recommended_checks"]
        )

    def test_cached_report_mode_uses_cache_without_calling_llm(
        self,
        client: TestClient,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("CYBERSENTRY_REPORT_MODE", "cached")
        upload_csv(client, ATTACKS)
        incident_id = client.get("/incidents").json()[0]["incident_id"]

        first = client.post(f"/incidents/{incident_id}/report")
        assert first.status_code == 200
        assert first.json()["fallback"] is True

        def unexpected_llm_call(_detail: dict) -> None:
            raise AssertionError("cached mode must not invoke the LLM")

        monkeypatch.setattr(api, "generate_report", unexpected_llm_call)
        second = client.post(f"/incidents/{incident_id}/report")
        assert second.status_code == 200
        assert second.json() == first.json()

    def test_report_unknown_incident_404(self, client: TestClient) -> None:
        response = client.post("/incidents/inc-doesnotexist/report")
        assert response.status_code == 404


class TestCors:
    def test_preflight_allows_frontend_dev_server(self, client: TestClient) -> None:
        response = client.options(
            "/incidents",
            headers={
                "Origin": DEV_ORIGINS[0],
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.status_code == 200
        assert response.headers["access-control-allow-origin"] == DEV_ORIGINS[0]

    def test_other_origins_not_allowed(self, client: TestClient) -> None:
        response = client.options(
            "/incidents",
            headers={
                "Origin": "https://evil.example.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert "access-control-allow-origin" not in response.headers


class TestSamples:
    """GET /samples — the synthetic log files behind the frontend's
    "use sample dataset" button."""

    def test_samples_list_contains_sample_attacks(self, client: TestClient) -> None:
        body = client.get("/samples").json()
        names = {sample["name"] for sample in body}
        assert "sample_attacks.csv" in names
        assert "sample_benign.csv" in names
        assert "assets.csv" not in names        # inventory, not logs
        by_name = {sample["name"]: sample for sample in body}
        assert by_name["sample_attacks.csv"]["url"] == "/samples/sample_attacks.csv"

    @pytest.mark.skipif(not ATTACKS.exists(), reason="generated fixtures not present")
    def test_sample_file_is_served_byte_for_byte(self, client: TestClient) -> None:
        response = client.get("/samples/sample_attacks.csv")
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/csv")
        assert response.content == ATTACKS.read_bytes()

    def test_unknown_sample_is_404(self, client: TestClient) -> None:
        assert client.get("/samples/no-such-file.csv").status_code == 404

    def test_traversal_style_name_is_rejected(self, client: TestClient) -> None:
        assert client.get("/samples/%2e%2e%2fmain.py").status_code == 404
