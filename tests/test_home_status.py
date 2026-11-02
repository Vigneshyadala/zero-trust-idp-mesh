import re

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
PATHS = {"/health", "/.well-known/openid-configuration", "/ledger/chain", "/jwks.json"}


def test_status_script_is_served_with_the_page_headers():
    r = client.get("/assets/status.js")
    assert r.status_code == 200
    assert "javascript" in r.headers["content-type"]
    assert "content-security-policy" in r.headers


def test_status_script_never_writes_html_or_evaluates_code():
    js = client.get("/assets/status.js").text
    for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert forbidden not in js


def test_status_script_reads_only_the_four_same_origin_endpoints():
    js = client.get("/assets/status.js").text
    targets = set(re.findall(r'get\("(/[^"]*)"\)', js))
    assert targets == PATHS
    assert not re.search(r"https?://", js)


def test_home_page_has_the_status_slots_and_loads_the_script():
    html = client.get("/").text
    for slot in ("st-service", "st-issuer", "st-ledger", "st-key"):
        assert f'id="{slot}"' in html
    assert 'src="/assets/status.js"' in html


def test_every_status_endpoint_answers_without_credentials():
    assert client.get("/health").json() == {"status": "ok"}
    assert "issuer" in client.get("/.well-known/openid-configuration").json()
    chain = client.get("/ledger/chain").json()
    assert chain["valid"] is True and isinstance(chain["length"], int)
    key = client.get("/jwks.json").json()["keys"][0]
    assert key["alg"] == "EdDSA" and key["kid"]