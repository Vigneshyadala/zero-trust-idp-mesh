import re

from fastapi.testclient import TestClient

from app.core.version import NAME, VERSION
from app.main import app

client = TestClient(app)


def test_version_endpoint_reports_name_and_version():
    r = client.get("/version")
    assert r.status_code == 200
    assert r.json() == {"name": NAME, "version": VERSION}


def test_version_looks_like_a_release_number():
    assert re.fullmatch(r"\d+\.\d+(\.\d+)?", VERSION)


def test_version_matches_the_openapi_document():
    assert client.get("/openapi.json").json()["info"]["version"] == VERSION


def test_landing_page_footer_shows_the_same_version():
    assert f"v{VERSION}" in client.get("/").text
