import re

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_home_page_is_served_with_the_page_headers():
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "content-security-policy" in r.headers
    assert "Zero-Trust" in r.text


def test_home_page_has_no_inline_script_or_style():
    html = client.get("/").text
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "<style" not in html and " style=" not in html and "onclick=" not in html


def test_home_page_loads_nothing_from_other_hosts():
    html = client.get("/").text
    assert not re.search(r'<(?:script|link|img)[^>]+(?:src|href)="https?://', html)


def test_stylesheet_is_served_with_the_page_headers():
    r = client.get("/assets/site.css")
    assert r.status_code == 200
    assert "text/css" in r.headers["content-type"]
    assert "content-security-policy" in r.headers


def test_only_listed_assets_are_served():
    assert client.get("/assets/index.html").status_code == 404
    assert client.get("/assets/..%2Fmain.py").status_code == 404


def test_sign_in_button_starts_the_authorization_flow():
    assert 'href="/authorize?response_type=code' in client.get("/").text