import re

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
PAGE_IDS = {"key", "load", "lock", "outcome", "msg", "updated", "cards", "rows"}


def _ids(html):
    return set(re.findall(r'\bid="([\w-]+)"', html))


def test_admin_page_is_hardened_like_the_other_pages():
    r = client.get("/admin")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    assert "content-security-policy" in r.headers
    assert "no-store" in r.headers["cache-control"]
    html = r.text
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "<style" not in html and " style=" not in html and "onclick=" not in html
    assert not re.search(r'<(?:script|link|img)[^>]+(?:src|href)="https?://', html)
    assert 'src="/assets/admin.js"' in html


def test_admin_assets_are_served_with_the_page_headers():
    css = client.get("/assets/admin.css")
    js = client.get("/assets/admin.js")
    assert css.status_code == 200 and "text/css" in css.headers["content-type"]
    assert js.status_code == 200 and "javascript" in js.headers["content-type"]
    assert "content-security-policy" in css.headers and "content-security-policy" in js.headers


def test_admin_page_has_every_element_the_script_uses():
    html = client.get("/admin").text
    assert PAGE_IDS <= _ids(html)
    js = client.get("/assets/admin.js").text
    used = set(re.findall(r'\$\(\s*["\']([\w-]+)["\']\s*\)', js))
    used |= set(re.findall(r'getElementById\(\s*["\']([\w-]+)["\']\s*\)', js))
    assert used <= _ids(html)


def test_admin_script_never_writes_html_or_stores_the_key():
    js = client.get("/assets/admin.js").text
    for forbidden in (
        "innerHTML", "outerHTML", "insertAdjacentHTML", "document.write",
        "eval(", "new Function", "localStorage", "sessionStorage", "document.cookie",
    ):
        assert forbidden not in js


def test_admin_script_talks_only_to_the_admin_api_on_the_same_origin():
    js = client.get("/assets/admin.js").text
    targets = set(re.findall(r'"(/admin/api/[^"]*)"', js))
    assert targets == {"/admin/api/summary", "/admin/api/events?limit=100"}
    assert not re.search(r"https?://", js)