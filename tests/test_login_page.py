import re

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)
SCRIPT_IDS = {"did", "create-identity", "register", "login-section", "login", "no-request", "log"}


def _ids(html):
    return set(re.findall(r'\bid="([\w-]+)"', html))


def test_login_page_keeps_every_element_the_script_needs():
    html = client.get("/login").text
    assert SCRIPT_IDS <= _ids(html)


def test_every_id_the_script_looks_up_exists_in_the_page():
    js = client.get("/static/passkeys.js").text
    used = set()
    used |= set(re.findall(r'getElementById\(\s*["\']([\w-]+)["\']\s*\)', js))
    used |= set(re.findall(r'\$\(\s*["\']([\w-]+)["\']\s*\)', js))
    used |= set(re.findall(r'querySelector\(\s*["\']#([\w-]+)["\']\s*\)', js))
    assert used <= _ids(client.get("/login").text)


def test_login_page_is_served_with_the_page_headers_and_same_script():
    r = client.get("/login")
    assert r.status_code == 200
    assert "content-security-policy" in r.headers
    assert 'src="/static/passkeys.js"' in r.text
    css = client.get("/static/passkeys.css")
    assert css.status_code == 200 and "text/css" in css.headers["content-type"]


def test_login_page_has_no_inline_script_or_style_and_no_foreign_hosts():
    html = client.get("/login").text
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)
    assert "<style" not in html and " style=" not in html and "onclick=" not in html
    assert not re.search(r'<(?:script|link|img)[^>]+(?:src|href)="https?://', html)


def test_login_page_shares_the_site_stylesheet_and_links_home():
    html = client.get("/login").text
    assert 'href="/assets/site.css"' in html and 'href="/"' in html
    assert client.get("/assets/site.css").status_code == 200


def test_demo_alias_serves_the_same_page():
    assert client.get("/demo").text == client.get("/login").text