"""Exercise real WordPress cookie authentication and export serving on a local test site."""
import http.cookiejar
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request

root = os.environ.get("SSA_TEST_URL", "http://127.0.0.1:8888").rstrip("/")
assert urllib.parse.urlparse(root).hostname in {"localhost", "127.0.0.1", "::1"}, "Local test sites only"
client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
client.open(root + "/wp-login.php", timeout=20).read()
login = urllib.parse.urlencode({
    "log": os.environ.get("SSA_TEST_USER", "admin"),
    "pwd": os.environ.get("SSA_TEST_PASSWORD", "password"),
    "wp-submit": "Log In",
    "testcookie": "1",
    "redirect_to": root + "/wp-admin/",
}).encode()
client.open(root + "/wp-login.php", data=login, timeout=20).read()
page = client.open(root + "/wp-admin/admin.php?page=site-security-auditor", timeout=20).read().decode()
settings = re.search(r"window\.ssaSettings\s*=\s*(\{.*?\})\s*;", page)
assert settings, "Authenticated admin shell or nonce configuration missing"
nonce = json.loads(settings.group(1))["nonce"]


def request(path):
    req = urllib.request.Request(root + "/wp-json/site-security-auditor/v1" + path,
                                 headers={"X-WP-Nonce": nonce})
    with client.open(req, timeout=20) as response:
        return response.headers, response.read()


headers, body = request("/overview")
assert headers["Cache-Control"] and "no-store" in headers["Cache-Control"]
assert "latest" in json.loads(body)
_, body = request("/scans")
scans = json.loads(body)["items"]
scan = next(item for item in scans if item["status"] in {"completed", "partial"})
for format_name, mime_type in (("json", "application/json"), ("csv", "text/csv")):
    headers, body = request(f"/scans/{scan['id']}/export?format={format_name}")
    assert mime_type in headers["Content-Type"], "Incorrect export MIME type"
    assert headers["Content-Disposition"].endswith(f".{format_name}\""), "Missing attachment filename"
    assert "no-store" in headers["Cache-Control"], "Export must not be cached"
    assert headers["X-Content-Type-Options"] == "nosniff"
    text = body.decode("utf-8")
    assert "Warning:" not in text and "Fatal error:" not in text, "PHP diagnostics leaked"
    assert str(os.getcwd()) not in text, "Absolute workspace path leaked"
    if format_name == "json":
        report = json.loads(body)
        assert report["scan"]["id"] == scan["id"]
        assert len(report["scan"]["checks"]) == 16
        assert "progress" not in report["scan"]
    else:
        assert text.startswith("check_id,status,severity,")

try:
    urllib.request.urlopen(root + "/wp-json/site-security-auditor/v1/overview", timeout=20)
    raise AssertionError("Anonymous HTTP access succeeded")
except urllib.error.HTTPError as error:
    assert error.code == 403, f"Unexpected anonymous status: {error.code}"
print("PASS: real HTTP cookie/nonce authentication, private JSON/CSV attachments, headers and stored scan identity")
