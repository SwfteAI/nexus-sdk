"""The collector endpoint must be one this SDK is willing to speak to, and a
bearer token must never ride cleartext off the machine.

Two credential-exposure defects in the collector URL. Both were reachable by
setting a single environment variable in the customer's process — a compromised
sidecar, a leaked CI config, a mis-templated Helm chart.

Every assertion here failed before the fix. That is the point: four security
properties had accurate docstrings and no test that would fail if the behaviour
broke.
"""

import pytest

from nexus import config as config_mod
from nexus import transport

KEY = "SECRET-TOKEN-MUST-NOT-LEAK"


def _cfg(url: str) -> config_mod.Config:
    return config_mod.Config(
        service="probe", env="test", version="0", collector_url=url, api_key=KEY,
    )


# ── Only http and https, nothing else ──────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "ftp://example.invalid/x",
    "gopher://example.invalid",
    "notaurl",
])
def test_a_collector_url_the_sdk_must_not_speak_is_refused(url):
    """`build_opener` installs FileHandler, FTPHandler and DataHandler.

    Without an allowlist each of these was accepted and turned into an events
    URL, so one environment variable redirected the entire telemetry stream.
    """
    with pytest.raises(ValueError):
        config_mod._collector_url(url)


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8791",
    "https://collector.example.com",
])
def test_the_two_schemes_a_collector_may_speak_are_accepted(url):
    assert config_mod._collector_url(url) == url


def test_an_empty_value_means_unset_not_invalid(monkeypatch):
    """An empty string is an ABSENT setting, not a malformed one.

    Raising here would turn `NEXUS_COLLECTOR_URL=""` — which a shell exports for
    any unset variable in a templated env file — into a hard startup failure,
    and a telemetry SDK must not break its host over its own configuration
    being blank. It falls through to the host/port default instead.
    """
    monkeypatch.delenv("NEXUS_COLLECTOR_URL", raising=False)
    monkeypatch.delenv("NEXUS_COLLECTOR_HOST", raising=False)
    monkeypatch.delenv("NEXUS_COLLECTOR_SCHEME", raising=False)
    assert config_mod._collector_url("").startswith("http://127.0.0.1")


# ── The scheme is not hard-coded, and auth never rides cleartext ─────

def test_https_is_reachable_through_the_host_and_port_route(monkeypatch):
    """Half one: the scheme was hard-coded, so an operator wanting TLS
    had to abandon both documented variables for a whole URL.

    The default is deliberately still `http` — this route exists for a
    Kubernetes sidecar at `$(NODE_IP):8791` where cluster-internal plaintext is
    normal and no certificate exists. Forcing TLS here was tried and reverted:
    it broke `test_1_13_sidecar_collector_is_not_hardcoded_to_loopback`, and
    that test is right.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_HOST", "collector.example.com")
    monkeypatch.setenv("NEXUS_COLLECTOR_PORT", "443")
    monkeypatch.setenv("NEXUS_COLLECTOR_SCHEME", "https")
    monkeypatch.delenv("NEXUS_COLLECTOR_URL", raising=False)
    assert config_mod._collector_url(None) == "https://collector.example.com:443"


def test_a_sidecar_over_the_pod_network_still_gets_plaintext(monkeypatch):
    """The deployment this route exists for keeps working. The credential is
    protected by withholding the bearer token, not by breaking the transport."""
    monkeypatch.setenv("NEXUS_COLLECTOR_HOST", "10.0.0.5")
    monkeypatch.setenv("NEXUS_COLLECTOR_PORT", "8791")
    monkeypatch.delenv("NEXUS_COLLECTOR_URL", raising=False)
    monkeypatch.delenv("NEXUS_COLLECTOR_SCHEME", raising=False)
    assert config_mod._collector_url(None) == "http://10.0.0.5:8791"


def test_loopback_stays_plaintext(monkeypatch):
    """No transport to protect, and demanding a certificate for 127.0.0.1 would
    push people onto the full-URL escape hatch — which is how they end up on
    plaintext remotely in the first place."""
    monkeypatch.setenv("NEXUS_COLLECTOR_HOST", "127.0.0.1")
    monkeypatch.setenv("NEXUS_COLLECTOR_PORT", "8791")
    monkeypatch.delenv("NEXUS_COLLECTOR_URL", raising=False)
    monkeypatch.delenv("NEXUS_COLLECTOR_SCHEME", raising=False)
    assert config_mod._collector_url(None) == "http://127.0.0.1:8791"


def test_the_bearer_token_is_withheld_from_remote_plaintext():
    sink = transport.HttpSink(_cfg("http://collector.example.com:8791"))
    assert "Authorization" not in sink._headers(), (
        "regression: the API key was attached to a cleartext request "
        "leaving the machine"
    )


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8791",
    "http://localhost:8791",
    "https://collector.example.com",
])
def test_the_bearer_token_is_sent_where_it_is_safe(url):
    """Guard against over-correction: withholding it everywhere would break
    every real deployment and be 'fixed' by reverting the whole guard."""
    sink = transport.HttpSink(_cfg(url))
    assert sink._headers().get("Authorization") == f"Bearer {KEY}"


@pytest.mark.parametrize("url", [
    # Registrable domains. The guard used to end in `host.startswith("127.")`, and every one of
    # these is a name an attacker can own and point wherever they like.
    "http://127.0.0.1.attacker.example/v1/events",
    "http://127.0.0.1.evil.co.uk/v1/events",
    "http://127.0.0.1x.attacker.example/v1/events",
    "http://localhost.attacker.example/v1/events",
    # userinfo: the host is what follows the last '@'. Reading left to right finds "127.0.0.1"
    # and gets the destination exactly backwards.
    "http://127.0.0.1@attacker.example/v1/events",
    "http://localhost@attacker.example/v1/events",
])
def test_a_hostile_host_that_merely_looks_like_loopback_gets_no_credential(url):
    """The destination decides, and the destination is parsed, not prefix-matched.

    Each of these resolves somewhere an attacker controls while containing loopback text. A
    string test on the URL says "local"; the resolver says otherwise, and the resolver is the one
    that moves the bytes.
    """
    sink = transport.HttpSink(_cfg(url))
    assert "Authorization" not in sink._headers(), (
        f"regression: the API key was attached for {url!r}, which is not this machine")


def test_a_proxy_does_not_carry_the_credential_even_to_a_loopback_url(monkeypatch):
    """End to end against a real socket.

    A mock cannot show this. The finding is not "the SDK builds a bad header" — the header is
    correct for the URL as written. It is that urllib, for a *cleartext* destination, sends the
    entire request to the proxy instead of tunnelling, so a URL the guard cleared as local is
    delivered to a third party. Only a real proxy that records what it received can distinguish
    "routed direct" from "routed through the proxy", which is the whole question.

    Measured before the fix: the proxy received ``Authorization: Bearer <key>`` in cleartext and
    ``send()`` returned ``ok`` — while the collector port was closed and had received nothing.
    """
    import http.server
    import socket
    import threading

    seen = {}

    class Recorder(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen["headers"] = {k.lower(): v for k, v in self.headers.items()}
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Recorder)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        # A closed port, so anything the recorder sees can only have arrived via the proxy.
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        closed_port = s.getsockname()[1]
        s.close()

        monkeypatch.setenv("HTTP_PROXY", f"http://127.0.0.1:{srv.server_address[1]}")
        monkeypatch.setenv("http_proxy", f"http://127.0.0.1:{srv.server_address[1]}")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        monkeypatch.setattr(transport, "_PROXIES", None)   # module cache; re-read the env

        sink = transport.HttpSink(_cfg(f"http://127.0.0.1:{closed_port}/v1/events"))
        result = sink.send([{"event": "probe"}])

        assert not seen, (
            "regression: a loopback collector URL was routed through HTTP_PROXY; "
            f"the proxy received {seen.get('headers', {}).get('authorization')!r}")
        assert result.status != "ok", (
            "the collector port was closed, so a success here means the SDK reported delivery "
            "for a batch that reached no collector")
    finally:
        srv.shutdown()
        transport._PROXIES = None


def test_a_proxied_remote_plaintext_url_gets_no_credential(monkeypatch):
    """The other half: the guard must consult the same routing the opener performs."""
    monkeypatch.setenv("HTTP_PROXY", "http://proxy.internal:3128")
    monkeypatch.setenv("http_proxy", "http://proxy.internal:3128")
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setattr(transport, "_PROXIES", None)
    try:
        sink = transport.HttpSink(_cfg("http://collector.example.com/v1/events"))
        assert "Authorization" not in sink._headers()
        # ...while TLS through the same proxy is still fine: CONNECT tunnels, so the proxy sees a
        # hostname and never the header. Withholding here would be over-correction.
        tls = transport.HttpSink(_cfg("https://collector.example.com/v1/events"))
        assert tls._headers().get("Authorization") == f"Bearer {KEY}"
    finally:
        transport._PROXIES = None
