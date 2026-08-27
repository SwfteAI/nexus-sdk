"""The collector's bearer token must never reach a host the operator did not configure.

── Why this file exists ────────────────────────────────────────────────────

The redirect credential leak. `HttpSink` builds its opener with
`build_opener(ProxyHandler(...))`, which installs urllib's default
`HTTPRedirectHandler`. On CPython 3.12.13 a **302** from the configured
collector to a *different host* replayed `Authorization: Bearer <api_key>` to
that host — and because urllib followed the hop and the target answered 200,
`send()` returned `ok`. The customer's key reached a third party and nothing
reported it.

The path is ordinary, not exotic: `NEXUS_COLLECTOR_URL` is customer-configured,
so a typo, a stale CNAME, an expired domain someone else now owns, or a proxy
that upgrades a scheme is one redirect away. The SDK runs inside the customer's
production process, so the blast radius is their credential.

A second defect rides along: urllib rewrites POST to GET on a 302, so the event
body is dropped. Telemetry silently stops arriving while the transport reports
success.

── Why a test and not just a docstring ─────────────────────────────────────

A closing observation of that work: in four separate places a docstring
asserting a security property was more accurate about intent than the code was
about behaviour — and in each case **no test would have failed if it broke**.
This is that test. It asserts the behaviour, against a real socket, through the
shipped `HttpSink`, so the guarantee cannot rot into a comment.

── Why 302 specifically ────────────────────────────────────────────────────

The first probe used 307 and came back clean, which would have been a false
all-clear: urllib refuses to follow a 307 for POST, so nothing was replayed and
nothing was proven. It follows a **302** for POST (rewriting it to GET), and 302
is the redirect a misconfigured endpoint actually returns. A narrower test would
have passed this package for publication.
"""

import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from nexus import config as config_mod
from nexus import transport

TOKEN = "SECRET-TOKEN-MUST-NOT-LEAK"


def _handler(seen, name, redirect_to=None):
    class H(BaseHTTPRequestHandler):
        # HTTP/1.0 (the BaseHTTPRequestHandler default) means "no keep-alive", so the
        # handler closes the connection after replying. Combined with the undrained body below
        # that produced a RST, and the client sometimes never processed the 302 at all — the
        # redirect target was never contacted and the test's assertion ran over an empty list.
        # Measured, on CPython 3.12.13: with `_NoRedirect` removed to
        # reinstate the vulnerability, this test caught the leak 5 times in 8. Not vacuous, as
        # first diagnosed — RACING, which is worse, because three runs in eight said "safe".
        protocol_version = "HTTP/1.1"

        def _drain(self):
            """Read the request body before replying.

            This is the whole fix. A server that answers and closes while unread bytes sit in the
            receive buffer gets a RST sent on its behalf, and the client loses the response it was
            already reading. Every real HTTP server drains; this fixture did not, and so the
            redirect under test only sometimes happened.
            """
            try:
                n = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                n = 0
            if n:
                self.rfile.read(n)

        def do_POST(self):
            self._drain()
            seen.setdefault(name, []).append(self.headers.get("Authorization"))
            if redirect_to is not None:
                self.send_response(302)
                self.send_header("Location", redirect_to)
                # Explicit zero length: under HTTP/1.1 a response with neither Content-Length nor
                # chunked framing leaves the client waiting for a body that never comes.
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")

        # urllib rewrites POST to GET on a 302, so the target must answer GET or
        # the connection resets and the real question goes unanswered.
        do_GET = do_POST

        def log_message(self, *_a):
            pass

    return H


@pytest.fixture
def redirecting_collector():
    """A collector that 302s to a DIFFERENT host string on the same machine.

    `127.0.0.1` and `localhost` resolve identically but are different hosts to
    urllib's cross-origin check, which is what decides whether the header is
    carried.
    """
    seen: dict = {}
    target = HTTPServer(("127.0.0.1", 0), _handler(seen, "target"))
    threading.Thread(target=target.serve_forever, daemon=True).start()

    origin = HTTPServer(
        ("127.0.0.1", 0),
        _handler(seen, "origin", f"http://localhost:{target.server_port}/v1/events"),
    )
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    yield seen, origin.server_port

    origin.shutdown()
    target.shutdown()


def test_bearer_token_is_not_replayed_across_a_redirect(redirecting_collector):
    seen, origin_port = redirecting_collector
    cfg = config_mod.Config(
        service="leak-probe",
        env="test",
        version="0",
        collector_url=f"http://127.0.0.1:{origin_port}",
        api_key=TOKEN,
    )

    transport.HttpSink(cfg).send([{"type": "session", "session_id": "x"}])

    assert any(TOKEN in (h or "") for h in seen.get("origin", [])), (
        "the configured collector should have received the token — if this fails "
        "the test is not exercising the path it claims to"
    )
    assert not any(TOKEN in (h or "") for h in seen.get("target", [])), (
        "regression: the API key was replayed to a host the operator "
        "never configured"
    )


def test_a_redirect_is_reported_rather_than_followed(redirecting_collector):
    """The operator learns their URL is not the thing answering.

    Refusing beats stripping the header on cross-host hops: an observability
    sink that quietly follows its endpoint somewhere else is wrong even when no
    credential moves, because the events are then going somewhere nobody chose.
    A surfaced `http 302` says so; a silent success does not.
    """
    seen, origin_port = redirecting_collector
    cfg = config_mod.Config(
        service="leak-probe",
        env="test",
        version="0",
        collector_url=f"http://127.0.0.1:{origin_port}",
        api_key=TOKEN,
    )

    result = transport.HttpSink(cfg).send([{"type": "session", "session_id": "x"}])

    assert result.status != "ok", "a redirect must not be reported as a successful send"
    assert "302" in (result.detail or ""), f"the reason should name the status, got {result.detail!r}"
    assert seen.get("target") is None, "the redirect target should not have been contacted at all"


def test_the_fixture_can_actually_deliver_a_redirect(redirecting_collector):
    """The positive control. **This is the test that was missing.**

    Both tests above assert that the target was *not* contacted. That assertion also passes when
    the target *could not* be contacted — when the fixture is broken, the network never happens,
    and the suite reports safety it never established. That is precisely what was going on: the
    handler replied without draining the POST body, the kernel sent an RST, and the client
    sometimes never processed the 302. Measured with the fix removed, before the fixture was
    repaired: the leak was caught 5 runs in 8. After: 12 in 12.

    So this test drives the same fixture with a plain urllib opener — no `_NoRedirect`, redirects
    followed as urllib would — and asserts the target IS reached. It is the only test here that
    fails if the harness stops working, which makes it the one holding the other two up. If it
    ever goes red, the two tests above have stopped proving anything, whatever colour they show.

    **The body size is load-bearing and was calibrated, not guessed.** The failure mode is a
    server that replies without draining, so the kernel RSTs on close; whether that destroys the
    response depends on how much unread data is sitting in the receive buffer. With a 35-byte body
    this control caught the undrained fixture 1 run in 8 — a control as flaky as the defect it
    guards, which is no control at all. With a body past the socket buffer it is reliable. That
    number is a property of this machine's buffers, so it is generous rather than minimal.

    Note it asserts on the *header*, not merely on contact: the mechanism under test is urllib
    carrying `Authorization` across a cross-host hop, and a target that were contacted without the
    header would mean the sibling assertions are trivially true for the wrong reason.
    """
    import json as _json
    import urllib.request as _req

    seen, origin_port = redirecting_collector
    body = _json.dumps({"type": "session", "session_id": "x", "pad": "p" * 512_000}).encode()
    request = _req.Request(
        f"http://127.0.0.1:{origin_port}/v1/events",
        data=body,
        headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"},
    )
    _req.build_opener().open(request, timeout=5).read()

    assert seen.get("target"), (
        "the fixture never delivered the 302 to a redirect-following client, so the assertions "
        "in this file that the target was not contacted are vacuous"
    )
    assert any(TOKEN in (h or "") for h in seen["target"]), (
        "the target was contacted but without the credential — then urllib is no longer "
        "replaying the header and these tests are guarding a threat that no longer exists "
        "in this form. Re-derive the threat before deleting anything."
    )
