"""ANCHOR-INTEGRATION §6 — provenance, integration probes, service health, self-reported deploys.

Four additive entry points and one resolver. The assertions worth reading twice are the ones about
**absence**, because absence is what this whole feature is for: the console draws a *break* in the
provenance chain where a value is missing, and the shadow-deploy accent — "production contains
software that no release accounts for" — fires off that break. A default, a sentinel, or a guessed
value anywhere in this path does not merely record something slightly wrong; it silences a real
alarm permanently and makes it unfalsifiable. So most of what follows checks that a key is *not
there* rather than that it holds the right thing.
"""
from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from nexus import provenance


# -- §6.1 provenance detection ---------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_ambient_provenance(monkeypatch):
    """Strip every variable the detectors read, so a developer's own CI does not seed the tests."""
    for var in ("VERCEL", "VERCEL_ENV", "VERCEL_GIT_COMMIT_SHA", "VERCEL_GIT_REPO_OWNER",
                "VERCEL_GIT_REPO_SLUG", "VERCEL_GIT_COMMIT_REF", "VERCEL_DEPLOYMENT_ID",
                "GITHUB_ACTIONS", "GITHUB_SHA", "GITHUB_REPOSITORY", "GITHUB_SERVER_URL",
                "GITHUB_REF_NAME", "APP_KUBERNETES_IO_NAME", "APP_KUBERNETES_IO_VERSION",
                "K8S_APP_NAME", "K8S_APP_VERSION", "OCI_IMAGE_REVISION", "OCI_IMAGE_SOURCE",
                "OCI_IMAGE_VERSION", "ORG_OPENCONTAINERS_IMAGE_REVISION",
                "ORG_OPENCONTAINERS_IMAGE_SOURCE", "ORG_OPENCONTAINERS_IMAGE_VERSION",
                "NEXUS_APPLICATION", "NEXUS_REPO", "NEXUS_COMMIT", "NEXUS_BRANCH",
                "NEXUS_DEPLOYMENT_ID", "NEXUS_PODINFO_DIR"):
        monkeypatch.delenv(var, raising=False)
    # /etc/podinfo does not exist on a developer's laptop, but it does inside a pod, and a test run
    # in-cluster must not read the cluster's labels.
    monkeypatch.setenv("NEXUS_PODINFO_DIR", "/nonexistent-podinfo")


def test_6_1_nothing_detected_means_nothing_recorded():
    """The default state of the world. No platform, no keys — not keys holding ``None``.

    A key present with a null value is a claim that we looked and found emptiness. That is a
    different fact from not having looked, and only one of them should silence anything.
    """
    d = provenance.detect()
    assert d.values == {}
    assert d.sources == {}
    assert d.provenance_source is None


def test_6_1_vercel_records_the_variable_each_value_came_from(monkeypatch):
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_ENV", "production")
    monkeypatch.setenv("VERCEL_GIT_COMMIT_SHA", "c1e88a04d5f7")
    monkeypatch.setenv("VERCEL_GIT_REPO_OWNER", "example-org")
    monkeypatch.setenv("VERCEL_GIT_REPO_SLUG", "example-app")
    monkeypatch.setenv("VERCEL_GIT_COMMIT_REF", "main")
    monkeypatch.setenv("VERCEL_DEPLOYMENT_ID", "dpl_abc")

    d = provenance.detect()
    assert d.values["commit"] == "c1e88a04d5f7"
    assert d.sources["commit"] == "env:VERCEL_GIT_COMMIT_SHA"
    assert d.provenance_source == "env:VERCEL_GIT_COMMIT_SHA"
    assert d.values["repo"] == "example-org/example-app"
    assert d.values["branch"] == "main"
    assert d.values["deployment_id"] == "dpl_abc"
    assert d.values["env"] == "production"
    # No host: Vercel does not publish one, and mapping its provider word onto github.com is
    # correct until the customer is on GitHub Enterprise, where it joins to nothing.
    assert "github.com" not in d.values["repo"]


def test_6_1_a_half_known_repo_is_dropped_not_half_written(monkeypatch):
    """Owner absent, slug present. A bare name is not a repo identity, and half a join key joins to
    the wrong repository rather than to none."""
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_GIT_REPO_SLUG", "example-app")
    assert "repo" not in provenance.detect().values


def test_6_1_vercel_variables_without_vercel_are_not_read(monkeypatch):
    """``VERCEL_*`` with no ``VERCEL``/``VERCEL_ENV`` could be anything a customer exported."""
    monkeypatch.setenv("VERCEL_GIT_COMMIT_SHA", "c1e88a04d5f7")
    assert provenance.detect().values == {}


def test_6_1_github_actions_is_the_only_platform_that_supplies_a_host(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", "5d0c7712ab98")
    monkeypatch.setenv("GITHUB_REPOSITORY", "example-org/billing-api")
    monkeypatch.setenv("GITHUB_SERVER_URL", "https://github.example.com")
    monkeypatch.setenv("GITHUB_REF_NAME", "release/4.1")

    d = provenance.detect()
    assert d.values["repo"] == "github.example.com/example-org/billing-api"
    assert d.sources["repo"] == "env:GITHUB_SERVER_URL+GITHUB_REPOSITORY"
    assert d.values["commit"] == "5d0c7712ab98"
    assert d.values["branch"] == "release/4.1"


def test_6_1_kubernetes_labels_are_the_only_auto_detected_application(monkeypatch):
    """``app.kubernetes.io/name`` is an operator's declaration, not a similarity we noticed."""
    monkeypatch.setenv("APP_KUBERNETES_IO_NAME", "example-app")
    monkeypatch.setenv("APP_KUBERNETES_IO_VERSION", "2026.8.1")
    d = provenance.detect()
    assert d.values["application"] == "example-app"
    assert d.values["version"] == "2026.8.1"
    assert d.sources["application"] == "env:APP_KUBERNETES_IO_NAME"


def test_6_1_a_repo_slug_never_becomes_an_application(monkeypatch):
    """The refusal that keeps `app_id` meaningful. One application may span three repos; a repo
    slug that happens to equal an app slug is a coincidence, not a join."""
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "example-org/example-app")
    assert "application" not in provenance.detect().values


def test_6_1_podinfo_labels_file_is_read_and_cited(monkeypatch, tmp_path):
    (tmp_path / "labels").write_text(
        'app.kubernetes.io/name="example-app"\n'
        'app.kubernetes.io/version="2026.8.1"\n'
        'malformed line with no equals\n')
    monkeypatch.setenv("NEXUS_PODINFO_DIR", str(tmp_path))
    d = provenance.detect()
    assert d.values["application"] == "example-app"
    assert d.sources["application"].startswith("file:")
    assert d.sources["application"].endswith("#app.kubernetes.io/name")


def test_6_1_oci_labels_normalise_a_source_url_without_inventing_one(monkeypatch):
    monkeypatch.setenv("OCI_IMAGE_REVISION", "abc123def456")
    monkeypatch.setenv("OCI_IMAGE_SOURCE", "https://github.com/example-org/example-app.git")
    d = provenance.detect()
    assert d.values["commit"] == "abc123def456"
    assert d.values["repo"] == "github.com/example-org/example-app"
    assert d.sources["repo"] == "env:OCI_IMAGE_SOURCE"


def test_6_1_detection_order_is_first_hit_wins_per_field(monkeypatch):
    """Vercel before GitHub Actions: a Vercel build running inside Actions has both, and the
    deployment platform's answer is the one that describes the running process."""
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_GIT_COMMIT_SHA", "vercel-sha")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_SHA", "actions-sha")
    monkeypatch.setenv("GITHUB_REPOSITORY", "example-org/example-app")
    d = provenance.detect()
    assert d.values["commit"] == "vercel-sha"
    # …but a field Vercel did not supply is still filled by the next detector.
    assert d.values["repo"] == "example-org/example-app"


def test_6_1_a_detector_that_raises_does_not_break_the_others(monkeypatch):
    def boom(out, src):
        raise RuntimeError("detector regression")

    monkeypatch.setattr(provenance, "_DETECTORS", (boom, provenance._oci))
    monkeypatch.setenv("OCI_IMAGE_REVISION", "abc123")
    assert provenance.detect().values["commit"] == "abc123"


# -- §6.1 as it reaches the config ------------------------------------------------------------------

def test_6_1_explicit_beats_environment_beats_detection(monkeypatch):
    from nexus.config import resolve
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_GIT_COMMIT_SHA", "detected")
    monkeypatch.setenv("NEXUS_REPO", "env/repo")

    cfg = resolve(service="s", env="prod", version="1", commit="explicit")
    assert cfg.commit == "explicit"
    assert cfg.provenance_sources["commit"] == "explicit"
    assert cfg.repo == "env/repo"
    assert cfg.provenance_sources["repo"] == "explicit"


def test_6_1_absent_provenance_stays_absent_on_the_config():
    """The single most important assertion in this file.

    ``service``/``env``/``version`` fall back to the string ``"unknown"``. These do not, and must
    not: ``commit="unknown"`` is a claim, and it is the claim that makes a shadow deploy look
    accounted for.
    """
    from nexus.config import resolve
    cfg = resolve(service="s", env="prod", version="1")
    assert cfg.commit is None
    assert cfg.repo is None
    assert cfg.application is None
    assert cfg.provenance_source is None
    assert cfg.provenance_sources == {}
    assert cfg.service == "s"          # the contrast: these three still get their sentinel
    assert (cfg.env, cfg.version) == ("prod", "1")


def test_6_1_provenance_source_is_the_commits_source_and_nothing_elses(monkeypatch):
    """The ribbon prints this string under the ``running`` station. A source for some *other*
    field, printed while the commit is absent, attaches a provenance claim to a link that is not
    there."""
    from nexus.config import resolve
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_REPOSITORY", "example-org/example-app")     # repo, but no SHA
    cfg = resolve(service="s", env="prod", version="1")
    assert cfg.repo == "example-org/example-app"
    assert cfg.commit is None
    assert cfg.provenance_source is None


def test_6_1_a_detected_env_fills_only_the_unknown_sentinel(monkeypatch):
    from nexus.config import resolve
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_ENV", "production")
    assert resolve(service="s", version="1").env == "production"
    assert resolve(service="s", env="staging", version="1").env == "staging"


def test_6_1_session_event_carries_provenance_and_omits_what_is_missing(sdk, collector,
                                                                       monkeypatch):
    assert collector.wait_for(1, timeout=5)
    sessions = collector.of_type("session")
    assert sessions, collector.types()
    e = sessions[0]
    # The `sdk` fixture inits with no provenance, so the key is not written at all — not written
    # holding an empty object, which would read as "we looked and there is nothing to join".
    assert "provenance" not in e, f"provenance was written when nothing was read: {e.get('provenance')!r}"


def test_6_1_session_event_carries_what_was_read(collector, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("VERCEL", "1")
    monkeypatch.setenv("VERCEL_GIT_COMMIT_SHA", "c1e88a04")
    import nexus
    nexus.init(service="portal", env="prod", version="2026.8.1", application="example-app")
    try:
        assert collector.wait_for(1, timeout=5)
        e = collector.of_type("session")[0]
        p = e["provenance"]
        assert p["commit"] == "c1e88a04"
        assert p["application"] == "example-app"
        assert p["source"] == "env:VERCEL_GIT_COMMIT_SHA"
        assert p["sources"]["application"] == "explicit"
        # `session.repo` in the wrapper's contract is a dict. This producer must not put a string
        # under the same wire key, so the flat form stays absent.
        assert "repo" not in e
    finally:
        nexus.shutdown()


# -- §6.2 the integration probe ---------------------------------------------------------------------

def _probe(collector, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        got = collector.of_type("integration_probe")
        if got:
            return got[0]
        time.sleep(0.02)
    raise AssertionError(f"no integration_probe; saw {collector.types()}")


def test_6_2_liveness_and_freshness_are_two_fields(sdk, collector):
    import nexus
    with nexus.integration("salesforce", kind="crm") as io:
        io.data(rows=42, watermark="2026-08-20T09:00:00Z")
    nexus.flush()
    e = _probe(collector)
    assert e["type"] == "integration_probe"
    assert e["integration"] == "salesforce"
    assert e["kind"] == "crm"
    assert e["integration_up"] is True                  # LIVENESS: the call completed
    assert e["last_data_ts"] == "2026-08-20T09:00:00Z"  # FRESHNESS: the newest business timestamp
    assert e["rows"] == 42
    assert e["detected_by"] == "sdk"
    assert e["epistemic_class"] == "behavior_trace"
    assert e["producer"] == "sdk"
    assert isinstance(e["latency_ms"], int)


def test_6_2_succeeded_and_returned_nothing_is_recorded_as_such(sdk, collector):
    """The distinction the whole call exists for. Zero rows is an answer, not an absence."""
    import nexus
    with nexus.integration("salesforce") as io:
        io.data(rows=0)
    nexus.flush()
    e = _probe(collector)
    assert e["integration_up"] is True
    assert e["rows"] == 0
    # …and no watermark was seen, so freshness stays absent rather than borrowing the probe time.
    assert "last_data_ts" not in e


def test_6_2_a_probe_never_invents_a_watermark_from_the_clock(sdk, collector):
    import nexus
    with nexus.integration("salesforce"):
        pass
    nexus.flush()
    e = _probe(collector)
    assert e["integration_up"] is True
    assert "last_data_ts" not in e
    assert "rows" not in e
    assert "auth_ok" not in e, "auth was never asserted; inferring it would invent a fact"


def test_6_2_an_exception_marks_it_down_and_still_propagates(sdk, collector):
    import nexus
    with pytest.raises(ValueError):
        with nexus.integration("salesforce"):
            raise ValueError("token expired")
    nexus.flush()
    e = _probe(collector)
    assert e["integration_up"] is False
    assert "auth_ok" not in e, "a 403 from a rate limiter and one from a dead credential differ"


def test_6_2_a_handled_failure_can_be_reported_without_raising(sdk, collector):
    """Clients that return an error object rather than raising would otherwise be reported up."""
    import nexus
    with nexus.integration("legacy-ftp") as io:
        io.fail("connection reset by peer", error_class="transport")
    nexus.flush()
    e = _probe(collector)
    assert e["integration_up"] is False
    assert e["error_class"] == "transport"


def test_6_2_error_text_is_tier_gated_and_the_class_is_not(collector, monkeypatch):
    """``error`` carries token fragments and query strings; ``error_class`` is content-free and
    must survive every tier, because the alarm branches on it and a T2-only alarm is not an alarm.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import nexus
    nexus.init(service="svc", env="test", version="1")      # default tier: metadata_only
    try:
        with nexus.integration("stripe") as io:
            io.fail("401 for key sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA", error_class="auth")
        nexus.flush()
        e = _probe(collector)
        assert "error" not in e, "raw vendor text must not leave the process at T0"
        assert "error_preview" not in e
        assert e["error_class"] == "auth"
        assert e["error_chars"] > 0 and e["error_fingerprint"]
    finally:
        nexus.shutdown()


def test_6_2_full_tier_carries_the_text_and_hashed_carries_a_redacted_preview(collector,
                                                                             monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import nexus
    nexus.init(service="svc", env="test", version="1", tier="hashed")
    try:
        with nexus.integration("stripe") as io:
            io.fail("401 for key sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA", error_class="auth")
        nexus.flush()
        e = _probe(collector)
        assert "error" not in e
        assert "sk-ant-" not in e["error_preview"], "the redactor did not run on the preview"
        assert e["error_preview_redacted"] is True
    finally:
        nexus.shutdown()


def test_6_2_a_millisecond_watermark_is_dropped_not_converted(sdk, collector):
    """A ms epoch read as seconds lands in the year 5138, which does not read as an error on a
    freshness cell — it reads as permanently fresh."""
    import nexus
    with nexus.integration("crm") as io:
        io.data(watermark=1_756_000_000_000)
    nexus.flush()
    assert "last_data_ts" not in _probe(collector)


def test_6_2_a_datetime_watermark_is_used_as_given(sdk, collector):
    import datetime as dt
    import nexus
    when = dt.datetime(2026, 8, 20, 9, 0, 0)
    with nexus.integration("crm") as io:
        io.data(watermark=when)
    nexus.flush()
    assert _probe(collector)["last_data_ts"] == when.isoformat()


def test_6_2_schema_fingerprint_carries_shape_and_never_values(sdk, collector):
    import nexus
    with nexus.integration("crm") as io:
        io.schema({"id": 1, "email": "person@example.com"})
    nexus.flush()
    e = _probe(collector)
    assert e["schema_fingerprint"]
    assert "example.com" not in json.dumps(e)


def test_6_2_expects_data_probes_every_call_and_parses_its_window(sdk, collector):
    import nexus
    from nexus import api

    @nexus.expects_data("crm_sync", within="24h", kind="crm")
    def sync():
        return "done"

    assert sync() == "done"
    nexus.flush()
    e = _probe(collector)
    assert e["integration"] == "crm_sync"
    assert e["kind"] == "crm"
    assert api.DECLARED["crm_sync"]["within_ms"] == 86_400_000


def test_6_2_an_unparseable_window_is_recorded_unparsed_never_defaulted(sdk):
    """A declaration that silently became "24h" because the caller typed "1 day" is an alarm whose
    threshold nobody chose."""
    import nexus
    from nexus import api

    @nexus.expects_data("odd_sync", within="1 day")
    def sync():
        return 1

    assert sync() == 1
    assert api.DECLARED["odd_sync"]["within_ms"] is None
    assert api.DECLARED["odd_sync"]["within"] == "1 day"


def test_6_2_the_decorated_function_keeps_its_identity_and_its_exception(sdk):
    import nexus

    @nexus.expects_data("boom_sync", within="1h")
    def sync(a, b=2):
        """docstring survives"""
        raise KeyError("app bug")

    assert sync.__name__ == "sync"
    assert sync.__doc__ == "docstring survives"
    with pytest.raises(KeyError):
        sync(1)


# -- §6.3 service health -----------------------------------------------------------------------------

def test_6_3_health_is_rolled_up_from_spans_already_collected(collector, monkeypatch):
    """No new instrumentation ask: the input is the ``tool_action`` spans the SDK already emits."""
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    monkeypatch.setenv("NEXUS_FLUSH_INTERVAL_S", "0.1")
    monkeypatch.setenv("NEXUS_HEALTH_INTERVAL_S", "1")
    import nexus
    nexus.init(service="rollup-svc", env="test", version="1")
    try:
        with nexus.agent("job") as run:
            for i in range(10):
                with run.action("op", target=f"t{i}"):
                    pass
            with run.action("bad"):
                try:
                    raise RuntimeError("nope")
                except RuntimeError:
                    pass
        # Deliberately no ``nexus.flush()``: an explicit flush drains on the *calling* thread,
        # which by design does not aggregate (see the test below). The worker's own 100 ms tick is
        # the path under test, and it is the path production actually uses.
        end = time.time() + 8
        rolled = []
        while time.time() < end and not rolled:
            rolled = collector.of_type("service_health")
            time.sleep(0.1)
        assert rolled, f"no service_health rolled up; saw {collector.types()}"
        e = rolled[0]
        assert e["service"] == "rollup-svc"
        assert e["detected_by"] == "sdk"
        assert e["epistemic_class"] == "behavior_trace"
        assert e["requests"] >= 11
        assert e["window_from"] and e["window_to"]
        assert e["p50_ms"] is not None
        # Not measured, so not written. A latency-derived saturation would be a derived figure
        # wearing a measured one's typeface.
        assert "saturation" not in e
    finally:
        nexus.shutdown()


def test_6_3_an_empty_window_emits_nothing_rather_than_a_zero(sdk):
    """Zero observed spans means "nothing was instrumented" far more often than "no traffic".
    ``requests: 0`` there would read on the console as a measured outage."""
    from nexus.health import HealthRollup
    from nexus import client as client_mod
    r = HealthRollup()
    assert r.roll("sid", client_mod.get_client().cfg) is None


def test_6_3_heartbeat_states_liveness_without_inventing_quantities(sdk, collector):
    """A worker with no request loop. The window is the claim; the numbers are absent, because a
    worker that served no HTTP requests is a fact about instrumentation, not about health."""
    import nexus
    assert nexus.heartbeat() is True
    nexus.flush()
    end = time.time() + 5
    got = []
    while time.time() < end and not got:
        got = collector.of_type("service_health")
        time.sleep(0.02)
    assert got, collector.types()
    e = got[0]
    assert e["window_from"] and e["window_to"]
    for absent in ("requests", "errors", "p50_ms", "p95_ms", "p99_ms", "saturation"):
        assert absent not in e, f"{absent} was fabricated for an unmeasured window"


def test_6_3_the_rollup_runs_on_the_worker_thread_and_nowhere_else(sdk):
    """§6.3's constraint, asserted structurally. An explicit ``nexus.flush()`` from the
    application's own thread drains without aggregating; only the flush worker observes.
    """
    import nexus
    from nexus import client as client_mod
    c = client_mod.get_client()
    threads = []
    real = c.health.observe

    def spy(batch):
        threads.append(threading.current_thread().name)
        return real(batch)

    c.transport.on_batch = spy
    try:
        with nexus.agent("job") as run:
            for _ in range(5):
                with run.action("op"):
                    pass
        nexus.flush()                       # calling thread: must not aggregate
        assert threading.current_thread().name not in threads
        time.sleep(1.0)                     # let the worker drain whatever is left
        assert all(n != "MainThread" for n in threads), threads
    finally:
        c.transport.on_batch = real


def test_6_3_percentiles_are_absent_not_zero_for_an_unmeasured_sample():
    from nexus.health import _pct
    assert _pct([], 0.5) is None
    assert _pct([1.0, 2.0, 3.0, 4.0], 0.5) == 2.0


def test_6_3_health_interval_zero_disables_the_rollup(monkeypatch):
    from nexus.config import resolve
    monkeypatch.setenv("NEXUS_HEALTH_INTERVAL_S", "0")
    assert resolve(service="s", env="t", version="1").health_interval_s == 0.0
    monkeypatch.setenv("NEXUS_HEALTH_INTERVAL_S", "not-a-number")
    assert resolve(service="s", env="t", version="1").health_interval_s == 60.0


# -- §6.4 the self-reported deployment ---------------------------------------------------------------

def _deploys(collector, timeout=5.0):
    end = time.time() + timeout
    while time.time() < end:
        got = collector.of_type("deployment")
        if got:
            return got
        time.sleep(0.02)
    raise AssertionError(f"no deployment; saw {collector.types()}")


def test_6_4_a_self_report_is_stamped_self_and_cannot_claim_otherwise(sdk, collector):
    import nexus
    assert nexus.deployment(version="2026.8.1", commit="c1e88a04", env="prod") is True
    nexus.flush()
    e = _deploys(collector)[0]
    assert e["detected_by"] == "self", "the weakest claim on the plane, and not the caller's choice"
    assert e["version"] == "2026.8.1"
    assert e["commit"] == "c1e88a04"
    assert e["env"] == "prod"
    assert e["outcome"] == "succeeded"
    assert e["epistemic_class"] == "behavior_trace"
    assert e["producer"] == "sdk"


def test_the_mirror_only_builders_still_build(sdk):
    """``incident``, ``infra_cost`` and ``ownership`` have no SDK entry point — they belong to the
    console and the connectors. They are mirrored here so the two hand-written contracts cannot
    drift apart while the generated artifact is landing, and untested mirrored code is how a
    mirror rots. Each must carry ``producer`` and ``epistemic_class`` like everything else.
    """
    from nexus import contract, client as client_mod
    cfg = client_mod.get_client().cfg
    made = [
        contract.incident("s", cfg, incident_id="inc-1", severity="p2",
                          detected_ts="2026-08-23T10:00:00Z", affected_services=["portal"]),
        contract.infra_cost("s", cfg, provider="vercel", resource_class="compute",
                            currency="EUR", amount_minor=28000),
        contract.ownership("s", cfg, app_id="example-app", principal="u_1", role="owner",
                           asserted_by="u_2", asserted_ts="2026-08-23T10:00:00Z"),
    ]
    for e in made:
        assert e["producer"] == "sdk"
        assert e["epistemic_class"] == "behavior_trace"
        assert e["detected_by"] in contract.DETECTED_BY
    assert made[0]["type"] == "incident"
    # Free text on `incident.title` is gated like `prompt`: nothing at T0 but shape.
    titled = contract.incident("s", cfg, incident_id="inc-2", title="checkout 500s for eu-west")
    assert "title" not in titled and titled["title_chars"] > 0


def test_6_4_detected_by_is_not_a_parameter():
    """A self-report that could pass ``detected_by="cloud"`` would make the ranking worthless.

    Asserted on the signature rather than by calling: the guard would swallow the ``TypeError`` and
    return the safe default, so a runtime probe here would pass whether or not the door was open.
    """
    import inspect
    from nexus import api
    params = inspect.signature(api.deployment).parameters
    assert "detected_by" not in params
    assert "epistemic_class" not in params


def test_6_4_a_deployment_with_no_version_and_no_commit_is_refused(collector, monkeypatch):
    """The most important refusal in §6.4.

    A contentless deployment record still *counts* as a deployment record, so it would satisfy the
    join the shadow-deploy alarm tests — the alarm would go quiet while knowing strictly less.
    """
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import nexus
    nexus.init(service="unversioned", env="prod")       # version resolves to "unknown"
    try:
        assert nexus.deployment() is False
        nexus.flush()
        time.sleep(0.3)
        assert collector.of_type("deployment") == []
    finally:
        nexus.shutdown()


def test_6_4_a_deployment_with_no_environment_is_refused(sdk):
    """Nowhere to put it on the estate grid, and a guessed environment puts staging's version in
    the prod column."""
    import nexus
    from nexus import client as client_mod
    from dataclasses import replace
    c = client_mod.get_client()
    c.cfg = replace(c.cfg, env="unknown")
    assert nexus.deployment(version="9.9.9") is False


def test_6_4_replicas_of_one_release_report_one_deployment(sdk, collector):
    """A uuid per boot would make twelve replicas read as twelve deploys, and a restart as a
    redeploy. The id is derived from values we were given, never invented."""
    import nexus
    nexus.deployment(version="2026.8.1", commit="c1e88a04", env="prod")
    nexus.deployment(version="2026.8.1", commit="c1e88a04", env="prod")
    nexus.deployment(version="2026.8.2", commit="ffffffff", env="prod")
    nexus.flush()
    end = time.time() + 5
    while time.time() < end and len(collector.of_type("deployment")) < 3:
        time.sleep(0.02)
    ids = {e["deployment_id"] for e in collector.of_type("deployment")}
    assert len(ids) == 2, ids
    assert all(i.startswith("self-") for i in ids)


def test_6_4_provenance_from_init_fills_the_deployment(collector, monkeypatch):
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import nexus
    nexus.init(service="portal", env="prod", version="2026.8.1",
               application="example-app", repo="github.com/example-org/example-app", commit="c1e88a04")
    try:
        assert nexus.deployment() is True
        nexus.flush()
        e = _deploys(collector)[0]
        assert (e["app_id"], e["repo"], e["commit"]) == (
            "example-app", "github.com/example-org/example-app", "c1e88a04")
    finally:
        nexus.shutdown()


def test_6_4_actor_is_tier_gated(collector, monkeypatch):
    """``deployment.actor`` is a person. It keeps its *shape* at every tier — a ledger that cannot
    say who deployed is not a ledger — and its *text* only at ``hashed`` and above, because it
    arrives from a forge as a commit author's email."""
    monkeypatch.setenv("NEXUS_COLLECTOR_URL", collector.url)
    import nexus
    nexus.init(service="portal", env="prod", version="1")
    try:
        nexus.deployment(version="1", commit="abc", env="prod",
                         actor="deploy-bot token=ghp_AAAAAAAAAAAAAAAAAAAAAAAA")
        nexus.flush()
        e = _deploys(collector)[0]
        # The previous version of this test asserted ``"deploy-bot" in e["actor"]`` at the
        # default tier, which is the defect written down as a requirement: ``actor`` is free text
        # and very often a commit author's email, and T0 promises to fingerprint the shape and
        # never the content. Shape is what survives — and it is enough for every question the
        # deployment ledger actually asks of this field.
        assert "actor" not in e, "free text on actor at the default tier"
        assert "actor_preview" not in e
        assert e["actor_chars"] and e["actor_fingerprint"]
        assert "ghp_AAAA" not in json.dumps(e), e
    finally:
        nexus.shutdown()


# -- the guarantees the new surface must not break -----------------------------------------------

def test_the_new_entry_points_are_all_guarded():
    """Belt and braces beside ``test_every_public_entry_point_is_guarded``: this one names them, so
    a rename that silently drops a guard cannot pass by no longer being inspected."""
    from nexus import _safety, api, client  # noqa: F401
    for hook in ("integration", "integration.data", "integration.auth", "integration.fail",
                 "integration.schema", "integration.close", "deployment", "heartbeat",
                 "client.heartbeat", "client.roll_health"):
        assert hook in _safety.HOOKS, f"{hook} is not in the guard registry"


def test_the_new_calls_never_touch_the_network_on_the_calling_thread(sdk, monkeypatch):
    import nexus
    calls = []
    real = socket.socket.connect

    def spy(self, addr):
        calls.append(addr)
        return real(self, addr)

    monkeypatch.setattr(socket.socket, "connect", spy)
    with nexus.integration("salesforce", kind="crm") as io:
        io.auth(True).data(rows=1, watermark="2026-08-20T09:00:00Z")
    nexus.deployment(version="1", commit="abc", env="test")
    nexus.heartbeat()
    assert calls == [], f"the calling thread opened {len(calls)} connections"


def test_the_kill_switch_keeps_the_new_calls_inert(tmp_path):
    """Not "initialised then no-op". No threads, no imports of our own, no sockets."""
    from conftest import run_script
    body = (
        "import json, sys, threading\n"
        "import nexus\n"
        "before = set(sys.modules)\n"
        "nexus.init(service='off', env='prod', version='1', commit='abc')\n"
        "\n"
        "@nexus.expects_data('crm_sync', within='24h')\n"
        "def sync():\n"
        "    return 'ran'\n"
        "\n"
        "assert sync() == 'ran'\n"
        "with nexus.integration('salesforce', kind='crm') as io:\n"
        "    io.auth(True).data(rows=3, watermark='2026-08-20T09:00:00Z').schema({'a': 1})\n"
        "    io.fail('nope', error_class='auth')\n"
        "assert nexus.deployment(version='1', commit='abc', env='prod') is False\n"
        "assert nexus.heartbeat() is False\n"
        "ours = [m for m in set(sys.modules) - before if m.startswith('nexus')]\n"
        "print(json.dumps({'ours': sorted(ours), 'threads': threading.active_count()}))\n"
    )
    r = run_script(body, tmp_path, env={"NEXUS_ENABLED": "0"})
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert out["ours"] == [], f"the disabled SDK imported {out['ours']}"
    assert out["threads"] == 1, "the disabled SDK started a thread"


def test_the_disabled_integration_block_still_runs_the_body(tmp_path):
    """The kill switch must not change the host program's control flow."""
    from conftest import run_script
    body = (
        "import nexus\n"
        "ran = []\n"
        "with nexus.integration('salesforce') as io:\n"
        "    ran.append('body')\n"
        "    io.data(rows=1)\n"
        "print('ok' if ran == ['body'] else 'BROKEN')\n"
    )
    r = run_script(body, tmp_path, env={"NEXUS_ENABLED": "0"})
    assert r.returncode == 0, r.stderr
    assert "ok" in r.stdout


def test_a_probe_survives_a_broken_builder(sdk, monkeypatch):
    """Our own contract code raising on a value it did not expect must not reach the caller."""
    import nexus
    from nexus import contract

    def explode(*a, **kw):
        raise TypeError("contract regression")

    monkeypatch.setattr(contract, "integration_probe", explode)
    with nexus.integration("salesforce") as io:
        io.data(rows=1)                 # must not raise
