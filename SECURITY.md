# Security policy

## Reporting a vulnerability

Email **[security@swfte.com](mailto:security@swfte.com)**, or use GitHub's
[private vulnerability reporting](https://github.com/SwfteAI/nexus-sdk/security/advisories/new) on
this repository.

Please do not open a public issue for a security problem, and please do not include a working
exploit in the first message — a description of the class of problem and the affected version is
enough to start.

We aim to acknowledge within **two working days** and to give you an assessment and a fix timeline
within **ten working days**. If you would like credit in the advisory, say so and tell us how you
want to be named.

## What we consider a vulnerability here

This SDK is embedded in other people's production services, so the threat model is unusual: the
interesting failures are ones where *our* code harms the *host* application or leaks its data.

**In scope, and treated seriously:**

- **Content escaping its privacy tier.** Any path where data leaves the process above the
  configured `NEXUS_TIER` — most severely, message content escaping under `metadata_only`.
- **Credential leakage.** Collector tokens or host-application secrets appearing in events, logs,
  error messages, or in a redirect to a host other than the configured collector.
- **Enforcement bypass.** Any way to obtain an allow from a rule marked `enforce: true` — for
  example an unsigned or replayed policy envelope being accepted, or a stale cached deny decaying
  into an allow.
- **Denial of service against the host.** A deadlock, an unbounded queue, an unbounded thread, or a
  hang on shutdown that outlives its deadline. A telemetry SDK must never be the reason a request
  fails, and a hung collector must never hang a container.
- **Anything that puts an exception in a host traceback** other than `policy.Denied`, which is the
  one exception this SDK will ever raise and requires opting in twice.

**Not vulnerabilities**, though we still want to hear about them as ordinary bugs:

- Reports against `src/nexus/vendor/`, which is third-party code carried with its licences — report
  those upstream, and tell us so we can pick up the fix.
- The documented `SIGKILL` behaviour. `SIGKILL` loses the in-flight buffer; that is not fixable and
  the suite asserts the loss rather than pretending otherwise.
- The documented redaction limits. `redacted_preview` strikes out values with a recognisable
  *shape*; it does not understand meaning. A name survives it because a name has no shape. This is
  specified in the README and is why `metadata_only` is the default — but a pattern that fails to
  match a shape it clearly claims to cover **is** a bug, so report it.
- Configuring the SDK to send content you did not want sent. Tier selection is the operator's.

## Supported versions

While the SDK is pre-1.0, security fixes land on the latest released minor version. There is no
long-term-support branch yet.

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Handling of your report

We will tell you what we found, what we changed, and when it shipped. If we conclude a report is
not a vulnerability we will say why rather than closing it silently — and if we are wrong about
that, please push back.

---

[www.swfte.com](https://www.swfte.com) · [sales@swfte.com](mailto:sales@swfte.com)
