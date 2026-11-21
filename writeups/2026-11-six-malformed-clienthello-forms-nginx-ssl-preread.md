# Six malformed ClientHello forms nginx still parses: the ssl_preread hardening note

*2026-11 · Matt Jesc, Nodejam*

**TL;DR:** After F5's 1.31.9 security wave fixed
[CVE-2026-123640](https://nvd.nist.gov/vuln/detail/CVE-2026-123640) —
forged `ngx_stream_ssl_preread_module` variables from a crafted ClientHello —
we asked a narrower question: *after* the fixes, how strict is `ssl_preread`
compared with the TLS stacks it typically fronts? A local differential lab
(nginx 1.31.9 with `ssl_preread` map routing, OpenSSL and Go backends, 17
hand-built ClientHellos) found six malformed forms preread still parses and
routes on while both backends refuse them. This is a hardening-consistency
note, not a vulnerability report — no memory-safety issue, no demonstrated
bypass — and it is filed publicly as
[nginx/nginx#2013](https://github.com/nginx/nginx/issues/2013).

All reproduction steps were verified hands-on against pinned versions; every
artifact referenced is public.

## Context

On 2026-11-18, F5 published the nginx 1.31.9 security advisories, including
[CVE-2026-123640](https://my.f5.com/manage/s/article/K000163935): with
`ngx_stream_ssl_preread_module` configured, a specially crafted ClientHello
causes forged values of the preread variables, affecting virtual server
selection, and can disagree with a proxied server that terminates TLS
without TLS 1.3 support. The 1.31.9 fixes make preread *decline* two
malformed SNI shapes (duplicate SNI extension, empty SNI list) instead of
routing on them.

That established a principle worth testing: preread should apply roughly the
ClientHello strictness of the stacks it fronts. Declined input upstream is
cheap; a routing decision made on input the destination stack will refuse is
a wrong-pool connection waiting to happen.

## The differential lab

Everything ran locally on loopback; no third-party system was contacted.

- **Frontend:** nginx 1.31.9, built with
  `--with-stream --with-stream_ssl_preread_module`,
  `ssl_preread on`, and `map $ssl_preread_server_name` routing between an
  allowlisted pool and a default pool.
- **Backends:** OpenSSL (via Python 3.12 `ssl`, SNI callback logging) and
  Go 1.27.4 `crypto/tls` (`GetConfigForClient` logging). GnuTLS was not
  tested.
- **Corpus:** 17 hand-built ClientHello records — 6 controls and 11 variants.
  Two of the controls are the exact shapes 1.31.9's fixes decline; both were
  verified declined, confirming the published fixes work as intended in our
  build.
- **Runner:** each hello goes to the frontend; the runner correlates the
  chosen pool with what each backend actually parsed or rejected. The Go
  column was produced by sending corpus hellos directly to the Go backend
  and reading its one-line-per-connection verdict log.

The full corpus generator, lab runner, nginx.conf and Go server are inline
in [the issue](https://github.com/nginx/nginx/issues/2013).

## The six leniencies

1. **Multi-entry SNI list** (`[a.example, b.example]`): preread routes on the
   *first* entry and silently skips the rest; both OpenSSL and Go reject the
   whole ClientHello.
2. **Odd `cipher_suites` length**: preread accepts and routes; OpenSSL
   rejects (`error_in_received_cipher_list`), Go rejects at decode.
3. **Zero-length `compression_methods`**: preread accepts and routes; OpenSSL
   rejects (`no_compression_specified`); Go parses the SNI, then rejects at
   negotiation.
4. **`supported_versions` listing only non-protocol versions**: the preread
   state machine marks the session TLSv1.3 from the extension's presence and
   size alone, without reading the version list; OpenSSL rejects
   (`unsupported_protocol`), and Go exposes the garbage versions in
   `ClientHelloInfo.SupportedVersions` before rejecting.
5. **Legacy `client_version` never sanity-checked** when `supported_versions`
   is absent (any two bytes accepted into the version state).
6. **Trailing-dot SNI** (`name.example.`) misses exact-match maps by one byte
   and falls to the default pool — a normalization footgun, suggested as a
   documentation note rather than a parser change.

## The 17-row result table

As published in the issue (2026-11-20 lab run):

```
item                          | preread SNI      | pool chosen   | OpenSSL backend                    | Go backend
c01 control single allowed    | allowed.local    | allowed-pool  | accept-parse allowed.local         | accept-parse allowed.local
c02 control single evil       | evil.example     | default-pool  | accept-parse evil.example          | accept-parse evil.example
c03 control no SNI            | (none)           | default-pool  | accept-parse (none)                | -
c13 control empty SNI list    | - (declined)     | default-pool  | reject bad_extension               | -
c14 control duplicate SNI ext | - (declined)     | default-pool  | reject bad_extension               | -
c12 control trailing bytes    | allowed.local    | allowed-pool  | accept-parse allowed.local         | accept-parse allowed.local
t03 SNI list [a,b]            | allowed.local    | allowed-pool  | reject bad_extension               | reject error-decoding-message
t04 SNI list [b,a]            | evil.example     | default-pool  | reject bad_extension               | reject error-decoding-message
t05 SNI list [a,b,c]          | allowed.local    | allowed-pool  | reject bad_extension               | reject error-decoding-message
t06 odd cipher_suites len     | allowed.local    | allowed-pool  | reject error_in_received_cipher_   | reject error-decoding-message
t07 zero compression methods  | allowed.local    | allowed-pool  | reject no_compression_specified    | accept-parse allowed.local, reject at negotiation
t08 garbage legacy ver +supver| allowed.local    | allowed-pool  | accept-parse allowed.local         | -
t09 garbage legacy ver only   | allowed.local    | allowed-pool  | accept-parse allowed.local         | accept-parse allowed.local
t10 record shorter than HS    | -                | default-pool  | reject wrong_version_number        | -
t11 SNI trailing dot          | allowed.local.   | default-pool  | accept-parse allowed.local.        | -
t15 ALPN list two protocols   | allowed.local    | allowed-pool  | accept-parse allowed.local         | -
t16 supver garbage only       | allowed.local    | allowed-pool  | reject unsupported_protocol        | accept-parse; SupportedVersions=[31354] exposed; reject at negotiation
```

The row worth staring at is **t04**: SNI list `[b,a]` with `a` allowlisted —
preread routes on `b` (first entry) while the list contains an allowlisted
name. No case in the corpus produced a routed-on-X / served-Y divergence —
every lenient form is either parsed identically by backend and preread, or
refused by the backend — which is exactly why this is filed as a
hardening-consistency note and not a vulnerability.

## Suggested hardening

Mirroring the 1.31.9 style (decline instead of route):

- Decline a `server_name` list with more than one entry.
- Decline odd `cipher_suites` length.
- Decline `compression_methods` length 0.
- In the supported-versions handler, check that listed versions are plausible
  TLS versions before marking the session TLSv1.3.
- Optionally sanity-check the legacy `client_version` when
  `supported_versions` is absent.

## Disclosure

Filed 2026-11-21 as
[nginx/nginx#2013](https://github.com/nginx/nginx/issues/2013) ("Stream:
ssl_preread still parses and routes on six malformed ClientHello forms
(1.31.9 hardening follow-up)"), open and labeled `bug` at the time of this
write. The note requests no embargo and leaves severity to the maintainers'
discretion.

---

*All reproduction steps verified hands-on against pinned versions; every
artifact referenced is public. All testing was local, on loopback interfaces
only; no third-party system was contacted.*
