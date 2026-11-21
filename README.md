# security-writeups

Public writeups of security research by **Matt Jesc ([matt-nodejam](https://github.com/matt-nodejam))** — independent security
researcher at [Nodejam](https://github.com/matt-nodejam), working from
Sweden/Nordics.

These writeups are also rendered as an indexed blog at
[matt-nodejam.github.io](https://matt-nodejam.github.io).

**Focus areas:** offensive security, memory corruption in media parsers and
network infrastructure, model/file-format parsing surfaces, and measurement
of AI-assisted security tooling.

## Disclosure-first

Everything in this repository describes work that was reported to the
affected maintainers through their preferred channel (private vulnerability
advisory, security issue, or maintainer discussion), waited for fixes or
maintainer acknowledgement, and was published only after the public record
exists. Nothing here pre-discloses an unreported vulnerability. Testing was
performed against locally built software from pinned, public source releases;
no third-party production system was contacted for any of this work.

All reproduction steps were verified hands-on against pinned versions; every
artifact referenced is public.

## Writeups

| Date | Writeup | One-line |
|---|---|---|
| 2026-11 | [The fix moved the bug: a complete incomplete-fix arc on FLTK (CVE-2026-116724)](writeups/2026-11-the-fix-moved-the-bug-fltk-cve-2026-116724.md) | The fix for CVE-2026-116724 closed the allocation overflow but left the row-pointer wrap; reported with a tested fix shape, a two-site fix shipped in ~49h, independent ASan replay verified clean, closed cooperatively in ~56h. |
| 2026-11 | [From issue to advisory: the vvdec campaign](writeups/2026-11-from-issue-to-advisory-the-vvdec-campaign.md) | Four credited GitHub security advisories in the Fraunhofer HHI VVC/H.266 decoder — one HIGH use-after-free write and three out-of-bounds reads — from fuzz harness to publication. |
| 2026-11 | [Six malformed ClientHello forms nginx still parses: the ssl_preread hardening note](writeups/2026-11-six-malformed-clienthello-forms-nginx-ssl-preread.md) | A differential lab for `ngx_stream_ssl_preread_module` after the CVE-2026-123640 fixes: where preread is still more lenient than the TLS stacks it fronts. |
| 2026-11 | [CVE-2026-123007 replay — coming soon](writeups/2026-11-cve-2026-123007-replay-coming-soon.md) | Placeholder: a replay study of the nginx HTTP/2 flow-control heap overflow, in progress. |

## Public record index

**FLTK (BMP image loader, incomplete-fix follow-up)** — verification and cooperative close:

- [fltk/fltk#1647](https://github.com/fltk/fltk/issues/1647) — Fl_BMP_Image: the #1632 fix closes the allocation overflow, the row pointer still wraps (filed 2026-11-19, fix `a28e392` 2026-11-21, verified and closed 2026-11-21)
- [CVE-2026-116724](https://nvd.nist.gov/vuln/detail/CVE-2026-116724) — the published advisory (HaiND, VulnCheck CNA) our incomplete-fix report follows up on

**vvdec (VVC/H.266 decoder, Fraunhofer HHI)** — reporter credit on all four:

- [GHSA-pw57-fxvc-2qgr](https://github.com/fraunhoferhhi/vvdec/security/advisories/GHSA-pw57-fxvc-2qgr) — HIGH — Heap use-after-free write in `Picture::fillGrey` on a picture buffer reused for 4:0:0
- [GHSA-p27c-vmfj-jh2f](https://github.com/fraunhoferhhi/vvdec/security/advisories/GHSA-p27c-vmfj-jh2f) — Medium — Heap out-of-bounds read in `vvdec_get_nal_unit_type` for short access units (co-credited with [4KVCD](https://github.com/4KVCD), independent discovery)
- [GHSA-qgqj-f693-2fqc](https://github.com/fraunhoferhhi/vvdec/security/advisories/GHSA-qgqj-f693-2fqc) — Medium — Heap out-of-bounds read in LMCS forward reshaping after an SPS change within a CLVS
- [GHSA-f7mj-r2mj-rfvh](https://github.com/fraunhoferhhi/vvdec/security/advisories/GHSA-f7mj-r2mj-rfvh) — Medium — Heap out-of-bounds read and NULL pointer dereference via PPS not re-validated after its SPS is replaced (originated as [issue #469](https://github.com/fraunhoferhhi/vvdec/issues/469))

**nginx**

- [nginx/nginx#2013](https://github.com/nginx/nginx/issues/2013) — Stream: ssl_preread still parses and routes on six malformed ClientHello forms (1.31.9 hardening follow-up)
- [CVE-2026-123640](https://nvd.nist.gov/vuln/detail/CVE-2026-123640) — the published ssl_preread advisory our note follows up on (F5, 2026-11-18)
- [CVE-2026-123007](https://nvd.nist.gov/vuln/detail/CVE-2026-123007) — the published nginx HTTP/2 heap overflow our upcoming replay studies (F5, 2026-11-18)

## License

[MIT](LICENSE)
