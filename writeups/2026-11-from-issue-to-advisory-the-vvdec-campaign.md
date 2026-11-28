# From issue to advisory: the vvdec campaign

*2026-11 · Matt Jesc, Nodejam*

**TL;DR:** Over twelve days in November 2026, a small fuzzing-and-code-reading
campaign against [vvdec](https://github.com/fraunhoferhhi/vvdec), Fraunhofer
HHI's open-source VVC/H.266 decoder, went from target selection to four
published GitHub security advisories with reporter credit: one HIGH
use-after-free **write** in the error-concealment path, and three
out-of-bounds reads reachable from attacker-controlled bitstreams. All four
were fixed upstream within ten days of report. This writeup tells the story:
how the target was picked, how the harness was qualified, how each bug was
found and verified, and what the maintainers did with the reports.

All reproduction steps were verified hands-on against pinned versions; every
referenced artifact is public or reconstructable from public material.

## The four advisories

| Advisory | Severity | Class | Site |
|---|---|---|---|
| [GHSA-pw57-fxvc-2qgr](https://github.com/fraunhoferhhi/vvdec/security/advisories/GHSA-pw57-fxvc-2qgr) | **High (7.5)** | Heap use-after-free **write** | `Picture::fillGrey`, concealment path |
| [GHSA-p27c-vmfj-jh2f](https://github.com/fraunhoferhhi/vvdec/security/advisories/GHSA-p27c-vmfj-jh2f) | Medium | Heap out-of-bounds read (1–2 bytes) | `vvdec_get_nal_unit_type`, public API |
| [GHSA-qgqj-f693-2fqc](https://github.com/fraunhoferhhi/vvdec/security/advisories/GHSA-qgqj-f693-2fqc) | Medium | Heap out-of-bounds read | LMCS forward reshaping (`rspFwdCore`) |
| [GHSA-f7mj-r2mj-rfvh](https://github.com/fraunhoferhhi/vvdec/security/advisories/GHSA-f7mj-r2mj-rfvh) | Medium | OOB read + NULL deref | `extendPicBorderWrap`, stale PPS |

(As of this writing the advisories carry GHSA IDs; CVE numbers had not yet
appeared on the records.)

## Picking the target

On 8 November 2026, vvdec ticked every box on our target screen:

- **Fresh security history.** An October 2026 batch of five advisories, four of them with CVE IDs, had
  just landed, and at least one was still live on the newest release tag (v3.2.1),
  meaning the class of bug (parameter-set confusion driving memory errors)
  had recent, reproducible precedent in the code.
- **No upstream fuzzing.** vvdec had no OSS-Fuzz integration at the time, and
  its in-tree fuzzer had two structural blind spots (below). The parsing
  surface (an attacker-controlled bitstream fed to a decoder) was real but
  under-instrumented.
- **A cooperative disclosure channel.** Their SECURITY.md offers GitHub
  private vulnerability advisories, and the October CVE wave showed an active
  maintainer who fixes and credits.

Everything ran against locally built trees from public tags and commits. No
third-party system was ever contacted.

## Qualifying the instrument: canary first, campaign second

The first day went not to fuzzing but to proving the harness could find known
bugs. We rebuilt the most recent public memory-safety issue in the family,
the collocated-picture out-of-bounds read recorded as
[CVE-2026-124312](https://nvd.nist.gov/vuln/detail/CVE-2026-124312), and
certified the harness **in both directions**: it fires the exact known
AddressSanitizer report on the pre-fix master commit, and goes silent on the
fix commit. A harness that cannot reproduce yesterday's bug has no standing
to report tomorrow's.

That qualification work surfaced the finding that shaped the whole campaign:
**the in-tree fuzzer was doubly blind.** It fed whole streams in one call and
ran with error-handling flags at zero, so it never exercised the decoder's
error-concealment machinery, exactly the path where the October CVEs lived.
The harness that worked copies the shipped `vvdecapp` binary's discipline
instead: one NAL unit per decode call, timestamps advancing only on slice
NALs. With that shape, the concealment path became reachable and the crashes
started.

## The campaign and the triage

An overnight run on a 32-core Linux machine, seeded with conformance streams
and canary-derived units, produced **1,167 crash artifacts in twelve hours**.
Raw crash counts mean nothing; the triage did:

1. Every artifact was re-run under ASan and deduplicated by `SUMMARY` stack
   signature.
2. Signatures were clustered and each cluster classified as known (already
   reported by us or public) or novel.
3. Novel clusters were minimized, reduced to standalone C reproducers where
   possible, and root-caused in source before anything was reported.

Three of the four advisories came out of that pipeline. The fourth came from
the other half of the method: reading the code the fuzzer kept bumping into.

## The findings

### 1. The HIGH one: use-after-free write in `Picture::fillGrey` (GHSA-pw57-fxvc-2qgr)

**How found:** the first overnight harvest. The concealment path
(`sanitizeBrokenPicture` at flush, and later a second route through
`prepareUnavailablePicture`) fills a broken picture with grey. If parameter
sets are reactivated mid-stream such that a 4:2:0 picture buffer is reused
for a 4:0:0 (monochrome) picture, the chroma planes are freed while the
fill routine still writes Cb/Cr through stale plane entries: a
use-after-free **write** on the heap, deterministic across three runs on the
shipped v3.2.1 tag and current master.

**Verification:** ASan builds at the release tag and at pinned master
commits; deterministic 3/3; a byte-exact build of the fix PR confirmed the
write disappears; the second route found days later was verified covered by
the same one-site fix and posted to the advisory thread.

**Outcome:** filed privately 2026-11-08; accepted by the maintainer
2026-11-11 with the root cause corrected (the 4:2:0→4:0:0 reuse mechanism
above); fix merged 2026-11-16; published 2026-11-20 at HIGH with
CVSS 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H), CWE-416.

### 2. The API-edge one: 1–2 byte overread in `vvdec_get_nal_unit_type` (GHSA-p27c-vmfj-jh2f)

**How found:** signature cluster "A" in the campaign triage: 29 artifacts,
all one bug. The scanner gates only `payloadSize < 3`, then reads
`pcBuf[4]`/`pcBuf[5]` unconditionally to skip a start code: any 3–5 byte
payload with a leading start code reads 1–2 bytes past the caller's buffer.
The minimal reproducer is five bytes: `00 00 00 01 60`.

**Verification:** fires 3/3 on tag and master via the **public C API**
(`vvdec_get_nal_unit_type`), boundary-exact (a six-byte payload is silent),
and reproduced from a standalone, fuzzer-free C program to rule out harness
padding artifacts.

**The twist:** independent discovery. [4KVCD](https://github.com/4KVCD) had
found the same overread by code review weeks earlier (their fix PR #458,
opened 2026-10-18, was still unmerged, so shipped releases remained
affected). The maintainer added them as co-credited reporter on our advisory.
Independent confirmation from two methods, fuzzing and reading, is exactly
what you want on a small edge-case bug.

**Outcome:** filed privately 2026-11-11; fix merged 2026-11-17; published
2026-11-20 at Medium with dual reporter credit.

### 3. The subtle one: LMCS reshaping overread after an SPS change (GHSA-qgqj-f693-2fqc)

**How found:** signature cluster "B": 21 artifacts that first looked like
two bugs (a use-after-free and an out-of-bounds read in
`rspFwdCore_SIMD`, the LMCS forward-reshaping kernel, reached from
thread-pool CTU tasks).

**Verification:** deterministic 10/10 on the tag build and 5/5 on master.
PoC bitstreams were minimized, then delivered in-thread when the maintainer
asked, with download-of-the-attachment hash-matched against the certified
packs.

**The root cause was better than our report:** Gabriel Hege unified both
variants to a single mechanism: a 10-bit SPS re-sent as 8-bit with LMCS
active within the same coded video sequence leaves a stale 10-bit reference
picture in the reference list, and the scalar branch of the reshaping kernel
indexes 16-entry LMCS pivot LUTs with a pixel-derived, unchecked index. He
re-titled and re-scoped the advisory (CWE-125, CVSS 4.3), merged the fix
(PR #472) on 2026-11-18, and left the credit intact. When a maintainer
improves your root cause, the report was worth filing.

**Outcome:** filed privately 2026-11-11; accepted 2026-11-17; fix merged
2026-11-18; published 2026-11-20 at Medium.

### 4. The reading one: wrap-around desync, stale PPS (GHSA-f7mj-r2mj-rfvh)

**How found:** not by blind fuzzing. Reading the parameter-set activation
code that the fuzzing kept disturbing showed an asymmetry: the wrap-around
flag on an SPS is not re-validated against the PPS that references it. A
**legal** sequence (an SPS re-sent at a coding-boundary with identical
geometry but the wrap flag flipped from 1 to 0) replaces the SPS map entry
while the PPS keeps wrap=1, so new pictures are allocated without
wrap-around buffers and `extendPicBorderWrap` dereferences near-NULL. We
located the flag bit by a decoder-oracle search seeded from public JVET
conformance streams, then had a crashing, standards-conformant-input case.

**Verification:** ASan SEGV 3/3 on master and on a build that already carried
the earlier fix (so not a duplicate of it), plus a native SIGSEGV 3/3 on the
shipped release build; byte-identical original streams decode clean as
controls. When the maintainer's fix PR (#470) appeared ~12 hours after the
report, we attacked it: five variant streams (including one re-sending the
PPS to test a retention gap we thought the first fix missed), all clean on a
byte-exact fix build (×3 runs), all five still crashing on unpatched. No
bypass.

**Outcome:** posted 2026-11-13 as public issue
[#469](https://github.com/fraunhoferhhi/vvdec/issues/469); fix merged
2026-11-17; published 2026-11-20 at Medium.

## What "verified" means here

- **Pinned builds.** Every claim was reproduced on a specific release tag
  (v3.2.1) and pinned master commits, with commit hashes recorded in the
  reports, never "recent master".
- **Both directions.** The harness was qualified by reproducing a known CVE
  before it was trusted; fixes were verified by rebuilding the fix commits
  byte-exact and re-firing every variant.
- **Determinism and boundaries.** Reproductions are reported as N/N counts,
  with boundary-exact controls (byte-identical clean streams; the silent
  six-byte neighbor of a five-byte PoC).
- **Honest severity.** Two of the reads are sanitizer-diagnosed: production
  builds survive them. The reports say so, and the severities reflect it:
  the maintainer's downward re-scope of the LMCS advisory was correct.

## Timeline

| Date (2026) | Event |
|---|---|
| Nov 8 | Target scouted; canary certified both directions; overnight campaign; fillGrey UAF filed privately (evening) |
| Nov 11 | Maintainer accepts the UAF report; corrects root cause; the 1,167-artifact triage lands `getNalUnitType` and LMCS reshaping, both filed privately |
| Nov 13 | Wrap-desync posted as public issue #469; fix PR #470 opened |
| Nov 14 | Our 5-variant no-bypass battery on the fix build; LMCS PoC streams delivered in-thread |
| Nov 16 | FillGrey fix (PR #468) merged |
| Nov 17 | Fix PRs #458 and #470 merged; LMCS advisory accepted |
| Nov 18 | LMCS root cause unified; fix (PR #472) merged |
| Nov 20 | All four advisories **published** (13:28–13:32 UTC) |

## Credits

Reporter credit: matt-nodejam on all four; 4KVCD co-credited on
GHSA-p27c-vmfj-jh2f for independent discovery. The fixes, the root-cause
corrections on pw57 and qgqj, and the advisory re-scoping are the work of
the vvdec maintainers, Gabriel Hege in particular handled all four threads
fast and well. This campaign reports bugs; they shipped the fixes.

---

*All reproduction steps verified hands-on against pinned versions; every
referenced artifact is public or reconstructable from public material. Testing was confined to locally built
software; no third-party production system was contacted. The PoC
bitstreams went to the maintainers through the private advisory process.*
