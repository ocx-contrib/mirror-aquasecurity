# mirror-aquasecurity

OCX mirrors for [Aqua Security](https://github.com/aquasecurity) tooling. One
repository, one spec directory per package.

| Package | Spec | Publishes to | Announced as | Upstream SPDX |
|---|---|---|---|---|
| [trivy](https://github.com/aquasecurity/trivy) | [`trivy/mirror.yml`](trivy/mirror.yml) | `ghcr.io/ocx-contrib/aquasecurity/trivy` | [`ocx.sh/aquasecurity/trivy`](https://index.ocx.sh/aquasecurity/trivy) | `Apache-2.0` |

Each upstream release is discovered, re-bundled, smoke-tested per
`(version, platform)` and only then pushed with cascade tags, after which the
result is announced into the OCX index.

The GitHub org is the vendor's own brand and plausibly holds more than one
mirrorable tool, so the org names the namespace and the tool names the package:
`aquasecurity/trivy`.

## Layout

```
mirror-base.yml         repo-wide policy every spec inherits via `extends:`
trivy/
├── mirror.yml          the spec — never at the repo root
├── metadata.json       bundle interface
├── CATALOG.md          → ocx package describe
├── logo.svg / logo.png describe assets, 512px PNG
└── tests/smoke.star    Starlark smoke test
```

`LICENSE` and `NOTICE.md` are shared at the root. Logos are **not** — each
package carries its own, because a repo-root `logo.*` sits in no workflow's
`paths:` filter, so replacing it would publish nothing until some unrelated
edit happened to fire.

⚠️ `extends:` is a **shallow** merge of top-level keys. A spec that restates
`platforms:` to change one runner drops every `containers:` entry with it, and
nothing reds — the legs simply stop existing, and every `os.features` claim
goes back to being asserted rather than verified. Restate a block in full or
not at all. `trivy/mirror.yml` does not restate it at all, which removes the
trap structurally.

## Platforms

`trivy` publishes both Linux arches; `darwin/amd64`, `darwin/arm64` and
`windows/amd64` are pre-written **commented** in both `trivy/mirror.yml` and
`mirror-base.yml` and are enabled one rollout pass at a time (linux → darwin →
windows), since macOS runner minutes cost 10× Linux and Windows 2×.

Upstream's Linux binaries are Go builds with cgo disabled. That is a claim
until measured, so both declared arches were byte-measured — plus the amd64
asset at both ends of the mirrored range — and all three are `statically
linked`, with zero `PT_INTERP` and zero `DT_NEEDED`. They are also not
UPX-packed (`Start of section headers: 400`, zero `^UPX` strings), which
matters because a packer stub carries no `PT_INTERP` either and would make
`file` report a glibc-dynamic binary as "statically linked". `os.features`
states what an artifact requires *of the host*, so both Linux keys are
**bare** — `+libc.glibc` would be a false requirement that hid the package
from every musl host it in fact runs on. The `alpine:3.20` container leg on
both arches in `mirror-base.yml` is what turns that claim into evidence; the
measurement transcript is recorded above the `assets:` block in
`trivy/mirror.yml`.

### ⚠️ Asset casing is inconsistent by design

There is no `{os}`/`{arch}` template that produces upstream's asset set. The OS
token is capitalised for `Linux` and `macOS` but **lowercase** for `windows`,
and within the Linux family the arch token is uppercase for `ARM64`/`PPC64LE`
but **lowercase** for `s390x`:

| Platform | Asset |
|---|---|
| `linux/amd64` | `trivy_<V>_Linux-64bit.tar.gz` |
| `linux/arm64` | `trivy_<V>_Linux-ARM64.tar.gz` |
| `darwin/amd64` | `trivy_<V>_macOS-64bit.tar.gz` |
| `darwin/arm64` | `trivy_<V>_macOS-ARM64.tar.gz` |
| `windows/amd64` | `trivy_<V>_windows-64bit.zip` |

Every pattern in the spec therefore spells its own leg's casing out literally.
A single case rule across the legs silently **0-matches** one of them, and a
0-match is skipped rather than reported — a green run with a missing platform.

Each pattern is also anchored at both ends. The end anchor is load-bearing
twice over: unanchored, `Linux-64bit` reaches the `.deb` and `.rpm` twins (an
ambiguous-match hard error) and `Linux-ARM` reaches `Linux-ARM64`. Upstream
ships a large noise set around each tarball — `.deb`, `.rpm`, a
`.sigstore.json` sidecar per asset, `trivy_<V>_checksums.txt`, and a
release-level `bom.json`.

### What is not mirrored

Upstream also ships `Linux-32bit`, `Linux-ARM` (32-bit), `Linux-PPC64LE`,
`Linux-s390x` and `FreeBSD-64bit`. None maps to an OCX platform — ocx expresses
`amd64` and `arm64` on `linux`/`darwin`/`windows` only — so none is mirrored.

There is **no `windows-ARM64` asset at any version**: upstream ships exactly
one Windows artifact per release. `windows/arm64` is therefore absent rather
than staged, since a declared platform that resolves no asset does not red — it
boots a real `windows-11-arm` runner and reports SUCCESS having tested nothing.

Resolution was verified **both ways on every in-range release** (0.71.2,
0.72.0, 0.73.0): each of the five patterns matches exactly one asset, every
time, and every asset name embeds the version of the tag carrying it.

## Editing

| File | Edit | Regenerate after |
|------|------|------------------|
| `mirror-base.yml`, `trivy/mirror.yml` | hand | yes — see below |
| `trivy/{metadata.json,CATALOG.md,logo.*}` | hand | — |
| `trivy/tests/smoke.star` | hand | — |
| `.github/workflows/*.yml` | **generated — never hand-edit** | re-run when a spec changes |

```bash
ocx-mirror package pipeline generate ci --spec trivy/mirror.yml
```

**Name every spec.** `--spec` *appends* rather than replaces, so a command
naming a subset silently stops rendering the rest while staying green — and the
drift guard reds on a generated workflow the current spec set no longer
produces.

`verify-generated.yml` exits 65 on drift. If a generated workflow is wrong, the
spec or the renderer template is wrong — fix it there and regenerate.

Run `direnv allow` once to put the pinned toolchain on `PATH`, and invoke
`ocx-mirror` directly — never `ocx run -- ocx-mirror`, which pins
`OCX_BINARY_PIN` to the bootstrap `ocx` and false-reds the nested push.

## The binaries claim

`trivy/metadata.json` declares `binaries: ["trivy"]` by hand, and
`trivy/mirror.yml` sets `bin_scan: "off"` — forced, not preferred. The scan
only inspects an interface-visible `${installPath}/<dir>` PATH entry, and
trivy's archives are **flat**: `trivy(.exe)`, `LICENSE`, `README.md` and a
`contrib/` directory of 0644 report templates sit at the archive root, with no
binary-bearing subdirectory to point a PATH entry at. With nothing to inspect
the scan would pass green whatever the archive contained, so `auto` and
`verify` both fail spec load at exit 65 rather than offer a hollow check. The
hand-written list is what the error message itself directs, and it is short and
stable — `trivy` is the only mode-0755 entry.

`strip_components` is **0** for the same reason: on a flat archive
`strip_components: 1` would delete the binary and hoist `contrib/`'s contents
in its place.

## The smoke test

A scanner's contract is bidirectional: input containing something the tool is
built to find must produce findings, and input containing nothing must produce
none. `trivy/tests/smoke.star` writes both into the test scratch sandbox, scans
each, and asserts the finding **count** parsed from the JSON report file — not
the colorized human-readable table.

The scanner used is `--scanners secret`, deliberately not trivy's headline
vulnerability scan. The vulnerability database is a multi-hundred-megabyte OCI
artifact downloaded on first use, so a vuln-based smoke would test a CDN as
much as the binary and would red on any network hiccup in any of six container
legs; `trivy config` is no better, fetching an OCI check bundle unless
`--skip-check-update` is passed. The secret rule set is compiled into the
binary — no database, no bundle, no network, and measurably no cache directory
created.

**Exit codes are not the assertion, because trivy has none to give here.**
`trivy fs` exits 0 whether it finds three secrets or none (`--exit-code`
defaults to 0), so "the scan succeeded" is satisfied by a binary that scanned
nothing. Three files carrying three different providers' credentials must yield
exactly three findings, attributed to `aws-access-key-id`, `github-pat` and
`slack-access-token` — rule ids that come from trivy's own engine and not from
the input, so a tool that merely echoed its arguments could not produce them —
and the clean tree must yield exactly zero.

The planted credentials are synthetic and deliberately *not* a vendor's own
documentation example: AWS's `AKIAIOSFODNN7EXAMPLE` is allowlisted by trivy's
default config and yields zero findings, which is exactly the silent pass the
negative control exists to catch.

## Required secrets

| Secret | Use |
|--------|-----|
| `OCX_ANNOUNCE_TOKEN` | opens the index pull request from the `ocx-contrib/index` fork |
| `OCX_MIRROR_DISCORD_HOOK` | notify-stage Discord webhook URL |

(Inherited from the `ocx-contrib` org with visibility ALL. GHCR pushes use the
run's own `GITHUB_TOKEN` — no registry secret needed.)

## License

Apache-2.0 — see [`LICENSE`](LICENSE). Upstream assets are out of scope; each
package's redistribution license is recorded in [`NOTICE.md`](NOTICE.md). The
logo reproduces upstream's own mark, unmodified apart from scaling, solely to
identify the software being mirrored.
