# NOTICE

This repository packages and redistributes upstream software published by
[Aqua Security](https://github.com/aquasecurity). The Apache-2.0 license in
[`LICENSE`](LICENSE) covers the OCX pipeline files authored here. It does
**not** cover any upstream-derived asset — each package's redistributed bytes
carry their own license, recorded below.

Each package's logo in this repository reproduces the **upstream project's own
mark** at 512 px, unmodified apart from scaling, solely to identify the
software being mirrored. No endorsement or affiliation is implied, and no
trademark right is claimed. "Trivy" and "Aqua" are marks of Aqua Security
Software Ltd.

| Package | GHCR path | Upstream SPDX |
|---|---|---|
| `trivy` | `ghcr.io/ocx-contrib/aquasecurity/trivy` | `Apache-2.0` |

---

## `trivy`

Upstream: <https://github.com/aquasecurity/trivy>
Published to `ghcr.io/ocx-contrib/aquasecurity/trivy`.

| Component | SPDX | Holder |
|---|---|---|
| Trivy (`trivy`) | **Apache-2.0** | Copyright Aqua Security Software Ltd. |

Verified at the license gate:

```
$ gh api repos/aquasecurity/trivy/license --jq '{spdx: .license.spdx_id, path: .path}'
{"path":"LICENSE","spdx":"Apache-2.0"}
```

The Apache License 2.0 grants a perpetual, worldwide, royalty-free copyright
licence to reproduce and distribute the work and derivative works in source or
**object** form, on the conditions in §4: recipients receive a copy of the
licence, modified files are marked, and any `NOTICE` text is retained. Those
conditions are met by construction — upstream's `LICENSE` file ships **inside
every mirrored archive**, at the archive root beside the binary, and is
republished unmodified as part of the bundle content. Nothing is modified, so
§4(b) does not arise.

§6 of the licence grants no trademark rights; the reproduction of upstream's
mark above is nominative use to identify the mirrored software, not a claim
under it.

The published binaries statically link third-party Go modules under permissive
licenses, enumerated in the `go.mod`/`go.sum` of the tagged upstream source for
each mirrored version. Upstream also publishes a per-release SBOM (`bom.json`)
alongside its release assets.

No modifications are made to any upstream artifact in this repository; they are
republished byte-for-byte inside an OCX bundle.
