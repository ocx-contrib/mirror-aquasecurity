---
title: trivy
description: All-in-one security scanner — vulnerabilities, misconfigurations, secrets, licenses and SBOMs across containers, filesystems, git repos, Kubernetes and IaC
keywords: trivy,aquasecurity,security,vulnerability-scanner,sca,sbom,cve,secret-scanning,misconfiguration,iac,kubernetes,containers,devsecops,cli,go
---

# trivy

[Trivy](https://github.com/aquasecurity/trivy) is Aqua Security's all-in-one
open-source security scanner. One binary finds known vulnerabilities (OS
packages and language dependencies), infrastructure-as-code
misconfigurations, hardcoded secrets and license issues — across container
images, filesystems, git repositories, Kubernetes clusters, VM images and
cloud accounts. It also generates and scans SBOMs (CycloneDX, SPDX).

Findings are reported as a table, JSON, SARIF, CycloneDX, SPDX, GitHub
dependency-snapshot JSON, JUnit or any Go template, so it drops into CI, a
pre-commit hook or a one-off audit equally well.

## What's included

- **trivy** — the binary. `trivy image`, `trivy fs`, `trivy repo`,
  `trivy k8s`, `trivy config`, `trivy sbom` and `trivy vm` cover the scan
  targets; `trivy server`/`trivy client` run it in client-server mode.

The archive also ships upstream's `LICENSE`, `README.md` and a `contrib/`
directory of report templates (`asff.tpl`, `gitlab.tpl`,
`gitlab-codequality.tpl`, `html.tpl`, `junit.tpl`) for `--format template`.

**What needs network, and what does not.** The **secret** scanner's rule set
is compiled into the binary and runs fully offline. The **vulnerability**
scanner downloads a trivy-db OCI artifact on first use (`--skip-db-update` to
reuse a cached one, `--download-db-only` to pre-warm), and **misconfiguration**
scanning fetches an OCI check bundle unless `--skip-check-update` is passed.
Plan for a writable cache directory (`--cache-dir`, default
`$HOME/.cache/trivy`) in air-gapped or read-only environments.

## Usage

```sh
# scan a directory tree for hardcoded secrets — no database, no network
trivy fs --scanners secret .
```

```sh
# scan a container image for vulnerabilities, machine-readable report
trivy image --format json --output report.json alpine:3.20
```

```sh
# scan Terraform / Kubernetes manifests for misconfigurations
trivy config ./infra
```

```sh
# generate a CycloneDX SBOM for a project
trivy fs --format cyclonedx --output sbom.cdx.json .
```

Per-project defaults go in a `trivy.yaml`, findings are suppressed by
fingerprint in a `.trivyignore`, and `--exit-code 1` turns any finding into a
failing CI step.

## Install with ocx

```sh
ocx install ocx.sh/aquasecurity/trivy
```

```sh
# or pin a specific version
ocx install ocx.sh/aquasecurity/trivy:0.73.0
```

## Links

- [Trivy on GitHub](https://github.com/aquasecurity/trivy)
- [trivy.dev](https://trivy.dev)
- [Documentation](https://trivy.dev/latest/docs/)
- [trivy-action](https://github.com/aquasecurity/trivy-action)
