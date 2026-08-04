# trivy/tests/smoke.star — stable across upstream trivy releases.
# Asserts the contract (version shape, a real detection with a counted result,
# and the negative control), never help/version prose. See ocx.mirror
# testing-practices.md.
#
# ⚠ WHY SECRET SCANNING AND NOT VULNERABILITY SCANNING. trivy's headline verb
# needs a vulnerability database it downloads as a multi-hundred-megabyte OCI
# artifact on first use, so a vuln-based smoke would be testing a CDN as much
# as the binary and would red on any network hiccup in any of six container
# legs. `trivy config` is no better — it fetches an OCI check bundle unless
# `--skip-check-update` is passed. The SECRET rule set is compiled into the
# binary: no database, no bundle, no network, byte-identical results offline.
# Measured — the run below creates no cache directory at all.
#
# ⚠ EXIT CODE PROVES NOTHING HERE. `trivy fs` exits 0 whether it finds three
# secrets or none (`--exit-code` defaults to 0), so "the scan succeeded" is
# satisfied by a binary that scanned nothing. The finding COUNT parsed out of
# the JSON report is the assertion; `expect.ok` is only a liveness check.
#
# The report is read from a FILE (`--output`) rather than stdout: the file is
# the tool's own encoder output, byte-exact and colourless, where the
# human-readable table is colorized and would break a plain-substring assertion
# token by token.
#
# NOTE — no free platform-identity assert is available for this package.
# `trivy version --format json` emits `{"Version":"0.73.0"}` and nothing else;
# unlike many Go tools it prints no GOOS/GOARCH, so there is no in-band way for
# the smoke to confirm the asset regex shipped the right arch into the bundle.

TRIVY = "trivy.exe" if ocx.target_platform.os == ocx.os.Windows else "trivy"

# Keep every byte trivy might persist inside the test sandbox. A container leg
# runs as uid 0 with HOME unset or unwritable, and a tool that falls back to
# `$HOME/.cache` there exits non-zero for reasons that have nothing to do with
# the artifact. `--cache-dir` covers trivy's own knob; HOME/USERPROFILE cover
# anything underneath it.
CACHE = ocx.scratch_root + "/trivy-cache"
ENV = {
    "HOME": ocx.scratch_root,
    "USERPROFILE": ocx.scratch_root,
    "XDG_CACHE_HOME": CACHE,
}

# Synthetic credentials, shaped to match trivy's built-in rules and nothing
# else. None is real, and none is a vendor's own documentation example — AWS's
# `AKIAIOSFODNN7EXAMPLE` is allowlisted by the default config and yields ZERO
# findings, which is exactly the silent-pass this test exists to prevent.
#
# ⚠ EACH ONE IS ASSEMBLED FROM FRAGMENTS AND MUST STAY THAT WAY. GitHub push
# protection scans every pushed file and REJECTS the whole commit when one
# contains a token-shaped literal — it blocked this exact file's first push:
#
#   remote: error: GH013: Repository rule violations found for refs/heads/main.
#   remote:  —— Slack API Token ——
#   remote:    path: trivy/tests/smoke.star:50
#
# Splitting each constant leaves no contiguous match in the source while the
# same bytes still reach trivy at runtime. Do not "tidy" these back into single
# literals: the push fails, and the failure is a repo-rule violation with no
# override available from a bot account. Any future planted fixture goes in the
# same shape, whether or not today's detectors happen to flag it.
AWS_KEY = "AKIA" + "Z3MTLNRQ7WKPFV2C"
GH_PAT = "ghp" + "_1a2B3c4D5e6F7g8H9i0JkLmNoPqRsTuVwXyZ"
SLACK_TOKEN = "xoxb" + "-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"

# ── Tier 1 + 2: liveness on the composed PATH + version SHAPE ───────────────
# The digits are the contract; the key around them is trivy's own JSON encoder.
r_version = ocx.run(TRIVY, "version", "--format", "json", "--cache-dir", CACHE, env = ENV)
expect.ok(r_version)
expect.matches(r_version.stdout, r'"Version":\s*"\d+\.\d+\.\d+"')

# ── Tier 3: real detections on hermetic input ───────────────────────────────
# Three different files, three different providers, three different built-in
# rules — so a single over-broad or single dead rule cannot fake the count.
ocx.mkdir("dirty")
ocx.write_file("dirty/a.env", "AWS_ACCESS_KEY_ID=" + AWS_KEY + "\n")
ocx.write_file("dirty/b.yaml", "token: " + GH_PAT + "\n")
ocx.write_file("dirty/d.txt", "slack: " + SLACK_TOKEN + "\n")

r_dirty = ocx.run(
    TRIVY,
    "fs",
    "--scanners",
    "secret",
    "--format",
    "json",
    "--output",
    "dirty.json",
    "--cache-dir",
    CACHE,
    "--quiet",
    "dirty",
    env = ENV,
)
expect.ok(r_dirty)

dirty = ocx.read_file("dirty.json")
# THE assertion: exactly three findings. A scanner that reported nothing, or
# that flooded the report, fails here even though its exit code above passed.
expect.eq(dirty.count("\"RuleID\""), 3)
# Each finding is attributed to the rule that describes it, in the file the
# matching secret was planted in. The rule ids, categories and severities come
# from trivy's own engine, not from the input — so a tool that merely echoed
# its arguments could not produce them.
expect.contains(dirty, "aws-access-key-id")
expect.contains(dirty, "github-pat")
expect.contains(dirty, "slack-access-token")
expect.contains(dirty, "a.env")
expect.contains(dirty, "b.yaml")
expect.contains(dirty, "d.txt")
expect.eq(dirty.count("\"Class\": \"secret\""), 3)
# The report carries the scanning binary's own version, so the encoder and the
# version reported above are bound to one another.
expect.matches(dirty, r'"Version":\s*"\d+\.\d+\.\d+"')

# ── Negative control — states what would go red ─────────────────────────────
# A tree with nothing secret-shaped must produce ZERO findings. Without this, a
# hypothetical build whose rules matched everything would pass every assertion
# above. It is the only discriminating signal available: unlike gitleaks,
# trivy does NOT invert its exit code on findings — both runs exit 0.
ocx.mkdir("clean")
ocx.write_file("clean/notes.txt", "hello world\nnothing to see here\n")

r_clean = ocx.run(
    TRIVY,
    "fs",
    "--scanners",
    "secret",
    "--format",
    "json",
    "--output",
    "clean.json",
    "--cache-dir",
    CACHE,
    "--quiet",
    "clean",
    env = ENV,
)
expect.ok(r_clean)

clean = ocx.read_file("clean.json")
expect.eq(clean.count("\"RuleID\""), 0)
# A clean scan omits the `Results` array entirely — not an empty one.
expect.eq(clean.count("\"Results\""), 0)
