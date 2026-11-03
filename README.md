# Security Report Diff

Compare two SARIF 2.1.0 reports offline and list new findings, resolved findings and severity changes. Output deliberately excludes result messages, source snippets, arbitrary properties, raw fingerprints and scanner names. Requires Python 3.10 or newer and has no third-party runtime dependencies.

## Install and run

From this project directory:

```sh
python -m venv .venv
# POSIX: . .venv/bin/activate
# PowerShell: .venv/Scripts/Activate.ps1
python -m pip install -e .
security-report-diff samples/before.sarif samples/after.sarif
security-report-diff samples/before.sarif samples/after.sarif --format json
python -m unittest discover -s tests -v
```

The generated samples show one new finding, one resolved finding and one severity change. Output goes to stdout; no report is saved automatically. Exit status is `0` on successful comparison (even with new findings), or `2` on invalid input or CLI arguments. This MVP does not implement a CI failure policy for findings.

## Matching and output

Findings match by hashed scanner driver name, `ruleId`, normalized primary artifact path, and location identity. A sorted `fingerprints` map is preferred, followed by a sorted `partialFingerprints` map; each entire map is SHA-256 hashed to a 24-character identifier. With a fingerprint, line/column movement does not create a new finding. Without one, primary start line and column form the location identity. A path change produces a resolved/new pair even with an unchanged fingerprint. Changed fingerprint maps also produce resolved/new pairs.

Duplicates are a multiset: identical severities match first; remaining occurrences are paired deterministically for severity changes; surplus occurrences become new/resolved. Output is stably sorted. SARIF levels `none`, `note`, `warning`, `error` are supported. For fail results, an omitted level uses its driver's rule default or `warning`; non-fail kinds default to `none` and reject other levels. `ruleIndex` is supported when it resolves within driver rules. The tool compares emitted results, including non-fail and suppressed results, without interpreting suppression policy or `baselineState`.

Relative artifact URIs are treated as repository-relative paths, with slash normalization, percent decoding and dot-segment normalization. External absolute paths, escaping `../` paths, control characters and non-file URI schemes are replaced by `[external:<hash>]`. Supply the same repository root for both reports to make contained absolute paths relative:

```sh
security-report-diff before.sarif after.sarif --repo-root /work/example-repo --format json
```

Windows drive paths and `file:///` URIs are supported without accessing the referenced files. External hashes are stable for the same original URI, but changing an external path can produce a resolved/new pair. Queries/fragments on relative URIs, remote URIs, and direct Windows drive paths cause the whole location to be masked; file URI query/fragment data is discarded. Relative paths and rule identifiers remain visible: review these before sharing output. Hashes reduce accidental disclosure and are not encryption or an anonymity guarantee.

## Supported subset and limits

Inputs must be UTF-8 SARIF JSON version `2.1.0` with a `runs` array. The supported subset reads driver rules, result rule identity/kind/level, the first physical location, region start line/column, and fingerprints. It does not resolve `uriBaseId`, indexed artifact locations, result `rule` references, invocation configuration overrides, tool extensions, logical locations, related locations or multi-location identities. Relative URIs using a base ID are assumed already relative to the repository; indexed-only physical locations behave as `[no-location]`. Findings without usable physical locations share that placeholder and rely on fingerprints or zero line/column, so ambiguous inputs should be normalized by the producer before comparison. Unsupported metadata is ignored; this is not a complete SARIF validator. A report with zero runs/results is valid.

Each report is limited to 20 MiB and 100,000 findings. Malformed JSON/required supported fields produce controlled errors without echoing report contents. Nested JSON is bounded by Python's parser recursion limit. No files referenced by SARIF are opened. No scanner is executed, no network request is made, and there is no telemetry. Only synthetic fixtures belong in this repository; keep real scanner reports and secrets outside version control. Consult the [SARIF 2.1.0 specification](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html) for the full format.
