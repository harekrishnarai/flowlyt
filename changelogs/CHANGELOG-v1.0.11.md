# v1.0.11 — 2026-03-27

## What's Changed

### Bug Fixes

- **CACHE_WRITE_IN_PR_WORKFLOW**: Deduplicate findings across matrix-expanded jobs — same `actions/cache@vX` step now produces one finding instead of N (e330835)
- **DANGEROUS_WRITE_OPERATION**: Deduplicate findings across matrix-expanded jobs, keyed per pattern — prevents N identical CRITICAL findings for the same step (c8c02a9)
- **MATRIX_INJECTION**: Exempt arithmetic expansion context (`$(( ${{ matrix.var }} + 1 ))`) from MEDIUM finding when the matrix is statically defined; `fromJSON(inputs.*)` and `fromJSON(github.event.*)` sources still fire (2352007, 3f5ee13)
- **SHELL_SCRIPT_ISSUES**: Exempt double-quoted `$VAR` references from unquoted-variable findings for file-operation commands (`rm`, `cp`, `mv`, `mkdir`, `chmod`, `chown`, `ln`, `rsync`, `tar`, `zip`, `unzip`); `eval`, `curl`, `wget`, and `find` remain fully flagged (05c3c0b)
- **IMPOSTOR_COMMIT**: Downgrade severity from HIGH to LOW for known GitHub service bot identities (`github-actions[bot]`, `github-actions`, `dependabot[bot]`); finding is still emitted; variable-based identities remain CRITICAL (1668afe)
- **EXTERNAL_TRIGGER_DEBUG, BROAD_PERMISSIONS, ARTIPACKED_VULNERABILITY, UNSOUND_CONTAINS**: Additional false positive reductions from v1.0.10 wave — runner label matrix expression suppression, permission block scoping, checkout step deduplication, and `contains()` guard narrowing (5be8c78)

### Improvements

- Promote `knownBotRe` to package-level compiled regex, eliminating unnecessary recompilation on every step in the impostor-commit hot loop (9e31829)

## Upgrade Notes

No breaking changes. Existing `.flowlyt.yml` suppressions remain valid.
Scanning the same workflow files as v1.0.10 will produce fewer duplicate findings for matrix workflows and fewer medium-severity findings for arithmetic-safe matrix interpolations.
