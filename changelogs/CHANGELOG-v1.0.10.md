# v1.0.10 — 2026-03-19

## What's Changed

### Bug Fixes

- **REF_CONFUSION**: Stable semver version tags (`@v1`, `@v2`, `@v1.2.3`) no longer produce false positive findings. Only genuinely mutable refs (`@main`, `@master`, `@develop`, bare branch-style names) fire. Severity is now differentiated: `main`/`master` = HIGH, others = MEDIUM. The `git checkout`/`git pull` sub-rule is unchanged.

- **EXTERNAL_TRIGGER_DEBUG**: `workflow_dispatch` findings are now gated on effective write permissions. Workflows with `permissions: read-all`, `permissions: none`, or all-read scope maps are suppressed — a read-only manually triggered workflow poses no meaningful attack surface. Workflows with no `permissions:` block (GitHub default = write-all) or any write scope still fire. `issue_comment`, `pull_request_target`, `workflow_run`, and `repository_dispatch` behaviour is unchanged.

- **SHELL_SCRIPT_ISSUES (unquoted variable)**: The broad unquoted-variable check has been replaced with a precise per-line scan. Variables used in safe command positions (`echo`, `printf`, `cat`) are no longer flagged. Only variables in genuinely dangerous positions (`rm`, `cp`, `mv`, `curl`, `wget`, `eval`, `bash -c`, `sudo`-prefixed variants, etc.) produce findings.

- **Data flow analysis**: Fixed two false positive patterns in the taint engine — self-referential env var flows (a variable assigned from a secret and used in its own env block) and cross-variable same-step flows (unrelated env vars sharing a step being incorrectly linked).

### Improvements

- `permsImplyWrite` correctly handles all GitHub Actions permissions forms: `nil` (write-all default), string shorthands (`read-all`, `write-all`, `none`), boolean values (`false`/`true`), empty map (`{}`), and granular scope maps.
- `dangerousCmdRe` extended to match `sudo`-prefixed dangerous commands (`sudo rm`, `sudo chmod`, etc.).
- Added regression test fixtures for scs-feed workflows ensuring false positive suppression is stable across updates.

## Breaking Changes

None.

## Upgrade Notes

No special steps required. Existing `.flowlyt.yml` configuration files are fully compatible.
