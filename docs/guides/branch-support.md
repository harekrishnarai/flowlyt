# Ref Support (Branch, Tag, or Commit SHA)

## Overview

Flowlyt can scan any git ref of a remote repository — a **branch**, a **tag**,
or a **commit SHA** — using the `--ref` flag. When `--ref` is omitted, the
repository's default branch is detected automatically. Both the scanned
*content* and the file *links* in the report use the requested ref, so a report
is always consistent with the code it describes.

> `--branch` is kept as a backward-compatible **alias** for `--ref`. Existing
> commands continue to work unchanged.

## Key Features

### 1. Automatic default-branch detection

When no `--ref` is specified, Flowlyt detects the default branch:

- **GitHub**: `GET /repos/:owner/:repo` → `default_branch`
- **GitLab**: `GET /api/v4/projects/:id` → `default_branch`
- **Fallback**: `main` if detection fails

### 2. Ref-specific scanning

```bash
# Branch
flowlyt scan --url https://github.com/owner/repo --ref develop

# Tag
flowlyt scan --url https://github.com/owner/repo --ref v2.0.0

# Commit SHA
flowlyt scan --url https://github.com/owner/repo --ref 5c9ec1c5f51d682dbf65b0c16f856d8b9303adff

# Backward-compatible alias
flowlyt scan --url https://github.com/owner/repo --branch develop
```

### 3. Content and links both follow the ref

The ref controls the workflow content that is analyzed, not just the links:

- **GitHub** fetches workflow files at the ref via the contents API
  (`RepositoryContentGetOptions.Ref`).
- **GitLab** clones the ref: branches and tags use a shallow
  `git clone --branch`; a commit SHA (which `--branch` cannot resolve) falls
  back to a full clone followed by `git checkout <ref>`.

Generated links use the same ref:

```
https://github.com/{owner}/{repo}/blob/{ref}/{path}#L{line}
https://gitlab.com/{owner}/{repo}/-/blob/{ref}/{path}#L{line}
```

## Ref resolution priority

1. **Explicit `--ref` (or `--branch`)** — highest priority.
2. **Auto-detected default branch** via the platform API.
3. **Fallback to `main`** if detection fails.

## Verbose mode

```bash
flowlyt scan --url https://github.com/owner/repo --ref v2.0.0 --verbose
```

```
Downloading workflow files from GitHub repository: owner/repo (ref: v2.0.0)
```

## Error handling

### Ref not found

```bash
$ flowlyt scan --url https://github.com/owner/repo --ref nonexistent
Error: failed to fetch workflow files ... (ref not found)
```

### API rate limiting

Provide a token to raise GitHub's rate limit (and to access private repos):

```bash
export GITHUB_TOKEN=$(gh auth token)
flowlyt scan --url https://github.com/owner/repo --ref develop
```

## Organization scans

`flowlyt analyze-org` always uses each repository's default branch; `--ref` is a
single-repository (`scan`) option.

## Notes for reproducible / audit scans

Because a `--ref` can be a tag or a full commit SHA, you can pin a scan to an
exact, immutable point in history — useful for auditing a release or producing a
reproducible result in CI:

```bash
flowlyt scan --url https://github.com/owner/repo --ref v2.0.0   --output sarif --output-file release.sarif
flowlyt scan --url https://github.com/owner/repo --ref <commit> --output sarif --output-file audit.sarif
```

## Related documentation

- [CLI Reference](../reference/cli-reference.md)
- [CI/CD Integration](../integrations/cicd-integration.md)
- [SARIF Output](../integrations/sarif-output.md)
