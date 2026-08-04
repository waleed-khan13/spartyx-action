# Spartyx security scan — GitHub Action

Scans a repository on every pull request and comments with what it found.

## Quick start

1. Create an API key: **Dashboard → Settings → API keys**.
2. Add it to the repository as a secret named `SPARTYX_API_KEY`
   (*Settings → Secrets and variables → Actions*).
3. Add the workflow below.

```yaml
name: Security

on:
  pull_request:

permissions:
  contents: read          # read the repository to scan it
  pull-requests: write    # write the summary comment

jobs:
  spartyx:
    runs-on: ubuntu-latest
    steps:
      - uses: waleed-khan13/spartyx-action@v1
        with:
          api-key: ${{ secrets.SPARTYX_API_KEY }}
```

That is the whole setup. There is no checkout step — the scan reads the
repository through the GitHub API — and nothing to install.

## What it does to your permissions

Nothing outside the job.

The repository is read using the workflow's own `GITHUB_TOKEN`, which GitHub
mints for that single run, scopes to that single repository, and expires when
the job ends. The comment is posted with the same token. The Spartyx GitHub App
is not involved and does not need to be installed, so turning this on grants
Spartyx no standing access to your code.

The API key identifies your account for quota. It is not a GitHub credential and
cannot read anything by itself.

## Inputs

| Input | Default | What it does |
| --- | --- | --- |
| `api-key` | — | **Required.** Your Spartyx API key. Always from a secret. |
| `github-token` | `${{ github.token }}` | Reads the repository and writes the comment. |
| `mode` | `ghost` | `ghost` (fast), `recon`, or `axiom` (deepest). |
| `fail-on` | `high` | Fail at or above this severity. `critical`, `high`, `medium`, `low`, or `none`. |
| `comment` | `true` | Post the pull request comment. |
| `sarif-file` | `spartyx.sarif` | Where the SARIF result is written. |
| `timeout-minutes` | `20` | How long to wait before giving up. |
| `api-url` | hosted API | Only for a self-hosted backend. |

## Outputs

`total`, `critical`, `high`, and `sarif-file`.

## Findings in the Security tab

The Action always writes SARIF. Hand it to GitHub's uploader to get findings
annotated on the diff and tracked in *Security → Code scanning*:

```yaml
      - uses: waleed-khan13/spartyx-action@v1
        id: scan
        with:
          api-key: ${{ secrets.SPARTYX_API_KEY }}
          fail-on: none        # let the Security tab be the gate instead

      - uses: github/codeql-action/upload-sarif@v3
        if: always()           # upload even when the scan step failed
        with:
          sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

That needs `security-events: write` alongside the permissions above.

## Notes

- **Start with `fail-on: none`.** Turn the gate on once you have seen what a
  first scan reports on your codebase, so an unfamiliar finding does not block a
  release on day one.
- **Repeat runs edit one comment** rather than adding a new one per push.
- **Forked pull requests** get a read-only `GITHUB_TOKEN`, so the comment step
  is skipped there. The scan still runs and the SARIF is still written.
- **Nothing is retained.** A CI scan asks the backend not to keep a copy of the
  source.

## Development

```bash
node --test index.test.js   # parsing and comment building
node --test e2e.test.js     # the whole Action against stub servers
```

No build step and no dependencies: `index.js` is what runs.
