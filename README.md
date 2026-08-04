# Spartyx security scan

Scans your repository on every pull request and comments with what it found —
SQL injection, XSS, command injection, path traversal, hardcoded secrets and
vulnerable dependencies, across 14 languages.

It parses each file into a syntax tree and follows untrusted data through it
rather than grepping for patterns, so it can report the path from where input
arrives to where it does damage — including when that path crosses files.

```yaml
- uses: waleed-khan13/spartyx-action@v1
  with:
    api-key: ${{ secrets.SPARTYX_API_KEY }}
```

No checkout step. Nothing to install. No GitHub App.

---

## Contents

- [Quick start](#quick-start)
- [What access it needs](#what-access-it-needs)
- [Inputs](#inputs)
- [Outputs](#outputs)
- [Recipes](#recipes)
- [Scan modes](#scan-modes)
- [What the comment looks like](#what-the-comment-looks-like)
- [Behaviour worth knowing](#behaviour-worth-knowing)
- [Troubleshooting](#troubleshooting)
- [How it works](#how-it-works)
- [What happens to your code](#what-happens-to-your-code)
- [Development](#development)

---

## Quick start

**1. Create an API key.** In your Spartyx dashboard: **Settings → API keys →
Create key**. It is shown once — copy it then.

**2. Store it as a repository secret.** In your repository: **Settings → Secrets
and variables → Actions → New repository secret**, named `SPARTYX_API_KEY`.

**3. Add the workflow** at `.github/workflows/security.yml`:

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
          fail-on: none   # report first; turn the gate on once you have looked
```

Open a pull request. The comment appears when the scan finishes.

> **Start with `fail-on: none`.** Let it report on a few pull requests before you
> let it block one. A first scan on an unfamiliar codebase usually surfaces
> things worth discussing rather than things worth stopping a release for.

---

## What access it needs

Nothing that outlives the job.

The repository is read using the workflow's own `GITHUB_TOKEN` — the one GitHub
mints for that single run, scopes to that single repository, and invalidates
when the job ends. The pull request comment is posted with the same token.

**The Spartyx GitHub App is not involved and does not need to be installed.**
Adding this action grants Spartyx no standing access to your code. Delete the
workflow and there is nothing left to revoke.

The API key identifies your account so the scan is counted against it. It is not
a GitHub credential and cannot read anything on its own.

Both credentials are redacted from everything the action prints, so a failing
scan cannot spill either into your build log.

---

## Inputs

| Input | Required | Default | Description |
| --- | --- | --- | --- |
| `api-key` | **yes** | — | Your Spartyx API key. Always from a secret, never inline. |
| `github-token` | no | `${{ github.token }}` | Reads the repository and writes the comment. The default is almost always right. |
| `mode` | no | `ghost` | Scan depth. See [Scan modes](#scan-modes). |
| `fail-on` | no | `high` | Fail the job at or above this severity: `critical`, `high`, `medium`, `low`, or `none` to never fail. |
| `comment` | no | `true` | Post the pull request comment. Set to `false` to scan quietly. |
| `sarif-file` | no | `spartyx.sarif` | Where to write the SARIF result. Parent directories are created. |
| `timeout-minutes` | no | `20` | How long to wait for the scan before giving up and failing. |
| `api-url` | no | hosted API | Only set this if you run your own Spartyx backend. |

## Outputs

| Output | Description |
| --- | --- |
| `total` | Total number of findings. |
| `critical` | Number of critical findings. |
| `high` | Number of high findings. |
| `sarif-file` | Path to the SARIF file that was written. |

---

## Recipes

### Report only, never block

Good for the first week, and for repositories where you want visibility without
a gate.

```yaml
- uses: waleed-khan13/spartyx-action@v1
  with:
    api-key: ${{ secrets.SPARTYX_API_KEY }}
    fail-on: none
```

### Block a pull request on serious findings

```yaml
- uses: waleed-khan13/spartyx-action@v1
  with:
    api-key: ${{ secrets.SPARTYX_API_KEY }}
    fail-on: high     # critical and high fail; medium and low are reported
```

Make it a required check under **Settings → Branches → Branch protection rules**
if you want it enforced rather than advisory.

### Findings in the Security tab, annotated on the diff

The action always writes SARIF. Hand it to GitHub's uploader and findings appear
inline on the changed lines and are tracked in **Security → Code scanning**,
with GitHub deciding which are new and which are already known.

```yaml
permissions:
  contents: read
  pull-requests: write
  security-events: write    # required by upload-sarif

steps:
  - uses: waleed-khan13/spartyx-action@v1
    id: scan
    with:
      api-key: ${{ secrets.SPARTYX_API_KEY }}
      fail-on: none         # let the Security tab be the gate instead

  - uses: github/codeql-action/upload-sarif@v3
    if: always()            # upload even if the scan step failed
    with:
      sarif_file: ${{ steps.scan.outputs.sarif-file }}
```

### Scan the default branch on every push

```yaml
on:
  push:
    branches: [main]
```

Works as-is. There is no pull request to comment on, so it scans, writes the
SARIF, and reports in the log.

### A weekly scan that catches newly published advisories

Code that was clean last month is not clean today if an advisory has since
landed against one of its dependencies.

```yaml
on:
  schedule:
    - cron: '0 6 * * 1'   # Mondays, 06:00 UTC
  workflow_dispatch:      # and on demand
```

### Use the counts in a later step

```yaml
- uses: waleed-khan13/spartyx-action@v1
  id: scan
  with:
    api-key: ${{ secrets.SPARTYX_API_KEY }}
    fail-on: none

- name: Shout if anything is critical
  if: steps.scan.outputs.critical != '0'
  run: echo "::warning::${{ steps.scan.outputs.critical }} critical finding(s)"
```

### Keep the SARIF as a build artifact

```yaml
- uses: actions/upload-artifact@v4
  if: always()
  with:
    name: spartyx-sarif
    path: ${{ steps.scan.outputs.sarif-file }}
```

---

## Scan modes

| Mode | What it does | When to use it |
| --- | --- | --- |
| `ghost` *(default)* | The static analysis: syntax-tree parsing, cross-file taint tracking, secret detection, and dependency advisories. | Every pull request. Fast enough to sit in the critical path. |
| `recon` | Everything in `ghost`, plus external intelligence on the packages it finds. | Scheduled runs, or release branches. |
| `axiom` | Everything in `recon`, plus AI reasoning over the paths it could not settle statically. | A deeper look before a release. Falls back to `recon` if AI is unavailable, rather than failing. |

Deeper modes take longer. If you raise the mode, consider raising
`timeout-minutes` with it.

---

## What the comment looks like

This is the markdown it posts, taken from a real run:

```markdown
## Spartyx security scan

3 findings — **3** high.

| Severity | Finding | Location |
| --- | --- | --- |
| high | AST analysis confirmed unsafe command execution. | `app/lookup.py:23` |
| high | AST analysis found a credential-like variable assigned to a string literal. | `app/lookup.py:8` |
| high | AST analysis found filesystem access using a dynamic path. | `app/lookup.py:29` |

[Full report](https://www.cybertool.dev/dashboard/scans/...)
```

A clean scan says so rather than staying silent, so "nothing found" is
distinguishable from "never ran".

Up to 15 findings are listed, worst first, with a count of any beyond that. The
full set is in the SARIF and in the linked report.

---

## Behaviour worth knowing

**One comment, edited in place.** Each run finds its own previous comment and
updates it. Ten pushes to a branch leave one comment showing the current state,
not ten showing its history.

**Pull requests from forks are not scanned.** GitHub withholds repository
secrets from workflows triggered by a fork, so `api-key` arrives empty and the
action stops immediately with `No api-key supplied`. This is GitHub protecting
your secrets from code you have not reviewed, and it applies to every action
that needs a credential — not something this one can work around.

If you accept contributions from forks, the usual options are to scan on `push`
to your own branches, or to run a separate scan after merge. There is a
`pull_request_target` trigger that does receive secrets, but it runs with a
write-capable token in your repository's context while checking out the fork's
code, which is a well-known way to hand an attacker your token — do not reach
for it without understanding that trade-off.

**A comment that cannot be posted is a warning, not a failure.** If the workflow
lacks `pull-requests: write`, the action says so and carries on: the scan still
ran, the SARIF is still written, and `fail-on` still applies. It will not fail
your build over a comment it was never allowed to post.

**Not a pull request?** It scans and skips the comment. Not an error.

**The head commit, not the merge commit.** On a pull request GitHub checks out a
merge commit that exists nowhere else. The scan targets the branch head, which is
what a reviewer is actually reading.

**Timeouts fail loudly.** If the scan has not finished within `timeout-minutes`,
the job fails saying so rather than passing on no result.

**A failed scan fails the build.** If the backend reports the job failed,
cancelled or stalled, the action fails with whatever detail it was given, with
credentials stripped out.

---

## Troubleshooting

**`No api-key supplied.`**
Either the secret is missing or misnamed — check **Settings → Secrets and
variables → Actions**, and that the `with:` block uses the same name — or this
run was triggered by a pull request from a fork, which GitHub deliberately
denies access to your secrets. See
[Behaviour worth knowing](#behaviour-worth-knowing).

**`POST /api/scan-repo failed (401)`**
The API key is wrong, revoked, or belongs to a suspended account. Create a new
one under **Settings → API keys** and update the secret.

**`Could not post the comment (403)` — and the job still passed**
The workflow is missing `pull-requests: write`. Add the permission block:

```yaml
permissions:
  contents: read
  pull-requests: write
```

**`The scan did not start: no job id was returned.`**
The backend accepted the request but did not queue a job. Usually transient —
re-run the job.

**`Scan failed: ...`**
The scan itself broke, and the message carries the backend's reason.

**`The scan did not finish within 20 minutes.`**
Raise `timeout-minutes`, or use a lighter `mode`. A large repository on `axiom`
can take a while.

**`N finding(s) at or above high.`**
Working as configured — this is the gate doing its job. Fix them, lower
`fail-on`, or set it to `none` while you triage.

**`Node.js 20 is deprecated`**
You are pinned to an old tag. Move to `@v1`, which targets Node 24.

---

## How it works

1. Reads the event to work out the repository, the branch, and whether this is a
   pull request.
2. Asks the Spartyx API to scan that repository, passing the workflow's
   `GITHUB_TOKEN` so the backend can read it — for that request only.
3. Polls the job every 5 seconds, logging each stage as it changes.
4. Fetches the result as SARIF and writes it to `sarif-file`.
5. Posts or updates the pull request comment.
6. Applies `fail-on` and sets the exit code.

The action is a single dependency-free JavaScript file. Actions with
dependencies have to commit a built bundle, and the bundle — not the source — is
what runs, so what a reviewer reads and what executes can drift apart. Here
`index.js` is the whole thing, and it is what runs.

---

## What happens to your code

A CI scan asks the backend not to retain a copy of your source. Findings and the
report are kept against your account, so the linked report works and so scans can
be compared over time.

Repository access is per-request and confined to the job, as described in
[What access it needs](#what-access-it-needs).

---

## Development

```bash
node --test index.test.js   # SARIF parsing and comment building
node --test e2e.test.js     # the whole action, against stub API and GitHub servers
```

No build step, no dependencies, no lockfile. `index.js` is what ships.

The end-to-end tests run the action in a child process against local stub
servers, covering what it sends, that it edits its comment rather than
reposting, that `fail-on` sets the exit code, and that neither credential
reaches the log.

---

## Links

- [Spartyx](https://www.cybertool.dev) — the scanner behind this action
- [Free scan](https://www.cybertool.dev/scan) — try it on a public repository, no account needed

## License

MIT. See [LICENSE](LICENSE).
