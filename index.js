/**
 * Spartyx security scan — GitHub Action.
 *
 * Deliberately dependency-free. An Action with dependencies has to be built and
 * the bundle committed, and the bundle is then the thing that actually runs -
 * so what a reader reviews and what executes can drift apart. Node 20 has
 * fetch, and everything else here is string handling, so there is nothing to
 * bundle and this file is exactly what runs.
 *
 * The GitHub App is not involved. The scan reads the repository with the
 * workflow's own token, which is scoped to this repository and expires when the
 * job ends, and the comment is posted with that same token. So enabling this
 * grants Spartyx no standing access to anyone's code.
 */

const fs = require("fs");
const path = require("path");

const SEVERITY_RANK = { critical: 4, high: 3, medium: 2, low: 1 };

// --- Actions plumbing -------------------------------------------------------

function input(name, fallback = "") {
  const value = process.env[`INPUT_${name.toUpperCase().replace(/ /g, "_")}`];
  return (value === undefined || value === "" ? fallback : value).trim();
}

function setOutput(name, value) {
  const file = process.env.GITHUB_OUTPUT;
  if (!file) return;
  // The heredoc form is required for values that could contain newlines.
  const delimiter = `ghadelimiter_${Math.random().toString(36).slice(2)}`;
  fs.appendFileSync(file, `${name}<<${delimiter}\n${value}\n${delimiter}\n`);
}

const log = (message) => process.stdout.write(`${message}\n`);
const startGroup = (name) => log(`::group::${name}`);
const endGroup = () => log("::endgroup::");
const warn = (message) => log(`::warning::${message}`);

function fail(message) {
  log(`::error::${message}`);
  process.exitCode = 1;
}

/** Everything secret that could end up in a message, so it cannot be printed. */
const secrets = [];
function redact(text) {
  let out = String(text);
  for (const secret of secrets) {
    if (secret && secret.length > 6) out = out.split(secret).join("***");
  }
  return out;
}

// --- HTTP -------------------------------------------------------------------

async function api(url, { method = "GET", headers = {}, body, apiKey } = {}) {
  const response = await fetch(url, {
    method,
    headers: {
      Authorization: `Bearer ${apiKey}`,
      Accept: "application/json",
      ...(body ? { "Content-Type": "application/json" } : {}),
      ...headers,
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const text = await response.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }

  if (!response.ok) {
    // A plan or limit refusal arrives as an object with its own message and an
    // upgrade url. Reading it as a string printed "[object Object]" in place of
    // the one sentence that says what to do.
    const raw = parsed && (parsed.detail || parsed.error);
    const detail =
      (typeof raw === "string" && raw) ||
      (raw && typeof raw === "object" && [raw.error, raw.upgrade_url && `See https://www.cybertool.dev${raw.upgrade_url}`].filter(Boolean).join(" ")) ||
      text.slice(0, 300);
    throw new Error(redact(`${method} ${new URL(url).pathname} failed (${response.status}): ${detail}`));
  }
  return parsed;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// --- SARIF ------------------------------------------------------------------

/**
 * SARIF carries severity in `level` (error/warning/note) and, when the producer
 * sets it, a precise severity in properties. Prefer the precise one so a
 * "critical" is not flattened into "error" alongside every "high".
 *
 * Spartyx writes `spartyxSeverity` on each result for exactly this reason. The
 * other keys are for SARIF from anywhere else, and the numeric
 * `security-severity` - which is what GitHub itself reads - is the last resort
 * before falling back to the three-way level.
 */
function severityFromScore(score) {
  const value = Number(score);
  if (!Number.isFinite(value)) return null;
  // GitHub's own buckets, so a number we did not write is read the way the
  // Security tab will read it.
  if (value >= 9) return "critical";
  if (value >= 7) return "high";
  if (value >= 4) return "medium";
  return "low";
}

function findingsFromSarif(sarif) {
  const findings = [];
  for (const run of sarif?.runs || []) {
    const rules = new Map(
      (run.tool?.driver?.rules || []).map((rule) => [rule.id, rule]),
    );
    for (const result of run.results || []) {
      const rule = rules.get(result.ruleId) || {};
      const precise =
        result.properties?.spartyxSeverity ||
        result.properties?.severity ||
        rule.properties?.["security-severity-label"] ||
        rule.properties?.severity ||
        severityFromScore(rule.properties?.["security-severity"]);

      const level = result.level || rule.defaultConfiguration?.level || "warning";
      const severity = String(
        precise || (level === "error" ? "high" : level === "note" ? "low" : "medium"),
      ).toLowerCase();

      const location = result.locations?.[0]?.physicalLocation;
      findings.push({
        severity: SEVERITY_RANK[severity] ? severity : "medium",
        title:
          result.message?.text ||
          rule.shortDescription?.text ||
          result.ruleId ||
          "Security finding",
        file: location?.artifactLocation?.uri || null,
        line: location?.region?.startLine || null,
      });
    }
  }
  return findings;
}

function countBySeverity(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    if (counts[finding.severity] !== undefined) counts[finding.severity] += 1;
  }
  return counts;
}

// --- Comment ----------------------------------------------------------------

// Identifies our own comment so each run edits it rather than adding another.
// A scanner that posts a fresh comment on every push buries the conversation.
const COMMENT_MARKER = "<!-- spartyx-scan-comment -->";

function buildComment({ findings, counts, repository, sha, scanUrl }) {
  const total = findings.length;
  const lines = [COMMENT_MARKER, "## Spartyx security scan", ""];

  if (total === 0) {
    lines.push(`No findings in \`${repository}\` at \`${sha.slice(0, 7)}\`.`);
  } else {
    const parts = ["critical", "high", "medium", "low"]
      .filter((key) => counts[key] > 0)
      .map((key) => `**${counts[key]}** ${key}`);
    lines.push(`${total} finding${total === 1 ? "" : "s"} — ${parts.join(", ")}.`, "");
    lines.push("| Severity | Finding | Location |", "| --- | --- | --- |");

    const shown = [...findings]
      .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])
      .slice(0, 15);

    for (const finding of shown) {
      // Escaped so a finding title containing a pipe cannot break the table,
      // and so nothing in scanned source is rendered as markup in the comment.
      const title = String(finding.title).replace(/[|\\`]/g, "\\$&").slice(0, 140);
      const where = finding.file
        ? `\`${finding.file}${finding.line ? `:${finding.line}` : ""}\``
        : "—";
      lines.push(`| ${finding.severity} | ${title} | ${where} |`);
    }

    if (total > shown.length) {
      lines.push("", `_${total - shown.length} more not shown._`);
    }
  }

  if (scanUrl) lines.push("", `[Full report](${scanUrl})`);
  return lines.join("\n");
}

async function upsertComment({ token, repository, prNumber, body }) {
  const base = `${process.env.GITHUB_API_URL || "https://api.github.com"}/repos/${repository}`;
  const headers = {
    Authorization: `Bearer ${token}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
    "Content-Type": "application/json",
  };

  const listed = await fetch(`${base}/issues/${prNumber}/comments?per_page=100`, { headers });
  if (!listed.ok) {
    // Not fatal: the findings are in the log and the SARIF file either way.
    warn(`Could not read existing comments (${listed.status}). Posting a new one.`);
  }

  const existing = listed.ok
    ? (await listed.json()).find((comment) => (comment.body || "").includes(COMMENT_MARKER))
    : null;

  const target = existing
    ? `${base}/issues/comments/${existing.id}`
    : `${base}/issues/${prNumber}/comments`;

  const response = await fetch(target, {
    method: existing ? "PATCH" : "POST",
    headers,
    body: JSON.stringify({ body }),
  });

  if (!response.ok) {
    const detail = (await response.text()).slice(0, 300);
    throw new Error(
      `Could not ${existing ? "update" : "post"} the comment (${response.status}): ${detail}. ` +
        "The workflow needs `permissions: pull-requests: write`.",
    );
  }
  log(existing ? "Updated the existing scan comment." : "Posted a scan comment.");
}

// --- Main -------------------------------------------------------------------

/** What the runner claims about itself, for the dashboard to display. */
function ciContext({ repository, branch, sha, prNumber }) {
  const runId = process.env.GITHUB_RUN_ID;
  const serverUrl = process.env.GITHUB_SERVER_URL || "https://github.com";
  return {
    provider: "github-actions",
    repository,
    ref: branch || undefined,
    sha: sha || undefined,
    run_id: runId || undefined,
    run_url: runId ? `${serverUrl}/${repository}/actions/runs/${runId}` : undefined,
    pull_request: prNumber || undefined,
    actor: process.env.GITHUB_ACTOR || undefined,
    event: process.env.GITHUB_EVENT_NAME || undefined,
  };
}

async function run() {
  const apiKey = input("api-key");
  const githubToken = input("github-token");
  secrets.push(apiKey, githubToken);

  if (!apiKey) {
    return fail("No api-key supplied. Create one under Settings -> API keys and store it as a repository secret.");
  }

  const apiUrl = input("api-url", "https://cypertech.onrender.com").replace(/\/$/, "");
  const mode = input("mode", "ghost");
  const failOn = input("fail-on", "high").toLowerCase();
  const shouldComment = input("comment", "true") !== "false";
  const sarifFile = input("sarif-file", "spartyx.sarif");
  const timeoutMs = Number(input("timeout-minutes", "20")) * 60_000;

  const repository = process.env.GITHUB_REPOSITORY;
  if (!repository) return fail("GITHUB_REPOSITORY is not set. This must run inside GitHub Actions.");

  const event = process.env.GITHUB_EVENT_PATH
    ? JSON.parse(fs.readFileSync(process.env.GITHUB_EVENT_PATH, "utf8"))
    : {};
  const prNumber = event.pull_request?.number || null;
  // On a pull_request event GITHUB_SHA is the merge commit; the head sha is
  // what a reviewer is actually looking at.
  const sha = event.pull_request?.head?.sha || process.env.GITHUB_SHA || "";
  const branch =
    event.pull_request?.head?.ref ||
    (process.env.GITHUB_REF || "").replace(/^refs\/heads\//, "") ||
    null;
  const isPrivate = event.repository?.private === true;

  startGroup("Starting scan");
  log(`Repository: ${repository}${branch ? ` (${branch})` : ""}`);
  log(`Mode: ${mode}`);

  const started = await api(`${apiUrl}/api/scan-repo`, {
    method: "POST",
    apiKey,
    // The repository is read with the workflow's own token rather than a
    // Spartyx GitHub App installation, so this works with no app installed and
    // grants no access that outlives the job.
    headers: {
      "X-GitHub-Token": githubToken,
      // Provenance only, so the scan in the dashboard can be traced back to
      // the run that caused it. Nothing here authorises anything.
      "X-CI-Context": JSON.stringify(ciContext({ repository, branch, sha, prNumber })),
    },
    body: {
      repository,
      branch,
      // The branch can move between this call and the scan finishing. Pinning
      // the commit means the report is about the code that was reviewed, not
      // whatever landed while it ran.
      commit_sha: /^[0-9a-f]{7,64}$/i.test(sha) ? sha : undefined,
      mode,
      async_job: true,
      retain_source: false,
      is_private: isPrivate,
    },
  });

  const jobId = started?.job_id;
  if (!jobId) return fail("The scan did not start: no job id was returned.");
  log(`Job: ${jobId}`);
  endGroup();

  startGroup("Waiting for the scan");
  const deadline = Date.now() + timeoutMs;
  let scanId = null;
  let lastStage = "";

  while (Date.now() < deadline) {
    await sleep(5000);
    const payload = await api(`${apiUrl}/api/scan-jobs/${jobId}`, { apiKey });
    const job = payload?.job || {};

    if (job.stage && job.stage !== lastStage) {
      lastStage = job.stage;
      log(`${job.stage} — ${job.progress ?? 0}%`);
    }

    if (job.status === "completed") {
      scanId = job.scan_id;
      break;
    }
    if (["failed", "cancelled", "stale"].includes(job.status)) {
      endGroup();
      return fail(redact(`Scan ${job.status}: ${job.last_error || job.message || "no detail given"}`));
    }
  }
  endGroup();

  if (!scanId) {
    return fail(`The scan did not finish within ${timeoutMs / 60_000} minutes.`);
  }

  const sarif = await api(`${apiUrl}/api/scans/${scanId}/sarif`, { apiKey });
  fs.mkdirSync(path.dirname(path.resolve(sarifFile)), { recursive: true });
  fs.writeFileSync(sarifFile, JSON.stringify(sarif, null, 2));
  log(`SARIF written to ${sarifFile}`);

  const findings = findingsFromSarif(sarif);
  const counts = countBySeverity(findings);

  setOutput("total", String(findings.length));
  setOutput("critical", String(counts.critical));
  setOutput("high", String(counts.high));
  setOutput("medium", String(counts.medium));
  setOutput("low", String(counts.low));
  setOutput("scan-id", String(scanId));
  setOutput("sarif-file", sarifFile);

  log(
    `${findings.length} finding(s): ${counts.critical} critical, ${counts.high} high, ` +
      `${counts.medium} medium, ${counts.low} low.`,
  );

  if (shouldComment && prNumber) {
    try {
      await upsertComment({
        token: githubToken,
        repository,
        prNumber,
        body: buildComment({
          findings,
          counts,
          repository,
          sha,
          scanUrl: `https://www.cybertool.dev/dashboard/scans/${scanId}`,
        }),
      });
    } catch (error) {
      // A comment that cannot be posted must not turn a clean scan into a
      // failed build - the result is already in the log and the SARIF.
      warn(redact(error.message));
    }
  } else if (shouldComment && !prNumber) {
    log("Not a pull request, so no comment was posted.");
  }

  if (failOn !== "none") {
    const threshold = SEVERITY_RANK[failOn];
    if (!threshold) {
      warn(`Unrecognised fail-on value "${failOn}". Not failing on severity.`);
      return;
    }
    const breaching = findings.filter((f) => SEVERITY_RANK[f.severity] >= threshold);
    if (breaching.length) {
      return fail(
        `${breaching.length} finding(s) at or above ${failOn}. ` +
          "Lower fail-on, or set it to none, to stop this failing the build.",
      );
    }
  }
}

// Guarded so importing or test-running this file does not start a scan.
// require.main alone is not enough: `node --test` executes each file as its own
// main module, so pointing it at this directory would run the action for real.
// NODE_TEST_CONTEXT is set by that runner and by nothing else.
if (require.main === module && !process.env.NODE_TEST_CONTEXT) {
  run().catch((error) => fail(redact(error?.stack || error?.message || String(error))));
}

module.exports = {
  ciContext,
  severityFromScore,
  findingsFromSarif,
  countBySeverity,
  buildComment,
  redact,
  secrets,
  COMMENT_MARKER,
  SEVERITY_RANK,
};
