/**
 * Drives the whole Action against a stub API and a stub GitHub, in a child
 * process, exactly as GitHub would run it.
 *
 * The unit tests cover the parsing; this covers the parts that only exist when
 * the thing actually runs - which endpoints it calls, what it sends, whether it
 * edits its comment instead of adding another, whether fail-on sets the exit
 * code, and whether a token can escape into the log.
 */

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const { execFile } = require("node:child_process");

const API_KEY = "spx_live_testkeyvalue0123456789"; // pragma: allowlist secret
const GH_TOKEN = "ghs_testgithubtokenvalue0123"; // pragma: allowlist secret

function startStub(handler) {
  return new Promise((resolve) => {
    const calls = [];
    const server = http.createServer(async (req, res) => {
      let body = "";
      for await (const chunk of req) body += chunk;
      calls.push({
        method: req.method,
        url: req.url,
        headers: req.headers,
        body: body ? JSON.parse(body) : null,
      });
      handler(req, res, calls);
    });
    server.listen(0, "127.0.0.1", () => resolve({ server, calls, port: server.address().port }));
  });
}

function runAction(env, cwd) {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [path.join(__dirname, "index.js")],
      { env: { ...process.env, ...env, NODE_TEST_CONTEXT: "" }, cwd },
      (error, stdout, stderr) => {
        resolve({ code: error ? error.code ?? 1 : 0, stdout, stderr });
      },
    );
  });
}

/** An API stub that completes a scan and returns the given SARIF. */
function apiHandler(sarif, { jobStatus = "completed" } = {}) {
  return (req, res) => {
    const json = (payload, status = 200) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    if (req.url === "/api/scan-repo") return json({ status: "queued", job_id: "job-1" }, 202);
    if (req.url.startsWith("/api/scan-jobs/")) {
      return json({ job: { status: jobStatus, stage: jobStatus, progress: 100, scan_id: "scan-1", last_error: "boom" } });
    }
    if (req.url.startsWith("/api/scans/")) return json(sarif);
    return json({ detail: "not found" }, 404);
  };
}

function githubHandler(existingComments = []) {
  return (req, res) => {
    const json = (payload, status = 200) => {
      res.writeHead(status, { "content-type": "application/json" });
      res.end(JSON.stringify(payload));
    };
    if (req.method === "GET" && req.url.includes("/comments")) return json(existingComments);
    return json({ id: 999 }, 201);
  };
}

function sarifWith(results) {
  return { runs: [{ tool: { driver: { rules: [] } }, results }] };
}

function eventFile(payload) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-")), "event.json");
  fs.writeFileSync(file, JSON.stringify(payload));
  return file;
}

function baseEnv({ apiPort, ghPort, event, workdir, extra = {} }) {
  return {
    "INPUT_API-KEY": API_KEY,
    "INPUT_GITHUB-TOKEN": GH_TOKEN,
    "INPUT_API-URL": `http://127.0.0.1:${apiPort}`,
    "INPUT_SARIF-FILE": path.join(workdir, "out.sarif"),
    "INPUT_TIMEOUT-MINUTES": "1",
    GITHUB_REPOSITORY: "acme/api",
    GITHUB_SHA: "abcdef1234567890", // pragma: allowlist secret
    GITHUB_REF: "refs/heads/feature",
    GITHUB_EVENT_PATH: event,
    GITHUB_API_URL: `http://127.0.0.1:${ghPort}`,
    GITHUB_OUTPUT: path.join(workdir, "output.txt"),
    ...extra,
  };
}

test("scans, writes SARIF, comments on the PR and fails on a high finding", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-run-"));
  const api = await startStub(
    apiHandler(sarifWith([{ ruleId: "r1", level: "error", message: { text: "SQL injection" } }])),
  );
  const gh = await startStub(githubHandler([]));
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const event = eventFile({
    pull_request: { number: 7, head: { sha: "headsha1234567", ref: "feature" } },
    repository: { private: true },
  });

  const result = await runAction(
    baseEnv({ apiPort: api.port, ghPort: gh.port, event, workdir }),
    workdir,
  );

  // The repository is read with the workflow's token, not a Spartyx app.
  const scanCall = api.calls.find((c) => c.url === "/api/scan-repo");
  assert.equal(scanCall.headers["x-github-token"], GH_TOKEN);
  assert.equal(scanCall.headers.authorization, `Bearer ${API_KEY}`);
  assert.equal(scanCall.body.repository, "acme/api");
  assert.equal(scanCall.body.is_private, true);
  // Nothing of the customer's code should be kept for a CI run.
  assert.equal(scanCall.body.retain_source, false);
  // The head sha is what a reviewer sees, not the merge commit.
  assert.equal(scanCall.body.branch, "feature");

  // SARIF landed where the workflow can hand it to upload-sarif.
  const sarifPath = path.join(workdir, "out.sarif");
  assert.ok(fs.existsSync(sarifPath));
  assert.ok(JSON.parse(fs.readFileSync(sarifPath, "utf8")).runs);

  // Comment posted to the right PR, with the marker for later edits.
  const posted = gh.calls.find((c) => c.method === "POST");
  assert.match(posted.url, /\/issues\/7\/comments/);
  assert.match(posted.body.body, /Spartyx security scan/);
  assert.match(posted.body.body, /SQL injection/);

  // fail-on defaults to high, and this finding is high.
  assert.equal(result.code, 1);
  assert.match(result.stdout, /::error::.*at or above high/);

  // Outputs for later workflow steps.
  const outputs = fs.readFileSync(path.join(workdir, "output.txt"), "utf8");
  assert.match(outputs, /^total<</m);
  assert.match(outputs, /^high<</m);
});

test("edits its own comment instead of adding another", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-edit-"));
  const api = await startStub(apiHandler(sarifWith([])));
  const gh = await startStub(
    githubHandler([{ id: 555, body: "<!-- spartyx-scan-comment -->\nold results" }]),
  );
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const event = eventFile({ pull_request: { number: 9, head: { sha: "h", ref: "b" } } });
  const result = await runAction(
    baseEnv({ apiPort: api.port, ghPort: gh.port, event, workdir }),
    workdir,
  );

  const patched = gh.calls.find((c) => c.method === "PATCH");
  assert.ok(patched, "should PATCH the existing comment");
  assert.match(patched.url, /\/issues\/comments\/555/);
  assert.equal(gh.calls.filter((c) => c.method === "POST").length, 0);
  // No findings, so nothing to fail on.
  assert.equal(result.code, 0);
});

test("a clean scan passes and says so", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-clean-"));
  const api = await startStub(apiHandler(sarifWith([])));
  const gh = await startStub(githubHandler([]));
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const event = eventFile({ pull_request: { number: 3, head: { sha: "h", ref: "b" } } });
  const result = await runAction(
    baseEnv({ apiPort: api.port, ghPort: gh.port, event, workdir }),
    workdir,
  );

  assert.equal(result.code, 0);
  const posted = gh.calls.find((c) => c.method === "POST");
  assert.match(posted.body.body, /No findings/);
});

test("fail-on none reports findings without failing the build", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-none-"));
  const api = await startStub(
    apiHandler(sarifWith([{ ruleId: "r1", properties: { severity: "critical" }, message: { text: "RCE" } }])),
  );
  const gh = await startStub(githubHandler([]));
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const event = eventFile({ pull_request: { number: 1, head: { sha: "h", ref: "b" } } });
  const result = await runAction(
    baseEnv({ apiPort: api.port, ghPort: gh.port, event, workdir, extra: { "INPUT_FAIL-ON": "none" } }),
    workdir,
  );

  assert.equal(result.code, 0);
});

test("a failed scan job fails the build and does not leak the key", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-fail-"));
  const api = await startStub(apiHandler(sarifWith([]), { jobStatus: "failed" }));
  const gh = await startStub(githubHandler([]));
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const event = eventFile({ pull_request: { number: 1, head: { sha: "h", ref: "b" } } });
  const result = await runAction(
    baseEnv({ apiPort: api.port, ghPort: gh.port, event, workdir }),
    workdir,
  );

  assert.equal(result.code, 1);
  assert.match(result.stdout, /Scan failed/);
  assert.ok(!result.stdout.includes(API_KEY), "the API key must never reach the log");
  assert.ok(!result.stdout.includes(GH_TOKEN), "the GitHub token must never reach the log");
});

test("a push with no pull request scans but posts nothing", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-push-"));
  const api = await startStub(apiHandler(sarifWith([])));
  const gh = await startStub(githubHandler([]));
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const event = eventFile({});
  const result = await runAction(
    baseEnv({ apiPort: api.port, ghPort: gh.port, event, workdir }),
    workdir,
  );

  assert.equal(result.code, 0);
  assert.equal(gh.calls.length, 0);
  assert.match(result.stdout, /Not a pull request/);
});

test("a comment that cannot be posted does not fail an otherwise clean build", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-noperm-"));
  const api = await startStub(apiHandler(sarifWith([])));
  const gh = await startStub((req, res) => {
    res.writeHead(403, { "content-type": "application/json" });
    res.end(JSON.stringify({ message: "Resource not accessible by integration" }));
  });
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const event = eventFile({ pull_request: { number: 5, head: { sha: "h", ref: "b" } } });
  const result = await runAction(
    baseEnv({ apiPort: api.port, ghPort: gh.port, event, workdir }),
    workdir,
  );

  assert.equal(result.code, 0);
  assert.match(result.stdout, /::warning::/);
  assert.match(result.stdout, /pull-requests: write/);
});

test("a missing api key fails immediately without calling anything", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-nokey-"));
  const api = await startStub(apiHandler(sarifWith([])));
  const gh = await startStub(githubHandler([]));
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const event = eventFile({});
  const env = baseEnv({ apiPort: api.port, ghPort: gh.port, event, workdir });
  env["INPUT_API-KEY"] = "";

  const result = await runAction(env, workdir);

  assert.equal(result.code, 1);
  assert.equal(api.calls.length, 0);
  assert.match(result.stdout, /No api-key supplied/);
});

test("pins the head commit and sends the run's provenance", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-run-"));
  const api = await startStub(apiHandler(sarifWith([])));
  const gh = await startStub(githubHandler([]));
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const headSha = "0123456789abcdef0123456789abcdef01234567"; // pragma: allowlist secret
  const event = eventFile({
    pull_request: { number: 7, head: { sha: headSha, ref: "feature" } },
    repository: { private: false },
  });

  await runAction(
    baseEnv({
      apiPort: api.port,
      ghPort: gh.port,
      event,
      workdir,
      extra: { GITHUB_RUN_ID: "4242", GITHUB_ACTOR: "someone", GITHUB_EVENT_NAME: "pull_request" },
    }),
    workdir,
  );

  const scanCall = api.calls.find((c) => c.url === "/api/scan-repo");
  // The branch could move while the scan runs. The commit cannot.
  assert.equal(scanCall.body.commit_sha, headSha);
  assert.equal(scanCall.body.branch, "feature");

  const context = JSON.parse(scanCall.headers["x-ci-context"]);
  assert.equal(context.provider, "github-actions");
  assert.equal(context.sha, headSha);
  assert.equal(context.pull_request, 7);
  assert.equal(context.run_id, "4242");
  // Provenance travels in a header, and carries no credential of any kind.
  assert.equal(scanCall.headers["x-ci-context"].includes(GH_TOKEN), false);
  assert.equal(scanCall.headers["x-ci-context"].includes(API_KEY), false);
});

test("a plan refusal is reported as its own sentence, not [object Object]", async (t) => {
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), "spartyx-run-"));
  const api = await startStub((req, res) => {
    res.writeHead(402, { "content-type": "application/json" });
    // The exact shape the backend returns for a plan refusal.
    res.end(
      JSON.stringify({
        detail: {
          error: "API keys and CI scanning are part of Pro. This account is on the Beta plan.",
          upgrade_required: true,
          upgrade_url: "/pricing",
        },
      }),
    );
  });
  const gh = await startStub(githubHandler([]));
  t.after(() => {
    api.server.close();
    gh.server.close();
  });

  const event = eventFile({ pull_request: { number: 7, head: { sha: "abc1234", ref: "f" } } });
  const result = await runAction(
    baseEnv({ apiPort: api.port, ghPort: gh.port, event, workdir }),
    workdir,
  );

  assert.equal(result.code, 1);
  assert.match(result.stdout, /part of Pro/);
  assert.match(result.stdout, /pricing/);
  assert.equal(result.stdout.includes("[object Object]"), false);
  // Even on the error path, nothing secret is printed.
  assert.equal(result.stdout.includes(API_KEY), false);
});
