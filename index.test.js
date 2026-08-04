/**
 * Tests for the Action's pure parts. Run with `node --test action/`.
 *
 * Node's own test runner, so this stays dependency-free like the Action.
 */

const test = require("node:test");
const assert = require("node:assert/strict");

const {
  findingsFromSarif,
  countBySeverity,
  buildComment,
  redact,
  secrets,
  COMMENT_MARKER,
} = require("./index.js");

function sarif(results, rules = []) {
  return { runs: [{ tool: { driver: { rules } }, results }] };
}

test("prefers a precise severity over the coarse SARIF level", () => {
  const findings = findingsFromSarif(
    sarif([{ ruleId: "r1", level: "error", properties: { severity: "critical" }, message: { text: "SQLi" } }]),
  );
  // Without this, every critical would be flattened into "high" alongside
  // ordinary errors and fail-on: critical would never match.
  assert.equal(findings[0].severity, "critical");
});

test("falls back to the SARIF level when no precise severity is given", () => {
  const findings = findingsFromSarif(
    sarif([
      { ruleId: "a", level: "error", message: { text: "one" } },
      { ruleId: "b", level: "warning", message: { text: "two" } },
      { ruleId: "c", level: "note", message: { text: "three" } },
    ]),
  );
  assert.deepEqual(findings.map((f) => f.severity), ["high", "medium", "low"]);
});

test("reads severity off the rule when the result does not carry one", () => {
  const findings = findingsFromSarif(
    sarif(
      [{ ruleId: "r1", message: { text: "hardcoded secret" } }],
      [{ id: "r1", properties: { "security-severity-label": "critical" } }],
    ),
  );
  assert.equal(findings[0].severity, "critical");
});

test("an unrecognised severity becomes medium rather than being dropped", () => {
  const findings = findingsFromSarif(
    sarif([{ ruleId: "r1", properties: { severity: "spicy" }, message: { text: "x" } }]),
  );
  assert.equal(findings[0].severity, "medium");
});

test("reads the file and line out of the location", () => {
  const findings = findingsFromSarif(
    sarif([
      {
        ruleId: "r1",
        message: { text: "x" },
        locations: [
          { physicalLocation: { artifactLocation: { uri: "app/db.py" }, region: { startLine: 42 } } },
        ],
      },
    ]),
  );
  assert.equal(findings[0].file, "app/db.py");
  assert.equal(findings[0].line, 42);
});

test("empty and malformed SARIF produce no findings rather than throwing", () => {
  assert.deepEqual(findingsFromSarif({}), []);
  assert.deepEqual(findingsFromSarif({ runs: [] }), []);
  assert.deepEqual(findingsFromSarif({ runs: [{}] }), []);
});

test("counts by severity", () => {
  const counts = countBySeverity([
    { severity: "critical" },
    { severity: "high" },
    { severity: "high" },
    { severity: "low" },
  ]);
  assert.deepEqual(counts, { critical: 1, high: 2, medium: 0, low: 1 });
});

test("a clean scan says so", () => {
  const body = buildComment({
    findings: [],
    counts: countBySeverity([]),
    repository: "acme/api",
    sha: "abcdef1234567890", // pragma: allowlist secret
    scanUrl: null,
  });
  assert.match(body, /No findings/);
  assert.match(body, /abcdef1/);
  assert.ok(body.startsWith(COMMENT_MARKER));
});

test("the marker is present so repeat runs edit one comment", () => {
  const body = buildComment({
    findings: [{ severity: "high", title: "x", file: null, line: null }],
    counts: countBySeverity([{ severity: "high" }]),
    repository: "acme/api",
    sha: "abcdef1",
    scanUrl: null,
  });
  assert.ok(body.includes(COMMENT_MARKER));
});

test("a pipe in a finding title cannot break the table", () => {
  const body = buildComment({
    findings: [{ severity: "high", title: "a | b | c", file: "x.py", line: 1 }],
    counts: countBySeverity([{ severity: "high" }]),
    repository: "acme/api",
    sha: "abcdef1",
    scanUrl: null,
  });
  const row = body.split("\n").find((line) => line.includes("a \\|"));
  assert.ok(row, "the pipe should be escaped");
  // Header, separator and exactly one data row - not three.
  assert.equal(body.split("\n").filter((l) => l.startsWith("| ")).length, 3);
});

test("findings are listed worst first and long lists are truncated", () => {
  const findings = [
    ...Array.from({ length: 20 }, () => ({ severity: "low", title: "low one", file: null, line: null })),
    { severity: "critical", title: "the critical one", file: null, line: null },
  ];
  const body = buildComment({
    findings,
    counts: countBySeverity(findings),
    repository: "acme/api",
    sha: "abcdef1",
    scanUrl: null,
  });
  const rows = body.split("\n").filter((l) => l.startsWith("| ")).slice(2);
  assert.equal(rows.length, 15);
  assert.match(rows[0], /the critical one/);
  assert.match(body, /6 more not shown/);
});

test("secrets are redacted from anything printed", () => {
  secrets.length = 0;
  secrets.push("spx_live_supersecretvalue", "ghs_tokenvalue123456");
  const out = redact("failed with spx_live_supersecretvalue and ghs_tokenvalue123456");
  assert.ok(!out.includes("spx_live_supersecretvalue"));
  assert.ok(!out.includes("ghs_tokenvalue123456"));
  assert.match(out, /\*\*\*/);
});

test("redaction ignores values too short to be a real secret", () => {
  secrets.length = 0;
  secrets.push("abc");
  // Otherwise a short value would blank out ordinary words in the log.
  assert.equal(redact("abc def"), "abc def");
});
