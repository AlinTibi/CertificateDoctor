import test from "node:test";
import assert from "node:assert/strict";
import {
  escapeHTML,
  validityLabel,
  validityTone,
  formatDate,
  plural,
  availableConversions,
  pfxPasswordProblem,
  sortFiles,
} from "../src/presentation.mjs";

test("escapes untrusted certificate text", () => {
  assert.equal(
    escapeHTML(`<img src=x onerror="a('b')">&`),
    "&lt;img src=x onerror=&quot;a(&#39;b&#39;)&quot;&gt;&amp;",
  );
  assert.equal(escapeHTML(null), "");
});

test("describes validity states", () => {
  assert.equal(validityLabel("expired", -1), "Expired 1 day ago");
  assert.equal(validityLabel("expiring-soon", 12), "Expires in 12 days");
  assert.equal(validityLabel("valid", 300), "Valid · 300 days left");
  assert.equal(validityLabel("not-yet-valid", 400), "Not yet valid");
  assert.equal(validityTone("valid"), "ok");
  assert.equal(validityTone("expiring-soon"), "warning");
  assert.equal(validityTone("expired"), "error");
});

test("formats dates in UTC", () => {
  assert.equal(formatDate("2026-06-01T08:05:00Z"), "2026-06-01 08:05 UTC");
  assert.equal(formatDate("not a date"), "");
  assert.equal(plural(1, "file"), "1 file");
  assert.equal(plural(3, "file"), "3 files");
});

test("key conversions require a matching key", () => {
  const without = availableConversions(false);
  assert.ok(without.filter((c) => c.needsKey).every((c) => c.disabled));
  assert.ok(without.filter((c) => !c.needsKey).every((c) => !c.disabled));
  assert.ok(availableConversions(true).every((c) => !c.disabled));
});

test("validates new PFX passwords", () => {
  assert.equal(pfxPasswordProblem("short", "short"), "Use at least 8 characters.");
  assert.equal(pfxPasswordProblem("long enough", "different"), "The passwords do not match.");
  assert.equal(pfxPasswordProblem("long enough", "long enough"), "");
});

test("files needing attention are listed first", () => {
  const sorted = sortFiles([
    { name: "a", state: "ready" },
    { name: "b", state: "error" },
    { name: "c", state: "password" },
  ]);
  assert.deepEqual(sorted.map((f) => f.name), ["c", "b", "a"]);
});
