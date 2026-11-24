#!/usr/bin/env node
"use strict";

const assert = require("assert");
const {
  MARKER,
  MAX_GITHUB_COMMENT_CHARS,
  findExistingCommentId,
  resolvePullRequestNumber,
  clampCommentBody,
  upsertPrComment,
} = require("./comment-pr.js");

async function runTests() {
  assert.strictEqual(
    findExistingCommentId([
      { id: 10, body: "unrelated comment" },
      { id: 42, body: `${MARKER}\n### Vexa SCA` },
    ]),
    42
  );
  assert.strictEqual(findExistingCommentId([{ id: 10, body: "nope" }]), null);

  assert.strictEqual(resolvePullRequestNumber({ pull_request: { number: 77 } }), 77);
  assert.strictEqual(resolvePullRequestNumber({ issue: { number: 12 } }), 12);
  assert.strictEqual(resolvePullRequestNumber({}), null);

  const oversized = "a".repeat(MAX_GITHUB_COMMENT_CHARS + 500);
  const clamped = clampCommentBody(oversized);
  assert.ok(clamped.length <= MAX_GITHUB_COMMENT_CHARS);
  assert.ok(clamped.includes("truncated"));

  // Creates comment when none exists
  const calls = [];
  const createRes = await upsertPrComment({
    token: "tok",
    repo: "org/repo",
    prNumber: 9,
    markdown: `${MARKER}\nhello`,
    requestFn: async (method, path, _tok, body) => {
      calls.push({ method, path, body });
      if (method === "GET") return { status: 200, body: [] };
      return { status: 201, body: { id: 99 } };
    },
  });
  assert.strictEqual(createRes.created, true);
  assert.strictEqual(createRes.commentId, 99);
  assert.strictEqual(calls[1].method, "POST");

  // Updates existing comment when marker matches
  const updateCalls = [];
  const updateRes = await upsertPrComment({
    token: "tok",
    repo: "org/repo",
    prNumber: 9,
    markdown: `${MARKER}\nupdated`,
    requestFn: async (method, path, _tok, body) => {
      updateCalls.push({ method, path, body });
      if (method === "GET") {
        return { status: 200, body: [{ id: 55, body: `${MARKER}\nold` }] };
      }
      return { status: 200, body: { id: 55 } };
    },
  });
  assert.strictEqual(updateRes.updated, true);
  assert.strictEqual(updateRes.commentId, 55);
  assert.strictEqual(updateCalls[1].method, "PATCH");
  assert.strictEqual(updateCalls[1].path, "/repos/org/repo/issues/comments/55");

  // Gracefully skips on 403 (e.g. fork PR read-only token)
  const forkRes = await upsertPrComment({
    token: "tok",
    repo: "org/repo",
    prNumber: 9,
    markdown: `${MARKER}\nfork`,
    requestFn: async () => ({ status: 403, body: { message: "Forbidden" } }),
  });
  assert.strictEqual(forkRes.skipped, true);

  console.log("comment-pr.test.js: all assertions passed");
}

runTests().catch((err) => {
  console.error(err);
  process.exit(1);
});
