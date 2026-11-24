#!/usr/bin/env node
"use strict";

const fs = require("fs");
const https = require("https");

const MARKER = "<!-- vexa-sca-pr-report -->";
const MAX_GITHUB_COMMENT_CHARS = 65000;

function githubRequest(method, apiPath, token, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request(
      {
        hostname: "api.github.com",
        path: apiPath,
        method,
        headers: {
          "User-Agent": "vexa-sca-action",
          Accept: "application/vnd.github+json",
          Authorization: `Bearer ${token}`,
          "X-GitHub-Api-Version": "2022-11-28",
          ...(data
            ? {
                "Content-Type": "application/json",
                "Content-Length": Buffer.byteLength(data),
              }
            : {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const text = Buffer.concat(chunks).toString("utf8");
          let json = null;
          try {
            json = text ? JSON.parse(text) : null;
          } catch (_) {
            json = null;
          }
          resolve({ status: res.statusCode, body: json, raw: text });
        });
      }
    );
    req.on("error", reject);
    if (data) req.write(data);
    req.end();
  });
}

function findExistingCommentId(comments) {
  if (!Array.isArray(comments)) return null;
  const match = comments.find(
    (c) => typeof c.body === "string" && c.body.includes(MARKER)
  );
  return match ? match.id : null;
}

function resolvePullRequestNumber(event) {
  return event?.pull_request?.number || event?.issue?.number || null;
}

function clampCommentBody(markdown) {
  if (typeof markdown !== "string") return "";
  if (markdown.length <= MAX_GITHUB_COMMENT_CHARS) return markdown;
  const suffix = "\n\n*Report truncated to fit GitHub PR comment size limit.*\n";
  return markdown.slice(0, MAX_GITHUB_COMMENT_CHARS - suffix.length) + suffix;
}

async function upsertPrComment({
  token,
  repo,
  prNumber,
  markdown,
  requestFn = githubRequest,
}) {
  if (!token || !repo || !prNumber) {
    return { skipped: true, reason: "missing token, repo, or PR number" };
  }
  const safeBody = clampCommentBody(markdown);
  const commentsPath = `/repos/${repo}/issues/${prNumber}/comments?per_page=100`;
  const listRes = await requestFn("GET", commentsPath, token, null);
  if (listRes.status < 200 || listRes.status >= 300) {
    return { skipped: true, reason: `list comments failed (${listRes.status})` };
  }

  const existingId = findExistingCommentId(listRes.body);
  if (existingId) {
    const patchRes = await requestFn(
      "PATCH",
      `/repos/${repo}/issues/comments/${existingId}`,
      token,
      { body: safeBody }
    );
    return { updated: true, commentId: existingId, status: patchRes.status };
  }

  const postRes = await requestFn(
    "POST",
    `/repos/${repo}/issues/${prNumber}/comments`,
    token,
    { body: safeBody }
  );
  return { created: true, commentId: postRes.body?.id ?? null, status: postRes.status };
}

async function main() {
  const token = process.env.GITHUB_TOKEN;
  const repo = process.env.GITHUB_REPOSITORY;
  const eventPath = process.env.GITHUB_EVENT_PATH;
  const reportPath = process.env.VEXA_REPORT_PATH;

  if (!reportPath || !fs.existsSync(reportPath)) {
    process.stderr.write("[vexa-sca-action] Report file not found; skipping PR comment.\n");
    return;
  }
  if (!eventPath || !fs.existsSync(eventPath)) {
    process.stderr.write("[vexa-sca-action] GITHUB_EVENT_PATH missing; skipping PR comment.\n");
    return;
  }

  const event = JSON.parse(fs.readFileSync(eventPath, "utf8"));
  const prNumber = resolvePullRequestNumber(event);
  const markdown = fs.readFileSync(reportPath, "utf8");

  const res = await upsertPrComment({ token, repo, prNumber, markdown });
  if (res.skipped) {
    process.stderr.write(`[vexa-sca-action] Skipped PR comment: ${res.reason}\n`);
  } else {
    process.stdout.write(
      `[vexa-sca-action] PR comment ${res.updated ? "updated" : "created"} (id=${res.commentId}, status=${res.status})\n`
    );
  }
}

if (require.main === module) {
  main().catch((err) => {
    process.stderr.write(`[vexa-sca-action] PR comment warning: ${err.message}\n`);
  });
}

module.exports = {
  MARKER,
  MAX_GITHUB_COMMENT_CHARS,
  findExistingCommentId,
  resolvePullRequestNumber,
  clampCommentBody,
  upsertPrComment,
};
