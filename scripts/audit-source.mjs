import { readFileSync } from "node:fs";
import { extname } from "node:path";
import { execFileSync } from "node:child_process";

const FORBIDDEN_TRACKED = [
  "WORK_HANDOFF.md",
  ".dev-evidence/",
  ".hexscry-dev/",
  "artifacts/",
  "release/",
  "node_modules/",
];
const BINARY_EXTENSIONS = new Set([".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".exe", ".dll", ".bin", ".zip", ".7z", ".pdf"]);
const MAX_TEXT_BYTES = 4 * 1024 * 1024;
const SECRET_PATTERNS = [
  ["private key", /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/u],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u],
  ["GitHub fine-grained token", /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u],
  ["OpenAI-style secret", /\bsk-[A-Za-z0-9]{20,}\b/u],
  ["OpenAI project secret", /\bsk-proj-[A-Za-z0-9_-]{20,}\b/u],
  ["Anthropic secret", /\bsk-ant-[A-Za-z0-9_-]{20,}\b/u],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{30,}\b/u],
  ["AWS access key", /\bAKIA[0-9A-Z]{16}\b/u],
];
const PRIVATE_PATH_PATTERNS = [
  /[A-Za-z]:\\Users\\[^\\\r\n`"' ]+(?:\\|\b)/iu,
  /[A-Za-z]:\/Users\/[^/\r\n`"' ]+(?:\/|\b)/iu,
  /\/home\/[^/\s`"']+(?:\/|\b)/u,
  /\/Users\/[^/\s`"']+(?:\/|\b)/u,
];

function git(args, options = {}) {
  return execFileSync("git", args, { encoding: "utf8", windowsHide: true, ...options });
}

function forbiddenPath(path) {
  if (path === ".env" || (path.startsWith(".env.") && path !== ".env.example")) return ".env file";
  if (path.endsWith(".hexscry")) return "analyst project file";
  for (const entry of FORBIDDEN_TRACKED) {
    if (entry.endsWith("/") ? path.startsWith(entry) : path === entry) return entry;
  }
  return null;
}

function scanText(path, text, where, failures) {
  for (const [label, pattern] of SECRET_PATTERNS) {
    if (pattern.test(text)) failures.push(`${where}: ${path}: possible ${label}`);
  }
  for (const pattern of PRIVATE_PATH_PATTERNS) {
    if (pattern.test(text)) failures.push(`${where}: ${path}: NUC-private absolute path`);
  }
}

const failures = [];
const tracked = git(["ls-files", "-z"]).split("\0").filter(Boolean);
for (const path of tracked) {
  const reason = forbiddenPath(path);
  if (reason) failures.push(`tracked: ${path}: forbidden (${reason})`);
  if (BINARY_EXTENSIONS.has(extname(path).toLowerCase())) continue;
  const bytes = readFileSync(path);
  if (bytes.length > MAX_TEXT_BYTES || bytes.includes(0)) continue;
  scanText(path, bytes.toString("utf8"), "tracked", failures);
}

const historicalPaths = git(["log", "--all", "--name-only", "--pretty=format:"])
  .split(/\r?\n/u)
  .map((line) => line.trim())
  .filter(Boolean);
for (const path of new Set(historicalPaths)) {
  const reason = forbiddenPath(path);
  if (reason) failures.push(`history: ${path}: forbidden path appeared (${reason})`);
}

const objectLines = git(["rev-list", "--objects", "--all"])
  .split(/\r?\n/u)
  .filter(Boolean);
const objectPath = new Map();
for (const line of objectLines) {
  const firstSpace = line.indexOf(" ");
  const sha = firstSpace === -1 ? line : line.slice(0, firstSpace);
  const path = firstSpace === -1 ? "(unnamed object)" : line.slice(firstSpace + 1);
  if (!objectPath.has(sha)) objectPath.set(sha, path);
}
const shas = [...objectPath.keys()];
if (shas.length > 0) {
  const checked = git(["cat-file", "--batch-check"], { input: `${shas.join("\n")}\n` })
    .split(/\r?\n/u)
    .filter(Boolean);
  for (const line of checked) {
    const [sha, type, sizeText] = line.split(" ");
    const size = Number(sizeText);
    if (type !== "blob" || !Number.isFinite(size) || size > MAX_TEXT_BYTES) continue;
    const buffer = execFileSync("git", ["cat-file", "blob", sha], { windowsHide: true, maxBuffer: MAX_TEXT_BYTES + 1024 });
    if (buffer.includes(0)) continue;
    scanText(objectPath.get(sha) ?? "(unknown path)", buffer.toString("utf8"), `history:${sha.slice(0, 12)}`, failures);
  }
}

if (failures.length > 0) {
  console.error("Source audit: FAIL");
  for (const failure of [...new Set(failures)]) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log(`Source audit: PASS (${tracked.length} tracked files, ${shas.length} reachable Git objects inspected).`);
  console.log("- no forbidden local/evidence/build paths tracked or present in history");
  console.log("- no absolute user-home paths in tracked/reachable text blobs");
  console.log("- no configured high-signal credential patterns in tracked/reachable text blobs");
}
