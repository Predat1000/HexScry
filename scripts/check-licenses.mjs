import { readFile } from "node:fs/promises";

const REVIEWED_COPYLEFT = new Map([
  ["openpgp@6.3.2", "LGPL-3.0+"],
  ["frida@17.23.2", "LGPL-2.0 WITH WxWindows-exception-3.1"],
]);

const FORBIDDEN = [
  /AGPL/iu,
  /SSPL/iu,
  /BUSL/iu,
  /Elastic-License/iu,
  /Commons-Clause/iu,
  /PolyForm-Noncommercial/iu,
  /CC-BY-NC/iu,
  /^UNLICENSED$/iu,
];

const REVIEW_REQUIRED = /(?:^|\W)(?:L?GPL)(?:\W|$)/iu;

function packageName(path, metadata) {
  if (typeof metadata.name === "string" && metadata.name) return metadata.name;
  const marker = "node_modules/";
  const index = path.lastIndexOf(marker);
  if (index < 0) return path || "hexscry";
  return path.slice(index + marker.length);
}

const lock = JSON.parse(await readFile(new URL("../package-lock.json", import.meta.url), "utf8"));
const packages = Object.entries(lock.packages ?? {});
const failures = [];
const reviewed = [];
const licenseCounts = new Map();
let checked = 0;

for (const [path, metadata] of packages) {
  if (metadata?.link === true) continue;
  const name = packageName(path, metadata ?? {});
  const version = typeof metadata?.version === "string" ? metadata.version : "workspace";
  const key = `${name}@${version}`;
  const license = typeof metadata?.license === "string" ? metadata.license.trim() : "";
  checked += 1;

  if (!license) {
    failures.push(`${key}: missing license metadata in package-lock.json`);
    continue;
  }
  licenseCounts.set(license, (licenseCounts.get(license) ?? 0) + 1);

  if (FORBIDDEN.some((pattern) => pattern.test(license))) {
    failures.push(`${key}: license ${license} requires an explicit architecture/release decision`);
    continue;
  }

  if (REVIEW_REQUIRED.test(license)) {
    const expected = REVIEWED_COPYLEFT.get(key);
    if (expected !== license) {
      failures.push(`${key}: unreviewed copyleft license ${license}`);
      continue;
    }
    reviewed.push(`${key} (${license})`);
  }
}

for (const [key, expectedLicense] of REVIEWED_COPYLEFT) {
  const [name, version] = key.split(/@(?=[^@]+$)/u);
  const found = packages.some(([path, metadata]) =>
    metadata?.link !== true &&
    packageName(path, metadata ?? {}) === name &&
    metadata?.version === version &&
    metadata?.license === expectedLicense,
  );
  if (!found) reviewed.push(`${key} not present in this lockfile`);
}

console.log(`License check: ${checked} package entries inspected.`);
console.log(
  [...licenseCounts.entries()]
    .sort((left, right) => right[1] - left[1] || left[0].localeCompare(right[0]))
    .map(([license, count]) => `${license}: ${count}`)
    .join("\n"),
);
if (reviewed.length) {
  console.log("Reviewed copyleft exceptions:");
  for (const item of reviewed) console.log(`- ${item}`);
}

if (failures.length) {
  console.error("License policy failures:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log("License policy: PASS");
}
