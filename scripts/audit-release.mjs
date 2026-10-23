import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(new URL("..", import.meta.url).pathname.replace(/^\/(?:([A-Za-z]:))/u, "$1"));
const readJson = async (path) => JSON.parse(await readFile(resolve(root, path), "utf8"));
const failures = [];
const assert = (condition, message) => { if (!condition) failures.push(message); };

const [lock, providerPackage, desktopPackage, builderConfig, reaPackage, openpgpPackage] = await Promise.all([
  readJson("package-lock.json"),
  readJson("packages/provider-rea/package.json"),
  readJson("apps/desktop/package.json"),
  readJson("electron-builder.json"),
  readJson("node_modules/rea-agents/package.json"),
  readJson("node_modules/openpgp/package.json"),
]);

const reaLock = lock.packages?.["node_modules/rea-agents"];
const fridaLock = lock.packages?.["node_modules/frida"];
const openpgpLock = lock.packages?.["node_modules/openpgp"];

assert(providerPackage.dependencies?.["rea-agents"] === reaPackage.version, "Provider must pin the installed REA runtime exactly.");
assert(reaPackage.license === "MIT" && reaLock?.license === "MIT", "REA runtime license metadata must remain MIT.");
assert(reaPackage.optionalDependencies?.frida === fridaLock?.version, "Frida must remain an optional REA dependency.");
assert(fridaLock?.optional === true, "Lockfile must mark Frida optional.");
assert(openpgpPackage.version === openpgpLock?.version && openpgpLock?.license === "LGPL-3.0+", "OpenPGP runtime license/version metadata changed and needs review.");

const filePatterns = builderConfig.files ?? [];
assert(builderConfig.asar === false, "v0.1 intentionally keeps ASAR disabled; changing it requires a fresh REA filesystem/runtime packaging review.");
assert(filePatterns.some((item) => String(item).includes("node_modules/frida")), "Packaging config must explicitly exclude Frida.");
const bundledDeps = Object.keys(desktopPackage.dependencies ?? {}).map((item) => item.toLowerCase());
assert(!bundledDeps.some((item) => item.includes("ghidra") || item.includes("jadx")), "Ghidra/JADX must remain external engines, not desktop dependencies.");

const requiredNotices = [
  "LICENSE",
  "node_modules/rea-agents/LICENSE",
  "node_modules/rea-agents/THIRD_PARTY_NOTICES.md",
  "node_modules/rea-agents/licenses/npm-runtime-notices.txt",
  "node_modules/openpgp/LICENSE",
];
for (const path of requiredNotices) {
  try { await access(resolve(root, path)); }
  catch { failures.push(`Required release notice is missing: ${path}`); }
}

const resourceSources = (builderConfig.extraResources ?? []).map((item) => typeof item === "string" ? item : item.from);
for (const path of ["LICENSE", "node_modules/rea-agents/LICENSE", "node_modules/rea-agents/THIRD_PARTY_NOTICES.md", "node_modules/rea-agents/licenses", "node_modules/openpgp/LICENSE"]) {
  assert(resourceSources.includes(path), `Packaging config must expose release notice/resource: ${path}`);
}
assert(!resourceSources.some((path) => /ghidra|jadx/iu.test(String(path))), "Packaging config must not redistribute Ghidra or JADX.");

if (failures.length) {
  console.error("Release audit failures:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exitCode = 1;
} else {
  console.log("Release audit: PASS");
  console.log(`- REA ${reaPackage.version} (${reaPackage.license}) embedded with upstream notices.`);
  console.log(`- Frida ${fridaLock.version} is optional and explicitly excluded from packaging.`);
  console.log(`- OpenPGP ${openpgpPackage.version} (${openpgpLock.license}) notice is exposed in release resources.`);
  console.log("- Ghidra and JADX remain separately supplied external engines.");
}
