import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const root = resolve(new URL("..", import.meta.url).pathname.replace(/^\/(?:[A-Za-z]:)/u, (m) => m.slice(1)));
const results = [];

function add(name, ok, detail, required = false) {
  results.push({ name, ok, detail, required });
}

function commandVersion(command, args = ["--version"]) {
  const result = spawnSync(command, args, { encoding: "utf8", windowsHide: true, shell: false });
  if (result.error || result.status !== 0) return null;
  return (result.stdout || result.stderr || "").trim().split(/\r?\n/u)[0] || null;
}

function userEnvironment(name) {
  const inherited = process.env[name]?.trim();
  if (inherited) return inherited;
  if (process.platform !== "win32") return null;
  const script = `[Environment]::GetEnvironmentVariable('${name}','User')`;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-Command", script], {
    encoding: "utf8",
    windowsHide: true,
  });
  return result.status === 0 ? result.stdout.trim() || null : null;
}

const nodeMajor = Number(process.versions.node.split(".")[0]);
add("Node.js 24.x", nodeMajor === 24, `v${process.versions.node}`, true);

const npmVersion = process.platform === "win32"
  ? commandVersion("cmd.exe", ["/d", "/c", "npm", "--version"])
  : commandVersion("npm");
add("npm", Boolean(npmVersion), npmVersion ?? "not found", true);

add("package-lock.json", existsSync(join(root, "package-lock.json")), "required for npm ci", true);
add("@hexscry/core workspace", existsSync(join(root, "packages", "core", "package.json")), "packages/core", true);
add("@hexscry/provider-rea workspace", existsSync(join(root, "packages", "provider-rea", "package.json")), "packages/provider-rea", true);
add("desktop workspace", existsSync(join(root, "apps", "desktop", "package.json")), "apps/desktop", true);

const reaEntrypoints = [
  join(root, "node_modules", "rea-agents", "scripts", "rea.mjs"),
  join(root, "node_modules", "rea-agents", "dist", "rea.mjs"),
];
const reaPath = reaEntrypoints.find((path) => existsSync(path));
add("REA 6.7.0 local dependency", Boolean(reaPath), reaPath ?? "run npm ci", false);

const javaHome = userEnvironment("JAVA_HOME");
const javaExe = javaHome
  ? join(javaHome, "bin", process.platform === "win32" ? "java.exe" : "java")
  : null;
const javaVersion = javaExe && existsSync(javaExe)
  ? commandVersion(javaExe, ["-version"])
  : commandVersion(process.platform === "win32" ? "java.exe" : "java", ["-version"]);
add("Java / JDK", Boolean(javaVersion), javaVersion ?? (javaHome ? `JAVA_HOME=${javaHome} but java was not runnable` : "optional for deep analysis"), false);

const ghidra = userEnvironment("GHIDRA_INSTALL_DIR");
add("Ghidra", Boolean(ghidra && existsSync(ghidra)), ghidra || "set GHIDRA_INSTALL_DIR for deep analysis", false);

const jadx = userEnvironment("REA_JADX_MCP_JAR");
add("JADX MCP", Boolean(jadx && existsSync(jadx)), jadx || "optional until Android workflows are enabled", false);

const requiredFailures = results.filter((result) => result.required && !result.ok);

console.log("HexScry environment doctor\n");
for (const result of results) {
  const mark = result.ok ? "PASS" : result.required ? "FAIL" : "INFO";
  console.log(`${mark.padEnd(4)}  ${result.name}: ${result.detail}`);
}

console.log(`\nRequired checks: ${results.filter((r) => r.required && r.ok).length}/${results.filter((r) => r.required).length} passed.`);
if (requiredFailures.length > 0) {
  console.error("Fix required checks before running npm run check.");
  process.exitCode = 1;
} else {
  console.log("Core development environment looks ready. Optional deep-analysis tools may still need configuration.");
}
