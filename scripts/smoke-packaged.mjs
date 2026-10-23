import { spawn, spawnSync } from "node:child_process";
import { copyFile, mkdir, rm, stat, writeFile } from "node:fs/promises";
import { basename, dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

if (process.platform !== "win32") {
  console.log("Packaged desktop smoke: SKIP (Windows release check).");
  process.exit(0);
}

const scriptDir = dirname(fileURLToPath(import.meta.url));
const root = dirname(scriptDir);
const executable = resolve(process.argv[2] ?? join(root, "artifacts", "win-unpacked", "AxiomRE.exe"));
const fixture = join(root, "fixtures", "pe", "minimal-x64.exe");
const evidenceDir = join(root, ".dev-evidence");
const runId = `packaged-smoke-${process.pid}`;
const smokeExecutable = join(dirname(executable), `AxiomRE-Smoke-${process.pid}.exe`);
const userDataDir = join(evidenceDir, `${runId}-userdata`);
const capturePath = join(evidenceDir, `${runId}.png`);
const stdoutPath = join(evidenceDir, `${runId}.out.log`);
const stderrPath = join(evidenceDir, `${runId}.err.log`);

await mkdir(evidenceDir, { recursive: true });
await rm(userDataDir, { recursive: true, force: true });
await rm(capturePath, { force: true });
await copyFile(executable, smokeExecutable);

let stdout = "";
let stderr = "";
const appendBounded = (current, chunk) => (current + chunk).slice(-1_000_000);
let child = null;
let exitCode = null;

try {
  child = spawn(smokeExecutable, [`--user-data-dir=${userDataDir}`], {
    cwd: root,
    env: {
      ...process.env,
      AXIOMRE_DEMO_TARGET: fixture,
      AXIOMRE_DEMO_DEEP: "1",
      AXIOMRE_DEMO_CAPTURE: capturePath,
      AXIOMRE_DEMO_EXIT_AFTER_CAPTURE: "1",
    },
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });

  child.stdout.on("data", (chunk) => { stdout = appendBounded(stdout, chunk.toString()); });
  child.stderr.on("data", (chunk) => { stderr = appendBounded(stderr, chunk.toString()); });

  const timeoutMs = 180_000;
  exitCode = await new Promise((resolveExit, rejectExit) => {
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      rejectExit(new Error(`Packaged desktop smoke exceeded ${timeoutMs / 1000}s.`));
    }, timeoutMs);
    child.once("error", (error) => {
      clearTimeout(timer);
      rejectExit(error);
    });
    child.once("exit", (code, signal) => {
      clearTimeout(timer);
      if (signal) rejectExit(new Error(`Packaged desktop exited via signal ${signal}.`));
      else resolveExit(code);
    });
  });
} finally {
  await writeFile(stdoutPath, stdout, "utf8");
  await writeFile(stderrPath, stderr, "utf8");

  // Chromium utility/GPU children can outlive the main process in remote sessions.
  // The smoke uses a uniquely named executable so cleanup cannot touch a user's
  // normal AxiomRE instance or lock the canonical release executable for the next build.
  spawnSync("taskkill", ["/F", "/T", "/IM", basename(smokeExecutable)], {
    windowsHide: true,
    stdio: "ignore",
  });
  await rm(smokeExecutable, { force: true }).catch(() => undefined);
  await rm(userDataDir, { recursive: true, force: true }).catch(() => undefined);
}

if (exitCode !== 0) {
  throw new Error(`Packaged desktop exited with code ${exitCode}. See ${stderrPath}.`);
}

const capture = await stat(capturePath).catch(() => null);
if (!capture?.isFile() || capture.size < 10_000) {
  throw new Error(`Packaged desktop did not produce a valid final-state capture at ${capturePath}.`);
}
// A direct Electron executable forwards the demo marker to stdout, but the NSIS
// portable wrapper does not reliably forward child stdout. The capture is the
// authoritative completion proof: it is removed before each run, uses a unique
// path, and is written only after the renderer reaches the final deep-analysis state.
console.log(`Packaged desktop smoke: PASS (${capture.size} bytes).`);
console.log(`- executable: ${executable}`);
console.log(`- capture: ${capturePath}`);
