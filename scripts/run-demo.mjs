import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const deep = process.argv.includes("--deep");
const capture = process.argv.includes("--capture");
const target = resolve("fixtures/pe/minimal-x64.exe");
const capturePath = resolve("docs/assets/axiomre-v0.1-demo.png");

if (capture) await mkdir(dirname(capturePath), { recursive: true });

const command = process.platform === "win32"
  ? (process.env.ComSpec || "cmd.exe")
  : "npm";
const args = process.platform === "win32"
  ? ["/d", "/s", "/c", "npm.cmd run dev"]
  : ["run", "dev"];

const child = spawn(command, args, {
  stdio: "inherit",
  env: {
    ...process.env,
    AXIOMRE_DEMO_TARGET: target,
    AXIOMRE_DEMO_DEEP: deep ? "1" : "0",
    ...(capture
      ? {
          AXIOMRE_DEMO_CAPTURE: capturePath,
          AXIOMRE_DEMO_EXIT_AFTER_CAPTURE: "1",
        }
      : {}),
  },
});

child.on("error", (error) => {
  console.error(`Unable to launch AxiomRE demo: ${error.message}`);
  process.exitCode = 1;
});

child.on("exit", (code, signal) => {
  if (signal) {
    console.error(`AxiomRE demo stopped by ${signal}.`);
    process.exitCode = 1;
    return;
  }
  process.exitCode = code ?? 1;
});
