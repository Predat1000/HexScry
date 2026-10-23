import { spawn } from "node:child_process";
import { mkdir } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const deep = process.argv.includes("--deep");
const capture = process.argv.includes("--capture");
const target = resolve("fixtures/pe/minimal-x64.exe");
const capturePath = resolve("docs/assets/hexscry-v0.1-demo.png");

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
    HEXSCRY_DEMO_TARGET: target,
    HEXSCRY_DEMO_DEEP: deep ? "1" : "0",
    ...(capture
      ? {
          HEXSCRY_DEMO_CAPTURE: capturePath,
          HEXSCRY_DEMO_EXIT_AFTER_CAPTURE: "1",
        }
      : {}),
  },
});

child.on("error", (error) => {
  console.error(`Unable to launch HexScry demo: ${error.message}`);
  process.exitCode = 1;
});

child.on("exit", (code, signal) => {
  if (signal) {
    console.error(`HexScry demo stopped by ${signal}.`);
    process.exitCode = 1;
    return;
  }
  process.exitCode = code ?? 1;
});
