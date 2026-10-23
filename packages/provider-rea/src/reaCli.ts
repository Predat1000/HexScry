import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { createRequire } from "node:module";
import { join } from "node:path";
import { promisify } from "node:util";
import type { ProcedureSummary } from "@axiomre/core";

const execFileAsync = promisify(execFile);
const requireFromHere = createRequire(import.meta.url);
const DEFAULT_TIMEOUT_MS = 5 * 60_000;
const DEFAULT_MAX_BUFFER = 64 * 1024 * 1024;
const REA_ENVIRONMENT_KEYS = ["GHIDRA_INSTALL_DIR", "JAVA_HOME", "REA_JADX_MCP_JAR"] as const;

async function windowsUserEnvironment(name: string): Promise<string | undefined> {
  if (process.platform !== "win32") return undefined;
  try {
    const { stdout } = await execFileAsync("reg.exe", ["query", "HKCU\\Environment", "/v", name], {
      windowsHide: true,
      timeout: 5_000,
    });
    const line = stdout.split(/\r?\n/u).find((candidate) => candidate.includes(name));
    return line?.trim().split(/\s{2,}/u).at(-1) || undefined;
  } catch {
    return undefined;
  }
}

export async function resolveReaEnvironment(
  base: NodeJS.ProcessEnv = process.env,
): Promise<NodeJS.ProcessEnv> {
  const environment: NodeJS.ProcessEnv = { ...base };
  for (const name of REA_ENVIRONMENT_KEYS) {
    if (environment[name]) continue;
    const value = await windowsUserEnvironment(name);
    if (value) environment[name] = value;
  }
  return environment;
}

export function reaNodeEnvironment(
  base: NodeJS.ProcessEnv = process.env,
): NodeJS.ProcessEnv {
  return {
    ...base,
    ELECTRON_RUN_AS_NODE: "1",
  };
}

export interface ReaCliOptions {
  entrypoint?: string;
  environment?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  maxBufferBytes?: number;
}

interface ReaEnvelope {
  normalized_result?: unknown;
}

function parseSearchProcedures(stdout: string): ProcedureSummary[] {
  const decoded: unknown = JSON.parse(stdout);
  if (!decoded || typeof decoded !== "object") {
    throw new Error("REA returned a non-object JSON response.");
  }

  const result = (decoded as ReaEnvelope).normalized_result;
  if (!Array.isArray(result)) {
    throw new Error("REA response omitted normalized_result procedure rows.");
  }

  return result.map((row, index) => {
    if (!row || typeof row !== "object") {
      throw new Error(`REA procedure row ${index} is not an object.`);
    }
    const address = (row as Record<string, unknown>).address;
    const value = (row as Record<string, unknown>).value;
    if (typeof address !== "string" || typeof value !== "string" || !address || !value) {
      throw new Error(`REA procedure row ${index} has an invalid address or name.`);
    }
    return { address, name: value, provider: "ghidra" as const };
  });
}

export function defaultReaEntrypoint(environment: NodeJS.ProcessEnv = process.env): string {
  try {
    return requireFromHere.resolve("rea-agents/scripts/rea.mjs");
  } catch {
    const appData = environment.APPDATA;
    if (!appData) {
      throw new Error("REA is not installed locally and APPDATA is unavailable; configure the REA entrypoint explicitly.");
    }
    return join(appData, "npm", "node_modules", "rea-agents", "scripts", "rea.mjs");
  }
}

export class ReaCli {
  readonly #entrypoint: string;
  readonly #environment: NodeJS.ProcessEnv;
  readonly #timeoutMs: number;
  readonly #maxBufferBytes: number;

  constructor(options: ReaCliOptions = {}) {
    this.#environment = reaNodeEnvironment(options.environment ?? process.env);
    this.#entrypoint = options.entrypoint ?? defaultReaEntrypoint(this.#environment);
    this.#timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.#maxBufferBytes = options.maxBufferBytes ?? DEFAULT_MAX_BUFFER;
  }

  async verifyInstallation(): Promise<void> {
    await access(this.#entrypoint);
  }

  async listProcedures(path: string, signal?: AbortSignal): Promise<ProcedureSummary[]> {
    const { stdout } = await execFileAsync(
      process.execPath,
      [
        this.#entrypoint,
        "search",
        path,
        ".",
        "--kind",
        "procedures",
        "--mode",
        "regex",
        "--provider",
        "ghidra",
        "--format",
        "json",
      ],
      {
        env: this.#environment,
        timeout: this.#timeoutMs,
        maxBuffer: this.#maxBufferBytes,
        windowsHide: true,
        ...(signal ? { signal } : {}),
      },
    );

    return parseSearchProcedures(stdout);
  }
}

export const __test = { parseSearchProcedures };
