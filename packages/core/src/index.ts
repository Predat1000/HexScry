import { readFile } from "node:fs/promises";
import type { BinaryReport } from "./model.js";
import { parsePortableExecutable } from "./pe.js";

export * from "./binaryWindow.js";
export * from "./model.js";
export * from "./pe.js";
export * from "./project.js";

export async function inspectBinary(path: string): Promise<BinaryReport> {
  const buffer = await readFile(path);
  return parsePortableExecutable(path, buffer);
}
