import { readFile, stat } from "node:fs/promises";
import type { BinaryReport } from "./model.js";
import { parsePortableExecutable } from "./pe.js";

export * from "./binaryWindow.js";
export * from "./model.js";
export * from "./pe.js";
export * from "./project.js";

export const MAX_FOUNDATION_PE_BYTES = 512 * 1024 * 1024;

export function assertSupportedFoundationPeSize(size: number): void {
  if (!Number.isSafeInteger(size) || size < 0) {
    throw new Error("PE file size is invalid.");
  }
  if (size > MAX_FOUNDATION_PE_BYTES) {
    throw new Error(
      `PE foundation analysis currently supports files up to ${MAX_FOUNDATION_PE_BYTES} bytes (512 MiB).`,
    );
  }
}

export async function inspectBinary(path: string): Promise<BinaryReport> {
  const info = await stat(path);
  if (!info.isFile()) throw new Error("Binary target is not a regular file.");
  assertSupportedFoundationPeSize(info.size);
  const buffer = await readFile(path);
  return parsePortableExecutable(path, buffer);
}
