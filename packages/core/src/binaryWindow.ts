import { open } from "node:fs/promises";
import type { BinaryReport, BinaryWindow } from "./model.js";

const MAX_WINDOW_BYTES = 4096;

export function addressToFileOffset(report: BinaryReport, address: string): number | null {
  let virtualAddress: bigint;
  let imageBase: bigint;
  try {
    virtualAddress = BigInt(address);
    imageBase = BigInt(report.imageBase);
  } catch {
    return null;
  }
  if (virtualAddress < imageBase) return null;

  const rvaBig = virtualAddress - imageBase;
  if (rvaBig > BigInt(Number.MAX_SAFE_INTEGER)) return null;
  const rva = Number(rvaBig);

  for (const section of report.sections) {
    if (rva < section.virtualAddress) continue;
    const delta = rva - section.virtualAddress;
    if (delta < section.rawSize) {
      const offset = section.rawOffset + delta;
      return offset >= 0 && offset < report.fileSize ? offset : null;
    }
  }
  return null;
}

export async function readBinaryWindow(
  report: BinaryReport,
  fileOffset: number,
  length = 256,
): Promise<BinaryWindow> {
  if (!Number.isInteger(fileOffset) || fileOffset < 0 || fileOffset >= report.fileSize) {
    throw new Error("Hex window file offset is outside the target.");
  }
  if (!Number.isInteger(length) || length <= 0) {
    throw new Error("Hex window length must be a positive integer.");
  }

  const boundedLength = Math.min(length, MAX_WINDOW_BYTES, report.fileSize - fileOffset);
  const handle = await open(report.path, "r");
  try {
    const buffer = Buffer.allocUnsafe(boundedLength);
    const { bytesRead } = await handle.read(buffer, 0, boundedLength, fileOffset);
    return {
      fileOffset,
      bytes: [...buffer.subarray(0, bytesRead)],
    };
  } finally {
    await handle.close();
  }
}

export async function readBinaryWindowAtAddress(
  report: BinaryReport,
  address: string,
  length = 256,
): Promise<BinaryWindow> {
  const fileOffset = addressToFileOffset(report, address);
  if (fileOffset === null) {
    throw new Error(`Address ${address} does not map to file-backed bytes.`);
  }
  return readBinaryWindow(report, fileOffset, length);
}
