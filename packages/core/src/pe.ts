import { createHash } from "node:crypto";
import { basename } from "node:path";
import type { BinaryReport, ExportInfo, ExtractedString, ImportInfo, SectionInfo } from "./model.js";

const PE_SIGNATURE = 0x00004550;
const MAX_STRINGS = 500;
const MIN_STRING_LENGTH = 5;
const MAX_IMPORT_LIBRARIES = 256;
const MAX_IMPORT_SYMBOLS = 4096;
const MAX_EXPORT_SYMBOLS = 4096;
const MAX_PE_STRING_BYTES = 512;

function ensureRange(buffer: Buffer, offset: number, size: number, label: string): void {
  if (!Number.isInteger(offset) || offset < 0 || size < 0 || offset + size > buffer.length) {
    throw new Error(`Invalid or truncated PE while reading ${label}.`);
  }
}

function machineName(machine: number): string {
  switch (machine) {
    case 0x014c:
      return "x86";
    case 0x8664:
      return "x86-64";
    case 0x01c0:
      return "ARM";
    case 0xaa64:
      return "ARM64";
    default:
      return `unknown (0x${machine.toString(16).padStart(4, "0")})`;
  }
}

function readSectionName(buffer: Buffer, offset: number): string {
  ensureRange(buffer, offset, 8, "section name");
  const raw = buffer.subarray(offset, offset + 8);
  const nul = raw.indexOf(0);
  return raw.subarray(0, nul === -1 ? raw.length : nul).toString("ascii");
}

function rvaToFileOffset(
  sections: readonly SectionInfo[],
  rva: number,
  fileSize: number,
  sizeOfHeaders: number,
): number | null {
  if (!Number.isInteger(rva) || rva < 0) return null;
  if (rva < Math.min(sizeOfHeaders, fileSize)) return rva;

  for (const section of sections) {
    if (rva < section.virtualAddress) continue;
    const delta = rva - section.virtualAddress;
    if (delta >= section.rawSize) continue;
    const offset = section.rawOffset + delta;
    return offset >= 0 && offset < fileSize ? offset : null;
  }
  return null;
}

function readAsciiZ(buffer: Buffer, offset: number, label: string): string {
  ensureRange(buffer, offset, 1, label);
  const endLimit = Math.min(buffer.length, offset + MAX_PE_STRING_BYTES);
  let end = offset;
  while (end < endLimit && buffer[end] !== 0) end += 1;
  if (end === endLimit) throw new Error(`${label} is not NUL-terminated within ${MAX_PE_STRING_BYTES} bytes.`);
  return buffer.subarray(offset, end).toString("ascii");
}

function parseImports(
  buffer: Buffer,
  format: "PE32" | "PE32+",
  optional: number,
  optionalSize: number,
  sections: readonly SectionInfo[],
  sizeOfHeaders: number,
): { imports: ImportInfo[]; limitations: string[] } {
  const limitations: string[] = [];
  const imports: ImportInfo[] = [];
  const numberOfDirectoriesOffset = format === "PE32+" ? 108 : 92;
  const dataDirectoryOffset = format === "PE32+" ? 112 : 96;

  if (optionalSize < numberOfDirectoriesOffset + 4) {
    return { imports, limitations: ["PE optional header does not expose data-directory metadata."] };
  }

  const directoryCount = buffer.readUInt32LE(optional + numberOfDirectoriesOffset);
  if (directoryCount < 2) return { imports, limitations };
  if (optionalSize < dataDirectoryOffset + 16) {
    return { imports, limitations: ["PE optional header truncates the import data-directory entry."] };
  }

  const importDirectory = optional + dataDirectoryOffset + 8;
  const importRva = buffer.readUInt32LE(importDirectory);
  const importSize = buffer.readUInt32LE(importDirectory + 4);
  if (importRva === 0 || importSize === 0) return { imports, limitations };

  const descriptorOffset = rvaToFileOffset(sections, importRva, buffer.length, sizeOfHeaders);
  if (descriptorOffset === null) {
    return { imports, limitations: [`Import directory RVA 0x${importRva.toString(16)} is not file-backed.`] };
  }

  const pointerSize = format === "PE32+" ? 8 : 4;
  const ordinalFlag = format === "PE32+" ? 1n << 63n : 1n << 31n;
  const addressMask = ordinalFlag - 1n;
  const maxDescriptors = Math.min(MAX_IMPORT_LIBRARIES, Math.max(1, Math.floor(importSize / 20)));
  let sawTerminator = false;

  for (let descriptorIndex = 0; descriptorIndex < maxDescriptors; descriptorIndex += 1) {
    const descriptor = descriptorOffset + descriptorIndex * 20;
    if (descriptor + 20 > buffer.length) {
      limitations.push("Import descriptor table is truncated.");
      break;
    }

    const originalFirstThunk = buffer.readUInt32LE(descriptor);
    const timeDateStamp = buffer.readUInt32LE(descriptor + 4);
    const forwarderChain = buffer.readUInt32LE(descriptor + 8);
    const nameRva = buffer.readUInt32LE(descriptor + 12);
    const firstThunk = buffer.readUInt32LE(descriptor + 16);
    if (originalFirstThunk === 0 && timeDateStamp === 0 && forwarderChain === 0 && nameRva === 0 && firstThunk === 0) {
      sawTerminator = true;
      break;
    }

    const libraryOffset = rvaToFileOffset(sections, nameRva, buffer.length, sizeOfHeaders);
    if (libraryOffset === null) {
      limitations.push(`Import descriptor ${descriptorIndex} has a non-file-backed library name RVA.`);
      continue;
    }

    let library: string;
    try {
      library = readAsciiZ(buffer, libraryOffset, `import library ${descriptorIndex}`);
    } catch (error) {
      limitations.push(error instanceof Error ? error.message : String(error));
      continue;
    }
    if (!library) {
      limitations.push(`Import descriptor ${descriptorIndex} has an empty library name.`);
      continue;
    }

    const lookupTableRva = originalFirstThunk || firstThunk;
    if (lookupTableRva === 0) continue;

    for (let symbolIndex = 0; imports.length < MAX_IMPORT_SYMBOLS; symbolIndex += 1) {
      const lookupRva = lookupTableRva + symbolIndex * pointerSize;
      const lookupOffset = rvaToFileOffset(sections, lookupRva, buffer.length, sizeOfHeaders);
      if (lookupOffset === null || lookupOffset + pointerSize > buffer.length) {
        limitations.push(`${library} import lookup table is truncated or not file-backed.`);
        break;
      }

      const value = format === "PE32+"
        ? buffer.readBigUInt64LE(lookupOffset)
        : BigInt(buffer.readUInt32LE(lookupOffset));
      if (value === 0n) break;

      const iatRva = firstThunk + symbolIndex * pointerSize;
      if ((value & ordinalFlag) !== 0n) {
        imports.push({
          library,
          name: null,
          ordinal: Number(value & 0xffffn),
          hint: null,
          iatRva,
        });
        continue;
      }

      const importByNameRvaBig = value & addressMask;
      if (importByNameRvaBig > BigInt(Number.MAX_SAFE_INTEGER)) {
        limitations.push(`${library} import name RVA exceeds JavaScript's safe integer range.`);
        break;
      }
      const importByNameRva = Number(importByNameRvaBig);
      const nameOffset = rvaToFileOffset(sections, importByNameRva, buffer.length, sizeOfHeaders);
      if (nameOffset === null || nameOffset + 2 > buffer.length) {
        limitations.push(`${library} import name RVA 0x${importByNameRva.toString(16)} is not file-backed.`);
        break;
      }

      const hint = buffer.readUInt16LE(nameOffset);
      try {
        imports.push({
          library,
          name: readAsciiZ(buffer, nameOffset + 2, `${library} import name`),
          ordinal: null,
          hint,
          iatRva,
        });
      } catch (error) {
        limitations.push(error instanceof Error ? error.message : String(error));
        break;
      }
    }

    if (imports.length >= MAX_IMPORT_SYMBOLS) {
      limitations.push(`Import output is intentionally capped at ${MAX_IMPORT_SYMBOLS} symbols.`);
      break;
    }
  }

  if (!sawTerminator && maxDescriptors === MAX_IMPORT_LIBRARIES) {
    limitations.push(`Import library scan is intentionally capped at ${MAX_IMPORT_LIBRARIES} descriptors.`);
  }
  return { imports, limitations };
}

function parseExports(
  buffer: Buffer,
  format: "PE32" | "PE32+",
  optional: number,
  optionalSize: number,
  sections: readonly SectionInfo[],
  sizeOfHeaders: number,
): { exports: ExportInfo[]; limitations: string[] } {
  const limitations: string[] = [];
  const exports: ExportInfo[] = [];
  const numberOfDirectoriesOffset = format === "PE32+" ? 108 : 92;
  const dataDirectoryOffset = format === "PE32+" ? 112 : 96;

  if (optionalSize < numberOfDirectoriesOffset + 4) {
    return { exports, limitations: ["PE optional header does not expose data-directory metadata."] };
  }
  const directoryCount = buffer.readUInt32LE(optional + numberOfDirectoriesOffset);
  if (directoryCount < 1) return { exports, limitations };
  if (optionalSize < dataDirectoryOffset + 8) {
    return { exports, limitations: ["PE optional header truncates the export data-directory entry."] };
  }

  const exportRva = buffer.readUInt32LE(optional + dataDirectoryOffset);
  const exportSize = buffer.readUInt32LE(optional + dataDirectoryOffset + 4);
  if (exportRva === 0 || exportSize === 0) return { exports, limitations };

  const directoryFileOffset = rvaToFileOffset(sections, exportRva, buffer.length, sizeOfHeaders);
  if (directoryFileOffset === null || directoryFileOffset + 40 > buffer.length) {
    return { exports, limitations: [`Export directory RVA 0x${exportRva.toString(16)} is not fully file-backed.`] };
  }

  const ordinalBase = buffer.readUInt32LE(directoryFileOffset + 16);
  const functionCount = buffer.readUInt32LE(directoryFileOffset + 20);
  const nameCount = buffer.readUInt32LE(directoryFileOffset + 24);
  const functionsRva = buffer.readUInt32LE(directoryFileOffset + 28);
  const namesRva = buffer.readUInt32LE(directoryFileOffset + 32);
  const nameOrdinalsRva = buffer.readUInt32LE(directoryFileOffset + 36);

  if (functionCount === 0) return { exports, limitations };
  const boundedFunctionCount = Math.min(functionCount, MAX_EXPORT_SYMBOLS);
  if (functionCount > MAX_EXPORT_SYMBOLS) {
    limitations.push(`Export output is intentionally capped at ${MAX_EXPORT_SYMBOLS} function slots.`);
  }

  const functionsOffset = rvaToFileOffset(sections, functionsRva, buffer.length, sizeOfHeaders);
  if (functionsOffset === null || functionsOffset + boundedFunctionCount * 4 > buffer.length) {
    return { exports, limitations: [...limitations, "Export address table is truncated or not file-backed."] };
  }

  const namesByFunction = new Map<number, string[]>();
  const boundedNameCount = Math.min(nameCount, MAX_EXPORT_SYMBOLS);
  if (nameCount > MAX_EXPORT_SYMBOLS) {
    limitations.push(`Export name scan is intentionally capped at ${MAX_EXPORT_SYMBOLS} names.`);
  }

  if (boundedNameCount > 0) {
    const namesOffset = rvaToFileOffset(sections, namesRva, buffer.length, sizeOfHeaders);
    const ordinalsOffset = rvaToFileOffset(sections, nameOrdinalsRva, buffer.length, sizeOfHeaders);
    if (
      namesOffset === null ||
      ordinalsOffset === null ||
      namesOffset + boundedNameCount * 4 > buffer.length ||
      ordinalsOffset + boundedNameCount * 2 > buffer.length
    ) {
      limitations.push("Export name or ordinal table is truncated or not file-backed; ordinal exports remain available.");
    } else {
      for (let nameIndex = 0; nameIndex < boundedNameCount; nameIndex += 1) {
        const functionIndex = buffer.readUInt16LE(ordinalsOffset + nameIndex * 2);
        if (functionIndex >= functionCount || functionIndex >= boundedFunctionCount) {
          limitations.push(`Export name ${nameIndex} points outside the bounded function table.`);
          continue;
        }
        const nameRva = buffer.readUInt32LE(namesOffset + nameIndex * 4);
        const nameOffset = rvaToFileOffset(sections, nameRva, buffer.length, sizeOfHeaders);
        if (nameOffset === null) {
          limitations.push(`Export name RVA 0x${nameRva.toString(16)} is not file-backed.`);
          continue;
        }
        try {
          const name = readAsciiZ(buffer, nameOffset, `export name ${nameIndex}`);
          const names = namesByFunction.get(functionIndex) ?? [];
          names.push(name);
          namesByFunction.set(functionIndex, names);
        } catch (error) {
          limitations.push(error instanceof Error ? error.message : String(error));
        }
      }
    }
  }

  const exportEnd = BigInt(exportRva) + BigInt(exportSize);
  for (let functionIndex = 0; functionIndex < boundedFunctionCount; functionIndex += 1) {
    const functionRva = buffer.readUInt32LE(functionsOffset + functionIndex * 4);
    if (functionRva === 0) continue;

    let forwarder: string | null = null;
    const functionRvaBig = BigInt(functionRva);
    if (functionRvaBig >= BigInt(exportRva) && functionRvaBig < exportEnd) {
      const forwarderOffset = rvaToFileOffset(sections, functionRva, buffer.length, sizeOfHeaders);
      if (forwarderOffset === null) {
        limitations.push(`Export forwarder RVA 0x${functionRva.toString(16)} is not file-backed.`);
      } else {
        try {
          forwarder = readAsciiZ(buffer, forwarderOffset, `export forwarder ${functionIndex}`);
        } catch (error) {
          limitations.push(error instanceof Error ? error.message : String(error));
        }
      }
    }

    const names = namesByFunction.get(functionIndex);
    if (names?.length) {
      for (const name of names) {
        exports.push({
          name,
          ordinal: ordinalBase + functionIndex,
          rva: functionRva,
          forwarder,
        });
      }
    } else {
      exports.push({
        name: null,
        ordinal: ordinalBase + functionIndex,
        rva: functionRva,
        forwarder,
      });
    }
  }

  return { exports, limitations };
}

export function extractAsciiStrings(
  buffer: Buffer,
  minLength = MIN_STRING_LENGTH,
  maxStrings = MAX_STRINGS,
): ExtractedString[] {
  const result: ExtractedString[] = [];
  let start = -1;

  const flush = (end: number): void => {
    if (start >= 0 && end - start >= minLength) {
      result.push({ offset: start, value: buffer.subarray(start, end).toString("ascii") });
    }
    start = -1;
  };

  for (let i = 0; i < buffer.length && result.length < maxStrings; i += 1) {
    const value = buffer[i]!;
    const printable = value >= 0x20 && value <= 0x7e;
    if (printable) {
      if (start === -1) start = i;
    } else {
      flush(i);
    }
  }

  if (result.length < maxStrings) flush(buffer.length);
  return result.slice(0, maxStrings);
}

export function parsePortableExecutable(path: string, buffer: Buffer): BinaryReport {
  ensureRange(buffer, 0, 0x40, "DOS header");
  if (buffer.readUInt16LE(0) !== 0x5a4d) {
    throw new Error("Not a PE file: missing MZ header.");
  }

  const peOffset = buffer.readUInt32LE(0x3c);
  ensureRange(buffer, peOffset, 24, "PE/COFF header");
  if (buffer.readUInt32LE(peOffset) !== PE_SIGNATURE) {
    throw new Error("Not a PE file: invalid PE signature.");
  }

  const coff = peOffset + 4;
  const machine = buffer.readUInt16LE(coff);
  const sectionCount = buffer.readUInt16LE(coff + 2);
  const timestamp = buffer.readUInt32LE(coff + 4);
  const optionalSize = buffer.readUInt16LE(coff + 16);
  const optional = coff + 20;
  ensureRange(buffer, optional, optionalSize, "optional header");

  const magic = buffer.readUInt16LE(optional);
  const format = magic === 0x10b ? "PE32" : magic === 0x20b ? "PE32+" : "unknown";
  if (format === "unknown") {
    throw new Error(`Unsupported PE optional-header magic 0x${magic.toString(16)}.`);
  }

  if (optionalSize < 64) throw new Error("Invalid or truncated PE optional header.");
  ensureRange(buffer, optional, 64, "PE entry point/image base/header size");
  const entryPointRva = buffer.readUInt32LE(optional + 16);
  const imageBase =
    format === "PE32+"
      ? `0x${buffer.readBigUInt64LE(optional + 24).toString(16)}`
      : `0x${buffer.readUInt32LE(optional + 28).toString(16)}`;
  const sizeOfHeaders = buffer.readUInt32LE(optional + 60);

  const sectionTable = optional + optionalSize;
  const sections: SectionInfo[] = [];
  for (let index = 0; index < sectionCount; index += 1) {
    const offset = sectionTable + index * 40;
    ensureRange(buffer, offset, 40, `section ${index}`);
    sections.push({
      name: readSectionName(buffer, offset),
      virtualSize: buffer.readUInt32LE(offset + 8),
      virtualAddress: buffer.readUInt32LE(offset + 12),
      rawSize: buffer.readUInt32LE(offset + 16),
      rawOffset: buffer.readUInt32LE(offset + 20),
      characteristics: buffer.readUInt32LE(offset + 36),
    });
  }

  const importResult = parseImports(buffer, format, optional, optionalSize, sections, sizeOfHeaders);
  const exportResult = parseExports(buffer, format, optional, optionalSize, sections, sizeOfHeaders);
  const strings = extractAsciiStrings(buffer);
  const limitations: string[] = [
    ...importResult.limitations,
    ...exportResult.limitations,
    "This foundation parser does not yet resolve relocations, debug symbols, functions or cross-references.",
  ];
  if (strings.length >= MAX_STRINGS) {
    limitations.push(`Printable string output is intentionally capped at ${MAX_STRINGS} entries.`);
  }

  return {
    path,
    fileName: basename(path),
    fileSize: buffer.length,
    sha256: createHash("sha256").update(buffer).digest("hex"),
    format,
    architecture: machineName(machine),
    machine,
    entryPointRva,
    imageBase,
    timestamp,
    sections,
    imports: importResult.imports,
    exports: exportResult.exports,
    strings,
    limitations,
  };
}
