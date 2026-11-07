import { createHash } from "node:crypto";
import { basename } from "node:path";
import type { BinaryReport, CodeViewInfo, DebugInfo, ExportInfo, ExtractedString, ImportInfo, RelocationInfo, SectionInfo, TlsInfo } from "./model.js";

const PE_SIGNATURE = 0x00004550;
const MAX_STRINGS = 500;
const MIN_STRING_LENGTH = 5;
const MAX_IMPORT_LIBRARIES = 256;
const MAX_IMPORT_SYMBOLS = 4096;
const MAX_EXPORT_SYMBOLS = 4096;
const MAX_RELOCATION_BLOCKS = 16_384;
const MAX_RELOCATION_ENTRIES = 262_144;
const MAX_DEBUG_ENTRIES = 1024;
const MAX_TLS_CALLBACKS = 4096;
const MAX_PE_STRING_BYTES = 512;
const MAX_CODEVIEW_PATH_BYTES = 4096;

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

function readAsciiZ(buffer: Buffer, offset: number, label: string, maxBytes = MAX_PE_STRING_BYTES): string {
  ensureRange(buffer, offset, 1, label);
  const endLimit = Math.min(buffer.length, offset + maxBytes);
  let end = offset;
  while (end < endLimit && buffer[end] !== 0) end += 1;
  if (end === endLimit) throw new Error(`${label} is not NUL-terminated within ${maxBytes} bytes.`);
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

function relocationType(type: number): { typeName: string; widthBytes: number | null } {
  switch (type) {
    case 0:
      return { typeName: "ABSOLUTE", widthBytes: 0 };
    case 1:
      return { typeName: "HIGH", widthBytes: 2 };
    case 2:
      return { typeName: "LOW", widthBytes: 2 };
    case 3:
      return { typeName: "HIGHLOW", widthBytes: 4 };
    case 4:
      return { typeName: "HIGHADJ", widthBytes: 2 };
    case 10:
      return { typeName: "DIR64", widthBytes: 8 };
    default:
      return { typeName: `TYPE_${type}`, widthBytes: null };
  }
}

function parseRelocations(
  buffer: Buffer,
  format: "PE32" | "PE32+",
  optional: number,
  optionalSize: number,
  sections: readonly SectionInfo[],
  sizeOfHeaders: number,
): { relocations: RelocationInfo[]; limitations: string[] } {
  const relocations: RelocationInfo[] = [];
  const limitations: string[] = [];
  const numberOfDirectoriesOffset = format === "PE32+" ? 108 : 92;
  const dataDirectoryOffset = format === "PE32+" ? 112 : 96;
  const relocationDirectoryIndex = 5;

  if (optionalSize < numberOfDirectoriesOffset + 4) {
    return { relocations, limitations: ["PE optional header does not expose data-directory metadata for relocations."] };
  }
  const directoryCount = buffer.readUInt32LE(optional + numberOfDirectoriesOffset);
  if (directoryCount <= relocationDirectoryIndex) return { relocations, limitations };

  const directoryRelativeOffset = dataDirectoryOffset + relocationDirectoryIndex * 8;
  if (optionalSize < directoryRelativeOffset + 8) {
    return { relocations, limitations: ["PE optional header truncates the base-relocation data-directory entry."] };
  }

  const relocationRva = buffer.readUInt32LE(optional + directoryRelativeOffset);
  const relocationSize = buffer.readUInt32LE(optional + directoryRelativeOffset + 4);
  if (relocationRva === 0 || relocationSize === 0) return { relocations, limitations };

  let consumed = 0;
  let blockCount = 0;
  let capped = false;

  while (consumed < relocationSize && blockCount < MAX_RELOCATION_BLOCKS) {
    const blockDirectoryRva = relocationRva + consumed;
    if (!Number.isSafeInteger(blockDirectoryRva) || blockDirectoryRva > 0xffff_ffff) {
      limitations.push("Base-relocation directory address exceeds the PE32 RVA range.");
      break;
    }

    const blockOffset = rvaToFileOffset(sections, blockDirectoryRva, buffer.length, sizeOfHeaders);
    if (blockOffset === null || blockOffset + 8 > buffer.length) {
      limitations.push(`Base-relocation block at RVA 0x${blockDirectoryRva.toString(16)} is not fully file-backed.`);
      break;
    }

    const pageRva = buffer.readUInt32LE(blockOffset);
    const blockSize = buffer.readUInt32LE(blockOffset + 4);
    if (blockSize === 0) break;
    if (blockSize < 8) {
      limitations.push(`Base-relocation block at RVA 0x${blockDirectoryRva.toString(16)} has invalid size ${blockSize}.`);
      break;
    }
    if (blockSize > relocationSize - consumed) {
      limitations.push(`Base-relocation block at RVA 0x${blockDirectoryRva.toString(16)} exceeds the declared directory size.`);
      break;
    }

    const payloadBytes = blockSize - 8;
    if (payloadBytes % 2 !== 0) {
      limitations.push(`Base-relocation block for page RVA 0x${pageRva.toString(16)} has an odd entry payload size.`);
    }
    const entryCount = Math.floor(payloadBytes / 2);

    for (let entryIndex = 0; entryIndex < entryCount; entryIndex += 1) {
      if (relocations.length >= MAX_RELOCATION_ENTRIES) {
        capped = true;
        break;
      }

      const entryDirectoryRva = blockDirectoryRva + 8 + entryIndex * 2;
      const entryOffset = rvaToFileOffset(sections, entryDirectoryRva, buffer.length, sizeOfHeaders);
      if (entryOffset === null || entryOffset + 2 > buffer.length) {
        limitations.push(`Base-relocation entry ${entryIndex} for page RVA 0x${pageRva.toString(16)} is not file-backed.`);
        break;
      }

      const raw = buffer.readUInt16LE(entryOffset);
      const type = raw >>> 12;
      const pageOffset = raw & 0x0fff;
      if (type === 0) continue;

      const rva = pageRva + pageOffset;
      if (rva > 0xffff_ffff) {
        limitations.push(`Base-relocation entry at page RVA 0x${pageRva.toString(16)} overflows the PE32 RVA range.`);
        continue;
      }
      const metadata = relocationType(type);
      relocations.push({ rva, type, ...metadata });

      // HIGHADJ consumes the following 16-bit slot as an addend rather than as a
      // second relocation entry. Preserve the relocation but do not misclassify
      // that paired value as another fixup.
      if (type === 4) {
        if (entryIndex + 1 < entryCount) entryIndex += 1;
        else limitations.push(`HIGHADJ relocation at RVA 0x${rva.toString(16)} is missing its paired addend.`);
      }
    }

    if (capped) break;
    consumed += blockSize;
    blockCount += 1;
  }

  if (blockCount >= MAX_RELOCATION_BLOCKS && consumed < relocationSize) {
    limitations.push(`Base-relocation scan is intentionally capped at ${MAX_RELOCATION_BLOCKS} blocks.`);
  }
  if (capped) {
    limitations.push(`Base-relocation output is intentionally capped at ${MAX_RELOCATION_ENTRIES} entries.`);
  }

  return { relocations, limitations };
}

function debugTypeName(type: number): string {
  switch (type) {
    case 0: return "UNKNOWN";
    case 1: return "COFF";
    case 2: return "CODEVIEW";
    case 3: return "FPO";
    case 4: return "MISC";
    case 5: return "EXCEPTION";
    case 6: return "FIXUP";
    case 7: return "OMAP_TO_SRC";
    case 8: return "OMAP_FROM_SRC";
    case 9: return "BORLAND";
    case 10: return "RESERVED10";
    case 11: return "CLSID";
    case 12: return "VC_FEATURE";
    case 13: return "POGO";
    case 14: return "ILTCG";
    case 16: return "REPRO";
    case 17: return "EMBEDDED_PORTABLE_PDB";
    case 19: return "PDB_CHECKSUM";
    case 20: return "EX_DLLCHARACTERISTICS";
    default: return `TYPE_${type}`;
  }
}

function formatRsdsGuid(buffer: Buffer, offset: number): string {
  ensureRange(buffer, offset, 16, "CodeView RSDS GUID");
  const data1 = buffer.readUInt32LE(offset).toString(16).padStart(8, "0");
  const data2 = buffer.readUInt16LE(offset + 4).toString(16).padStart(4, "0");
  const data3 = buffer.readUInt16LE(offset + 6).toString(16).padStart(4, "0");
  const data4a = buffer.subarray(offset + 8, offset + 10).toString("hex");
  const data4b = buffer.subarray(offset + 10, offset + 16).toString("hex");
  return `${data1}-${data2}-${data3}-${data4a}-${data4b}`.toUpperCase();
}

function parseCodeView(
  buffer: Buffer,
  dataOffset: number,
  sizeOfData: number,
  label: string,
): { codeView: CodeViewInfo | null; limitation: string | null } {
  if (sizeOfData < 4) {
    return { codeView: null, limitation: `${label} is too small to contain a CodeView signature.` };
  }
  const signature = buffer.subarray(dataOffset, dataOffset + 4).toString("ascii");

  try {
    if (signature === "RSDS") {
      if (sizeOfData < 25) {
        return { codeView: null, limitation: `${label} RSDS payload is truncated.` };
      }
      const pathBytes = Math.min(MAX_CODEVIEW_PATH_BYTES, sizeOfData - 24);
      return {
        codeView: {
          signature: "RSDS",
          pdbPath: readAsciiZ(buffer, dataOffset + 24, `${label} PDB path`, pathBytes),
          guid: formatRsdsGuid(buffer, dataOffset + 4),
          age: buffer.readUInt32LE(dataOffset + 20),
          timestamp: null,
        },
        limitation: null,
      };
    }

    if (signature === "NB10") {
      if (sizeOfData < 17) {
        return { codeView: null, limitation: `${label} NB10 payload is truncated.` };
      }
      const pathBytes = Math.min(MAX_CODEVIEW_PATH_BYTES, sizeOfData - 16);
      return {
        codeView: {
          signature: "NB10",
          pdbPath: readAsciiZ(buffer, dataOffset + 16, `${label} PDB path`, pathBytes),
          guid: null,
          age: buffer.readUInt32LE(dataOffset + 12),
          timestamp: buffer.readUInt32LE(dataOffset + 8),
        },
        limitation: null,
      };
    }
  } catch (error) {
    return { codeView: null, limitation: error instanceof Error ? error.message : String(error) };
  }

  const printable = /^[ -~]{4}$/u.test(signature) ? signature : `0x${buffer.subarray(dataOffset, dataOffset + 4).toString("hex")}`;
  return { codeView: null, limitation: `${label} uses unsupported CodeView signature ${printable}.` };
}

function parseDebugDirectory(
  buffer: Buffer,
  format: "PE32" | "PE32+",
  optional: number,
  optionalSize: number,
  sections: readonly SectionInfo[],
  sizeOfHeaders: number,
): { debug: DebugInfo[]; limitations: string[] } {
  const debug: DebugInfo[] = [];
  const limitations: string[] = [];
  const numberOfDirectoriesOffset = format === "PE32+" ? 108 : 92;
  const dataDirectoryOffset = format === "PE32+" ? 112 : 96;
  const debugDirectoryIndex = 6;

  if (optionalSize < numberOfDirectoriesOffset + 4) {
    return { debug, limitations: ["PE optional header does not expose data-directory metadata for debug entries."] };
  }
  const directoryCount = buffer.readUInt32LE(optional + numberOfDirectoriesOffset);
  if (directoryCount <= debugDirectoryIndex) return { debug, limitations };

  const directoryRelativeOffset = dataDirectoryOffset + debugDirectoryIndex * 8;
  if (optionalSize < directoryRelativeOffset + 8) {
    return { debug, limitations: ["PE optional header truncates the debug data-directory entry."] };
  }

  const debugRva = buffer.readUInt32LE(optional + directoryRelativeOffset);
  const debugSize = buffer.readUInt32LE(optional + directoryRelativeOffset + 4);
  if (debugRva === 0 || debugSize === 0) return { debug, limitations };
  if (debugSize < 28) {
    return { debug, limitations: [`Debug directory size ${debugSize} is smaller than one IMAGE_DEBUG_DIRECTORY entry.`] };
  }
  if (debugSize % 28 !== 0) {
    limitations.push(`Debug directory size ${debugSize} is not a multiple of 28 bytes; trailing bytes are ignored.`);
  }

  const declaredEntries = Math.floor(debugSize / 28);
  const entryCount = Math.min(declaredEntries, MAX_DEBUG_ENTRIES);
  if (declaredEntries > MAX_DEBUG_ENTRIES) {
    limitations.push(`Debug directory scan is intentionally capped at ${MAX_DEBUG_ENTRIES} entries.`);
  }

  for (let index = 0; index < entryCount; index += 1) {
    const entryRva = debugRva + index * 28;
    if (!Number.isSafeInteger(entryRva) || entryRva > 0xffff_ffff) {
      limitations.push("Debug directory entry address exceeds the PE32 RVA range.");
      break;
    }
    const entryOffset = rvaToFileOffset(sections, entryRva, buffer.length, sizeOfHeaders);
    if (entryOffset === null || entryOffset + 28 > buffer.length) {
      limitations.push(`Debug directory entry ${index} at RVA 0x${entryRva.toString(16)} is not fully file-backed.`);
      break;
    }

    const timestamp = buffer.readUInt32LE(entryOffset + 4);
    const majorVersion = buffer.readUInt16LE(entryOffset + 8);
    const minorVersion = buffer.readUInt16LE(entryOffset + 10);
    const type = buffer.readUInt32LE(entryOffset + 12);
    const sizeOfData = buffer.readUInt32LE(entryOffset + 16);
    const dataRva = buffer.readUInt32LE(entryOffset + 20);
    const pointerToRawData = buffer.readUInt32LE(entryOffset + 24);

    let dataFileOffset: number | null = null;
    if (sizeOfData > 0) {
      if (pointerToRawData > 0 && pointerToRawData < buffer.length) {
        dataFileOffset = pointerToRawData;
      } else if (dataRva > 0) {
        dataFileOffset = rvaToFileOffset(sections, dataRva, buffer.length, sizeOfHeaders);
      }
    }

    let codeView: CodeViewInfo | null = null;
    if (type === 2 && sizeOfData > 0) {
      if (dataFileOffset === null) {
        limitations.push(`CodeView debug entry ${index} does not point to file-backed data.`);
      } else if (sizeOfData > buffer.length - dataFileOffset) {
        limitations.push(`CodeView debug entry ${index} payload is truncated.`);
      } else {
        const parsed = parseCodeView(buffer, dataFileOffset, sizeOfData, `CodeView debug entry ${index}`);
        codeView = parsed.codeView;
        if (parsed.limitation) limitations.push(parsed.limitation);
      }
    }

    debug.push({
      type,
      typeName: debugTypeName(type),
      timestamp,
      majorVersion,
      minorVersion,
      sizeOfData,
      dataRva,
      dataFileOffset,
      codeView,
    });
  }

  return { debug, limitations };
}

function readPePointer(buffer: Buffer, offset: number, format: "PE32" | "PE32+", label: string): bigint {
  const width = format === "PE32+" ? 8 : 4;
  ensureRange(buffer, offset, width, label);
  return format === "PE32+" ? buffer.readBigUInt64LE(offset) : BigInt(buffer.readUInt32LE(offset));
}

function formatPeAddress(address: bigint): string {
  return `0x${address.toString(16)}`;
}

function virtualAddressToRva(address: bigint, imageBase: bigint): number | null {
  if (address < imageBase) return null;
  const rva = address - imageBase;
  if (rva > 0xffff_ffffn) return null;
  return Number(rva);
}

function parseTlsDirectory(
  buffer: Buffer,
  format: "PE32" | "PE32+",
  optional: number,
  optionalSize: number,
  sections: readonly SectionInfo[],
  sizeOfHeaders: number,
  imageBase: bigint,
): { tls: TlsInfo | null; limitations: string[] } {
  const limitations: string[] = [];
  const numberOfDirectoriesOffset = format === "PE32+" ? 108 : 92;
  const dataDirectoryOffset = format === "PE32+" ? 112 : 96;
  const tlsDirectoryIndex = 9;

  if (optionalSize < numberOfDirectoriesOffset + 4) {
    return { tls: null, limitations: ["PE optional header does not expose data-directory metadata for TLS."] };
  }
  const directoryCount = buffer.readUInt32LE(optional + numberOfDirectoriesOffset);
  if (directoryCount <= tlsDirectoryIndex) return { tls: null, limitations };

  const directoryRelativeOffset = dataDirectoryOffset + tlsDirectoryIndex * 8;
  if (optionalSize < directoryRelativeOffset + 8) {
    return { tls: null, limitations: ["PE optional header truncates the TLS data-directory entry."] };
  }

  const tlsRva = buffer.readUInt32LE(optional + directoryRelativeOffset);
  const tlsSize = buffer.readUInt32LE(optional + directoryRelativeOffset + 4);
  if (tlsRva === 0 || tlsSize === 0) return { tls: null, limitations };

  const pointerSize = format === "PE32+" ? 8 : 4;
  const structureSize = format === "PE32+" ? 40 : 24;
  if (tlsSize < structureSize) {
    return { tls: null, limitations: [`TLS directory size ${tlsSize} is smaller than the ${structureSize}-byte ${format} structure.`] };
  }

  const tlsOffset = rvaToFileOffset(sections, tlsRva, buffer.length, sizeOfHeaders);
  if (tlsOffset === null || tlsOffset + structureSize > buffer.length) {
    return { tls: null, limitations: [`TLS directory RVA 0x${tlsRva.toString(16)} is not fully file-backed.`] };
  }

  const rawDataStart = readPePointer(buffer, tlsOffset, format, "TLS raw-data start address");
  const rawDataEnd = readPePointer(buffer, tlsOffset + pointerSize, format, "TLS raw-data end address");
  const indexAddress = readPePointer(buffer, tlsOffset + pointerSize * 2, format, "TLS index address");
  const callbacksAddress = readPePointer(buffer, tlsOffset + pointerSize * 3, format, "TLS callbacks address");
  const scalarOffset = tlsOffset + pointerSize * 4;
  const sizeOfZeroFill = buffer.readUInt32LE(scalarOffset);
  const characteristics = buffer.readUInt32LE(scalarOffset + 4);
  const callbacks: TlsInfo["callbacks"] = [];

  if (callbacksAddress !== 0n) {
    const callbacksRva = virtualAddressToRva(callbacksAddress, imageBase);
    if (callbacksRva === null) {
      limitations.push(`TLS callback table address ${formatPeAddress(callbacksAddress)} is outside the image-base RVA range.`);
    } else {
      let terminated = false;
      for (let index = 0; index < MAX_TLS_CALLBACKS; index += 1) {
        const pointerRva = callbacksRva + index * pointerSize;
        if (!Number.isSafeInteger(pointerRva) || pointerRva > 0xffff_ffff) {
          limitations.push("TLS callback table address exceeds the PE32 RVA range.");
          break;
        }
        const pointerOffset = rvaToFileOffset(sections, pointerRva, buffer.length, sizeOfHeaders);
        if (pointerOffset === null || pointerOffset + pointerSize > buffer.length) {
          limitations.push(`TLS callback table is truncated or not file-backed at RVA 0x${pointerRva.toString(16)}.`);
          break;
        }

        const callbackAddress = readPePointer(buffer, pointerOffset, format, `TLS callback ${index}`);
        if (callbackAddress === 0n) {
          terminated = true;
          break;
        }
        const callbackRva = virtualAddressToRva(callbackAddress, imageBase);
        if (callbackRva === null) {
          limitations.push(`TLS callback ${formatPeAddress(callbackAddress)} is outside the image-base RVA range.`);
        }
        callbacks.push({ address: formatPeAddress(callbackAddress), rva: callbackRva });
      }
      if (!terminated && callbacks.length >= MAX_TLS_CALLBACKS) {
        limitations.push(`TLS callback scan is intentionally capped at ${MAX_TLS_CALLBACKS} entries.`);
      }
    }
  }

  return {
    tls: {
      rawDataStartAddress: formatPeAddress(rawDataStart),
      rawDataEndAddress: formatPeAddress(rawDataEnd),
      indexAddress: formatPeAddress(indexAddress),
      callbacksAddress: formatPeAddress(callbacksAddress),
      sizeOfZeroFill,
      characteristics,
      callbacks,
    },
    limitations,
  };
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
  const imageBaseValue = format === "PE32+"
    ? buffer.readBigUInt64LE(optional + 24)
    : BigInt(buffer.readUInt32LE(optional + 28));
  const imageBase = `0x${imageBaseValue.toString(16)}`;
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
  const relocationResult = parseRelocations(buffer, format, optional, optionalSize, sections, sizeOfHeaders);
  const debugResult = parseDebugDirectory(buffer, format, optional, optionalSize, sections, sizeOfHeaders);
  const tlsResult = parseTlsDirectory(buffer, format, optional, optionalSize, sections, sizeOfHeaders, imageBaseValue);
  const strings = extractAsciiStrings(buffer);
  // Windows images support up to 96 sections. Keep malformed inputs cheap and
  // only offer a jump when the entire string fits one file-backed section.
  if (sections.length <= 96) {
    for (const entry of strings) {
      const matches = sections.filter((section) => {
        const delta = entry.offset - section.rawOffset;
        const mappedSize = Math.min(section.rawSize, section.virtualSize || section.rawSize);
        return delta >= 0 && delta + entry.value.length <= mappedSize;
      });
      const section = matches[0];
      if (section && matches.length === 1) {
        const rva = section.virtualAddress + (entry.offset - section.rawOffset);
        entry.address = `0x${(imageBaseValue + BigInt(rva)).toString(16)}`;
      }
    }
  }
  const limitations: string[] = [
    ...importResult.limitations,
    ...exportResult.limitations,
    ...relocationResult.limitations,
    ...debugResult.limitations,
    ...tlsResult.limitations,
    "This foundation parser does not yet resolve full debug symbols, functions or cross-references.",
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
    relocations: relocationResult.relocations,
    debug: debugResult.debug,
    tls: tlsResult.tls,
    strings,
    limitations,
  };
}
