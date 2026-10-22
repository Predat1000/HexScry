import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(dirname(fileURLToPath(import.meta.url)));
const fixtureDir = join(root, "fixtures", "pe");
const output = join(fixtureDir, "minimal-x64.exe");

const FILE_ALIGNMENT = 0x200;
const SECTION_ALIGNMENT = 0x1000;
const PE_OFFSET = 0x80;
const RAW_OFFSET = 0x200;
const buffer = Buffer.alloc(0x400, 0);

// DOS header: only the signature and e_lfanew are required for this fixture.
buffer.write("MZ", 0, "ascii");
buffer.writeUInt32LE(PE_OFFSET, 0x3c);

// PE signature + COFF header.
buffer.write("PE\0\0", PE_OFFSET, "binary");
let cursor = PE_OFFSET + 4;
buffer.writeUInt16LE(0x8664, cursor); cursor += 2; // AMD64
buffer.writeUInt16LE(1, cursor); cursor += 2; // one section
buffer.writeUInt32LE(0, cursor); cursor += 4; // deterministic timestamp
buffer.writeUInt32LE(0, cursor); cursor += 4;
buffer.writeUInt32LE(0, cursor); cursor += 4;
buffer.writeUInt16LE(0xf0, cursor); cursor += 2; // PE32+ optional header size
buffer.writeUInt16LE(0x0022, cursor); cursor += 2; // executable + large-address-aware

// PE32+ optional header.
const optional = cursor;
buffer.writeUInt16LE(0x20b, optional + 0x00);
buffer.writeUInt32LE(0x200, optional + 0x04); // SizeOfCode
buffer.writeUInt32LE(0x1000, optional + 0x10); // AddressOfEntryPoint
buffer.writeUInt32LE(0x1000, optional + 0x14); // BaseOfCode
buffer.writeBigUInt64LE(0x140000000n, optional + 0x18); // ImageBase
buffer.writeUInt32LE(SECTION_ALIGNMENT, optional + 0x20);
buffer.writeUInt32LE(FILE_ALIGNMENT, optional + 0x24);
buffer.writeUInt16LE(6, optional + 0x28); // OS major
buffer.writeUInt16LE(6, optional + 0x30); // subsystem major
buffer.writeUInt32LE(0x2000, optional + 0x38); // SizeOfImage
buffer.writeUInt32LE(0x200, optional + 0x3c); // SizeOfHeaders
buffer.writeUInt16LE(3, optional + 0x44); // console subsystem
buffer.writeUInt16LE(0x8160, optional + 0x46); // DEP/ASLR-friendly flags
buffer.writeBigUInt64LE(0x100000n, optional + 0x48); // stack reserve
buffer.writeBigUInt64LE(0x1000n, optional + 0x50); // stack commit
buffer.writeBigUInt64LE(0x100000n, optional + 0x58); // heap reserve
buffer.writeBigUInt64LE(0x1000n, optional + 0x60); // heap commit
buffer.writeUInt32LE(16, optional + 0x6c); // data-directory count

// .text section header.
const section = optional + 0xf0;
buffer.write(".text\0\0\0", section, "binary");
buffer.writeUInt32LE(0x40, section + 0x08); // VirtualSize
buffer.writeUInt32LE(0x1000, section + 0x0c); // VirtualAddress
buffer.writeUInt32LE(0x200, section + 0x10); // SizeOfRawData
buffer.writeUInt32LE(RAW_OFFSET, section + 0x14); // PointerToRawData
buffer.writeUInt32LE(0x60000020, section + 0x24); // code + execute + read

// Entry function: xor eax,eax; ret. Remaining bytes are deterministic padding.
buffer.set([0x31, 0xc0, 0xc3], RAW_OFFSET);
buffer.write("AxiomRE deterministic PE fixture\0", RAW_OFFSET + 0x20, "ascii");

await mkdir(fixtureDir, { recursive: true });
await writeFile(output, buffer);
console.log(output);
