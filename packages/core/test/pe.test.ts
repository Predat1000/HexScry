import assert from "node:assert/strict";
import test from "node:test";
import { assertSupportedFoundationPeSize, extractAsciiStrings, MAX_FOUNDATION_PE_BYTES, parsePortableExecutable } from "../src/index.js";

function syntheticPe64(): Buffer {
  const buffer = Buffer.alloc(0x400);
  buffer.writeUInt16LE(0x5a4d, 0);
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.writeUInt32LE(0x00004550, 0x80);

  const coff = 0x84;
  buffer.writeUInt16LE(0x8664, coff);
  buffer.writeUInt16LE(1, coff + 2);
  buffer.writeUInt32LE(1234567890, coff + 4);
  buffer.writeUInt16LE(0xf0, coff + 16);

  const optional = coff + 20;
  buffer.writeUInt16LE(0x20b, optional);
  buffer.writeUInt32LE(0x1234, optional + 16);
  buffer.writeBigUInt64LE(0x140000000n, optional + 24);
  buffer.writeUInt32LE(0x200, optional + 60);

  const section = optional + 0xf0;
  buffer.write(".text\0\0\0", section, "ascii");
  buffer.writeUInt32LE(0x200, section + 8);
  buffer.writeUInt32LE(0x1000, section + 12);
  buffer.writeUInt32LE(0x200, section + 16);
  buffer.writeUInt32LE(0x200, section + 20);
  buffer.writeUInt32LE(0x60000020, section + 36);

  buffer.write("hello-hexscry\0", 0x200, "ascii");
  return buffer;
}

function syntheticPe32WithTls(): Buffer {
  const buffer = Buffer.alloc(0x400);
  buffer.writeUInt16LE(0x5a4d, 0);
  buffer.writeUInt32LE(0x80, 0x3c);
  buffer.writeUInt32LE(0x00004550, 0x80);

  const coff = 0x84;
  buffer.writeUInt16LE(0x014c, coff);
  buffer.writeUInt16LE(1, coff + 2);
  buffer.writeUInt16LE(0xe0, coff + 16);

  const optional = coff + 20;
  buffer.writeUInt16LE(0x10b, optional);
  buffer.writeUInt32LE(0x1000, optional + 16);
  buffer.writeUInt32LE(0x00400000, optional + 28);
  buffer.writeUInt32LE(0x200, optional + 60);
  buffer.writeUInt32LE(16, optional + 92);

  const tlsDirectory = optional + 96 + 9 * 8;
  buffer.writeUInt32LE(0x1100, tlsDirectory);
  buffer.writeUInt32LE(24, tlsDirectory + 4);

  const section = optional + 0xe0;
  buffer.write(".text\0\0\0", section, "ascii");
  buffer.writeUInt32LE(0x200, section + 8);
  buffer.writeUInt32LE(0x1000, section + 12);
  buffer.writeUInt32LE(0x200, section + 16);
  buffer.writeUInt32LE(0x200, section + 20);
  buffer.writeUInt32LE(0x60000020, section + 36);

  const tls = 0x300;
  buffer.writeUInt32LE(0x00401060, tls);
  buffer.writeUInt32LE(0x00401070, tls + 4);
  buffer.writeUInt32LE(0x00401050, tls + 8);
  buffer.writeUInt32LE(0x00401180, tls + 12);
  buffer.writeUInt32LE(0, tls + 16);
  buffer.writeUInt32LE(0, tls + 20);

  buffer.writeUInt32LE(0x00401020, 0x380);
  buffer.writeUInt32LE(0, 0x384);
  return buffer;
}

function syntheticPe64WithImports(): Buffer {
  const buffer = syntheticPe64();
  const optional = 0x84 + 20;
  buffer.writeUInt32LE(16, optional + 108);
  buffer.writeUInt32LE(0x1100, optional + 120);
  buffer.writeUInt32LE(40, optional + 124);

  const descriptor = 0x300;
  buffer.writeUInt32LE(0x1140, descriptor);
  buffer.writeUInt32LE(0x1180, descriptor + 12);
  buffer.writeUInt32LE(0x1160, descriptor + 16);

  buffer.writeBigUInt64LE(0x11a0n, 0x340);
  buffer.writeBigUInt64LE((1n << 63n) | 7n, 0x348);
  buffer.writeBigUInt64LE(0n, 0x350);

  buffer.write("KERNEL32.dll\0", 0x380, "ascii");
  buffer.writeUInt16LE(12, 0x3a0);
  buffer.write("ExitProcess\0", 0x3a2, "ascii");
  return buffer;
}

function syntheticPe64WithExports(): Buffer {
  const buffer = syntheticPe64();
  const optional = 0x84 + 20;
  buffer.writeUInt32LE(16, optional + 108);
  buffer.writeUInt32LE(0x1100, optional + 112);
  buffer.writeUInt32LE(0xe0, optional + 116);

  const directory = 0x300;
  buffer.writeUInt32LE(0x1180, directory + 12);
  buffer.writeUInt32LE(1, directory + 16);
  buffer.writeUInt32LE(3, directory + 20);
  buffer.writeUInt32LE(3, directory + 24);
  buffer.writeUInt32LE(0x1140, directory + 28);
  buffer.writeUInt32LE(0x1150, directory + 32);
  buffer.writeUInt32LE(0x1160, directory + 36);

  buffer.writeUInt32LE(0x1000, 0x340);
  buffer.writeUInt32LE(0x11c0, 0x344);
  buffer.writeUInt32LE(0x1020, 0x348);

  buffer.writeUInt32LE(0x1190, 0x350);
  buffer.writeUInt32LE(0x11a0, 0x354);
  buffer.writeUInt32LE(0x11b0, 0x358);
  buffer.writeUInt16LE(0, 0x360);
  buffer.writeUInt16LE(1, 0x362);
  buffer.writeUInt16LE(0, 0x364);

  buffer.write("fixture.dll\0", 0x380, "ascii");
  buffer.write("NamedOne\0", 0x390, "ascii");
  buffer.write("Forwarded\0", 0x3a0, "ascii");
  buffer.write("NamedAlias\0", 0x3b0, "ascii");
  buffer.write("KERNEL32.Sleep\0", 0x3c0, "ascii");
  return buffer;
}

function syntheticPe64WithRelocations(): Buffer {
  const buffer = syntheticPe64();
  const optional = 0x84 + 20;
  buffer.writeUInt32LE(16, optional + 108);

  const relocationDirectory = optional + 112 + 5 * 8;
  buffer.writeUInt32LE(0x1100, relocationDirectory);
  buffer.writeUInt32LE(14, relocationDirectory + 4);

  const block = 0x300;
  buffer.writeUInt32LE(0x1000, block);
  buffer.writeUInt32LE(14, block + 4);
  buffer.writeUInt16LE((10 << 12) | 0x010, block + 8);
  buffer.writeUInt16LE((3 << 12) | 0x020, block + 10);
  buffer.writeUInt16LE(0, block + 12);
  return buffer;
}

function syntheticPe64WithRsdsDebug(): Buffer {
  const buffer = syntheticPe64();
  const optional = 0x84 + 20;
  buffer.writeUInt32LE(16, optional + 108);

  const debugDirectory = optional + 112 + 6 * 8;
  buffer.writeUInt32LE(0x1100, debugDirectory);
  buffer.writeUInt32LE(28, debugDirectory + 4);

  const entry = 0x300;
  const pdbPath = "C:\\symbols\\fixture.pdb";
  const sizeOfData = 24 + Buffer.byteLength(pdbPath, "ascii") + 1;
  buffer.writeUInt32LE(0x12345678, entry + 4);
  buffer.writeUInt32LE(2, entry + 12);
  buffer.writeUInt32LE(sizeOfData, entry + 16);
  buffer.writeUInt32LE(0x1140, entry + 20);
  buffer.writeUInt32LE(0x340, entry + 24);

  const data = 0x340;
  buffer.write("RSDS", data, "ascii");
  buffer.writeUInt32LE(0x11223344, data + 4);
  buffer.writeUInt16LE(0x5566, data + 8);
  buffer.writeUInt16LE(0x7788, data + 10);
  Buffer.from([0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00]).copy(buffer, data + 12);
  buffer.writeUInt32LE(3, data + 20);
  buffer.write(`${pdbPath}\0`, data + 24, "ascii");
  return buffer;
}

function syntheticPe64WithNb10Debug(): Buffer {
  const buffer = syntheticPe64();
  const optional = 0x84 + 20;
  buffer.writeUInt32LE(16, optional + 108);

  const debugDirectory = optional + 112 + 6 * 8;
  buffer.writeUInt32LE(0x1100, debugDirectory);
  buffer.writeUInt32LE(28, debugDirectory + 4);

  const entry = 0x300;
  const pdbPath = "C:\\legacy\\fixture.pdb";
  const sizeOfData = 16 + Buffer.byteLength(pdbPath, "ascii") + 1;
  buffer.writeUInt32LE(2, entry + 12);
  buffer.writeUInt32LE(sizeOfData, entry + 16);
  buffer.writeUInt32LE(0x1140, entry + 20);
  buffer.writeUInt32LE(0x340, entry + 24);

  const data = 0x340;
  buffer.write("NB10", data, "ascii");
  buffer.writeUInt32LE(0, data + 4);
  buffer.writeUInt32LE(0xaabbccdd, data + 8);
  buffer.writeUInt32LE(2, data + 12);
  buffer.write(`${pdbPath}\0`, data + 16, "ascii");
  return buffer;
}

function syntheticPe64WithTls(): Buffer {
  const buffer = syntheticPe64();
  const optional = 0x84 + 20;
  buffer.writeUInt32LE(16, optional + 108);

  const tlsDirectory = optional + 112 + 9 * 8;
  buffer.writeUInt32LE(0x1100, tlsDirectory);
  buffer.writeUInt32LE(40, tlsDirectory + 4);

  const tls = 0x300;
  buffer.writeBigUInt64LE(0x140001060n, tls);
  buffer.writeBigUInt64LE(0x140001070n, tls + 8);
  buffer.writeBigUInt64LE(0x140001050n, tls + 16);
  buffer.writeBigUInt64LE(0x140001180n, tls + 24);
  buffer.writeUInt32LE(4, tls + 32);
  buffer.writeUInt32LE(0x00100000, tls + 36);

  buffer.writeBigUInt64LE(0x140001020n, 0x380);
  buffer.writeBigUInt64LE(0x140001030n, 0x388);
  buffer.writeBigUInt64LE(0n, 0x390);
  return buffer;
}

test("parses a bounded PE32+ foundation report", () => {
  const report = parsePortableExecutable("fixture.exe", syntheticPe64());
  assert.equal(report.format, "PE32+");
  assert.equal(report.architecture, "x86-64");
  assert.equal(report.entryPointRva, 0x1234);
  assert.equal(report.imageBase, "0x140000000");
  assert.equal(report.sections.length, 1);
  assert.equal(report.sections[0]?.name, ".text");
  assert.equal(report.imports.length, 0);
  assert.equal(report.exports.length, 0);
  assert.equal(report.relocations.length, 0);
  assert.equal(report.debug.length, 0);
  assert.equal(report.tls, null);
  assert.ok(report.strings.some((entry) => entry.value.includes("hello-hexscry")));
});

test("parses named and ordinal PE32+ imports with IAT RVAs", () => {
  const report = parsePortableExecutable("imports.exe", syntheticPe64WithImports());
  assert.deepEqual(report.imports, [
    { library: "KERNEL32.dll", name: "ExitProcess", ordinal: null, hint: 12, iatRva: 0x1160 },
    { library: "KERNEL32.dll", name: null, ordinal: 7, hint: null, iatRva: 0x1168 },
  ]);
  assert.ok(report.limitations.every((item) => !item.includes("does not yet resolve imports")));
});

test("parses PE32+ base relocations and ignores ABSOLUTE padding entries", () => {
  const report = parsePortableExecutable("relocs.exe", syntheticPe64WithRelocations());
  assert.deepEqual(report.relocations, [
    { rva: 0x1010, type: 10, typeName: "DIR64", widthBytes: 8 },
    { rva: 0x1020, type: 3, typeName: "HIGHLOW", widthBytes: 4 },
  ]);
  assert.ok(report.limitations.every((item) => !item.includes("does not yet resolve relocations")));
});

test("reports malformed base-relocation blocks without reading past the declared directory", () => {
  const buffer = syntheticPe64WithRelocations();
  buffer.writeUInt32LE(6, 0x300 + 4);
  const report = parsePortableExecutable("bad-relocs.exe", buffer);
  assert.deepEqual(report.relocations, []);
  assert.ok(report.limitations.some((item) => item.includes("invalid size 6")));
});

test("parses RSDS CodeView debug metadata with PDB identity", () => {
  const report = parsePortableExecutable("debug.exe", syntheticPe64WithRsdsDebug());
  assert.deepEqual(report.debug, [
    {
      type: 2,
      typeName: "CODEVIEW",
      timestamp: 0x12345678,
      majorVersion: 0,
      minorVersion: 0,
      sizeOfData: 47,
      dataRva: 0x1140,
      dataFileOffset: 0x340,
      codeView: {
        signature: "RSDS",
        pdbPath: "C:\\symbols\\fixture.pdb",
        guid: "11223344-5566-7788-99AA-BBCCDDEEFF00",
        age: 3,
        timestamp: null,
      },
    },
  ]);
});

test("parses NB10 CodeView debug metadata", () => {
  const report = parsePortableExecutable("legacy-debug.exe", syntheticPe64WithNb10Debug());
  assert.equal(report.debug.length, 1);
  assert.deepEqual(report.debug[0]?.codeView, {
    signature: "NB10",
    pdbPath: "C:\\legacy\\fixture.pdb",
    guid: null,
    age: 2,
    timestamp: 0xaabbccdd,
  });
});

test("preserves a debug entry while reporting a truncated CodeView payload", () => {
  const buffer = syntheticPe64WithRsdsDebug();
  buffer.writeUInt32LE(0x100, 0x300 + 16);
  buffer.writeUInt32LE(0, 0x300 + 20);
  buffer.writeUInt32LE(0x3f0, 0x300 + 24);
  const report = parsePortableExecutable("bad-debug.exe", buffer);
  assert.equal(report.debug.length, 1);
  assert.equal(report.debug[0]?.typeName, "CODEVIEW");
  assert.equal(report.debug[0]?.codeView, null);
  assert.ok(report.limitations.some((item) => item.includes("payload is truncated")));
});

test("parses PE32+ TLS directory and callback addresses", () => {
  const report = parsePortableExecutable("tls.exe", syntheticPe64WithTls());
  assert.deepEqual(report.tls, {
    rawDataStartAddress: "0x140001060",
    rawDataEndAddress: "0x140001070",
    indexAddress: "0x140001050",
    callbacksAddress: "0x140001180",
    sizeOfZeroFill: 4,
    characteristics: 0x00100000,
    callbacks: [
      { address: "0x140001020", rva: 0x1020 },
      { address: "0x140001030", rva: 0x1030 },
    ],
  });
  assert.ok(report.limitations.every((item) => !item.includes("TLS callback table")));
});

test("parses PE32 TLS directory and 32-bit callback addresses", () => {
  const report = parsePortableExecutable("tls-x86.exe", syntheticPe32WithTls());
  assert.equal(report.format, "PE32");
  assert.equal(report.architecture, "x86");
  assert.deepEqual(report.tls, {
    rawDataStartAddress: "0x401060",
    rawDataEndAddress: "0x401070",
    indexAddress: "0x401050",
    callbacksAddress: "0x401180",
    sizeOfZeroFill: 0,
    characteristics: 0,
    callbacks: [{ address: "0x401020", rva: 0x1020 }],
  });
});

test("preserves TLS metadata while reporting a truncated callback table", () => {
  const buffer = syntheticPe64WithTls();
  buffer.writeBigUInt64LE(0x1400011f8n, 0x300 + 24);
  buffer.writeBigUInt64LE(0x140001020n, 0x3f8);
  const report = parsePortableExecutable("bad-tls.exe", buffer);
  assert.equal(report.tls?.callbacks.length, 1);
  assert.equal(report.tls?.callbacks[0]?.rva, 0x1020);
  assert.ok(report.limitations.some((item) => item.includes("TLS callback table is truncated")));
});

test("parses named, aliased, ordinal-only and forwarded PE32+ exports", () => {
  const report = parsePortableExecutable("exports.dll", syntheticPe64WithExports());
  assert.deepEqual(report.exports, [
    { name: "NamedOne", ordinal: 1, rva: 0x1000, forwarder: null },
    { name: "NamedAlias", ordinal: 1, rva: 0x1000, forwarder: null },
    { name: "Forwarded", ordinal: 2, rva: 0x11c0, forwarder: "KERNEL32.Sleep" },
    { name: null, ordinal: 3, rva: 0x1020, forwarder: null },
  ]);
});

test("rejects non-PE input", () => {
  assert.throws(
    () => parsePortableExecutable("bad.bin", Buffer.alloc(128)),
    /missing MZ header/,
  );
});

test("extracts printable strings with offsets", () => {
  const strings = extractAsciiStrings(Buffer.from([0, 65, 66, 67, 68, 69, 0, 88, 89]));
  assert.deepEqual(strings, [{ offset: 1, value: "ABCDE" }]);
});


test("rejects oversized PE foundation inputs before allocating the file buffer", () => {
  assert.doesNotThrow(() => assertSupportedFoundationPeSize(MAX_FOUNDATION_PE_BYTES));
  assert.throws(
    () => assertSupportedFoundationPeSize(MAX_FOUNDATION_PE_BYTES + 1),
    /512 MiB/,
  );
});
