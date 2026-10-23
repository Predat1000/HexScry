import assert from "node:assert/strict";
import { mkdir, writeFile } from "node:fs/promises";
import { performance } from "node:perf_hooks";
import { fileURLToPath } from "node:url";
import { dirname, join, resolve } from "node:path";
import { ReaMcpSession, resolveReaEnvironment } from "../packages/provider-rea/dist/index.js";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const root = dirname(scriptDir);
const outputDir = join(root, ".hexscry-dev");
const outputPath = join(outputDir, "smoke-rea-provider-result.json");
const target = resolve(process.argv[2] ?? "C:\\Windows\\System32\\choice.exe");
const session = new ReaMcpSession({ environment: await resolveReaEnvironment(process.env) });
await mkdir(outputDir, { recursive: true });

try {
  const openStart = performance.now();
  await session.openBinary(target);
  const openMs = Math.round(performance.now() - openStart);

  const firstStart = performance.now();
  const procedures = await session.listProcedures();
  const firstListMs = Math.round(performance.now() - firstStart);
  assert.ok(procedures.length > 0, "Expected at least one procedure");

  const secondStart = performance.now();
  const second = await session.listProcedures();
  const secondListMs = Math.round(performance.now() - secondStart);
  assert.equal(second.length, procedures.length);

  const firstLocal = procedures.find((procedure) => procedure.external === false);
  assert.ok(firstLocal, "Expected at least one local procedure");
  const functionStart = performance.now();
  const dossier = await session.analyzeFunction(firstLocal.address);
  const functionMs = Math.round(performance.now() - functionStart);
  assert.equal(dossier.procedure.address, firstLocal.address);
  assert.ok(dossier.assembly.length > 0, "Expected assembly for a local function");

  const instructionStart = performance.now();
  const entryInstruction = await session.inspectInstruction(firstLocal.address);
  const instructionMs = Math.round(performance.now() - instructionStart);
  assert.equal(entryInstruction.address, firstLocal.address);
  assert.equal(entryInstruction.status, "decoded");

  const interiorAddress = `0x${(BigInt(firstLocal.address) + 1n).toString(16)}`;
  const interiorInstructionStart = performance.now();
  const interiorInstruction = await session.inspectInstruction(interiorAddress);
  const interiorInstructionMs = Math.round(performance.now() - interiorInstructionStart);
  assert.equal(interiorInstruction.address, interiorAddress);

  const resolveStart = performance.now();
  const resolution = await session.resolveContainingProcedure(interiorAddress);
  const resolveMs = Math.round(performance.now() - resolveStart);
  assert.equal(resolution.procedure?.address, firstLocal.address);

  const bytesStart = performance.now();
  const byteWindow = await session.readBytes(firstLocal.address, 64);
  const bytesMs = Math.round(performance.now() - bytesStart);
  assert.ok(byteWindow.returnedBytes > 0, "Expected provider bytes for a local procedure");
  assert.equal(byteWindow.bytes.length, byteWindow.returnedBytes);

  const result = {
    ok: true,
    target,
    openMs,
    firstListMs,
    secondListMs,
    functionMs,
    instructionMs,
    interiorInstructionMs,
    resolveMs,
    bytesMs,
    procedureCount: procedures.length,
    firstLocal,
    entryInstruction: {
      address: entryInstruction.address,
      status: entryInstruction.status,
      bytesHex: entryInstruction.bytesHex,
      rawDisassembly: entryInstruction.rawDisassembly,
      flow: entryInstruction.flow,
    },
    interiorInstruction: {
      address: interiorInstruction.address,
      status: interiorInstruction.status,
      rawDisassembly: interiorInstruction.rawDisassembly,
    },
    resolution,
    byteWindow: {
      address: byteWindow.address,
      requestedBytes: byteWindow.requestedBytes,
      returnedBytes: byteWindow.returnedBytes,
      complete: byteWindow.complete,
      first16: byteWindow.bytes.slice(0, 16),
    },
    dossier: {
      name: dossier.procedure.name,
      signature: dossier.signature,
      pseudocodeChars: dossier.pseudocode.length,
      assemblyLines: dossier.assembly.length,
      limitationCount: dossier.limitations.length,
    },
  };
  await writeFile(outputPath, `${JSON.stringify(result, null, 2)}\n`, "utf8");
  console.log(JSON.stringify(result, null, 2));
} catch (error) {
  const failure = {
    ok: false,
    target,
    error: error instanceof Error ? { name: error.name, message: error.message, stack: error.stack } : String(error),
  };
  await writeFile(outputPath, `${JSON.stringify(failure, null, 2)}\n`, "utf8");
  console.error(JSON.stringify(failure, null, 2));
  process.exitCode = 1;
} finally {
  await session.close().catch(() => undefined);
}
