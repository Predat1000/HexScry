import { access } from "node:fs/promises";
import type { FunctionDossier, InstructionInspection, InstructionReference, MemoryByteWindow, ProcedureResolution, ProcedureSummary, ReferenceEdge } from "@axiomre/core";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { defaultReaEntrypoint, reaNodeEnvironment } from "./reaCli.js";

export interface ReaMcpOptions {
  entrypoint?: string;
  environment?: NodeJS.ProcessEnv;
}

const MCP_OPEN_TIMEOUT_MS = 2 * 60_000;
const MCP_DEEP_ANALYSIS_TIMEOUT_MS = 5 * 60_000;
const MCP_INTERACTIVE_TIMEOUT_MS = 60_000;

interface ProcedureRow {
  address: string;
  value: string;
  procedure?: {
    external?: boolean;
    thunk?: boolean;
    thunk_target?: string | null;
  };
}

function cleanEnvironment(environment: NodeJS.ProcessEnv): Record<string, string> {
  return Object.fromEntries(
    Object.entries(environment).filter((entry): entry is [string, string] => typeof entry[1] === "string"),
  );
}

function providerErrorDetail(reply: unknown): string | null {
  if (!reply || typeof reply !== "object" || Array.isArray(reply)) return null;
  const response = reply as Record<string, unknown>;
  const textParts = Array.isArray(response.content)
    ? response.content.flatMap((item) => {
        if (!item || typeof item !== "object" || Array.isArray(item)) return [];
        const record = item as Record<string, unknown>;
        return typeof record.text === "string" && record.text.trim() ? [record.text.trim()] : [];
      })
    : [];
  if (textParts.length > 0) return textParts.join(" ");

  if (response.structuredContent && typeof response.structuredContent === "object" && !Array.isArray(response.structuredContent)) {
    const record = response.structuredContent as Record<string, unknown>;
    for (const key of ["message", "error", "reason", "detail"] as const) {
      const value = record[key];
      if (typeof value === "string" && value.trim()) return value.trim();
    }
  }
  return null;
}

function providerFailure(
  operation: string,
  reply: unknown,
  context?: string,
): Error {
  const detail = providerErrorDetail(reply);
  const evidence = `${detail ?? "The provider returned an unspecified error."}`;
  let hint = "";
  if (/GHIDRA_INSTALL_DIR|ghidra.+(?:missing|not found|unavailable|install)/iu.test(evidence)) {
    hint = " Verify Ghidra is installed and GHIDRA_INSTALL_DIR points to it.";
  } else if (/JAVA_HOME|\bJDK\b|java.+(?:missing|not found|unavailable)/iu.test(evidence)) {
    hint = " Verify a compatible JDK is installed and JAVA_HOME points to it.";
  }
  return new Error(`REA ${operation} failed${context ? ` (${context})` : ""}: ${evidence}${hint}`);
}

function normalizedResult(content: unknown, operation: string): unknown {
  if (!content || typeof content !== "object" || !("normalized_result" in content)) {
    throw new Error(`REA ${operation} response omitted normalized_result.`);
  }
  return (content as Record<string, unknown>).normalized_result;
}

function parseProcedures(content: unknown): ProcedureSummary[] {
  const result = normalizedResult(content, "list_procedures");
  if (!Array.isArray(result)) throw new Error("REA list_procedures normalized_result is not an array.");

  return result.map((raw, index) => {
    if (!raw || typeof raw !== "object") throw new Error(`REA procedure row ${index} is invalid.`);
    const row = raw as Partial<ProcedureRow>;
    if (typeof row.address !== "string" || typeof row.value !== "string") {
      throw new Error(`REA procedure row ${index} is missing address/name.`);
    }
    return {
      address: row.address,
      name: row.value,
      provider: "ghidra" as const,
      ...(typeof row.procedure?.external === "boolean" ? { external: row.procedure.external } : {}),
      ...(typeof row.procedure?.thunk === "boolean" ? { thunk: row.procedure.thunk } : {}),
      ...(row.procedure && "thunk_target" in row.procedure
        ? { thunkTarget: row.procedure.thunk_target ?? null }
        : {}),
    };
  });
}

function parseProcedureIdentity(raw: unknown, context: string): ProcedureSummary {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`REA ${context} procedure identity is invalid.`);
  }
  const identity = raw as Record<string, unknown>;
  if (typeof identity.address !== "string" || typeof identity.name !== "string") {
    throw new Error(`REA ${context} procedure has an invalid address or name.`);
  }
  const classification =
    identity.classification && typeof identity.classification === "object" && !Array.isArray(identity.classification)
      ? (identity.classification as Record<string, unknown>)
      : null;

  return {
    address: identity.address,
    name: identity.name,
    provider: "ghidra",
    ...(typeof classification?.external === "boolean" ? { external: classification.external } : {}),
    ...(typeof classification?.thunk === "boolean" ? { thunk: classification.thunk } : {}),
    ...(classification && "thunk_target" in classification
      ? { thunkTarget: typeof classification.thunk_target === "string" ? classification.thunk_target : null }
      : {}),
  };
}

function parseReferenceEdge(raw: unknown, context: string): ReferenceEdge {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`REA ${context} reference edge is invalid.`);
  }
  const edge = raw as Record<string, unknown>;
  if (typeof edge.source_address !== "string" || typeof edge.target_address !== "string") {
    throw new Error(`REA ${context} reference edge is missing endpoints.`);
  }

  const sourceProcedure = edge.source_procedure === null
    ? null
    : parseProcedureIdentity(edge.source_procedure, `${context} source`);
  const targetProcedure = edge.target_procedure === null
    ? null
    : parseProcedureIdentity(edge.target_procedure, `${context} target`);
  const kind = edge.kind;
  if (!kind || typeof kind !== "object" || Array.isArray(kind)) {
    throw new Error(`REA ${context} reference kind is invalid.`);
  }
  const kindRecord = kind as Record<string, unknown>;

  if (kindRecord.available === false) {
    if (typeof kindRecord.reason !== "string") {
      throw new Error(`REA ${context} unavailable reference kind omitted its reason.`);
    }
    return {
      sourceAddress: edge.source_address,
      targetAddress: edge.target_address,
      sourceProcedure,
      targetProcedure,
      type: null,
      tags: [],
      limitation: kindRecord.reason,
    };
  }
  if (kindRecord.available !== true || typeof kindRecord.type !== "string") {
    throw new Error(`REA ${context} available reference kind is malformed.`);
  }

  const flagNames = [
    "flow",
    "call",
    "jump",
    "data",
    "read",
    "write",
    "indirect",
    "computed",
    "conditional",
    "terminal",
    "primary",
    "external",
  ] as const;
  const tags = flagNames.filter((name) => kindRecord[name] === true);

  return {
    sourceAddress: edge.source_address,
    targetAddress: edge.target_address,
    sourceProcedure,
    targetProcedure,
    type: kindRecord.type,
    tags,
    limitation: null,
  };
}

function parseFunctionDossier(content: unknown): FunctionDossier {
  const result = normalizedResult(content, "analyze_function");
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("REA analyze_function normalized_result is not an object.");
  }

  const row = result as Record<string, unknown>;
  const procedure = row.procedure;
  if (!procedure || typeof procedure !== "object" || Array.isArray(procedure)) {
    throw new Error("REA analyze_function response omitted procedure identity.");
  }
  const identity = procedure as Record<string, unknown>;
  const parsedProcedure = parseProcedureIdentity(procedure, "analyze_function");
  const signature = identity.signature;
  const pseudocode = row.pseudocode;
  const assembly = row.assembly;
  const callers = row.callers;
  const callees = row.callees;
  const incomingReferences = row.incoming_references;
  const outgoingReferences = row.outgoing_references;
  const limitations = row.limitations;

  if (signature !== null && typeof signature !== "string") {
    throw new Error("REA analyze_function procedure signature is invalid.");
  }
  if (typeof pseudocode !== "string" || !Array.isArray(assembly) || !assembly.every((item) => typeof item === "string")) {
    throw new Error("REA analyze_function code facets are invalid.");
  }
  if (!Array.isArray(callers) || !Array.isArray(callees)) {
    throw new Error("REA analyze_function caller/callee facets are invalid.");
  }
  if (!Array.isArray(incomingReferences) || !Array.isArray(outgoingReferences)) {
    throw new Error("REA analyze_function reference facets are invalid.");
  }
  if (!Array.isArray(limitations) || !limitations.every((item) => typeof item === "string")) {
    throw new Error("REA analyze_function limitations are invalid.");
  }

  return {
    procedure: parsedProcedure,
    signature,
    pseudocode,
    assembly: assembly as string[],
    callers: callers.map((item, index) => parseProcedureIdentity(item, `analyze_function caller ${index}`)),
    callees: callees.map((item, index) => parseProcedureIdentity(item, `analyze_function callee ${index}`)),
    incomingReferences: incomingReferences.map((item, index) => parseReferenceEdge(item, `analyze_function incoming reference ${index}`)),
    outgoingReferences: outgoingReferences.map((item, index) => parseReferenceEdge(item, `analyze_function outgoing reference ${index}`)),
    limitations: limitations as string[],
  };
}

function parseInstructionReference(raw: unknown, context: string): InstructionReference {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error(`REA ${context} instruction reference is invalid.`);
  }
  const reference = raw as Record<string, unknown>;
  if (
    typeof reference.target_address !== "string" ||
    typeof reference.type !== "string" ||
    typeof reference.operand_index !== "number" ||
    !Number.isInteger(reference.operand_index) ||
    typeof reference.call !== "boolean" ||
    typeof reference.jump !== "boolean" ||
    typeof reference.indirect !== "boolean" ||
    typeof reference.computed !== "boolean"
  ) {
    throw new Error(`REA ${context} instruction reference is malformed.`);
  }
  const sourceAddress = reference.source_address;
  if (sourceAddress !== undefined && sourceAddress !== null && typeof sourceAddress !== "string") {
    throw new Error(`REA ${context} instruction reference source is malformed.`);
  }

  const flags: Array<[string, unknown]> = [
    ["call", reference.call],
    ["jump", reference.jump],
    ["indirect", reference.indirect],
    ["computed", reference.computed],
    ["data", reference.data],
    ["read", reference.read],
    ["write", reference.write],
    ["primary", reference.primary],
  ];
  return {
    sourceAddress: typeof sourceAddress === "string" ? sourceAddress : null,
    targetAddress: reference.target_address,
    type: reference.type,
    operandIndex: reference.operand_index,
    tags: flags.filter(([, value]) => value === true).map(([name]) => name),
  };
}

function parseInstructionInspection(content: unknown): InstructionInspection {
  const result = normalizedResult(content, "inspect_native_instruction");
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("REA inspect_native_instruction normalized_result is not an object.");
  }
  const row = result as Record<string, unknown>;
  const statuses = new Set(["decoded", "not-instruction-boundary", "data", "undecodable", "outside-memory"]);
  const flowKinds = new Set(["call", "jump", "return", "fallthrough", "terminal", "unavailable"]);
  if (
    typeof row.address !== "string" ||
    typeof row.status !== "string" || !statuses.has(row.status) ||
    (row.procedure !== null && typeof row.procedure !== "string") ||
    typeof row.architecture !== "string" ||
    typeof row.mode !== "string" ||
    (row.bytes !== null && typeof row.bytes !== "string") ||
    (row.length !== null && (typeof row.length !== "number" || !Number.isInteger(row.length) || row.length <= 0)) ||
    (row.mnemonic !== null && typeof row.mnemonic !== "string") ||
    (row.raw_disassembly !== null && typeof row.raw_disassembly !== "string") ||
    !Array.isArray(row.operands) ||
    !Array.isArray(row.references) ||
    !Array.isArray(row.limitations) || !row.limitations.every((item) => typeof item === "string")
  ) {
    throw new Error("REA inspect_native_instruction response is malformed.");
  }

  const operands = row.operands.map((raw, index) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
      throw new Error(`REA inspect_native_instruction operand ${index} is invalid.`);
    }
    const operand = raw as Record<string, unknown>;
    if (typeof operand.raw !== "string" || typeof operand.index !== "number" || !Number.isInteger(operand.index)) {
      throw new Error(`REA inspect_native_instruction operand ${index} is malformed.`);
    }
    return operand.raw;
  });

  const flow = row.flow;
  if (!flow || typeof flow !== "object" || Array.isArray(flow)) {
    throw new Error("REA inspect_native_instruction flow is invalid.");
  }
  const flowRecord = flow as Record<string, unknown>;
  if (
    typeof flowRecord.kind !== "string" || !flowKinds.has(flowRecord.kind) ||
    typeof flowRecord.conditional !== "boolean" ||
    typeof flowRecord.computed !== "boolean" ||
    !Array.isArray(flowRecord.direct_destinations) ||
    !flowRecord.direct_destinations.every((item) => typeof item === "string")
  ) {
    throw new Error("REA inspect_native_instruction flow is malformed.");
  }

  const incomingRaw = row.incoming_references;
  if (incomingRaw !== undefined && incomingRaw !== null && !Array.isArray(incomingRaw)) {
    throw new Error("REA inspect_native_instruction incoming references are malformed.");
  }

  return {
    address: row.address,
    status: row.status as InstructionInspection["status"],
    procedure: row.procedure as string | null,
    architecture: row.architecture,
    mode: row.mode,
    bytesHex: row.bytes as string | null,
    length: row.length as number | null,
    mnemonic: row.mnemonic as string | null,
    rawDisassembly: row.raw_disassembly as string | null,
    operands,
    flow: {
      kind: flowRecord.kind as InstructionInspection["flow"]["kind"],
      conditional: flowRecord.conditional,
      computed: flowRecord.computed,
      directDestinations: flowRecord.direct_destinations as string[],
    },
    outgoingReferences: row.references.map((item, index) => parseInstructionReference(item, `inspect_native_instruction outgoing reference ${index}`)),
    incomingReferences: Array.isArray(incomingRaw)
      ? incomingRaw.map((item, index) => parseInstructionReference(item, `inspect_native_instruction incoming reference ${index}`))
      : null,
    limitations: row.limitations as string[],
  };
}

function parseProcedureResolution(content: unknown): ProcedureResolution {
  const result = normalizedResult(content, "resolve_containing_procedure");
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("REA resolve_containing_procedure normalized_result is not an object.");
  }
  const row = result as Record<string, unknown>;
  if (typeof row.query_address !== "string" || typeof row.found !== "boolean") {
    throw new Error("REA resolve_containing_procedure response is malformed.");
  }

  if (row.found) {
    return {
      queryAddress: row.query_address,
      procedure: parseProcedureIdentity(row.procedure, "resolve_containing_procedure"),
      reason: null,
    };
  }

  if (row.procedure !== null || (row.reason !== "outside_segments" && row.reason !== "not_in_procedure")) {
    throw new Error("REA resolve_containing_procedure negative result is malformed.");
  }
  return {
    queryAddress: row.query_address,
    procedure: null,
    reason: row.reason,
  };
}

function parseMemoryByteWindow(content: unknown): MemoryByteWindow {
  const result = normalizedResult(content, "read_bytes");
  if (!result || typeof result !== "object" || Array.isArray(result)) {
    throw new Error("REA read_bytes normalized_result is not an object.");
  }

  const row = result as Record<string, unknown>;
  const address = row.address;
  const requestedBytes = row.requested_bytes;
  const returnedBytes = row.returned_bytes;
  const bytesHex = row.bytes_hex;
  const complete = row.complete;

  if (
    typeof address !== "string" ||
    typeof requestedBytes !== "number" ||
    !Number.isSafeInteger(requestedBytes) ||
    requestedBytes < 1 ||
    typeof returnedBytes !== "number" ||
    !Number.isSafeInteger(returnedBytes) ||
    returnedBytes < 0 ||
    returnedBytes > requestedBytes ||
    typeof bytesHex !== "string" ||
    !/^(?:[a-f0-9]{2})*$/u.test(bytesHex) ||
    bytesHex.length !== returnedBytes * 2 ||
    typeof complete !== "boolean" ||
    complete !== (returnedBytes === requestedBytes)
  ) {
    throw new Error("REA read_bytes response has inconsistent byte coverage.");
  }

  const bytes = Array.from({ length: returnedBytes }, (_, index) =>
    Number.parseInt(bytesHex.slice(index * 2, index * 2 + 2), 16),
  );

  return { address, requestedBytes, returnedBytes, bytes, complete };
}

export class ReaMcpSession {
  readonly #entrypoint: string;
  readonly #environment: NodeJS.ProcessEnv;
  #client: Client | null = null;
  #transport: StdioClientTransport | null = null;
  #targetPath: string | null = null;

  constructor(options: ReaMcpOptions = {}) {
    this.#environment = reaNodeEnvironment(options.environment ?? process.env);
    this.#entrypoint = options.entrypoint ?? defaultReaEntrypoint(this.#environment);
  }

  get targetPath(): string | null {
    return this.#targetPath;
  }

  async connect(): Promise<void> {
    if (this.#client) return;
    await access(this.#entrypoint);

    const transport = new StdioClientTransport({
      command: process.execPath,
      args: [this.#entrypoint, "mcp"],
      env: cleanEnvironment(this.#environment),
      stderr: "pipe",
    });
    const client = new Client(
      { name: "axiomre", version: "0.0.1" },
      { capabilities: {} },
    );

    try {
      await client.connect(transport);
      this.#transport = transport;
      this.#client = client;
    } catch (error) {
      await transport.close().catch(() => undefined);
      throw error;
    }
  }

  async openBinary(path: string): Promise<void> {
    await this.connect();
    if (this.#targetPath === path) return;
    const reply = await this.#client!.callTool(
      {
        name: "open_binary",
        arguments: { path, provider_id: "ghidra" },
      },
      undefined,
      { timeout: MCP_OPEN_TIMEOUT_MS },
    );
    if (reply.isError) throw providerFailure("open_binary", reply, path);
    this.#targetPath = path;
  }

  async listProcedures(signal?: AbortSignal): Promise<ProcedureSummary[]> {
    if (!this.#client || !this.#targetPath) throw new Error("No binary is open in the REA session.");
    if (signal?.aborted) throw signal.reason ?? new Error("Analysis cancelled.");

    const reply = await this.#client.callTool(
      { name: "list_procedures", arguments: {} },
      undefined,
      {
        timeout: MCP_DEEP_ANALYSIS_TIMEOUT_MS,
        ...(signal ? { signal } : {}),
      },
    );
    if (reply.isError) throw providerFailure("list_procedures", reply);
    return parseProcedures(reply.structuredContent);
  }

  async analyzeFunction(procedure: string, signal?: AbortSignal): Promise<FunctionDossier> {
    if (!this.#client || !this.#targetPath) throw new Error("No binary is open in the REA session.");
    if (!procedure) throw new Error("A procedure address or name is required.");
    if (signal?.aborted) throw signal.reason ?? new Error("Analysis cancelled.");

    const reply = await this.#client.callTool(
      { name: "analyze_function", arguments: { procedure } },
      undefined,
      {
        timeout: MCP_INTERACTIVE_TIMEOUT_MS,
        ...(signal ? { signal } : {}),
      },
    );
    if (reply.isError) throw providerFailure("analyze_function", reply, procedure);
    return parseFunctionDossier(reply.structuredContent);
  }

  async inspectInstruction(address: string, signal?: AbortSignal): Promise<InstructionInspection> {
    if (!this.#client || !this.#targetPath) throw new Error("No binary is open in the REA session.");
    if (!address) throw new Error("A memory address is required.");
    if (signal?.aborted) throw signal.reason ?? new Error("Analysis cancelled.");

    const reply = await this.#client.callTool(
      { name: "inspect_native_instruction", arguments: { address } },
      undefined,
      {
        timeout: MCP_INTERACTIVE_TIMEOUT_MS,
        ...(signal ? { signal } : {}),
      },
    );
    if (reply.isError) throw providerFailure("inspect_native_instruction", reply, address);
    return parseInstructionInspection(reply.structuredContent);
  }

  async resolveContainingProcedure(address: string, signal?: AbortSignal): Promise<ProcedureResolution> {
    if (!this.#client || !this.#targetPath) throw new Error("No binary is open in the REA session.");
    if (!address) throw new Error("A memory address is required.");
    if (signal?.aborted) throw signal.reason ?? new Error("Analysis cancelled.");

    const reply = await this.#client.callTool(
      { name: "resolve_containing_procedure", arguments: { address } },
      undefined,
      {
        timeout: MCP_INTERACTIVE_TIMEOUT_MS,
        ...(signal ? { signal } : {}),
      },
    );
    if (reply.isError) throw providerFailure("resolve_containing_procedure", reply, address);
    return parseProcedureResolution(reply.structuredContent);
  }

  async readBytes(address: string, length = 256, signal?: AbortSignal): Promise<MemoryByteWindow> {
    if (!this.#client || !this.#targetPath) throw new Error("No binary is open in the REA session.");
    if (!address) throw new Error("A memory address is required.");
    if (!Number.isSafeInteger(length) || length < 1 || length > 4096) {
      throw new Error("AxiomRE byte reads must request between 1 and 4096 bytes.");
    }
    if (signal?.aborted) throw signal.reason ?? new Error("Analysis cancelled.");

    const reply = await this.#client.callTool(
      { name: "read_bytes", arguments: { address, length } },
      undefined,
      {
        timeout: MCP_INTERACTIVE_TIMEOUT_MS,
        ...(signal ? { signal } : {}),
      },
    );
    if (reply.isError) throw providerFailure("read_bytes", reply, address);
    return parseMemoryByteWindow(reply.structuredContent);
  }

  async close(): Promise<void> {
    this.#targetPath = null;
    const client = this.#client;
    this.#client = null;
    this.#transport = null;
    if (client) await client.close();
  }
}

export const __mcpTest = {
  parseProcedures,
  parseFunctionDossier,
  parseInstructionInspection,
  parseProcedureResolution,
  parseMemoryByteWindow,
  cleanEnvironment,
  providerErrorDetail,
  providerFailure,
};
