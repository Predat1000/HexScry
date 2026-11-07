export type BinaryFormat = "PE32" | "PE32+" | "unknown";

export interface SectionInfo {
  name: string;
  virtualAddress: number;
  virtualSize: number;
  rawOffset: number;
  rawSize: number;
  characteristics: number;
}

export interface ExtractedString {
  address?: string;
  offset: number;
  value: string;
}

export interface ImportInfo {
  library: string;
  name: string | null;
  ordinal: number | null;
  hint: number | null;
  iatRva: number;
}

export interface ExportInfo {
  name: string | null;
  ordinal: number;
  rva: number;
  forwarder: string | null;
}

export interface RelocationInfo {
  rva: number;
  type: number;
  typeName: string;
  widthBytes: number | null;
}

export interface CodeViewInfo {
  signature: "RSDS" | "NB10";
  pdbPath: string;
  guid: string | null;
  age: number;
  timestamp: number | null;
}

export interface DebugInfo {
  type: number;
  typeName: string;
  timestamp: number;
  majorVersion: number;
  minorVersion: number;
  sizeOfData: number;
  dataRva: number;
  dataFileOffset: number | null;
  codeView: CodeViewInfo | null;
}

export interface TlsCallbackInfo {
  address: string;
  rva: number | null;
}

export interface TlsInfo {
  rawDataStartAddress: string;
  rawDataEndAddress: string;
  indexAddress: string;
  callbacksAddress: string;
  sizeOfZeroFill: number;
  characteristics: number;
  callbacks: TlsCallbackInfo[];
}

export interface ProcedureSummary {
  address: string;
  name: string;
  provider: "ghidra" | "rea" | "unknown";
  external?: boolean;
  thunk?: boolean;
  thunkTarget?: string | null;
}

export interface ReferenceEdge {
  sourceAddress: string;
  targetAddress: string;
  sourceProcedure: ProcedureSummary | null;
  targetProcedure: ProcedureSummary | null;
  type: string | null;
  tags: string[];
  limitation: string | null;
}

export interface InstructionReference {
  sourceAddress: string | null;
  targetAddress: string;
  type: string;
  operandIndex: number;
  tags: string[];
}

export interface InstructionInspection {
  address: string;
  status: "decoded" | "not-instruction-boundary" | "data" | "undecodable" | "outside-memory";
  procedure: string | null;
  architecture: string;
  mode: string;
  bytesHex: string | null;
  length: number | null;
  mnemonic: string | null;
  rawDisassembly: string | null;
  operands: string[];
  flow: {
    kind: "call" | "jump" | "return" | "fallthrough" | "terminal" | "unavailable";
    conditional: boolean;
    computed: boolean;
    directDestinations: string[];
  };
  outgoingReferences: InstructionReference[];
  incomingReferences: InstructionReference[] | null;
  limitations: string[];
}

export interface ProcedureResolution {
  queryAddress: string;
  procedure: ProcedureSummary | null;
  reason: "outside_segments" | "not_in_procedure" | null;
}

export interface MemoryByteWindow {
  address: string;
  requestedBytes: number;
  returnedBytes: number;
  bytes: number[];
  complete: boolean;
}

export interface FunctionDossier {
  procedure: ProcedureSummary;
  signature: string | null;
  pseudocode: string;
  assembly: string[];
  callers: ProcedureSummary[];
  callees: ProcedureSummary[];
  incomingReferences: ReferenceEdge[];
  outgoingReferences: ReferenceEdge[];
  limitations: string[];
}

export interface BinaryWindow {
  fileOffset: number;
  bytes: number[];
}

export interface BinaryReport {
  path: string;
  fileName: string;
  fileSize: number;
  sha256: string;
  format: BinaryFormat;
  architecture: string;
  machine: number;
  entryPointRva: number;
  imageBase: string;
  timestamp: number;
  sections: SectionInfo[];
  imports: ImportInfo[];
  exports: ExportInfo[];
  relocations: RelocationInfo[];
  debug: DebugInfo[];
  tls: TlsInfo | null;
  strings: ExtractedString[];
  limitations: string[];
}
