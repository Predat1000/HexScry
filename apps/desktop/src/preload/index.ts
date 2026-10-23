import { contextBridge, ipcRenderer } from "electron";
import type { AnalystAnnotations, BinaryReport, BinaryWindow, FunctionDossier, InstructionInspection, MemoryByteWindow, ProcedureResolution, ProcedureSummary } from "@axiomre/core";

export interface ToolStatus {
  rea: { available: boolean; version?: string };
  ghidra: { available: boolean; path?: string };
  jadx: { available: boolean; path?: string };
}

export interface HexWindowResult {
  address: string;
  file: BinaryWindow;
  memory: MemoryByteWindow | null;
  memoryError: string | null;
}

export interface BootstrapState {
  report: BinaryReport | null;
  autoDeep: boolean;
  error: string | null;
}

export interface AxiomApi {
  bootstrap(): Promise<BootstrapState>;
  openBinary(): Promise<BinaryReport | null>;
  openProject(): Promise<{ report: BinaryReport; selectedProcedure: string | null; annotations: AnalystAnnotations } | null>;
  saveProject(selectedProcedure: string | null, annotations: AnalystAnnotations): Promise<string | null>;
  deepProcedures(): Promise<ProcedureSummary[]>;
  analyzeFunction(procedure: string): Promise<FunctionDossier>;
  inspectInstruction(address: string): Promise<InstructionInspection>;
  resolveAddress(address: string): Promise<ProcedureResolution>;
  hexWindow(address: string, length?: number): Promise<HexWindowResult>;
  cancelDeepAnalysis(): Promise<boolean>;
  toolchain(): Promise<ToolStatus>;
}

const api: AxiomApi = {
  bootstrap: () => ipcRenderer.invoke("analysis:bootstrap"),
  openBinary: () => ipcRenderer.invoke("analysis:open-binary"),
  openProject: () => ipcRenderer.invoke("project:open"),
  saveProject: (selectedProcedure, annotations) => ipcRenderer.invoke("project:save", selectedProcedure, annotations),
  deepProcedures: () => ipcRenderer.invoke("analysis:deep-procedures"),
  analyzeFunction: (procedure) => ipcRenderer.invoke("analysis:function", procedure),
  inspectInstruction: (address) => ipcRenderer.invoke("analysis:instruction", address),
  resolveAddress: (address) => ipcRenderer.invoke("analysis:resolve-address", address),
  hexWindow: (address, length) => ipcRenderer.invoke("analysis:hex-window", address, length),
  cancelDeepAnalysis: () => ipcRenderer.invoke("analysis:cancel-deep"),
  toolchain: () => ipcRenderer.invoke("system:toolchain"),
};

contextBridge.exposeInMainWorld("axiom", api);
