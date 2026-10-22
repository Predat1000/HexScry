import type { BinaryReport } from "@axiomre/core";

export interface PluginManifest {
  id: string;
  name: string;
  version: string;
  apiVersion: 1;
  description?: string;
}

export interface AnalysisEvidence {
  kind: "address" | "file-range" | "symbol" | "string" | "provider";
  label: string;
  value: string;
}

export interface AnalysisFinding {
  id: string;
  title: string;
  summary: string;
  confidence: number;
  evidence: AnalysisEvidence[];
  limitations: string[];
}

export interface AnalyzerContext {
  report: BinaryReport;
  signal: AbortSignal;
}

export interface AnalyzerPlugin {
  manifest: PluginManifest;
  analyze(context: AnalyzerContext): Promise<AnalysisFinding[]>;
}
