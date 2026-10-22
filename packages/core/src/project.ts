import type { BinaryReport } from "./model.js";

export interface AnalystAnnotations {
  aliases: Record<string, string>;
  comments: Record<string, string>;
}

export interface AxiomProjectV1 {
  schema: "axiomre-project";
  version: 1;
  target: {
    path: string;
    sha256: string;
  };
  navigation: {
    selectedProcedure: string | null;
  };
  annotations: AnalystAnnotations;
}

const SHA256 = /^[a-f0-9]{64}$/u;
const MAX_ANNOTATIONS = 500;
const MAX_ALIAS_LENGTH = 128;
const MAX_COMMENT_LENGTH = 4000;

export function createProject(
  report: BinaryReport,
  selectedProcedure: string | null = null,
  annotations: AnalystAnnotations = { aliases: {}, comments: {} },
): AxiomProjectV1 {
  const normalizedAnnotations = parseAnnotations(annotations);
  const normalizedProcedure = parseSelectedProcedure(selectedProcedure);
  return {
    schema: "axiomre-project",
    version: 1,
    target: {
      path: report.path,
      sha256: report.sha256,
    },
    navigation: { selectedProcedure: normalizedProcedure },
    annotations: normalizedAnnotations,
  };
}

function parseAnnotationMap(value: unknown, label: string, maxLength: number): Record<string, string> {
  if (value === undefined) return {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Project ${label} annotations are invalid.`);
  }

  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length > MAX_ANNOTATIONS) {
    throw new Error(`Project ${label} annotations exceed the ${MAX_ANNOTATIONS} entry limit.`);
  }

  const normalized: Record<string, string> = {};
  for (const [address, text] of entries) {
    if (!address || address.length > 256 || typeof text !== "string" || text.length === 0 || text.length > maxLength) {
      throw new Error(`Project ${label} annotation is invalid at ${address || "(empty address)"}.`);
    }
    normalized[address] = text;
  }
  return normalized;
}

function parseSelectedProcedure(value: unknown): string | null {
  if (value === null) return null;
  if (typeof value !== "string" || value.length === 0 || value.length > 512) {
    throw new Error("Project selected procedure is invalid.");
  }
  return value;
}

function parseAnnotations(value: unknown): AnalystAnnotations {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Project annotations are invalid.");
  }
  const record = value as Record<string, unknown>;
  return {
    aliases: parseAnnotationMap(record.aliases, "alias", MAX_ALIAS_LENGTH),
    comments: parseAnnotationMap(record.comments, "comment", MAX_COMMENT_LENGTH),
  };
}

export function parseProject(text: string): AxiomProjectV1 {
  let decoded: unknown;
  try {
    decoded = JSON.parse(text);
  } catch (error) {
    throw new Error("Project file is not valid JSON.", { cause: error });
  }

  if (!decoded || typeof decoded !== "object" || Array.isArray(decoded)) {
    throw new Error("Project file root is invalid.");
  }
  const project = decoded as Record<string, unknown>;
  if (project.schema !== "axiomre-project" || project.version !== 1) {
    throw new Error("Unsupported AxiomRE project schema or version.");
  }

  const target = project.target;
  const navigation = project.navigation;
  if (!target || typeof target !== "object" || Array.isArray(target)) {
    throw new Error("Project target is missing or invalid.");
  }
  if (!navigation || typeof navigation !== "object" || Array.isArray(navigation)) {
    throw new Error("Project navigation state is missing or invalid.");
  }

  const targetRecord = target as Record<string, unknown>;
  const navigationRecord = navigation as Record<string, unknown>;
  if (typeof targetRecord.path !== "string" || targetRecord.path.length === 0) {
    throw new Error("Project target path is invalid.");
  }
  if (typeof targetRecord.sha256 !== "string" || !SHA256.test(targetRecord.sha256)) {
    throw new Error("Project target SHA-256 is invalid.");
  }
  const selectedProcedure = parseSelectedProcedure(navigationRecord.selectedProcedure);
  const annotations = project.annotations === undefined
    ? { aliases: {}, comments: {} }
    : parseAnnotations(project.annotations);

  return {
    schema: "axiomre-project",
    version: 1,
    target: {
      path: targetRecord.path,
      sha256: targetRecord.sha256,
    },
    navigation: { selectedProcedure },
    annotations,
  };
}

export function verifyProjectTarget(project: AxiomProjectV1, report: BinaryReport): void {
  if (report.sha256 !== project.target.sha256) {
    throw new Error(
      `Project target hash mismatch. Expected ${project.target.sha256}, observed ${report.sha256}.`,
    );
  }
}
