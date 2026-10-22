import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { readFile, writeFile } from "node:fs/promises";
import { promisify } from "node:util";
import { join } from "node:path";
import { app, BrowserWindow, dialog, ipcMain } from "electron";
import { electronApp, optimizer } from "@electron-toolkit/utils";
import {
  createProject,
  inspectBinary,
  parseProject,
  readBinaryWindowAtAddress,
  verifyProjectTarget,
  type AnalystAnnotations,
  type BinaryReport,
  type BinaryWindow,
  type FunctionDossier,
  type InstructionInspection,
  type MemoryByteWindow,
  type ProcedureResolution,
  type ProcedureSummary,
} from "@axiomre/core";
import { defaultReaEntrypoint, ReaMcpSession, resolveReaEnvironment } from "@axiomre/provider-rea";

const execFileAsync = promisify(execFile);

let currentBinaryPath: string | null = null;
let currentBinaryReport: BinaryReport | null = null;
let reaSession: ReaMcpSession | null = null;
let deepAnalysisController: AbortController | null = null;

interface ToolStatus {
  rea: { available: boolean; version?: string };
  ghidra: { available: boolean; path?: string };
  jadx: { available: boolean; path?: string };
}

interface HexWindowResult {
  address: string;
  file: BinaryWindow;
  memory: MemoryByteWindow | null;
  memoryError: string | null;
}

async function getReaSession(): Promise<ReaMcpSession> {
  if (reaSession) return reaSession;

  reaSession = new ReaMcpSession({ environment: await resolveReaEnvironment(process.env) });
  return reaSession;
}

async function probeToolchain(): Promise<ToolStatus> {
  const environment = await resolveReaEnvironment(process.env);
  const ghidraPath = environment.GHIDRA_INSTALL_DIR;
  const jadxPath = environment.REA_JADX_MCP_JAR;

  let reaVersion: string | undefined;
  try {
    const reaEntrypoint = defaultReaEntrypoint(process.env);
    const { stdout } = await execFileAsync(process.execPath, [reaEntrypoint, "--version"], {
      windowsHide: true,
      timeout: 10_000,
    });
    reaVersion = stdout.trim() || "installed";
  } catch {
    // Status remains unavailable; UI can still analyze with owned parsers.
  }

  return {
    rea: { available: Boolean(reaVersion), ...(reaVersion ? { version: reaVersion } : {}) },
    ghidra: {
      available: Boolean(ghidraPath && existsSync(ghidraPath)),
      ...(ghidraPath ? { path: ghidraPath } : {}),
    },
    jadx: {
      available: Boolean(jadxPath && existsSync(jadxPath)),
      ...(jadxPath ? { path: jadxPath } : {}),
    },
  };
}

function createWindow(): void {
  const mainWindow = new BrowserWindow({
    width: 1440,
    height: 900,
    minWidth: 1000,
    minHeight: 650,
    show: false,
    backgroundColor: "#0f1115",
    webPreferences: {
      preload: join(__dirname, "../preload/index.mjs"),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.once("ready-to-show", () => mainWindow.show());

  if (!app.isPackaged && process.env.ELECTRON_RENDERER_URL) {
    void mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL);
  } else {
    void mainWindow.loadFile(join(__dirname, "../renderer/index.html"));
  }
}

app.whenReady().then(() => {
  electronApp.setAppUserModelId("org.axiomre.workbench");

  app.on("browser-window-created", (_, window) => {
    optimizer.watchWindowShortcuts(window);
  });

  ipcMain.handle("analysis:open-binary", async () => {
    const selected = await dialog.showOpenDialog({
      title: "Open binary",
      properties: ["openFile"],
      filters: [
        { name: "Windows binaries", extensions: ["exe", "dll", "sys"] },
        { name: "All files", extensions: ["*"] },
      ],
    });
    if (selected.canceled || !selected.filePaths[0]) return null;
    const nextPath = selected.filePaths[0];
    deepAnalysisController?.abort(new Error("Target changed."));
    deepAnalysisController = null;
    if (reaSession && currentBinaryPath !== nextPath) {
      await reaSession.close();
      reaSession = null;
    }
    currentBinaryPath = nextPath;
    currentBinaryReport = await inspectBinary(currentBinaryPath);
    return currentBinaryReport;
  });

  ipcMain.handle("project:save", async (_event, selectedProcedure: string | null, annotations: AnalystAnnotations): Promise<string | null> => {
    if (!currentBinaryReport) throw new Error("Open a binary before saving a project.");
    const project = createProject(currentBinaryReport, selectedProcedure, annotations);
    const selected = await dialog.showSaveDialog({
      title: "Save AxiomRE project",
      defaultPath: `${currentBinaryReport.fileName}.axiomre`,
      filters: [{ name: "AxiomRE project", extensions: ["axiomre"] }],
    });
    if (selected.canceled || !selected.filePath) return null;
    await writeFile(selected.filePath, `${JSON.stringify(project, null, 2)}\n`, "utf8");
    return selected.filePath;
  });

  ipcMain.handle("project:open", async (): Promise<{ report: BinaryReport; selectedProcedure: string | null; annotations: AnalystAnnotations } | null> => {
    const selected = await dialog.showOpenDialog({
      title: "Open AxiomRE project",
      properties: ["openFile"],
      filters: [{ name: "AxiomRE project", extensions: ["axiomre"] }],
    });
    if (selected.canceled || !selected.filePaths[0]) return null;

    const project = parseProject(await readFile(selected.filePaths[0], "utf8"));
    const report = await inspectBinary(project.target.path);
    verifyProjectTarget(project, report);

    deepAnalysisController?.abort(new Error("Project changed."));
    deepAnalysisController = null;
    if (reaSession && currentBinaryPath !== report.path) {
      await reaSession.close();
      reaSession = null;
    }
    currentBinaryPath = report.path;
    currentBinaryReport = report;
    return {
      report,
      selectedProcedure: project.navigation.selectedProcedure,
      annotations: project.annotations,
    };
  });

  ipcMain.handle("analysis:deep-procedures", async (): Promise<ProcedureSummary[]> => {
    if (!currentBinaryPath) throw new Error("Open a binary before starting deep analysis.");

    deepAnalysisController?.abort(new Error("Superseded by a new analysis request."));
    const controller = new AbortController();
    deepAnalysisController = controller;
    const target = currentBinaryPath;

    try {
      const session = await getReaSession();
      await session.openBinary(target);
      const procedures = await session.listProcedures(controller.signal);
      if (currentBinaryPath !== target) throw new Error("Target changed during deep analysis.");
      return procedures;
    } finally {
      if (deepAnalysisController === controller) deepAnalysisController = null;
    }
  });

  ipcMain.handle("analysis:function", async (_event, procedure: string): Promise<FunctionDossier> => {
    if (!currentBinaryPath) throw new Error("Open a binary before analyzing a function.");
    if (!procedure) throw new Error("Select a procedure first.");

    deepAnalysisController?.abort(new Error("Superseded by a function analysis request."));
    const controller = new AbortController();
    deepAnalysisController = controller;
    const target = currentBinaryPath;

    try {
      const session = await getReaSession();
      await session.openBinary(target);
      const dossier = await session.analyzeFunction(procedure, controller.signal);
      if (currentBinaryPath !== target) throw new Error("Target changed during function analysis.");
      return dossier;
    } finally {
      if (deepAnalysisController === controller) deepAnalysisController = null;
    }
  });

  ipcMain.handle("analysis:instruction", async (_event, address: string): Promise<InstructionInspection> => {
    if (!currentBinaryPath) throw new Error("Open a binary before inspecting an instruction.");
    const target = currentBinaryPath;
    const session = await getReaSession();
    await session.openBinary(target);
    const inspection = await session.inspectInstruction(address);
    if (currentBinaryPath !== target) throw new Error("Target changed during instruction inspection.");
    return inspection;
  });

  ipcMain.handle("analysis:resolve-address", async (_event, address: string): Promise<ProcedureResolution> => {
    if (!currentBinaryPath) throw new Error("Open a binary before resolving an address.");
    const target = currentBinaryPath;
    const session = await getReaSession();
    await session.openBinary(target);
    const resolution = await session.resolveContainingProcedure(address);
    if (currentBinaryPath !== target) throw new Error("Target changed during address resolution.");
    return resolution;
  });

  ipcMain.handle("analysis:hex-window", async (_event, address: string, length = 256): Promise<HexWindowResult> => {
    if (!currentBinaryPath || !currentBinaryReport) throw new Error("Open a binary before reading bytes.");
    if (!address) throw new Error("Select an address before reading bytes.");
    const target = currentBinaryPath;
    const report = currentBinaryReport;
    const file = await readBinaryWindowAtAddress(report, address, length);

    let memory: MemoryByteWindow | null = null;
    let memoryError: string | null = null;
    try {
      const session = await getReaSession();
      await session.openBinary(target);
      memory = await session.readBytes(address, length);
    } catch (reason) {
      memoryError = reason instanceof Error ? reason.message : String(reason);
    }

    if (currentBinaryPath !== target) throw new Error("Target changed during byte read.");
    return { address, file, memory, memoryError };
  });

  ipcMain.handle("analysis:cancel-deep", () => {
    deepAnalysisController?.abort(new Error("Cancelled by user."));
    deepAnalysisController = null;
    return true;
  });

  ipcMain.handle("system:toolchain", () => probeToolchain());

  createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("before-quit", () => {
  deepAnalysisController?.abort(new Error("Application is closing."));
  deepAnalysisController = null;
  void reaSession?.close();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
