import { existsSync } from "node:fs";
import { readFile, stat, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
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
} from "@hexscry/core";
import { defaultReaEntrypoint, ReaMcpSession, resolveReaEnvironment } from "@hexscry/provider-rea";

let currentBinaryPath: string | null = null;
let currentBinaryReport: BinaryReport | null = null;
let reaSession: Promise<ReaMcpSession> | null = null;
let deepAnalysisController: AbortController | null = null;
let bootstrapError: string | null = null;
const demoAutoDeep = process.env.HEXSCRY_DEMO_DEEP === "1";

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

interface BootstrapState {
  report: BinaryReport | null;
  autoDeep: boolean;
  error: string | null;
}

const MAX_PROJECT_FILE_BYTES = 4 * 1024 * 1024;

function requireIpcString(value: unknown, label: string, maxLength = 512): string {
  if (typeof value !== "string" || value.length === 0 || value.length > maxLength) {
    throw new Error(`${label} must be a non-empty string no longer than ${maxLength} characters.`);
  }
  return value;
}

function requireByteReadLength(value: unknown): number {
  if (value === undefined) return 256;
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1 || value > 4096) {
    throw new Error("Byte window length must be an integer between 1 and 4096.");
  }
  return value;
}

async function readProjectText(path: string): Promise<string> {
  const info = await stat(path);
  if (!info.isFile()) throw new Error("HexScry project is not a regular file.");
  if (info.size > MAX_PROJECT_FILE_BYTES) {
    throw new Error("HexScry project exceeds the 4 MiB safety limit.");
  }
  return readFile(path, "utf8");
}

function getReaSession(target: string): Promise<ReaMcpSession> {
  if (target !== currentBinaryPath) throw new Error("Target changed.");
  if (reaSession) return reaSession;
  const pending = (async () => {
    const session = new ReaMcpSession({ environment: await resolveReaEnvironment(process.env) });
    try {
      await session.openBinary(target);
      return session;
    } catch (error) {
      await session.close();
      throw error;
    }
  })();
  reaSession = pending;
  void pending.catch(() => { if (reaSession === pending) reaSession = null; });
  return pending;
}

function retireSession(): void {
  const previous = reaSession;
  reaSession = null;
  if (previous) void previous.then((session) => session.close(), () => {}).catch((error) => console.error("REA session cleanup failed", error));
}

async function loadDemoTargetFromEnvironment(): Promise<void> {
  const configured = process.env.HEXSCRY_DEMO_TARGET?.trim();
  if (!configured) return;

  const target = resolve(configured);
  try {
    const report = await inspectBinary(target);
    currentBinaryPath = target;
    currentBinaryReport = report;
    bootstrapError = null;
  } catch (reason) {
    currentBinaryPath = null;
    currentBinaryReport = null;
    bootstrapError = `Demo target could not be opened: ${reason instanceof Error ? reason.message : String(reason)}`;
  }
}

async function probeToolchain(): Promise<ToolStatus> {
  const environment = await resolveReaEnvironment(process.env);
  const ghidraPath = environment.GHIDRA_INSTALL_DIR;
  const jadxPath = environment.REA_JADX_MCP_JAR;

  let reaAvailable = false;
  let reaVersion: string | undefined;
  try {
    const reaEntrypoint = defaultReaEntrypoint(environment);
    reaAvailable = existsSync(reaEntrypoint);
    if (reaAvailable) {
      try {
        const packageJson = JSON.parse(await readFile(join(dirname(dirname(reaEntrypoint)), "package.json"), "utf8")) as { version?: unknown };
        if (typeof packageJson.version === "string" && packageJson.version.trim()) {
          reaVersion = packageJson.version.trim();
        }
      } catch {
        // The executable entrypoint is sufficient to report installation; version is optional metadata.
      }
    }
  } catch {
    // Status remains unavailable; UI can still analyze with owned parsers.
  }

  return {
    rea: { available: reaAvailable, ...(reaVersion ? { version: reaVersion } : {}) },
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

async function captureDemoWhenReady(mainWindow: BrowserWindow): Promise<void> {
  const configuredPath = process.env.HEXSCRY_DEMO_CAPTURE?.trim();
  if (!configuredPath) return;

  const capturePath = resolve(configuredPath);
  const deadline = Date.now() + 120_000;
  while (!mainWindow.isDestroyed() && Date.now() < deadline) {
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 1_000));
    const rawState = await mainWindow.webContents.executeJavaScript(
      `JSON.stringify({hasEntry: document.querySelector('.procedure-row.selected .procedure-name')?.textContent === 'entry' && document.querySelector('.function-heading h3')?.textContent === 'entry' && Boolean(document.querySelector('.function-body pre')?.textContent?.trim()), analyzing: document.body.innerText.includes('Analyzing with Ghidra'), deepError: document.body.innerText.includes('Deep analysis:')})`,
    );
    const state = JSON.parse(rawState) as { hasEntry: boolean; analyzing: boolean; deepError: boolean };
    if (state.deepError) {
      console.error("[demo-capture] Deep analysis failed before the demo reached a stable state.");
      break;
    }
    if (state.hasEntry && !state.analyzing) {
      // Documentation captures should be stable across development machines and remote
      // desktop resolutions. This resize is only active when HEXSCRY_DEMO_CAPTURE is set.
      mainWindow.setContentSize(1424, 836, false);
      await new Promise((resolveDelay) => setTimeout(resolveDelay, 250));
      const image = await mainWindow.webContents.capturePage();
      await writeFile(capturePath, image.toPNG());
      console.log(`[demo-capture] ${capturePath}`);
      if (process.env.HEXSCRY_DEMO_EXIT_AFTER_CAPTURE === "1") app.quit();
      return;
    }
  }

  if (!mainWindow.isDestroyed()) {
    console.error("[demo-capture] Timed out waiting for a stable deep-analysis demo state.");
  }
  if (process.env.HEXSCRY_DEMO_EXIT_AFTER_CAPTURE === "1") app.quit();
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
      preload: join(__dirname, "../preload/index.cjs"),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false,
    },
  });

  mainWindow.once("ready-to-show", () => mainWindow.show());
  mainWindow.webContents.once("did-finish-load", () => {
    if (!mainWindow.isVisible()) mainWindow.show();
  });

  // The preload bridge is privileged. Never let renderer-controlled links or scripts
  // navigate this BrowserWindow to a different document or open a child window that
  // could inherit an unexpected trust context.
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  mainWindow.webContents.on("will-attach-webview", (event) => event.preventDefault());

  const lockRendererNavigation = (): void => {
    mainWindow.webContents.on("will-navigate", (event) => event.preventDefault());
  };

  if (!app.isPackaged) {
    mainWindow.webContents.on("did-fail-load", (_event, errorCode, errorDescription, validatedURL) => {
      console.error(`[renderer-load] ${errorCode} ${errorDescription} ${validatedURL}`);
    });
    mainWindow.webContents.on("render-process-gone", (_event, details) => {
      console.error(`[renderer-gone] ${details.reason} exit=${details.exitCode}`);
    });
  }

  const load = !app.isPackaged && process.env.ELECTRON_RENDERER_URL
    ? mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL)
    : mainWindow.loadFile(join(__dirname, "../renderer/index.html"));
  void load.then(() => {
    lockRendererNavigation();
    void captureDemoWhenReady(mainWindow);
  });
}

app.whenReady().then(async () => {
  await loadDemoTargetFromEnvironment();
  electronApp.setAppUserModelId("org.hexscry.workbench");

  app.on("browser-window-created", (_, window) => {
    optimizer.watchWindowShortcuts(window);
  });

  ipcMain.handle("analysis:bootstrap", (): BootstrapState => ({
    report: currentBinaryReport,
    autoDeep: Boolean(currentBinaryReport && demoAutoDeep),
    error: bootstrapError,
  }));

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

    // Parse successfully before mutating target state. A rejected/invalid file must not
    // leave the main process pointing at a path that disagrees with the renderer report.
    const nextReport = await inspectBinary(nextPath);

    deepAnalysisController?.abort(new Error("Target changed."));
    deepAnalysisController = null;
    // An explicit open is also a refresh. Close even when the path is identical so a
    // binary replaced in-place cannot inherit a stale provider analysis session.
    retireSession();
    currentBinaryPath = nextPath;
    currentBinaryReport = nextReport;
    return nextReport;
  });

  ipcMain.handle("project:save", async (_event, selectedProcedure: string | null, annotations: AnalystAnnotations): Promise<string | null> => {
    if (!currentBinaryReport) throw new Error("Open a binary before saving a project.");
    const project = createProject(currentBinaryReport, selectedProcedure, annotations);
    const selected = await dialog.showSaveDialog({
      title: "Save HexScry project",
      defaultPath: `${currentBinaryReport.fileName}.hexscry`,
      filters: [{ name: "HexScry project", extensions: ["hexscry"] }],
    });
    if (selected.canceled || !selected.filePath) return null;
    await writeFile(selected.filePath, `${JSON.stringify(project, null, 2)}\n`, "utf8");
    return selected.filePath;
  });

  ipcMain.handle("project:open", async (): Promise<{ report: BinaryReport; selectedProcedure: string | null; annotations: AnalystAnnotations } | null> => {
    const selected = await dialog.showOpenDialog({
      title: "Open HexScry project",
      properties: ["openFile"],
      filters: [{ name: "HexScry project", extensions: ["hexscry"] }],
    });
    if (selected.canceled || !selected.filePaths[0]) return null;

    const project = parseProject(await readProjectText(selected.filePaths[0]));
    const report = await inspectBinary(project.target.path);
    verifyProjectTarget(project, report);

    deepAnalysisController?.abort(new Error("Project changed."));
    deepAnalysisController = null;
    // Opening a project is an explicit target refresh too. Even an identical path may
    // have been replaced since the current provider session imported it.
    retireSession();
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
      const session = await getReaSession(target);
      const procedures = await session.listProcedures(controller.signal);
      if (currentBinaryPath !== target) throw new Error("Target changed during deep analysis.");
      return procedures;
    } finally {
      if (deepAnalysisController === controller) deepAnalysisController = null;
    }
  });

  ipcMain.handle("analysis:function", async (_event, procedure: unknown): Promise<FunctionDossier> => {
    if (!currentBinaryPath) throw new Error("Open a binary before analyzing a function.");
    const procedureId = requireIpcString(procedure, "Procedure identifier");

    deepAnalysisController?.abort(new Error("Superseded by a function analysis request."));
    const controller = new AbortController();
    deepAnalysisController = controller;
    const target = currentBinaryPath;

    try {
      const session = await getReaSession(target);
      const dossier = await session.analyzeFunction(procedureId, controller.signal);
      if (currentBinaryPath !== target) throw new Error("Target changed during function analysis.");
      return dossier;
    } finally {
      if (deepAnalysisController === controller) deepAnalysisController = null;
    }
  });

  ipcMain.handle("analysis:instruction", async (_event, address: unknown): Promise<InstructionInspection> => {
    if (!currentBinaryPath) throw new Error("Open a binary before inspecting an instruction.");
    const inspectedAddress = requireIpcString(address, "Instruction address", 256);
    const target = currentBinaryPath;
    const session = await getReaSession(target);
    const inspection = await session.inspectInstruction(inspectedAddress);
    if (currentBinaryPath !== target) throw new Error("Target changed during instruction inspection.");
    return inspection;
  });

  ipcMain.handle("analysis:resolve-address", async (_event, address: unknown): Promise<ProcedureResolution> => {
    if (!currentBinaryPath) throw new Error("Open a binary before resolving an address.");
    const resolvedAddress = requireIpcString(address, "Address", 256);
    const target = currentBinaryPath;
    const session = await getReaSession(target);
    const resolution = await session.resolveContainingProcedure(resolvedAddress);
    if (currentBinaryPath !== target) throw new Error("Target changed during address resolution.");
    return resolution;
  });

  ipcMain.handle("analysis:hex-window", async (_event, address: unknown, length: unknown): Promise<HexWindowResult> => {
    if (!currentBinaryPath || !currentBinaryReport) throw new Error("Open a binary before reading bytes.");
    const byteAddress = requireIpcString(address, "Byte-window address", 256);
    const byteLength = requireByteReadLength(length);
    const target = currentBinaryPath;
    const report = currentBinaryReport;
    const file = await readBinaryWindowAtAddress(report, byteAddress, byteLength);
    if (currentBinaryReport !== report) throw new Error("Target changed during byte read.");

    let memory: MemoryByteWindow | null = null;
    let memoryError: string | null = null;
    try {
      const session = await getReaSession(target);
      memory = await session.readBytes(byteAddress, byteLength);
    } catch (reason) {
      memoryError = reason instanceof Error ? reason.message : String(reason);
    }

    if (currentBinaryReport !== report) throw new Error("Target changed during byte read.");
    return { address: byteAddress, file, memory, memoryError };
  });

  ipcMain.handle("analysis:cancel-deep", () => {
    deepAnalysisController?.abort(new Error("Cancelled by user."));
    retireSession();
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
  retireSession();
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
