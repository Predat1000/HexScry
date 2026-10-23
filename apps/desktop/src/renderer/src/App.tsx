import { useEffect, useMemo, useState } from "react";
import type { AnalystAnnotations, BinaryReport, FunctionDossier, InstructionInspection, ProcedureSummary, ReferenceEdge } from "@hexscry/core";
import type { HexWindowResult, ToolStatus } from "../../preload/index";

function hex(value: number): string {
  return `0x${value.toString(16).toUpperCase()}`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 ** 2).toFixed(2)} MiB`;
}

function StatusPill({ name, ok, detail }: { name: string; ok: boolean; detail?: string | undefined }) {
  return (
    <div className={`status-pill ${ok ? "ok" : "off"}`} title={detail}>
      <span className="dot" />
      <strong>{name}</strong>
      <span>{ok ? "ready" : "not detected"}</span>
    </div>
  );
}

function ReferenceGroup({
  title,
  edges,
  direction,
  onNavigate,
}: {
  title: string;
  edges: ReferenceEdge[];
  direction: "incoming" | "outgoing";
  onNavigate: (procedure: ProcedureSummary) => void;
}) {
  return (
    <section className="xref-group">
      <header><strong>{title}</strong><span>{edges.length}</span></header>
      {edges.length === 0 && <p className="muted">No references reported.</p>}
      {edges.map((edge, index) => {
        const related = direction === "incoming" ? edge.sourceProcedure : edge.targetProcedure;
        return (
          <div className="xref-row" key={`${direction}-${edge.sourceAddress}-${edge.targetAddress}-${index}`}>
            <div className="xref-endpoints">
              <code>{edge.sourceAddress}</code><span>→</span><code>{edge.targetAddress}</code>
            </div>
            <div className="xref-kind">
              <strong>{edge.type ?? "unclassified"}</strong>
              <span>{edge.tags.length ? edge.tags.join(" · ") : edge.limitation ?? "no classification flags"}</span>
            </div>
            {related && !related.external ? (
              <button onClick={() => onNavigate(related)} title={related.address}>{related.name}</button>
            ) : (
              <span className="xref-related">{related?.name ?? "no resolved procedure"}</span>
            )}
          </div>
        );
      })}
    </section>
  );
}

function numericAddress(address: string): bigint | null {
  const marker = address.lastIndexOf(":0x");
  const numeric = marker >= 0 ? address.slice(marker + 1) : address;
  try {
    return BigInt(numeric);
  } catch {
    return null;
  }
}

function addAddress(address: string, offset: number): string {
  const marker = address.lastIndexOf(":0x");
  const prefix = marker >= 0 ? `${address.slice(0, marker + 1)}` : "";
  const numeric = numericAddress(address);
  return numeric === null
    ? (offset === 0 ? address : `${address}+${offset.toString(16)}`)
    : `${prefix}0x${(numeric + BigInt(offset)).toString(16)}`;
}

function HexComparison({ window, report }: { window: HexWindowResult; report: BinaryReport }) {
  const rows = Array.from({ length: Math.ceil(window.file.bytes.length / 16) }, (_, row) => row * 16);
  const relocationByOffset = new Map<number, BinaryReport["relocations"][number]>();
  const startAddress = numericAddress(window.address);
  if (startAddress !== null) {
    const imageBase = BigInt(report.imageBase);
    const endAddress = startAddress + BigInt(window.file.bytes.length);
    for (const relocation of report.relocations) {
      if (!relocation.widthBytes || relocation.widthBytes < 1) continue;
      const relocationStart = imageBase + BigInt(relocation.rva);
      const relocationEnd = relocationStart + BigInt(relocation.widthBytes);
      if (relocationStart >= endAddress || relocationEnd <= startAddress) continue;
      const coveredStart = relocationStart > startAddress ? relocationStart : startAddress;
      const coveredEnd = relocationEnd < endAddress ? relocationEnd : endAddress;
      for (let address = coveredStart; address < coveredEnd; address += 1n) {
        relocationByOffset.set(Number(address - startAddress), relocation);
      }
    }
  }
  const relocationCount = new Set([...relocationByOffset.values()].map((entry) => `${entry.rva}:${entry.type}`)).size;

  const byteClass = (changed: boolean, relocated: boolean): string | undefined => {
    const classes = [changed ? "changed" : "", relocated ? "relocation" : ""].filter(Boolean);
    return classes.length ? classes.join(" ") : undefined;
  };
  const relocationTitle = (offset: number): string | undefined => {
    const relocation = relocationByOffset.get(offset);
    return relocation
      ? `${relocation.typeName} base relocation · RVA ${hex(relocation.rva)} · ${relocation.widthBytes ?? "unknown"} B`
      : undefined;
  };

  return (
    <div className="hex-view">
      <div className="hex-legend">
        <span>File @ {hex(window.file.fileOffset)}</span>
        <span>{window.memory ? `Ghidra memory · ${window.memory.complete ? "complete" : "partial"}` : `Memory unavailable${window.memoryError ? ` · ${window.memoryError}` : ""}`}</span>
      </div>
      {relocationCount > 0 && (
        <div className="hex-relocation-summary">PE base relocation coverage: {relocationCount} fixup{relocationCount === 1 ? "" : "s"} in this window. Outlined bytes may legitimately differ after loading.</div>
      )}
      <div className="hex-header"><span>Address</span><span>Original file bytes</span><span>Loaded memory bytes</span><span>ASCII</span></div>
      {rows.map((offset) => {
        const fileBytes = window.file.bytes.slice(offset, offset + 16);
        const memoryBytes = window.memory?.bytes.slice(offset, offset + 16) ?? [];
        const ascii = fileBytes.map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".")).join("");
        return (
          <div className="hex-row" key={offset}>
            <code>{addAddress(window.address, offset)}</code>
            <code className="hex-cells">{fileBytes.map((byte, index) => {
              const byteOffset = offset + index;
              const changed = memoryBytes[index] !== undefined && memoryBytes[index] !== byte;
              const relocated = relocationByOffset.has(byteOffset);
              return <span className={byteClass(changed, relocated)} title={relocationTitle(byteOffset)} key={index}>{byte.toString(16).padStart(2, "0")}</span>;
            })}</code>
            <code className="hex-cells">{fileBytes.map((_, index) => {
              const byteOffset = offset + index;
              const changed = memoryBytes[index] !== undefined && memoryBytes[index] !== fileBytes[index];
              const relocated = relocationByOffset.has(byteOffset);
              return <span className={byteClass(changed, relocated)} title={relocationTitle(byteOffset)} key={index}>{memoryBytes[index] === undefined ? "--" : memoryBytes[index].toString(16).padStart(2, "0")}</span>;
            })}</code>
            <code className="hex-ascii">{ascii}</code>
          </div>
        );
      })}
    </div>
  );
}

function InstructionView({ instruction }: { instruction: InstructionInspection }) {
  const incoming = instruction.incomingReferences;
  return (
    <div className="instruction-view">
      <div className="instruction-summary">
        <span className={`instruction-status ${instruction.status}`}>{instruction.status}</span>
        <code>{instruction.address}</code>
        <span>{instruction.architecture} · {instruction.mode}</span>
        <span>{instruction.length === null ? "length unknown" : `${instruction.length} byte${instruction.length === 1 ? "" : "s"}`}</span>
      </div>

      <div className="instruction-disassembly">
        <code className="instruction-bytes">{instruction.bytesHex ?? "bytes unavailable"}</code>
        <strong>{instruction.rawDisassembly ?? instruction.mnemonic ?? "No decoded instruction"}</strong>
      </div>

      <div className="instruction-facts">
        <div><span>Procedure</span><code>{instruction.procedure ?? "none"}</code></div>
        <div><span>Flow</span><code>{instruction.flow.kind}{instruction.flow.conditional ? " · conditional" : ""}{instruction.flow.computed ? " · computed" : ""}</code></div>
        <div><span>Operands</span><code>{instruction.operands.length ? instruction.operands.join(", ") : "none"}</code></div>
        <div><span>Destinations</span><code>{instruction.flow.directDestinations.length ? instruction.flow.directDestinations.join(", ") : "none"}</code></div>
      </div>

      <div className="instruction-references">
        <section>
          <header><strong>Outgoing references</strong><span>{instruction.outgoingReferences.length}</span></header>
          {instruction.outgoingReferences.length === 0 && <p className="muted">No outgoing references reported.</p>}
          {instruction.outgoingReferences.map((reference, index) => (
            <div className="instruction-ref" key={`out-${reference.targetAddress}-${index}`}>
              <code>{reference.targetAddress}</code>
              <span>{reference.type}</span>
              <small>{reference.tags.join(" · ") || `operand ${reference.operandIndex}`}</small>
            </div>
          ))}
        </section>
        <section>
          <header><strong>Incoming references</strong><span>{incoming === null ? "?" : incoming.length}</span></header>
          {incoming === null && <p className="muted">Provider did not expose incoming-reference coverage.</p>}
          {incoming?.length === 0 && <p className="muted">No incoming references reported.</p>}
          {incoming?.map((reference, index) => (
            <div className="instruction-ref" key={`in-${reference.sourceAddress ?? "unknown"}-${index}`}>
              <code>{reference.sourceAddress ?? "unknown source"}</code>
              <span>{reference.type}</span>
              <small>{reference.tags.join(" · ") || `operand ${reference.operandIndex}`}</small>
            </div>
          ))}
        </section>
      </div>

      {instruction.limitations.length > 0 && (
        <details className="dossier-limitations" open={instruction.status !== "decoded"}>
          <summary>Instruction limitations ({instruction.limitations.length})</summary>
          {instruction.limitations.map((limitation) => <p key={limitation}>{limitation}</p>)}
        </details>
      )}
    </div>
  );
}

export default function App() {
  const [report, setReport] = useState<BinaryReport | null>(null);
  const [annotations, setAnnotations] = useState<AnalystAnnotations>({ aliases: {}, comments: {} });
  const [toolchain, setToolchain] = useState<ToolStatus | null>(null);
  const [busy, setBusy] = useState(false);
  const [navBusy, setNavBusy] = useState(false);
  const [navQuery, setNavQuery] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const [peSymbolView, setPeSymbolView] = useState<"imports" | "exports" | "relocations" | "debug" | "tls">("imports");
  const [peSymbolFilter, setPeSymbolFilter] = useState("");
  const [procedures, setProcedures] = useState<ProcedureSummary[]>([]);
  const [procedureFilter, setProcedureFilter] = useState("");
  const [deepBusy, setDeepBusy] = useState(false);
  const [deepError, setDeepError] = useState<string | null>(null);
  const [selectedProcedure, setSelectedProcedure] = useState<string | null>(null);
  const [dossier, setDossier] = useState<FunctionDossier | null>(null);
  const [instruction, setInstruction] = useState<InstructionInspection | null>(null);
  const [hexWindow, setHexWindow] = useState<HexWindowResult | null>(null);
  const [functionBusy, setFunctionBusy] = useState(false);
  const [codeView, setCodeView] = useState<"pseudocode" | "assembly" | "references" | "hex" | "instruction">("pseudocode");

  useEffect(() => {
    let active = true;
    void Promise.all([window.hexscry.toolchain(), window.hexscry.bootstrap()])
      .then(([nextToolchain, bootstrap]) => {
        if (!active) return;
        setToolchain(nextToolchain);
        if (bootstrap.error) setError(bootstrap.error);
        if (bootstrap.report) {
          applyReport(bootstrap.report);
          if (bootstrap.autoDeep) void deepAnalyze(true);
        }
      })
      .catch((reason) => {
        if (active) setError(reason instanceof Error ? reason.message : String(reason));
      });
    return () => {
      active = false;
    };
  }, []);

  const visibleStrings = useMemo(() => {
    if (!report) return [];
    const query = filter.trim().toLowerCase();
    return query
      ? report.strings.filter((entry) => entry.value.toLowerCase().includes(query))
      : report.strings;
  }, [report, filter]);

  const visibleImports = useMemo(() => {
    if (!report) return [];
    const query = peSymbolFilter.trim().toLowerCase();
    return query
      ? report.imports.filter((entry) =>
          entry.library.toLowerCase().includes(query) ||
          entry.name?.toLowerCase().includes(query) ||
          (entry.ordinal !== null && `#${entry.ordinal}`.includes(query)),
        )
      : report.imports;
  }, [report, peSymbolFilter]);

  const visibleExports = useMemo(() => {
    if (!report) return [];
    const query = peSymbolFilter.trim().toLowerCase();
    return query
      ? report.exports.filter((entry) =>
          entry.name?.toLowerCase().includes(query) ||
          `#${entry.ordinal}`.includes(query) ||
          entry.forwarder?.toLowerCase().includes(query),
        )
      : report.exports;
  }, [report, peSymbolFilter]);

  const visibleRelocations = useMemo(() => {
    if (!report) return [];
    const query = peSymbolFilter.trim().toLowerCase();
    return query
      ? report.relocations.filter((entry) =>
          hex(entry.rva).toLowerCase().includes(query) ||
          entry.typeName.toLowerCase().includes(query) ||
          String(entry.type).includes(query),
        )
      : report.relocations;
  }, [report, peSymbolFilter]);

  const visibleDebug = useMemo(() => {
    if (!report) return [];
    const query = peSymbolFilter.trim().toLowerCase();
    return query
      ? report.debug.filter((entry) =>
          entry.typeName.toLowerCase().includes(query) ||
          String(entry.type).includes(query) ||
          entry.codeView?.pdbPath.toLowerCase().includes(query) ||
          entry.codeView?.guid?.toLowerCase().includes(query) ||
          entry.codeView?.signature.toLowerCase().includes(query),
        )
      : report.debug;
  }, [report, peSymbolFilter]);

  const visibleTlsCallbacks = useMemo(() => {
    if (!report?.tls) return [];
    const query = peSymbolFilter.trim().toLowerCase();
    return query
      ? report.tls.callbacks.filter((entry) =>
          entry.address.toLowerCase().includes(query) ||
          (entry.rva !== null && hex(entry.rva).toLowerCase().includes(query)),
        )
      : report.tls.callbacks;
  }, [report, peSymbolFilter]);

  const visibleProcedures = useMemo(() => {
    const query = procedureFilter.trim().toLowerCase();
    const filtered = query
      ? procedures.filter((procedure) =>
          procedure.name.toLowerCase().includes(query) || procedure.address.toLowerCase().includes(query),
        )
      : procedures;
    return [...filtered].sort((left, right) => Number(Boolean(left.external)) - Number(Boolean(right.external)));
  }, [procedures, procedureFilter]);

  function applyReport(
    next: BinaryReport,
    restoredProcedure: string | null = null,
    restoredAnnotations: AnalystAnnotations = { aliases: {}, comments: {} },
  ) {
    setReport(next);
    setAnnotations(restoredAnnotations);
    setNavQuery("");
    setFilter("");
    setPeSymbolView("imports");
    setPeSymbolFilter("");
    setProcedures([]);
    setProcedureFilter("");
    setDeepError(null);
    setSelectedProcedure(restoredProcedure);
    setDossier(null);
    setInstruction(null);
    setHexWindow(null);
    setFunctionBusy(false);
    setCodeView("pseudocode");
  }

  async function openBinary() {
    setBusy(true);
    setError(null);
    try {
      const next = await window.hexscry.openBinary();
      if (next) applyReport(next);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function openProject() {
    setBusy(true);
    setError(null);
    try {
      const project = await window.hexscry.openProject();
      if (project) applyReport(project.report, project.selectedProcedure, project.annotations);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setBusy(false);
    }
  }

  async function saveProject() {
    setError(null);
    try {
      await window.hexscry.saveProject(selectedProcedure, annotations);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    }
  }

  async function navigateAddress(address: string) {
    const exactInstruction = await window.hexscry.inspectInstruction(address);
    const resolution = await window.hexscry.resolveAddress(address);

    if (resolution.procedure && !resolution.procedure.external) {
      await selectProcedure(resolution.procedure);
    } else {
      setSelectedProcedure(null);
      setDossier(null);
      setHexWindow(null);
      setFunctionBusy(false);
    }

    setInstruction(exactInstruction);
    try {
      setHexWindow(await window.hexscry.hexWindow(exactInstruction.address, 256));
    } catch {
      setHexWindow(null);
    }
    setCodeView("instruction");
  }

  async function navigateEvidenceAddress(address: string) {
    if (!report || procedures.length === 0 || navBusy) return;
    setNavQuery(address);
    setError(null);
    setNavBusy(true);
    try {
      await navigateAddress(address);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setNavBusy(false);
    }
  }

  async function navigateQuery() {
    const query = navQuery.trim();
    if (!query || !report) return;
    setError(null);
    setNavBusy(true);
    try {
      const addressLike = /^(?:(?:0[xX])?[0-9a-fA-F]+|(?:[A-Za-z0-9._~-]|%[0-9a-fA-F]{2})+:0[xX][0-9a-fA-F]+)$/u.test(query);
      if (addressLike) {
        await navigateAddress(query);
        return;
      }

      const lowered = query.toLowerCase();
      const procedure = procedures.find((item) => !item.external && item.name.toLowerCase() === lowered)
        ?? procedures.find((item) => !item.external && item.name.toLowerCase().includes(lowered));
      if (procedure) {
        await selectProcedure(procedure);
        return;
      }

      if (report.imports.some((item) =>
        item.library.toLowerCase().includes(lowered) || item.name?.toLowerCase().includes(lowered),
      )) {
        setPeSymbolView("imports");
        setPeSymbolFilter(query);
        return;
      }

      if (report.exports.some((item) =>
        item.name?.toLowerCase().includes(lowered) || item.forwarder?.toLowerCase().includes(lowered),
      )) {
        setPeSymbolView("exports");
        setPeSymbolFilter(query);
        return;
      }

      if (report.strings.some((item) => item.value.toLowerCase().includes(lowered))) {
        setFilter(query);
        return;
      }
      throw new Error(`No local procedure, PE import/export or foundation string matches “${query}”.`);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setNavBusy(false);
    }
  }

  async function deepAnalyze(autoSelectFirst = false) {
    setDeepBusy(true);
    setDeepError(null);
    try {
      const nextProcedures = await window.hexscry.deepProcedures();
      setProcedures(nextProcedures);
      const restored = selectedProcedure
        ? nextProcedures.find((procedure) => procedure.address === selectedProcedure && !procedure.external)
        : autoSelectFirst
          ? nextProcedures.find((procedure) => !procedure.external)
          : undefined;
      if (restored) await selectProcedure(restored);
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      if (!/cancel|aborted/i.test(message)) setDeepError(message);
    } finally {
      setDeepBusy(false);
    }
  }

  async function cancelDeepAnalysis() {
    await window.hexscry.cancelDeepAnalysis();
    setDeepBusy(false);
    setFunctionBusy(false);
  }

  function updateAnnotation(kind: "aliases" | "comments", address: string, value: string) {
    setAnnotations((previous) => {
      const next = { ...previous[kind] };
      if (value.length === 0) delete next[address];
      else next[address] = value;
      return kind === "aliases"
        ? { aliases: next, comments: previous.comments }
        : { aliases: previous.aliases, comments: next };
    });
  }

  async function selectProcedure(procedure: ProcedureSummary) {
    if (procedure.external) return;
    setSelectedProcedure(procedure.address);
    setFunctionBusy(true);
    setDeepError(null);
    setDossier(null);
    setInstruction(null);
    setHexWindow(null);
    try {
      const nextDossier = await window.hexscry.analyzeFunction(procedure.address);
      setDossier(nextDossier);
      try {
        setHexWindow(await window.hexscry.hexWindow(procedure.address, 256));
      } catch {
        setHexWindow(null);
      }
      setCodeView("pseudocode");
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason);
      if (!/cancel|aborted|superseded/i.test(message)) setDeepError(message);
    } finally {
      setFunctionBusy(false);
    }
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand">
          <span className="mark">AX</span>
          <div>
            <h1>HexScry</h1>
            <p>evidence-first reverse engineering workbench</p>
          </div>
        </div>
        <div className="topbar-actions">
          <button className="ghost toolbar-button" onClick={openProject} disabled={busy}>Open project</button>
          <button className="ghost toolbar-button" onClick={saveProject} disabled={!report || busy}>Save project</button>
          <div className="nav-box">
            <input
              value={navQuery}
              onChange={(event) => setNavQuery(event.target.value)}
              onKeyDown={(event) => { if (event.key === "Enter") void navigateQuery(); }}
              placeholder="Address / function / PE symbol / string"
              disabled={!report || busy || navBusy}
            />
            <button className="ghost toolbar-button" onClick={() => void navigateQuery()} disabled={!report || !navQuery.trim() || navBusy}>{navBusy ? "…" : "Go"}</button>
          </div>
          <button className="primary" onClick={openBinary} disabled={busy}>
            {busy ? "Opening…" : "Open binary"}
          </button>
        </div>
      </header>

      <section className="toolchain">
        <StatusPill name="REA" ok={Boolean(toolchain?.rea.available)} detail={toolchain?.rea.version} />
        <StatusPill name="Ghidra" ok={Boolean(toolchain?.ghidra.available)} detail={toolchain?.ghidra.path} />
        <StatusPill name="JADX" ok={Boolean(toolchain?.jadx.available)} detail={toolchain?.jadx.path} />
        <span className="foundation-label">foundation parser: PE32 / PE32+</span>
      </section>

      {error && <div className="error-banner">{error}</div>}
      {deepError && <div className="error-banner">Deep analysis: {deepError}</div>}

      {!report ? (
        <main className="empty-state">
          <div className="empty-card">
            <span className="eyebrow">PRE-ALPHA · VERTICAL SLICE 01</span>
            <h2>Start with evidence, not guesses.</h2>
            <p>
              Open a Windows executable or DLL. HexScry will inspect its PE structure using
              its own bounded parser before any deep-analysis provider is involved.
            </p>
            <button className="primary large" onClick={openBinary} disabled={busy}>
              Open your first binary
            </button>
          </div>
        </main>
      ) : (
        <main className="workspace">
          <aside className="sidebar panel">
            <span className="eyebrow">TARGET</span>
            <h2>{report.fileName}</h2>
            <dl>
              <dt>Format</dt><dd>{report.format}</dd>
              <dt>Architecture</dt><dd>{report.architecture}</dd>
              <dt>Size</dt><dd>{formatBytes(report.fileSize)}</dd>
              <dt>Image base</dt><dd>{report.imageBase}</dd>
              <dt>Entry RVA</dt><dd><button className="evidence-link" onClick={() => void navigateEvidenceAddress(addAddress(report.imageBase, report.entryPointRva))} disabled={procedures.length === 0 || navBusy} title={procedures.length === 0 ? "Run deep analysis before navigating PE evidence." : `Inspect entry point ${addAddress(report.imageBase, report.entryPointRva)}`}>{hex(report.entryPointRva)}</button></dd>
            </dl>
            <div className="hash">
              <span>SHA-256</span>
              <code>{report.sha256}</code>
            </div>
            <div className="deep-control">
              <span>DEEP ANALYSIS</span>
              <p>Ghidra analyzes once; the live REA session is then reused for fast navigation.</p>
              <div className="deep-actions">
                <button className="secondary" onClick={() => void deepAnalyze(false)} disabled={deepBusy || !toolchain?.ghidra.available}>
                  {deepBusy ? "Analyzing with Ghidra…" : procedures.length ? "Refresh procedures" : "Analyze with Ghidra"}
                </button>
                {deepBusy && <button className="ghost" onClick={cancelDeepAnalysis}>Cancel</button>}
              </div>
            </div>
            <div className="limitations">
              <span>Known limitations</span>
              {report.limitations.map((item) => <p key={item}>{item}</p>)}
            </div>
          </aside>

          <section className="content-grid">
            <div className="foundation-grid">
              <div className="panel sections-panel">
                <div className="panel-heading">
                  <div><span className="eyebrow">STRUCTURE</span><h3>Sections</h3></div>
                  <span>{report.sections.length}</span>
                </div>
                <div className="table">
                  <div className="row header">
                    <span>Name</span><span>RVA</span><span>Virtual</span><span>Raw size</span>
                  </div>
                  {report.sections.map((section, index) => (
                    <div className="row" key={`${section.name}-${index}`}>
                      <code>{section.name || "(unnamed)"}</code>
                      <code>{hex(section.virtualAddress)}</code>
                      <span>{formatBytes(section.virtualSize)}</span>
                      <span>{formatBytes(section.rawSize)}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="panel imports-panel">
                <div className="panel-heading symbol-heading">
                  <div>
                    <span className="eyebrow">PE EVIDENCE</span>
                    <div className="symbol-tabs">
                      <button className={peSymbolView === "imports" ? "active" : ""} onClick={() => { setPeSymbolView("imports"); setPeSymbolFilter(""); }}>Imports <span>{report.imports.length}</span></button>
                      <button className={peSymbolView === "exports" ? "active" : ""} onClick={() => { setPeSymbolView("exports"); setPeSymbolFilter(""); }}>Exports <span>{report.exports.length}</span></button>
                      <button className={peSymbolView === "relocations" ? "active" : ""} onClick={() => { setPeSymbolView("relocations"); setPeSymbolFilter(""); }}>Relocs <span>{report.relocations.length}</span></button>
                      <button className={peSymbolView === "debug" ? "active" : ""} onClick={() => { setPeSymbolView("debug"); setPeSymbolFilter(""); }}>Debug <span>{report.debug.length}</span></button>
                      <button className={peSymbolView === "tls" ? "active" : ""} onClick={() => { setPeSymbolView("tls"); setPeSymbolFilter(""); }}>TLS <span>{report.tls?.callbacks.length ?? 0}</span></button>
                    </div>
                  </div>
                  <input
                    value={peSymbolFilter}
                    onChange={(event) => setPeSymbolFilter(event.target.value)}
                    placeholder={peSymbolView === "imports" ? "Filter DLL / API…" : peSymbolView === "exports" ? "Filter export / forwarder…" : peSymbolView === "relocations" ? "Filter RVA / relocation type…" : peSymbolView === "debug" ? "Filter PDB / GUID / debug type…" : "Filter TLS callback address / RVA…"}
                    disabled={peSymbolView === "imports" ? report.imports.length === 0 : peSymbolView === "exports" ? report.exports.length === 0 : peSymbolView === "relocations" ? report.relocations.length === 0 : peSymbolView === "debug" ? report.debug.length === 0 : !report.tls || report.tls.callbacks.length === 0}
                  />
                </div>
                <div className="imports-list">
                  {peSymbolView === "imports" && (
                    <>
                      {visibleImports.map((entry, index) => (
                        <div className="import-row" key={`${entry.library}-${entry.name ?? entry.ordinal}-${entry.iatRva}-${index}`}>
                          <span className="import-library">{entry.library}</span>
                          <code>{entry.name ?? `ordinal #${entry.ordinal}`}</code>
                          <code>IAT {hex(entry.iatRva)}</code>
                          <span>{entry.hint === null ? "ordinal" : `hint ${entry.hint}`}</span>
                        </div>
                      ))}
                      {visibleImports.length === 0 && <p className="muted">{report.imports.length === 0 ? "No PE imports declared." : "No matching imports."}</p>}
                    </>
                  )}
                  {peSymbolView === "exports" && (
                    <>
                      {visibleExports.map((entry, index) => (
                        <div className="export-row" key={`${entry.ordinal}-${entry.rva}-${index}`}>
                          <code>#{entry.ordinal}</code>
                          <span>{entry.name ?? "(ordinal only)"}</span>
                          <code>RVA {hex(entry.rva)}</code>
                          <span className={entry.forwarder ? "forwarder" : "local-export"}>{entry.forwarder ?? "local"}</span>
                        </div>
                      ))}
                      {visibleExports.length === 0 && <p className="muted">{report.exports.length === 0 ? "No PE exports declared." : "No matching exports."}</p>}
                    </>
                  )}
                  {peSymbolView === "relocations" && (
                    <>
                      {visibleRelocations.map((entry, index) => (
                        <div className="export-row" key={`${entry.rva}-${entry.type}-${index}`}>
                          <code>RVA {hex(entry.rva)}</code>
                          <span>{entry.typeName}</span>
                          <code>type {entry.type}</code>
                          <span>{entry.widthBytes === null ? "width unknown" : `${entry.widthBytes} B fixup`}</span>
                        </div>
                      ))}
                      {visibleRelocations.length === 0 && <p className="muted">{report.relocations.length === 0 ? "No PE base relocations declared." : "No matching relocations."}</p>}
                    </>
                  )}
                  {peSymbolView === "debug" && (
                    <>
                      {visibleDebug.map((entry, index) => (
                        <div className="debug-row" key={`${entry.type}-${entry.dataRva}-${entry.dataFileOffset ?? "none"}-${index}`}>
                          <code>{entry.typeName}</code>
                          <span title={entry.codeView?.pdbPath}>{entry.codeView?.pdbPath ?? "(no CodeView identity)"}</span>
                          <code title={entry.codeView?.guid ?? undefined}>{entry.codeView?.guid ?? (entry.dataRva ? `RVA ${hex(entry.dataRva)}` : entry.dataFileOffset !== null ? `file ${hex(entry.dataFileOffset)}` : "no payload")}</code>
                          <span>{entry.codeView ? `${entry.codeView.signature} · age ${entry.codeView.age}` : `${entry.sizeOfData} B · v${entry.majorVersion}.${entry.minorVersion}`}</span>
                        </div>
                      ))}
                      {visibleDebug.length === 0 && <p className="muted">{report.debug.length === 0 ? "No PE debug-directory entries declared." : "No matching debug entries."}</p>}
                    </>
                  )}
                  {peSymbolView === "tls" && (
                    report.tls ? (
                      <>
                        <div className="tls-summary">
                          <div><span>Callbacks table</span><code>{report.tls.callbacksAddress}</code></div>
                          <div><span>Index</span><code>{report.tls.indexAddress}</code></div>
                          <div><span>Raw data</span><code>{report.tls.rawDataStartAddress} → {report.tls.rawDataEndAddress}</code></div>
                          <div><span>Zero fill / characteristics</span><code>{report.tls.sizeOfZeroFill} B · {hex(report.tls.characteristics)}</code></div>
                        </div>
                        {visibleTlsCallbacks.map((entry, index) => (
                          <div className="tls-row" key={`${entry.address}-${index}`}>
                            <code>callback {index}</code>
                            <button className="evidence-link tls-address" onClick={() => void navigateEvidenceAddress(entry.address)} disabled={procedures.length === 0 || navBusy || entry.rva === null} title={entry.rva === null ? "Callback address is outside the image RVA range." : procedures.length === 0 ? "Run deep analysis before navigating TLS callbacks." : `Inspect TLS callback ${entry.address}`}>{entry.address}</button>
                            <span>{entry.rva === null ? "outside image RVA" : `RVA ${hex(entry.rva)}`}</span>
                          </div>
                        ))}
                        {report.tls.callbacks.length === 0 && <p className="muted">TLS directory declared, but no callbacks are listed.</p>}
                        {report.tls.callbacks.length > 0 && visibleTlsCallbacks.length === 0 && <p className="muted">No matching TLS callbacks.</p>}
                      </>
                    ) : <p className="muted">No PE TLS directory declared.</p>
                  )}
                </div>
              </div>
            </div>

            <div className="panel strings-panel">
              <div className="panel-heading">
                <div><span className="eyebrow">EVIDENCE</span><h3>Printable strings</h3></div>
                <input
                  value={filter}
                  onChange={(event) => setFilter(event.target.value)}
                  placeholder="Filter strings…"
                />
              </div>
              <div className="strings-list">
                {visibleStrings.map((entry) => (
                  <div className="string-row" key={`${entry.offset}-${entry.value}`}>
                    <code>{hex(entry.offset)}</code>
                    <span>{entry.value}</span>
                  </div>
                ))}
                {visibleStrings.length === 0 && <p className="muted">No matching strings.</p>}
              </div>
            </div>

            <div className="deep-grid">
              <div className="panel procedures-panel">
                <div className="panel-heading">
                  <div><span className="eyebrow">GHIDRA · LIVE SESSION</span><h3>Procedures</h3></div>
                  <div className="heading-tools">
                    <span>{procedures.length || "—"}</span>
                    <input
                      value={procedureFilter}
                      onChange={(event) => setProcedureFilter(event.target.value)}
                      placeholder="Filter procedures…"
                      disabled={procedures.length === 0}
                    />
                  </div>
                </div>
                <div className="procedure-list">
                  {visibleProcedures.map((procedure) => (
                    <button
                      className={`procedure-row ${selectedProcedure === procedure.address ? "selected" : ""}`}
                      key={`${procedure.address}-${procedure.name}`}
                      onClick={() => void selectProcedure(procedure)}
                      disabled={Boolean(procedure.external)}
                      title={procedure.external ? "External functions have no local body to decompile." : `Analyze ${procedure.name}`}
                    >
                      <code>{procedure.address}</code>
                      <span className="procedure-name">{procedure.name}</span>
                      <span className={`kind-badge ${procedure.external ? "external" : "local"}`}>
                        {procedure.external ? "external" : procedure.thunk ? "thunk" : "local"}
                      </span>
                    </button>
                  ))}
                  {procedures.length === 0 && !deepBusy && (
                    <p className="muted">Run deep analysis to populate Ghidra's function inventory.</p>
                  )}
                  {deepBusy && <p className="muted">Ghidra is completing static analysis. This first pass is intentionally asynchronous.</p>}
                </div>
              </div>

              <div className="panel function-panel">
                <div className="panel-heading function-heading">
                  <div>
                    <span className="eyebrow">{instruction && !dossier ? "ADDRESS INSPECTOR" : "FUNCTION DOSSIER"}</span>
                    <h3>{dossier ? (annotations.aliases[dossier.procedure.address] ?? dossier.procedure.name) : instruction ? instruction.address : (functionBusy ? "Analyzing…" : "Select a function or address")}</h3>
                  </div>
                  <div className="code-tabs">
                    <button className={codeView === "pseudocode" ? "active" : ""} onClick={() => setCodeView("pseudocode")} disabled={!dossier}>Pseudocode</button>
                    <button className={codeView === "assembly" ? "active" : ""} onClick={() => setCodeView("assembly")} disabled={!dossier}>Assembly</button>
                    <button className={codeView === "instruction" ? "active" : ""} onClick={() => setCodeView("instruction")} disabled={!instruction}>Instruction</button>
                    <button className={codeView === "references" ? "active" : ""} onClick={() => setCodeView("references")} disabled={!dossier}>Xrefs</button>
                    <button className={codeView === "hex" ? "active" : ""} onClick={() => setCodeView("hex")} disabled={!hexWindow}>Hex</button>
                  </div>
                </div>
                <div className="function-body">
                  {functionBusy && <p className="muted">Decompiling the selected function through the existing Ghidra session…</p>}
                  {!functionBusy && !dossier && !instruction && <p className="muted">Choose a local function or enter an address to inspect evidence.</p>}
                  {(dossier || instruction) && (
                    <>
                      {dossier && (
                        <>
                          <div className="function-meta">
                            <code>{dossier.procedure.address}</code>
                            <span>{dossier.signature ?? "signature unavailable"}</span>
                          </div>
                          <div className="analyst-notes">
                            <label>
                              <span>Analyst alias</span>
                              <input
                                maxLength={128}
                                value={annotations.aliases[dossier.procedure.address] ?? ""}
                                onChange={(event) => updateAnnotation("aliases", dossier.procedure.address, event.target.value)}
                                placeholder={dossier.procedure.name}
                              />
                            </label>
                            <label>
                              <span>Comment</span>
                              <textarea
                                maxLength={4000}
                                value={annotations.comments[dossier.procedure.address] ?? ""}
                                onChange={(event) => updateAnnotation("comments", dossier.procedure.address, event.target.value)}
                                placeholder="Analyst-owned note; saved only in the .hexscry project"
                              />
                            </label>
                          </div>
                          {(dossier.callers.length > 0 || dossier.callees.length > 0) && (
                            <div className="function-relations">
                              <div>
                                <span>Callers</span>
                                <div className="relation-chips">
                                  {dossier.callers.length === 0 && <em>none resolved</em>}
                                  {dossier.callers.map((item) => (
                                    <button key={`caller-${item.address}`} disabled={Boolean(item.external)} onClick={() => void selectProcedure(item)} title={item.address}>{item.name}</button>
                                  ))}
                                </div>
                              </div>
                              <div>
                                <span>Callees</span>
                                <div className="relation-chips">
                                  {dossier.callees.length === 0 && <em>none resolved</em>}
                                  {dossier.callees.map((item) => (
                                    <button key={`callee-${item.address}`} disabled={Boolean(item.external)} onClick={() => void selectProcedure(item)} title={item.address}>{item.name}</button>
                                  ))}
                                </div>
                              </div>
                            </div>
                          )}
                        </>
                      )}

                      {codeView === "instruction" ? (
                        instruction ? <InstructionView instruction={instruction} /> : <p className="muted">No exact instruction inspection is loaded.</p>
                      ) : codeView === "references" ? (
                        dossier ? (
                          <div className="xref-view">
                            <ReferenceGroup title="Incoming references" edges={dossier.incomingReferences} direction="incoming" onNavigate={(procedure) => void selectProcedure(procedure)} />
                            <ReferenceGroup title="Outgoing references" edges={dossier.outgoingReferences} direction="outgoing" onNavigate={(procedure) => void selectProcedure(procedure)} />
                          </div>
                        ) : <p className="muted">Function references require a local procedure dossier.</p>
                      ) : codeView === "hex" ? (
                        hexWindow ? <HexComparison window={hexWindow} report={report} /> : <p className="muted">No file-backed hex window is available for this address.</p>
                      ) : dossier ? (
                        <pre>{codeView === "pseudocode" ? (dossier.pseudocode || "// Pseudocode unavailable") : (dossier.assembly.join("\n") || "; Assembly unavailable")}</pre>
                      ) : (
                        <p className="muted">Pseudocode and procedure assembly require a local procedure.</p>
                      )}

                      {dossier && codeView !== "instruction" && dossier.limitations.length > 0 && (
                        <details className="dossier-limitations">
                          <summary>Provider limitations ({dossier.limitations.length})</summary>
                          {dossier.limitations.map((limitation) => <p key={limitation}>{limitation}</p>)}
                        </details>
                      )}
                    </>
                  )}
                </div>
              </div>
            </div>
          </section>
        </main>
      )}
    </div>
  );
}
