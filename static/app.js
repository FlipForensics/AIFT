(() => {
  "use strict";

  const STEP_IDS = ["step-evidence", "step-artifacts", "step-parsing", "step-analysis", "step-results"];
  const RECOMMENDED_PRESET_EXCLUDED_ARTIFACTS = new Set(["mft", "usnjrnl", "evtx", "defender.evtx"]);
  const MODE_PARSE_AND_AI = "parse_and_ai";
  const MODE_PARSE_ONLY = "parse_only";
  const RECOMMENDED_PROFILE = "recommended";
  const DROP_HELP = "Drag and drop a forensic image here (.E01/.E02... or .zip)";
  const CONFIDENCE_TOKEN_PATTERN = /\b(CRITICAL|HIGH|MEDIUM|LOW)\b/gi;
  const CONFIDENCE_CLASS_MAP = {
    CRITICAL: "confidence-critical",
    HIGH: "confidence-high",
    MEDIUM: "confidence-medium",
    LOW: "confidence-low",
  };
  const st = {
    step: 1,
    caseId: "",
    caseName: "",
    artifacts: [],
    artifactNames: {},
    selected: [],
    selectedAi: [],
    profiles: [],
    pendingFiles: [],
    settings: null,
    settingsTab: "basic",
    parse: { run: false, done: false, fail: false, es: null, retry: null, seq: -1, rows: {}, status: {}, timer: null, started: 0 },
    analysis: { run: false, done: false, fail: false, es: null, retry: null, seq: -1, order: [], byKey: {}, summary: "", model: {}, timer: null, started: 0 },
  };

  const el = {};
  const q = (id) => document.getElementById(id);

  document.addEventListener("DOMContentLoaded", init);

  function init() {
    cache();
    if (!el.wizard) return;
    addMessages();
    addTimers();
    setupWizard();
    setupEvidence();
    setupArtifacts();
    setupAnalysis();
    setupResults();
    setupSettings();
    resetCaseUi();
    showStep(1);
    loadSettings().catch((e) => setMsg(el.settingsMsg, `Unable to load settings: ${e.message}`, "error"));
    loadArtifactProfiles().catch((e) => setMsg(el.artifactsMsg, `Unable to load profiles: ${e.message}`, "error"));
  }

  function cache() {
    el.wizard = q("wizard");
    el.steps = Array.from(document.querySelectorAll(".wizard-step"));
    el.indicators = Array.from(document.querySelectorAll(".step-indicator li"));

    el.evidenceForm = q("evidence-form");
    el.caseName = q("case-name");
    el.modeUpload = q("mode-upload");
    el.modePath = q("mode-path");
    el.uploadPanel = q("upload-mode-panel");
    el.pathPanel = q("path-mode-panel");
    el.drop = q("dropzone");
    el.dropHelp = q("dropzone-help");
    el.file = q("evidence-file");
    el.path = q("evidence-path");
    el.submitEvidence = q("submit-evidence");
    el.evidenceProgWrap = q("evidence-intake-progress");
    el.evidenceProg = q("evidence-progress");
    el.summaryCard = q("evidence-summary-card");
    el.sumHost = q("summary-hostname");
    el.sumOs = q("summary-os");
    el.sumDomain = q("summary-domain");
    el.sumIps = q("summary-ips");
    el.sumSha = q("summary-sha256");

    el.artifactsForm = q("artifacts-form");
    el.profileSelect = q("artifact-profile-select");
    el.profileLoadBtn = q("artifact-profile-load");
    el.profileName = q("artifact-profile-name");
    el.profileSaveBtn = q("artifact-profile-save");
    el.quickBtn = q("preset-quick-triage");
    el.clearBtn = q("preset-clear-all");
    el.parseBtn = q("parse-selected");
    el.analysisDateStart = q("analysis-date-start");
    el.analysisDateEnd = q("analysis-date-end");

    el.parseProgress = q("parse-overall-progress");
    el.parseErr = q("parse-error-message");
    el.parseRows = q("parse-progress-rows");

    el.analysisForm = q("analysis-form");
    el.prompt = q("investigation-context");
    el.runBtn = q("run-analysis");
    el.providerName = q("provider-name");
    el.settingsLink = q("provider-settings-link");
    el.analysisList = q("analysis-results-list");

    el.summaryOut = q("executive-summary-content");
    el.findings = q("artifact-findings");
    el.downloadReport = q("download-report");
    el.downloadCsvs = q("download-csvs");
    el.newAnalysis = q("new-analysis");

    el.settingsBtn = q("settings-button");
    el.settingsPanel = q("settings-panel");
    el.settingsForm = q("settings-form");
    el.setProvider = q("setting-provider");
    el.setApiKey = q("setting-api-key");
    el.setLocalUrl = q("setting-local-url");
    el.setModel = q("setting-model");
    el.setPort = q("setting-port");
    el.setSize = q("setting-size-threshold");
    el.setCsvOutputDir = q("setting-csv-output-dir");
    el.setCsvOutputHelp = q("setting-csv-output-help");
    el.saveSettings = q("save-settings");
    el.setApiLabel = document.querySelector('label[for="setting-api-key"]');
    el.setLocalLabel = document.querySelector('label[for="setting-local-url"]');
    el.setApiRow = el.setApiKey ? el.setApiKey.closest(".form-row") : null;
    el.setLocalRow = el.setLocalUrl ? el.setLocalUrl.closest(".form-row") : null;
    el.settingsTabButtons = Array.from(document.querySelectorAll("[data-settings-tab]"));
    el.settingsTabPanels = Array.from(document.querySelectorAll("[data-settings-panel]"));

    el.setAiMaxTokens = q("setting-ai-max-tokens");
    el.setConnectionMaxTokens = q("setting-connection-max-tokens");
    el.setDateBufferDays = q("setting-date-buffer-days");
    el.setCitationSpotCheckLimit = q("setting-citation-spot-check-limit");
    el.setArtifactDeduplicationEnabled = q("setting-artifact-deduplication-enabled");

    el.setAttachClaude = q("setting-attach-claude");
    el.setAttachOpenAI = q("setting-attach-openai");
    el.setAttachKimi = q("setting-attach-kimi");
    el.setAttachLocal = q("setting-attach-local");
  }

  function setCaseId(rawCaseId) {
    const caseId = String(rawCaseId || "").trim();
    st.caseId = caseId;
    if (el.wizard) {
      if (caseId) el.wizard.dataset.caseId = caseId;
      else delete el.wizard.dataset.caseId;
    }
    return st.caseId;
  }

  function activeCaseId() {
    if (st.caseId) return st.caseId;
    const domCaseId = el.wizard ? String(el.wizard.dataset.caseId || "").trim() : "";
    if (domCaseId) return setCaseId(domCaseId);
    return "";
  }

  function addMessages() {
    el.evidenceMsg = ensureMsg(el.evidenceForm, "evidence-message");
    el.artifactsMsg = ensureMsg(el.artifactsForm, "artifacts-message");
    el.analysisMsg = ensureMsg(el.analysisForm, "analysis-message");
    el.resultsMsg = ensureMsg(q("step-results"), "results-message");
    el.settingsMsg = ensureMsg(el.settingsForm, "settings-message");
    if (el.parseErr) el.parseErr.hidden = true;
  }

  function ensureMsg(parent, id) {
    let node = q(id);
    if (!node) {
      node = document.createElement("p");
      node.id = id;
      node.hidden = true;
      node.setAttribute("role", "alert");
      parent.appendChild(node);
    }
    return node;
  }

  function setMsg(node, text, kind = "info") {
    if (!node) return;
    if (!text) return clearMsg(node);
    node.hidden = false;
    node.textContent = text;
    node.dataset.status = kind === "error" ? "failed" : kind === "success" ? "success" : "in-progress";
  }

  function clearMsg(node) {
    if (!node) return;
    node.hidden = true;
    node.textContent = "";
    delete node.dataset.status;
  }

  function addTimers() {
    el.parseElapsed = ensureTimer(q("step-parsing"), "parse-elapsed");
    el.analysisElapsed = ensureTimer(q("step-analysis"), "analysis-elapsed");
  }

  function ensureTimer(container, id) {
    let n = q(id);
    if (!n) {
      n = document.createElement("p");
      n.id = id;
      n.textContent = "Elapsed: 00:00";
      const h = container ? container.querySelector("h2") : null;
      if (container && h) container.insertBefore(n, h.nextSibling);
      else if (container) container.appendChild(n);
    }
    n.hidden = true;
    return n;
  }

  function setupWizard() {
    addNavButtons();
    el.indicators.forEach((i) => {
      i.addEventListener("click", () => {
        const target = i.dataset.stepTarget ? q(i.dataset.stepTarget) : null;
        const n = target ? Number(target.dataset.step || 1) : 1;
        if (canGo(n)) showStep(n);
        else blockedMsg(n);
      });
    });
  }

  function addNavButtons() {
    const total = STEP_IDS.length;
    el.steps.forEach((s) => {
      if (!s || s.querySelector(".wizard-nav")) return;
      const n = Number(s.dataset.step || 1);
      const wrap = document.createElement("div");
      wrap.className = "wizard-nav";
      if (n > 1) {
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = "Back";
        b.addEventListener("click", () => showStep(n - 1));
        wrap.appendChild(b);
      }
      if (n < total) {
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = "Next";
        b.dataset.nextStep = String(n + 1);
        const hint = document.createElement("p");
        hint.className = "wizard-nav-hint";
        hint.hidden = true;
        const hintId = `wizard-next-hint-${n}`;
        hint.id = hintId;
        b.dataset.reasonHint = hintId;
        b.setAttribute("aria-describedby", hintId);
        b.addEventListener("click", () => (canGo(n + 1) ? showStep(n + 1) : blockedMsg(n + 1)));
        wrap.appendChild(b);
        wrap.appendChild(hint);
      }
      s.appendChild(wrap);
    });
    updateNav();
  }

  function updateNav() {
    Array.from(document.querySelectorAll(".wizard-nav button[data-next-step]")).forEach((b) => {
      const nextStep = Number(b.dataset.nextStep || 1);
      const reason = navBlockReason(nextStep);
      const disabled = !!reason;
      b.disabled = disabled;
      if (disabled) b.title = reason;
      else b.removeAttribute("title");

      const hintId = String(b.dataset.reasonHint || "");
      const hint = hintId ? q(hintId) : null;
      if (!hint) return;
      if (!disabled) {
        hint.hidden = true;
        hint.textContent = "";
        return;
      }
      hint.hidden = false;
      hint.textContent = reason;
    });
  }

  function showStep(n) {
    const rawStep = Number(n);
    const normalizedStep = Number.isFinite(rawStep) ? Math.trunc(rawStep) : 1;
    st.step = Math.max(1, Math.min(STEP_IDS.length, normalizedStep));
    el.steps.forEach((s) => {
      const on = Number(s.dataset.step || 0) === st.step;
      s.hidden = !on;
      s.classList.toggle("is-active", on);
    });
    el.indicators.forEach((i) => {
      const t = i.dataset.stepTarget ? q(i.dataset.stepTarget) : null;
      const on = t ? Number(t.dataset.step || 0) === st.step : false;
      i.classList.toggle("is-active", on);
      if (on) i.setAttribute("aria-current", "step");
      else i.removeAttribute("aria-current");
    });
    updateNav();
  }

  function canGo(n) {
    return !navBlockReason(n);
  }

  function navBlockReason(n) {
    const rawStep = Number(n);
    if (!Number.isFinite(rawStep)) return "";
    const step = Math.trunc(rawStep);
    if (step <= 1) return "";
    if (step === 2 && !activeCaseId()) return "Submit evidence first.";
    if (step === 3 && st.selected.length === 0) return "Select artifacts and click Parse Selected first.";
    if (step === 4) {
      if (st.parse.done) return "";
      if (st.parse.run) return "Parsing is still running. Wait for completion.";
      if (st.parse.fail) return "Parsing failed. Resolve the error in Step 3 and parse again.";
      return "Parse selected artifacts first.";
    }
    if (step === 5) {
      if (st.analysis.done) return "";
      if (st.analysis.run) return "Analysis is still running. Wait for completion.";
      if (st.analysis.fail) return "Analysis failed. Resolve the error and run analysis again.";
      return "Run and finish analysis first.";
    }
    return "Complete the previous step first.";
  }

  function blockedMsg(n) {
    const reason = navBlockReason(n);
    if (!reason) return;
    if (n === 2) return setMsg(el.evidenceMsg, reason, "error");
    if (n === 3) return setMsg(el.artifactsMsg, reason, "error");
    if (n === 4) return setMsg(el.parseErr, reason, "error");
    if (n === 5) return setMsg(el.analysisMsg, reason, "error");
  }

  function setupEvidence() {
    if (!el.evidenceForm) return;
    if (el.modeUpload) el.modeUpload.addEventListener("change", syncMode);
    if (el.modePath) el.modePath.addEventListener("change", syncMode);
    if (el.file) {
      el.file.addEventListener("change", () => {
        const files = el.file.files ? Array.from(el.file.files) : [];
        setPendingFiles(files);
      });
    }
    initDropzone();
    el.evidenceForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await submitEvidence();
    });
    syncMode();
  }

  function syncMode() {
    const pathMode = !!(el.modePath && el.modePath.checked);
    if (el.uploadPanel) el.uploadPanel.hidden = pathMode;
    if (el.pathPanel) el.pathPanel.hidden = !pathMode;
  }

  function initDropzone() {
    if (!el.drop) return;
    const prevent = (e) => {
      e.preventDefault();
      e.stopPropagation();
    };
    ["dragenter", "dragover"].forEach((t) => el.drop.addEventListener(t, (e) => {
      prevent(e);
      el.drop.classList.add("is-dragover");
      el.drop.dataset.dragover = "true";
    }));
    ["dragleave", "dragend", "drop"].forEach((t) => el.drop.addEventListener(t, (e) => {
      prevent(e);
      el.drop.classList.remove("is-dragover");
      el.drop.dataset.dragover = "false";
    }));
    el.drop.addEventListener("drop", (e) => {
      const files = e.dataTransfer && e.dataTransfer.files ? e.dataTransfer.files : null;
      if (!files || !files.length) return;
      const dropped = Array.from(files);
      setPendingFiles(dropped);
      if (!el.file) return;
      try {
        const dt = new DataTransfer();
        dropped.forEach((file) => dt.items.add(file));
        el.file.files = dt.files;
      } catch (_err) {
        // fallback: use st.pendingFiles
      }
    });
  }

  function setPendingFiles(files) {
    st.pendingFiles = Array.isArray(files) ? files.filter(Boolean) : [];
    if (!el.dropHelp) return;
    if (!st.pendingFiles.length) {
      el.dropHelp.textContent = DROP_HELP;
      return;
    }
    if (st.pendingFiles.length === 1) {
      const file = st.pendingFiles[0];
      el.dropHelp.textContent = `${file.name}${Number.isFinite(file.size) ? ` (${fmtBytes(file.size)})` : ""}`;
      return;
    }
    const totalSize = st.pendingFiles.reduce((sum, file) => sum + (Number.isFinite(file.size) ? file.size : 0), 0);
    el.dropHelp.textContent = `${st.pendingFiles.length} files selected (${fmtBytes(totalSize)})`;
  }

  function selectedFiles() {
    if (el.file && el.file.files && el.file.files.length) return Array.from(el.file.files);
    return Array.from(st.pendingFiles || []);
  }

  function sanitizeEvidencePath(raw) {
    return String(raw || "").replace(/["\u201c\u201d]/g, "").trim();
  }

  async function submitEvidence() {
    clearMsg(el.evidenceMsg);
    clearMsg(el.artifactsMsg);
    clearMsg(el.parseErr);

    const uploadMode = !!(el.modeUpload && el.modeUpload.checked);
    const files = selectedFiles();
    const path = sanitizeEvidencePath(val(el.path));
    if (uploadMode && files.length === 0) return setMsg(el.evidenceMsg, "Choose one or more evidence files first.", "error");
    if (!uploadMode && !path) return setMsg(el.evidenceMsg, "Enter a local evidence path.", "error");

    if (!uploadMode && el.path && el.path.value !== path) el.path.value = path;

    setEvidenceBusy(true);
    const intakeProgress = createIntakeProgressTracker();
    try {
      const c = await apiJson("/api/cases", { method: "POST", json: { case_name: val(el.caseName) } });
      const caseId = String(c.case_id || "").trim();
      st.caseName = String(c.case_name || "");
      if (!caseId) throw new Error("Case ID missing from create response.");
      intakeProgress.setPhase("case-created");

      let ev;
      if (uploadMode) {
        const fd = new FormData();
        files.forEach((file, index) => {
          fd.append("evidence_file", file, file.name || `evidence_${index + 1}.bin`);
        });
        ev = await apiJson(`/api/cases/${encodeURIComponent(caseId)}/evidence`, { method: "POST", body: fd });
      } else {
        ev = await apiJson(`/api/cases/${encodeURIComponent(caseId)}/evidence`, { method: "POST", json: { path } });
      }
      intakeProgress.complete();
      setCaseId(caseId);
      updateCsvOutputHelp();
      applyEvidence(ev);
      setMsg(el.evidenceMsg, "Evidence intake complete.", "success");
      showStep(2);
    } catch (e) {
      setMsg(el.evidenceMsg, `Evidence intake failed: ${e.message}`, "error");
    } finally {
      intakeProgress.stop();
      setEvidenceBusy(false);
      updateNav();
    }
  }

  function createIntakeProgressTracker() {
    if (!el.evidenceProg) {
      return {
        setPhase: () => {},
        complete: () => {},
        stop: () => {},
      };
    }

    let cap = 30;
    let barTicker = 0;
    let msgTicker = 0;
    const startedAt = Date.now();

    const updateMessage = () => {
      const elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
      const minutes = String(Math.floor(elapsedSeconds / 60)).padStart(2, "0");
      const seconds = String(elapsedSeconds % 60).padStart(2, "0");
      setMsg(el.evidenceMsg, `Intake in progress... (${minutes}:${seconds})`, "info");
    };

    const tickProgress = () => {
      const current = num(el.evidenceProg.value, 0);
      if (current >= cap) return;
      const remaining = cap - current;
      const step = Math.max(0.15, Math.min(3, remaining / 10));
      el.evidenceProg.value = Math.min(cap, current + step);
    };

    el.evidenceProg.value = 2;
    updateMessage();
    barTicker = window.setInterval(tickProgress, 350);
    msgTicker = window.setInterval(updateMessage, 1000);

    return {
      setPhase: (phase) => {
        if (phase === "case-created") {
          cap = 94;
          if (el.evidenceProg.value < 28) el.evidenceProg.value = 28;
        }
      },
      complete: () => {
        cap = 100;
        el.evidenceProg.value = 100;
      },
      stop: () => {
        if (barTicker) {
          window.clearInterval(barTicker);
          barTicker = 0;
        }
        if (msgTicker) {
          window.clearInterval(msgTicker);
          msgTicker = 0;
        }
      },
    };
  }

  function setEvidenceBusy(on) {
    if (el.submitEvidence) el.submitEvidence.disabled = on;
    if (el.evidenceProgWrap) el.evidenceProgWrap.hidden = !on;
  }

  function applyEvidence(data) {
    st.artifacts = Array.isArray(data.available_artifacts) ? data.available_artifacts : [];
    st.artifactNames = {};
    st.artifacts.forEach((a) => {
      if (a && a.key) st.artifactNames[String(a.key)] = String(a.name || a.key);
    });

    resetParseState();
    resetAnalysisState();
    st.selected = [];
    st.selectedAi = [];

    renderSummary(data.metadata || {}, data.hashes || {});
    populateArtifacts(st.artifacts);
    renderParsePlaceholder();
    renderAnalysis();
    renderExecSummary();
    renderFindings();

    updateParseButton();
  }

  function renderSummary(m, h) {
    if (el.sumHost) el.sumHost.textContent = String(m.hostname || "-");
    if (el.sumOs) el.sumOs.textContent = String(m.os_version || "-");
    if (el.sumDomain) el.sumDomain.textContent = String(m.domain || "-");
    if (el.sumIps) el.sumIps.textContent = String(m.ips || "-");
    if (el.sumSha) el.sumSha.textContent = String(h.sha256 || "-");
    if (el.summaryCard) el.summaryCard.hidden = false;
  }

  function populateArtifacts(list) {
    clearDynamicArtifacts();
    const map = new Map();
    list.forEach((a) => a && a.key && map.set(String(a.key), a));

    const known = new Set();
    artifactBoxes().forEach((cb) => {
      const key = cb.dataset.artifactKey;
      if (!key) return;
      known.add(key);
      const info = map.get(key);
      const available = !!(info && info.available);
      cb.disabled = !available;
      cb.checked = false;
      const li = cb.closest("li");
      if (li) {
        li.dataset.available = String(available);
        li.classList.toggle("artifact-unavailable", !available);
        li.title = available ? "" : "Not found in this image";
      }
      if (info && info.name) setLabelText(cb, String(info.name));
      const modeSelect = ensureArtifactModeControl(cb, MODE_PARSE_AND_AI);
      if (modeSelect) modeSelect.value = MODE_PARSE_AND_AI;
      syncArtifactModeControl(cb, modeSelect);
    });

    const extra = list.filter((a) => a && a.key && !known.has(String(a.key)));
    if (extra.length && el.artifactsForm && el.parseBtn) {
      const fs = document.createElement("fieldset");
      fs.className = "artifact-category";
      fs.dataset.category = "additional";
      fs.id = "dynamic-artifact-category";
      const lg = document.createElement("legend");
      lg.textContent = "Additional";
      fs.appendChild(lg);
      const ul = document.createElement("ul");
      extra.forEach((a) => {
        const key = String(a.key || "");
        const avail = !!a.available;
        const name = String(a.name || key);
        st.artifactNames[key] = name;
        const li = document.createElement("li");
        li.dataset.available = String(avail);
        li.classList.toggle("artifact-unavailable", !avail);
        if (!avail) li.title = "Not found in this image";
        const label = document.createElement("label");
        const cb = document.createElement("input");
        cb.type = "checkbox";
        cb.dataset.artifactKey = key;
        cb.disabled = !avail;
        label.appendChild(cb);
        label.appendChild(document.createTextNode(` ${name}`));
        li.appendChild(label);
        ul.appendChild(li);
      });
      fs.appendChild(ul);
      el.artifactsForm.insertBefore(fs, el.parseBtn);
    }
    ensureArtifactModeControls();
    updateParseButton();
  }

  function clearDynamicArtifacts() {
    const d = q("dynamic-artifact-category");
    if (d) d.remove();
  }

  function setLabelText(cb, text) {
    const label = cb.closest("label");
    if (!label) return;
    const txt = Array.from(label.childNodes).find((n) => n.nodeType === Node.TEXT_NODE);
    if (txt) txt.textContent = ` ${text}`;
    else label.appendChild(document.createTextNode(` ${text}`));
  }

  function artifactBoxes() {
    return el.artifactsForm
      ? Array.from(el.artifactsForm.querySelectorAll("input[type='checkbox'][data-artifact-key]"))
      : [];
  }

  function artifactModeSelectForKey(artifactKey) {
    if (!el.artifactsForm) return null;
    const key = String(artifactKey || "");
    if (!key) return null;
    const selects = Array.from(el.artifactsForm.querySelectorAll("select.artifact-mode-select[data-artifact-key]"));
    return selects.find((select) => String(select.dataset.artifactKey || "") === key) || null;
  }

  function artifactModeValue(rawMode) {
    return String(rawMode || "").trim().toLowerCase() === MODE_PARSE_ONLY ? MODE_PARSE_ONLY : MODE_PARSE_AND_AI;
  }

  function syncArtifactModeControl(cb, modeSelect = null) {
    if (!(cb instanceof HTMLInputElement)) return;
    const select = modeSelect || artifactModeSelectForKey(cb.dataset.artifactKey || "");
    if (!select) return;
    select.disabled = cb.disabled || !cb.checked;
    if (!select.disabled) select.value = artifactModeValue(select.value);
  }

  function ensureArtifactModeControl(cb, preferredMode = MODE_PARSE_AND_AI) {
    if (!(cb instanceof HTMLInputElement)) return null;
    const key = String(cb.dataset.artifactKey || "").trim();
    if (!key) return null;
    const li = cb.closest("li");
    if (!li) return null;

    let select = artifactModeSelectForKey(key);
    if (!select) {
      select = document.createElement("select");
      select.className = "artifact-mode-select";
      select.dataset.artifactKey = key;

      const parseAiOption = document.createElement("option");
      parseAiOption.value = MODE_PARSE_AND_AI;
      parseAiOption.textContent = "Parse and use in AI";
      select.appendChild(parseAiOption);

      const parseOnlyOption = document.createElement("option");
      parseOnlyOption.value = MODE_PARSE_ONLY;
      parseOnlyOption.textContent = "Parse only";
      select.appendChild(parseOnlyOption);

      li.appendChild(select);
    }

    select.value = artifactModeValue(preferredMode);
    syncArtifactModeControl(cb, select);
    return select;
  }

  function ensureArtifactModeControls() {
    artifactBoxes().forEach((cb) => {
      const select = ensureArtifactModeControl(cb, MODE_PARSE_AND_AI);
      syncArtifactModeControl(cb, select);
    });
  }

  function selectedArtifactOptions() {
    return artifactBoxes()
      .filter((cb) => cb.checked && !cb.disabled && cb.dataset.artifactKey)
      .map((cb) => {
        const key = String(cb.dataset.artifactKey || "");
        const select = artifactModeSelectForKey(key);
        return {
          artifact_key: key,
          mode: artifactModeValue(select ? select.value : MODE_PARSE_AND_AI),
        };
      });
  }

  function selectedArtifacts() {
    return selectedArtifactOptions().map((option) => option.artifact_key);
  }

  function selectedAiArtifacts(options = null) {
    const artifactOptions = Array.isArray(options) ? options : selectedArtifactOptions();
    return artifactOptions
      .filter((option) => artifactModeValue(option.mode) === MODE_PARSE_AND_AI)
      .map((option) => String(option.artifact_key || ""))
      .filter(Boolean);
  }

  function readAnalysisDateRangeInputs() {
    return {
      start: val(el.analysisDateStart),
      end: val(el.analysisDateEnd),
    };
  }

  function validateAnalysisDateRange() {
    const { start, end } = readAnalysisDateRangeInputs();

    if (!start && !end) return { ok: true, range: null };
    if (!start || !end) return { ok: false, message: "Provide both begin and end dates." };
    if (start > end) return { ok: false, message: "Begin date must be earlier than or equal to end date." };

    return {
      ok: true,
      range: {
        start_date: start,
        end_date: end,
      },
    };
  }

  function normalizeArtifactProfile(rawProfile) {
    if (!isObj(rawProfile)) return null;
    const name = String(rawProfile.name || "").trim();
    if (!name) return null;
    const options = Array.isArray(rawProfile.artifact_options) ? rawProfile.artifact_options : [];
    const artifactOptions = options
      .map((option) => (isObj(option) ? option : null))
      .filter(Boolean)
      .map((option) => ({
        artifact_key: String(option.artifact_key || option.key || "").trim(),
        mode: artifactModeValue(option.mode),
      }))
      .filter((option) => option.artifact_key);
    return {
      name,
      builtin: !!rawProfile.builtin,
      artifact_options: artifactOptions,
    };
  }

  function findProfileByName(name) {
    const wanted = String(name || "").trim().toLowerCase();
    if (!wanted) return null;
    return st.profiles.find((profile) => String(profile.name || "").trim().toLowerCase() === wanted) || null;
  }

  function renderArtifactProfileOptions(preferredName = "") {
    if (!el.profileSelect) return;
    const currentValue = String(preferredName || el.profileSelect.value || RECOMMENDED_PROFILE).trim().toLowerCase();
    el.profileSelect.innerHTML = "";

    st.profiles.forEach((profile) => {
      const name = String(profile.name || "").trim();
      if (!name) return;
      const opt = document.createElement("option");
      opt.value = name;
      opt.textContent = profile.builtin ? `${name} (built-in)` : name;
      el.profileSelect.appendChild(opt);
    });

    const fallback = findProfileByName(RECOMMENDED_PROFILE);
    const selected = findProfileByName(currentValue) || fallback || (st.profiles.length ? st.profiles[0] : null);
    if (selected) el.profileSelect.value = selected.name;
  }

  async function loadArtifactProfiles(preferredName = "") {
    const response = await apiJson("/api/artifact-profiles", { method: "GET" });
    const profilesRaw = Array.isArray(response && response.profiles) ? response.profiles : [];
    st.profiles = profilesRaw
      .map((profile) => normalizeArtifactProfile(profile))
      .filter(Boolean);
    if (!st.profiles.length) {
      st.profiles = [{ name: RECOMMENDED_PROFILE, builtin: true, artifact_options: [] }];
    }
    renderArtifactProfileOptions(preferredName);
  }

  function applyArtifactProfile(profile, opts = {}) {
    if (!profile) return false;
    const silent = !!opts.silent;
    const optionMap = new Map();
    const options = Array.isArray(profile.artifact_options) ? profile.artifact_options : [];
    options.forEach((option) => {
      const key = String(option.artifact_key || "").trim();
      if (!key) return;
      optionMap.set(key, artifactModeValue(option.mode));
    });

    artifactBoxes().forEach((cb) => {
      const key = String(cb.dataset.artifactKey || "").trim();
      const mode = optionMap.get(key) || MODE_PARSE_AND_AI;
      const modeSelect = ensureArtifactModeControl(cb, mode);
      if (cb.disabled || !optionMap.has(key)) cb.checked = false;
      else cb.checked = true;
      if (modeSelect) modeSelect.value = mode;
      syncArtifactModeControl(cb, modeSelect);
    });

    updateParseButton();
    if (!silent) setMsg(el.artifactsMsg, `Loaded profile: ${profile.name}`, "success");
    return true;
  }

  function applySelectedProfile() {
    clearMsg(el.artifactsMsg);
    const selectedName = el.profileSelect ? el.profileSelect.value : RECOMMENDED_PROFILE;
    const profile = findProfileByName(selectedName);
    if (!profile) return setMsg(el.artifactsMsg, "Selected profile is not available.", "error");
    applyArtifactProfile(profile);
  }

  async function saveCurrentProfile() {
    clearMsg(el.artifactsMsg);
    const profileName = val(el.profileName);
    if (!profileName) return setMsg(el.artifactsMsg, "Enter a profile name before saving.", "error");
    if (profileName.toLowerCase() === RECOMMENDED_PROFILE) {
      return setMsg(el.artifactsMsg, "`recommended` is reserved. Pick a different name.", "error");
    }
    const options = selectedArtifactOptions();
    if (!options.length) return setMsg(el.artifactsMsg, "Select at least one artifact before saving a profile.", "error");

    try {
      const response = await apiJson("/api/artifact-profiles", {
        method: "POST",
        json: { name: profileName, artifact_options: options },
      });
      const profilesRaw = Array.isArray(response && response.profiles) ? response.profiles : [];
      st.profiles = profilesRaw
        .map((profile) => normalizeArtifactProfile(profile))
        .filter(Boolean);
      renderArtifactProfileOptions(profileName);
      if (el.profileName) el.profileName.value = "";
      setMsg(el.artifactsMsg, `Profile saved: ${profileName}`, "success");
    } catch (e) {
      setMsg(el.artifactsMsg, `Failed to save profile: ${e.message}`, "error");
    }
  }

  function setupArtifacts() {
    if (!el.artifactsForm) return;
    el.artifactsForm.addEventListener("change", (e) => {
      const t = e.target;
      if (t instanceof HTMLInputElement && t.type === "checkbox" && t.dataset.artifactKey) {
        syncArtifactModeControl(t);
        return updateParseButton();
      }
      if (t instanceof HTMLSelectElement && t.classList.contains("artifact-mode-select") && t.dataset.artifactKey) {
        t.value = artifactModeValue(t.value);
        return updateParseButton();
      }
    });
    if (el.analysisDateStart) el.analysisDateStart.addEventListener("change", updateParseButton);
    if (el.analysisDateEnd) el.analysisDateEnd.addEventListener("change", updateParseButton);
    if (el.quickBtn) {
      el.quickBtn.addEventListener("click", () => {
        const recommendedProfile = findProfileByName(RECOMMENDED_PROFILE);
        if (recommendedProfile) return applyArtifactProfile(recommendedProfile);
        return applyPreset("recommended");
      });
    }
    if (el.clearBtn) el.clearBtn.addEventListener("click", () => applyPreset("clear"));
    if (el.profileLoadBtn) el.profileLoadBtn.addEventListener("click", () => applySelectedProfile());
    if (el.profileSaveBtn) el.profileSaveBtn.addEventListener("click", async () => saveCurrentProfile());
    el.artifactsForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await submitParse();
    });
  }

  function applyPreset(mode) {
    artifactBoxes().forEach((cb) => {
      const select = ensureArtifactModeControl(cb, MODE_PARSE_AND_AI);
      if (cb.disabled) {
        cb.checked = false;
        if (select) select.value = MODE_PARSE_AND_AI;
        return syncArtifactModeControl(cb, select);
      }
      if (mode === "clear") cb.checked = false;
      else cb.checked = !RECOMMENDED_PRESET_EXCLUDED_ARTIFACTS.has(String(cb.dataset.artifactKey || "").trim().toLowerCase());
      if (select) select.value = MODE_PARSE_AND_AI;
      syncArtifactModeControl(cb, select);
    });
    updateParseButton();
  }

  function updateParseButton() {
    const options = selectedArtifactOptions();
    const parseArtifacts = options.map((option) => option.artifact_key);
    const dateRangeValidation = validateAnalysisDateRange();
    const disabled = !activeCaseId() || st.parse.run || parseArtifacts.length === 0 || !dateRangeValidation.ok;
    if (el.parseBtn) el.parseBtn.disabled = disabled;
    updateNav();
  }

  async function submitParse() {
    clearMsg(el.artifactsMsg);
    clearMsg(el.parseErr);
    const caseId = activeCaseId();
    if (!caseId) {
      setMsg(el.artifactsMsg, "Create and intake a case first.", "error");
      showStep(1);
      return;
    }
    const artifactOptions = selectedArtifactOptions();
    const arts = artifactOptions.map((option) => option.artifact_key);
    const aiArtifacts = selectedAiArtifacts(artifactOptions);
    if (!arts.length) return setMsg(el.artifactsMsg, "Select at least one artifact.", "error");
    const dateRangeValidation = validateAnalysisDateRange();
    if (!dateRangeValidation.ok) return setMsg(el.artifactsMsg, dateRangeValidation.message, "error");

    st.selected = arts;
    st.selectedAi = aiArtifacts;
    resetParseState();
    st.parse.run = true;
    initParseRows(arts);
    updateParseProgress();
    if (el.parseBtn) el.parseBtn.disabled = true;

    try {
      const parsePayload = {
        artifacts: arts,
        ai_artifacts: aiArtifacts,
        artifact_options: artifactOptions,
      };
      if (dateRangeValidation.range) parsePayload.analysis_date_range = dateRangeValidation.range;
      await apiJson(`/api/cases/${encodeURIComponent(caseId)}/parse`, { method: "POST", json: parsePayload });
      startTimer("parse");
      startParseSse();
      showStep(3);
    } catch (e) {
      st.parse.run = false;
      stopTimer("parse");
      setMsg(el.artifactsMsg, `Failed to start parsing: ${e.message}`, "error");
      updateParseButton();
    } finally {
      updateNav();
    }
  }

  function initParseRows(keys) {
    if (!el.parseRows) return;
    st.parse.rows = {};
    st.parse.status = {};
    el.parseRows.innerHTML = "";
    keys.forEach((k) => {
      const tr = document.createElement("tr");
      tr.dataset.artifactKey = k;
      const tdA = document.createElement("td");
      tdA.textContent = artifactName(k);
      const tdS = document.createElement("td");
      tdS.textContent = "waiting";
      const tdR = document.createElement("td");
      tdR.textContent = "0";
      tr.appendChild(tdA);
      tr.appendChild(tdS);
      tr.appendChild(tdR);
      el.parseRows.appendChild(tr);
      st.parse.rows[k] = { tr, tdS, tdR };
      st.parse.status[k] = "waiting";
    });
  }

  function renderParsePlaceholder() {
    if (!el.parseRows) return;
    el.parseRows.innerHTML = "";
    const tr = document.createElement("tr");
    tr.innerHTML = "<td>Awaiting selection</td><td>waiting</td><td>0</td>";
    el.parseRows.appendChild(tr);
    st.parse.rows = {};
    st.parse.status = {};
    if (el.parseProgress) el.parseProgress.value = 0;
  }

  function startParseSse() {
    closeParseSse();
    clearMsg(el.parseErr);
    const caseId = activeCaseId();
    if (!caseId) return setMsg(el.parseErr, "No active case for parse stream.", "error");
    const es = new EventSource(`/api/cases/${encodeURIComponent(caseId)}/parse/progress`);
    st.parse.es = es;
    es.onmessage = (ev) => {
      const p = safeJson(ev.data);
      if (!p) return;
      const seq = num(p.sequence, -1);
      if (seq >= 0) {
        if (seq <= st.parse.seq) return;
        st.parse.seq = seq;
      }
      onParseEvent(p);
    };
    es.onerror = () => {
      if (st.parse.done || st.parse.fail || !st.parse.run) return;
      setMsg(el.parseErr, "Parse progress connection dropped. Attempting reconnect...", "error");
      if (es.readyState === EventSource.CLOSED) retryParseSse();
    };
  }

  function onParseEvent(p) {
    const t = String(p.type || "");
    if (t === "parse_started") {
      const arts = Array.isArray(p.artifacts) ? p.artifacts.map(String) : st.selected;
      const aiArtifacts = Array.isArray(p.analysis_artifacts) ? p.analysis_artifacts.map(String) : st.selectedAi;
      st.selected = arts;
      st.selectedAi = aiArtifacts;
      if (arts.length && !Object.keys(st.parse.rows).length) initParseRows(arts);
      updateParseProgress();
      return;
    }
    if (t === "artifact_started") return (setParseRow(String(p.artifact_key || ""), "parsing", num(p.record_count, null)), updateParseProgress());
    if (t === "artifact_progress") return setParseRow(String(p.artifact_key || ""), "parsing", num(p.record_count, 0));
    if (t === "artifact_completed") return (setParseRow(String(p.artifact_key || ""), "completed", num(p.record_count, 0)), updateParseProgress());
    if (t === "artifact_failed") {
      const key = String(p.artifact_key || "");
      setParseRow(key, "failed", num(p.record_count, 0), String(p.error || "Unknown parser error."));
      updateParseProgress();
      return setMsg(el.parseErr, `Parse failed for ${artifactName(key)}: ${String(p.error || "Unknown parser error.")}`, "error");
    }
    if (t === "parse_completed") {
      st.parse.run = false;
      st.parse.done = true;
      st.parse.fail = false;
      updateParseProgress(true);
      stopTimer("parse");
      closeParseSse();
      clearMsg(el.parseErr);
      updateParseButton();
      updateNav();
      return showStep(4);
    }
    if (t === "parse_failed") {
      st.parse.run = false;
      st.parse.done = false;
      st.parse.fail = true;
      stopTimer("parse");
      closeParseSse();
      setMsg(el.parseErr, String(p.error || "Parsing failed."), "error");
      updateParseButton();
      updateNav();
      return showStep(3);
    }
    if (t === "error") setMsg(el.parseErr, String(p.message || "Parse stream error."), "error");
  }

  function setParseRow(key, status, count, err) {
    if (!key) return;
    let row = st.parse.rows[key];
    if (!row && el.parseRows) {
      const tr = document.createElement("tr");
      tr.dataset.artifactKey = key;
      const tdA = document.createElement("td");
      tdA.textContent = artifactName(key);
      const tdS = document.createElement("td");
      tdS.textContent = "waiting";
      const tdR = document.createElement("td");
      tdR.textContent = "0";
      tr.appendChild(tdA);
      tr.appendChild(tdS);
      tr.appendChild(tdR);
      el.parseRows.appendChild(tr);
      row = { tr, tdS, tdR };
      st.parse.rows[key] = row;
    }
    if (!row) return;
    row.tdS.textContent = status;
    row.tdS.dataset.status = status;
    if (typeof count === "number" && Number.isFinite(count)) row.tdR.textContent = String(Math.max(0, Math.floor(count)));
    if (err) row.tr.title = err;
    st.parse.status[key] = status;
  }

  function updateParseProgress(force = false) {
    if (!el.parseProgress) return;
    if (force) return (el.parseProgress.value = 100);
    const keys = st.selected.length ? st.selected : Object.keys(st.parse.status);
    if (!keys.length) return (el.parseProgress.value = 0);
    const done = keys.filter((k) => st.parse.status[k] === "completed" || st.parse.status[k] === "failed").length;
    el.parseProgress.value = Math.max(0, Math.min(100, Math.round((done / keys.length) * 100)));
  }

  function retryParseSse() {
    if (st.parse.retry) return;
    closeParseSse();
    st.parse.retry = window.setTimeout(() => {
      st.parse.retry = null;
      if (!st.parse.done && !st.parse.fail && st.parse.run) startParseSse();
    }, 1500);
  }

  function closeParseSse() {
    if (st.parse.retry) {
      window.clearTimeout(st.parse.retry);
      st.parse.retry = null;
    }
    if (st.parse.es) {
      st.parse.es.close();
      st.parse.es = null;
    }
  }

  function resetParseState() {
    closeParseSse();
    stopTimer("parse");
    st.parse.run = false;
    st.parse.done = false;
    st.parse.fail = false;
    st.parse.seq = -1;
    st.parse.rows = {};
    st.parse.status = {};
    clearMsg(el.parseErr);
    renderParsePlaceholder();
    updateParseButton();
    updateNav();
  }

  function setupAnalysis() {
    if (!el.analysisForm) return;
    el.analysisForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await submitAnalysis();
    });
    if (el.settingsLink) {
      el.settingsLink.addEventListener("click", (e) => {
        e.preventDefault();
        openSettings();
      });
    }
  }

  async function submitAnalysis() {
    clearMsg(el.analysisMsg);
    const caseId = activeCaseId();
    if (!caseId) {
      setMsg(el.analysisMsg, "No active case. Intake evidence first.", "error");
      showStep(1);
      return;
    }
    if (!st.parse.done) {
      setMsg(el.analysisMsg, "Parsing must complete before analysis.", "error");
      showStep(3);
      return;
    }
    if (!st.selectedAi.length) {
      setMsg(el.analysisMsg, "No artifacts are set to `Parse and use in AI`. Update artifact options and parse again.", "error");
      showStep(2);
      return;
    }
    if (st.analysis.run) return setMsg(el.analysisMsg, "Analysis is already running.", "error");

    resetAnalysisState();
    st.analysis.run = true;
    clearMsg(el.resultsMsg);
    if (el.runBtn) el.runBtn.disabled = true;

    try {
      await apiJson(`/api/cases/${encodeURIComponent(caseId)}/analyze`, { method: "POST", json: { prompt: val(el.prompt) } });
      startTimer("analysis");
      startAnalysisSse();
      showStep(4);
    } catch (e) {
      st.analysis.run = false;
      stopTimer("analysis");
      if (el.runBtn) el.runBtn.disabled = false;
      setMsg(el.analysisMsg, `Failed to start analysis: ${e.message}`, "error");
    } finally {
      updateNav();
    }
  }

  function startAnalysisSse() {
    closeAnalysisSse();
    const caseId = activeCaseId();
    if (!caseId) return setMsg(el.analysisMsg, "No case ID for analysis stream.", "error");
    const es = new EventSource(`/api/cases/${encodeURIComponent(caseId)}/analyze/progress`);
    st.analysis.es = es;
    es.onmessage = (ev) => {
      const p = safeJson(ev.data);
      if (!p) return;
      const seq = num(p.sequence, -1);
      if (seq >= 0) {
        if (seq <= st.analysis.seq) return;
        st.analysis.seq = seq;
      }
      onAnalysisEvent(p);
    };
    es.onerror = () => {
      if (st.analysis.done || st.analysis.fail || !st.analysis.run) return;
      setMsg(el.analysisMsg, "Analysis progress connection dropped. Attempting reconnect...", "error");
      if (es.readyState === EventSource.CLOSED) retryAnalysisSse();
    };
  }

  function onAnalysisEvent(p) {
    const t = String(p.type || "");
    if (t === "analysis_started") {
      clearMsg(el.analysisMsg);
      renderAnalysis();
      renderFindings();
      return;
    }
    if (t === "artifact_analysis_started") {
      upsertAnalysisStarted(isObj(p.result) ? p.result : p);
      renderAnalysis();
      renderFindings();
      return;
    }
    if (t === "artifact_analysis_thinking") {
      upsertAnalysisThinking(isObj(p.result) ? p.result : p);
      renderAnalysis();
      renderFindings();
      return;
    }
    if (t === "artifact_analysis_completed") {
      upsertAnalysis(isObj(p.result) ? p.result : p);
      renderAnalysis();
      renderFindings();
      return;
    }
    if (t === "analysis_summary") {
      st.analysis.summary = String(p.summary || "");
      st.analysis.model = isObj(p.model_info) ? p.model_info : {};
      renderExecSummary();
      if (st.analysis.model.provider || st.analysis.model.model) {
        const display = st.analysis.model.model
          ? `${prettyProvider(String(st.analysis.model.provider || ""))} (${String(st.analysis.model.model || "")})`
          : prettyProvider(String(st.analysis.model.provider || ""));
        setProvider(display || "Not configured");
      }
      return;
    }
    if (t === "analysis_completed") {
      const finalArtifacts = Array.isArray(p.per_artifact) ? p.per_artifact : [];
      finalArtifacts.forEach((entry) => {
        if (isObj(entry)) upsertAnalysis(entry);
      });
      finalizeAnyThinkingArtifacts();
      renderAnalysis();
      renderFindings();
      st.analysis.run = false;
      st.analysis.done = true;
      st.analysis.fail = false;
      stopTimer("analysis");
      closeAnalysisSse();
      if (el.runBtn) el.runBtn.disabled = false;
      clearMsg(el.analysisMsg);
      updateNav();
      return showStep(5);
    }
    if (t === "analysis_failed") {
      st.analysis.run = false;
      st.analysis.done = false;
      st.analysis.fail = true;
      stopTimer("analysis");
      closeAnalysisSse();
      if (el.runBtn) el.runBtn.disabled = false;
      setMsg(el.analysisMsg, String(p.error || "Analysis failed."), "error");
      updateNav();
      return;
    }
    if (t === "error") setMsg(el.analysisMsg, String(p.message || "Analysis stream error."), "error");
  }

  function upsertAnalysis(r) {
    const key = String(r.artifact_key || r.key || `artifact_${st.analysis.order.length + 1}`);
    const name = String(r.artifact_name || artifactName(key));
    const rawText = String(r.analysis || r.result || "");
    const text = stripLeadingReasoningBlocks(rawText) || rawText;
    const model = String(r.model || "");
    if (!st.analysis.byKey[key]) st.analysis.order.push(key);
    st.analysis.byKey[key] = {
      key,
      name,
      text,
      model,
      thinkingText: "",
      partialText: "",
      isThinking: false,
    };
  }

  function upsertAnalysisStarted(r) {
    const key = String(r.artifact_key || r.key || `artifact_${st.analysis.order.length + 1}`);
    const name = String(r.artifact_name || artifactName(key));
    const model = String(r.model || "");
    if (!st.analysis.byKey[key]) st.analysis.order.push(key);
    const current = st.analysis.byKey[key] || {};
    st.analysis.byKey[key] = {
      key,
      name,
      text: String(current.text || ""),
      model: model || String(current.model || ""),
      thinkingText: String(current.thinkingText || "Model is thinking..."),
      partialText: String(current.partialText || ""),
      isThinking: true,
    };
  }

  function upsertAnalysisThinking(r) {
    const key = String(r.artifact_key || r.key || `artifact_${st.analysis.order.length + 1}`);
    const name = String(r.artifact_name || artifactName(key));
    const model = String(r.model || "");
    if (!st.analysis.byKey[key]) st.analysis.order.push(key);
    const current = st.analysis.byKey[key] || {};
    const thinkingText = String(r.thinking_text || current.thinkingText || "");
    const partialText = String(r.partial_text || current.partialText || "");
    st.analysis.byKey[key] = {
      key,
      name,
      text: String(current.text || ""),
      model: model || String(current.model || ""),
      thinkingText,
      partialText,
      isThinking: true,
    };
  }

  function renderAnalysis() {
    if (!el.analysisList) return;
    el.analysisList.innerHTML = "";
    if (!st.analysis.order.length) {
      const p = document.createElement("p");
      p.textContent = "No analysis output yet.";
      el.analysisList.appendChild(p);
      return;
    }
    st.analysis.order.forEach((k) => {
      const r = st.analysis.byKey[k];
      if (!r) return;
      const a = document.createElement("article");
      a.className = "analysis-card";
      const h = document.createElement("h4");
      h.textContent = r.name;
      const m = document.createElement("p");
      m.className = "mono";
      m.textContent = r.model ? `${r.key} | model: ${r.model}` : r.key;
      const b = document.createElement("div");
      b.className = "markdown-output";
      if (r.isThinking && !String(r.text || "").trim()) {
        const temporaryThinkingText = String(r.thinkingText || r.partialText || "Model is thinking...");
        renderMarkdownInto(b, temporaryThinkingText, "Model is thinking...");
      } else {
        renderMarkdownInto(b, r.text, "(No analysis text returned.)");
      }
      a.appendChild(h);
      a.appendChild(m);
      a.appendChild(b);
      el.analysisList.appendChild(a);
    });
  }

  function renderExecSummary() {
    if (!el.summaryOut) return;
    renderMarkdownInto(el.summaryOut, st.analysis.summary, "Summary is generated after analysis completes.");
  }

  function renderFindings() {
    if (!el.findings) return;
    Array.from(el.findings.children).forEach((c) => {
      if (c.id !== "artifact-findings-title") c.remove();
    });
    if (!st.analysis.order.length) {
      const p = document.createElement("p");
      p.textContent = "Findings will appear here.";
      el.findings.appendChild(p);
      return;
    }
    st.analysis.order.forEach((k, i) => {
      const r = st.analysis.byKey[k];
      if (!r) return;
      const d = document.createElement("details");
      d.open = i === 0;
      const s = document.createElement("summary");
      s.textContent = r.name;
      const p = document.createElement("div");
      p.className = "markdown-output";
      if (r.isThinking && !String(r.text || "").trim()) {
        const temporaryThinkingText = String(r.thinkingText || r.partialText || "Model is thinking...");
        renderMarkdownInto(p, temporaryThinkingText, "Model is thinking...");
      } else {
        renderMarkdownInto(p, r.text, "(No analysis text returned.)");
      }
      d.appendChild(s);
      d.appendChild(p);
      el.findings.appendChild(d);
    });
  }

  function renderMarkdownInto(container, text, emptyText) {
    if (!container) return;
    container.innerHTML = "";
    const raw = String(text || "");
    if (!raw.trim()) {
      const p = document.createElement("p");
      p.textContent = emptyText;
      container.appendChild(p);
      return;
    }
    container.appendChild(markdownToFragment(raw));
  }

  function markdownToFragment(text) {
    const fragment = document.createDocumentFragment();
    const lines = String(text || "").replace(/\r\n?/g, "\n").split("\n");
    let paragraphLines = [];
    let listNode = null;
    let listType = "";
    let inCodeFence = false;
    let codeFenceLines = [];

    const closeList = () => {
      if (!listNode) return;
      fragment.appendChild(listNode);
      listNode = null;
      listType = "";
    };

    const flushParagraph = () => {
      if (!paragraphLines.length) return;
      const p = document.createElement("p");
      const html = renderInlineMarkdown(paragraphLines.join("\n")).replace(/\n/g, "<br>");
      p.innerHTML = html;
      fragment.appendChild(p);
      paragraphLines = [];
    };

    const flushCodeFence = () => {
      const pre = document.createElement("pre");
      const code = document.createElement("code");
      code.textContent = codeFenceLines.join("\n");
      pre.appendChild(code);
      fragment.appendChild(pre);
      codeFenceLines = [];
    };

    lines.forEach((line) => {
      const trimmed = String(line || "").trim();

      if (inCodeFence) {
        if (trimmed.startsWith("```")) {
          inCodeFence = false;
          flushCodeFence();
          return;
        }
        codeFenceLines.push(line);
        return;
      }

      if (trimmed.startsWith("```")) {
        flushParagraph();
        closeList();
        inCodeFence = true;
        codeFenceLines = [];
        return;
      }

      if (!trimmed) {
        flushParagraph();
        closeList();
        return;
      }

      const heading = trimmed.match(/^(#{1,6})\s+(.*)$/);
      if (heading) {
        flushParagraph();
        closeList();
        const level = heading[1].length;
        const content = heading[2] || "";
        const h = document.createElement(`h${level}`);
        h.innerHTML = renderInlineMarkdown(content);
        fragment.appendChild(h);
        return;
      }

      const ordered = trimmed.match(/^\d+\.\s+(.*)$/);
      if (ordered) {
        flushParagraph();
        if (listType !== "ol") {
          closeList();
          listNode = document.createElement("ol");
          listType = "ol";
        }
        const li = document.createElement("li");
        li.innerHTML = renderInlineMarkdown(ordered[1] || "");
        listNode.appendChild(li);
        return;
      }

      const unordered = trimmed.match(/^[-*]\s+(.*)$/);
      if (unordered) {
        flushParagraph();
        if (listType !== "ul") {
          closeList();
          listNode = document.createElement("ul");
          listType = "ul";
        }
        const li = document.createElement("li");
        li.innerHTML = renderInlineMarkdown(unordered[1] || "");
        listNode.appendChild(li);
        return;
      }

      closeList();
      paragraphLines.push(trimmed);
    });

    if (inCodeFence) flushCodeFence();
    flushParagraph();
    closeList();
    return fragment;
  }

  function renderInlineMarkdown(text) {
    const source = String(text || "");
    if (!source) return "";
    const parts = source.split(/(`[^`\n]*`)/g);
    return parts
      .map((part) => {
        if (part.startsWith("`") && part.endsWith("`")) {
          return `<code>${escapeHtml(part.slice(1, -1))}</code>`;
        }
        let out = escapeHtml(part);
        out = out.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
        out = out.replace(/__(.+?)__/g, "<strong>$1</strong>");
        out = out.replace(/\*(.+?)\*/g, "<em>$1</em>");
        out = out.replace(/_(.+?)_/g, "<em>$1</em>");
        out = highlightConfidenceTokens(out);
        return out;
      })
      .join("");
  }

  function highlightConfidenceTokens(text) {
    CONFIDENCE_TOKEN_PATTERN.lastIndex = 0;
    return String(text || "").replace(CONFIDENCE_TOKEN_PATTERN, (match, token) => {
      const normalized = String(token || match || "").toUpperCase();
      const cssClass = CONFIDENCE_CLASS_MAP[normalized] || "confidence-unknown";
      return `<span class="confidence-inline ${cssClass}">${normalized}</span>`;
    });
  }

  function retryAnalysisSse() {
    if (st.analysis.retry) return;
    closeAnalysisSse();
    st.analysis.retry = window.setTimeout(() => {
      st.analysis.retry = null;
      if (!st.analysis.done && !st.analysis.fail && st.analysis.run) startAnalysisSse();
    }, 1500);
  }

  function closeAnalysisSse() {
    if (st.analysis.retry) {
      window.clearTimeout(st.analysis.retry);
      st.analysis.retry = null;
    }
    if (st.analysis.es) {
      st.analysis.es.close();
      st.analysis.es = null;
    }
  }

  function resetAnalysisState() {
    closeAnalysisSse();
    stopTimer("analysis");
    st.analysis.run = false;
    st.analysis.done = false;
    st.analysis.fail = false;
    st.analysis.seq = -1;
    st.analysis.order = [];
    st.analysis.byKey = {};
    st.analysis.summary = "";
    st.analysis.model = {};
    clearMsg(el.analysisMsg);
    if (el.runBtn) el.runBtn.disabled = false;
    renderAnalysis();
    renderExecSummary();
    renderFindings();

    updateNav();
  }

  function setupResults() {
    if (el.downloadReport) el.downloadReport.addEventListener("click", async () => downloadCaseFile("report"));
    if (el.downloadCsvs) el.downloadCsvs.addEventListener("click", async () => downloadCaseFile("csvs"));
    if (el.newAnalysis) el.newAnalysis.addEventListener("click", () => {
      resetCaseUi();
      showStep(1);
    });
  }

  async function downloadCaseFile(kind) {
    clearMsg(el.resultsMsg);
    const caseId = activeCaseId();
    if (!caseId) return setMsg(el.resultsMsg, "No active case to download from.", "error");
    const endpoint = kind === "report"
      ? `/api/cases/${encodeURIComponent(caseId)}/report`
      : `/api/cases/${encodeURIComponent(caseId)}/csvs`;
    const fallback = kind === "report" ? `${caseId}_report.html` : `${caseId}_parsed_csvs.zip`;
    try {
      const r = await fetch(endpoint, { method: "GET" });
      if (!r.ok) throw new Error((await readErr(r)) || `Download failed (${r.status}).`);
      const blob = await r.blob();
      const filename = getFilename(r.headers) || fallback;
      triggerDownload(blob, filename);
      setMsg(el.resultsMsg, `Download started: ${filename}`, "success");
    } catch (e) {
      setMsg(el.resultsMsg, `Download failed: ${e.message}`, "error");
    }
  }

  function triggerDownload(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  function getFilename(headers) {
    const cd = headers.get("content-disposition") || headers.get("Content-Disposition") || "";
    if (!cd) return "";
    const utf = cd.match(/filename\*=UTF-8''([^;]+)/i);
    if (utf && utf[1]) {
      try {
        return decodeURIComponent(utf[1].trim());
      } catch (_err) {
        return utf[1].trim();
      }
    }
    const plain = cd.match(/filename="?([^";]+)"?/i);
    return plain && plain[1] ? plain[1].trim() : "";
  }

  function setupSettings() {
    if (!el.settingsBtn || !el.settingsPanel || !el.settingsForm) return;
    ensureTestButton();
    if (el.settingsTabButtons.length) {
      el.settingsTabButtons.forEach((button) => {
        button.addEventListener("click", () => {
          const targetTab = String(button.dataset.settingsTab || "basic");
          showSettingsTab(targetTab);
        });
      });
    }
    el.settingsBtn.addEventListener("click", () => (el.settingsPanel.hidden ? openSettings() : closeSettings()));
    if (el.setProvider) {
      el.setProvider.addEventListener("change", () => {
        fillProviderFields();
        syncProviderFields();
      });
    }
    if (el.setCsvOutputDir) {
      el.setCsvOutputDir.addEventListener("input", updateCsvOutputHelp);
      el.setCsvOutputDir.addEventListener("change", updateCsvOutputHelp);
    }
    el.settingsForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await saveSettings();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !el.settingsPanel.hidden) closeSettings();
    });
    document.addEventListener("mousedown", (e) => {
      if (el.settingsPanel.hidden) return;
      const t = e.target;
      if (!(t instanceof Node)) return;
      if (el.settingsPanel.contains(t) || el.settingsBtn.contains(t) || (el.settingsLink && el.settingsLink.contains(t))) return;
      closeSettings();
    });
    syncProviderFields();
    showSettingsTab(st.settingsTab || "basic");
  }

  function ensureTestButton() {
    if (!el.settingsForm || q("test-connection")) return;
    const b = document.createElement("button");
    b.type = "button";
    b.id = "test-connection";
    b.textContent = "Test Connection";
    if (el.saveSettings && el.saveSettings.parentNode === el.settingsForm) el.settingsForm.insertBefore(b, el.saveSettings.nextSibling);
    else el.settingsForm.appendChild(b);
    el.testBtn = b;
    b.addEventListener("click", async () => testConnection());
  }

  function openSettings() {
    if (!el.settingsPanel || !el.settingsBtn) return;
    el.settingsPanel.hidden = false;
    el.settingsBtn.setAttribute("aria-expanded", "true");
    showSettingsTab(st.settingsTab || "basic");
    loadSettings().catch((e) => setMsg(el.settingsMsg, `Unable to refresh settings: ${e.message}`, "error"));
  }

  function closeSettings() {
    if (!el.settingsPanel || !el.settingsBtn) return;
    el.settingsPanel.hidden = true;
    el.settingsBtn.setAttribute("aria-expanded", "false");
  }

  function showSettingsTab(tabName) {
    const target = tabName === "advanced" ? "advanced" : "basic";
    st.settingsTab = target;
    if (el.settingsTabButtons.length) {
      el.settingsTabButtons.forEach((button) => {
        const current = String(button.dataset.settingsTab || "") === target;
        button.classList.toggle("is-active", current);
        button.setAttribute("aria-selected", current ? "true" : "false");
        button.tabIndex = current ? 0 : -1;
      });
    }
    if (el.settingsTabPanels.length) {
      el.settingsTabPanels.forEach((panel) => {
        panel.hidden = String(panel.dataset.settingsPanel || "") !== target;
      });
    }
  }

  async function loadSettings() {
    const s = await apiJson("/api/settings", { method: "GET" });
    st.settings = s;
    applySettings(s);
    updateProviderFromSettings(s);
    clearMsg(el.settingsMsg);
  }

  function applySettings(s) {
    if (!isObj(s)) return;
    const ai = obj(s.ai);
    const backend = normProvider(String(ai.provider || "claude"));
    if (el.setProvider) el.setProvider.value = toUiProvider(backend);
    if (el.setPort) el.setPort.value = String(num(obj(s.server).port, 5000));
    if (el.setSize) el.setSize.value = fmtNumber(num(obj(s.evidence).large_file_threshold_mb, 2048) / 1024, 3);
    if (el.setCsvOutputDir) el.setCsvOutputDir.value = String(obj(s.evidence).csv_output_dir || "");
    updateCsvOutputHelp();
    applyAdvancedSettings(s);
    fillProviderFields();
    syncProviderFields();
  }

  function applyAdvancedSettings(s) {
    if (!isObj(s)) return;
    const analysis = obj(s.analysis);
    setNumberInput(el.setAiMaxTokens, num(analysis.ai_max_tokens, 128000), 128000);
    setNumberInput(el.setConnectionMaxTokens, num(analysis.connection_test_max_tokens, 256), 256);
    setNumberInput(el.setDateBufferDays, num(analysis.date_buffer_days, 7), 7);
    setNumberInput(el.setCitationSpotCheckLimit, num(analysis.citation_spot_check_limit, 20), 20);
    if (el.setArtifactDeduplicationEnabled) {
      el.setArtifactDeduplicationEnabled.checked = boolSetting(analysis.artifact_deduplication_enabled, true);
    }

    const ai = obj(s.ai);
    if (el.setAttachClaude) el.setAttachClaude.checked = boolSetting(obj(ai.claude).attach_csv_as_file, true);
    if (el.setAttachOpenAI) el.setAttachOpenAI.checked = boolSetting(obj(ai.openai).attach_csv_as_file, true);
    if (el.setAttachKimi) el.setAttachKimi.checked = boolSetting(obj(ai.kimi).attach_csv_as_file, true);
    if (el.setAttachLocal) el.setAttachLocal.checked = boolSetting(obj(ai.local).attach_csv_as_file, true);
  }

  function setNumberInput(input, value, fallback) {
    if (!input) return;
    const numeric = typeof value === "number" && Number.isFinite(value) ? value : fallback;
    input.value = String(numeric);
  }

  function boolSetting(value, fallback = false) {
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
      if (normalized === "false" || normalized === "0" || normalized === "no") return false;
    }
    return fallback;
  }

  function defaultCsvOutputForCurrentCase() {
    const caseId = activeCaseId();
    if (caseId) return `cases/${caseId}/parsed`;
    return "cases/<case_id>/parsed";
  }

  function configuredCsvOutputForCurrentCase(rootPath) {
    const text = String(rootPath || "").trim();
    if (!text) return "";
    const trimmed = text.replace(/[\\/]+$/, "");
    const sep = trimmed.includes("\\") ? "\\" : "/";
    const caseToken = activeCaseId() || "<case_id>";
    return `${trimmed}${sep}${caseToken}${sep}parsed`;
  }

  function updateCsvOutputHelp() {
    if (!el.setCsvOutputHelp) return;
    const configuredPath = val(el.setCsvOutputDir);
    const defaultPath = defaultCsvOutputForCurrentCase();
    if (configuredPath) {
      const effectivePath = configuredCsvOutputForCurrentCase(configuredPath);
      el.setCsvOutputHelp.textContent = `Currently using: ${effectivePath}`;
      return;
    }
    el.setCsvOutputHelp.textContent = `Currently using: ${defaultPath}`;
  }

  function fillProviderFields() {
    if (!isObj(st.settings) || !el.setProvider) return;
    const provider = toBackendProvider(el.setProvider.value);
    const ai = obj(st.settings.ai);
    const pc = obj(ai[provider]);
    if (el.setApiKey) el.setApiKey.value = String(pc.api_key || "");
    if (el.setModel) el.setModel.value = String(pc.model || "");
    if (el.setLocalUrl) {
      if (provider === "local" || provider === "kimi") {
        el.setLocalUrl.value = String(pc.base_url || "");
      } else {
        el.setLocalUrl.value = String(obj(ai.local).base_url || "");
      }
    }
  }

  function syncProviderFields() {
    if (!el.setProvider) return;
    const p = el.setProvider.value;
    const usesEndpoint = p === "local" || p === "kimi";
    const isLocal = p === "local";
    if (el.setApiRow) el.setApiRow.hidden = isLocal;
    if (el.setApiKey) el.setApiKey.disabled = isLocal;
    if (el.setLocalRow) el.setLocalRow.hidden = !usesEndpoint;
    if (el.setLocalLabel) {
      if (p === "kimi") el.setLocalLabel.textContent = "Kimi API Endpoint URL";
      else el.setLocalLabel.textContent = "Local AI Endpoint URL";
    }
    if (el.setLocalUrl) {
      if (p === "kimi") el.setLocalUrl.placeholder = "https://api.moonshot.ai/v1";
      else el.setLocalUrl.placeholder = "http://127.0.0.1:11434/v1";
    }
    if (el.setApiLabel) {
      if (p === "anthropic") el.setApiLabel.textContent = "Anthropic API Key";
      else if (p === "kimi") el.setApiLabel.textContent = "Moonshot API Key";
      else el.setApiLabel.textContent = "OpenAI API Key";
    }
    if (el.setModel) {
      if (p === "anthropic") el.setModel.placeholder = "claude-sonnet-4-20250514";
      else if (p === "openai") el.setModel.placeholder = "gpt-5.2";
      else if (p === "kimi") el.setModel.placeholder = "kimi-k2-turbo-preview";
      else el.setModel.placeholder = "llama3.1:70b";
    }
  }

  async function saveSettings(opts = {}) {
    const silent = !!opts.silent;
    clearMsg(el.settingsMsg);
    try {
      const payload = buildSettingsPayload();
      const saved = await apiJson("/api/settings", { method: "POST", json: payload });
      st.settings = saved;
      applySettings(saved);
      updateProviderFromSettings(saved);
      if (!silent) setMsg(el.settingsMsg, "Settings saved.", "success");
      return true;
    } catch (e) {
      setMsg(el.settingsMsg, `Failed to save settings: ${e.message}`, "error");
      return false;
    }
  }

  function buildSettingsPayload() {
    const base = clone(st.settings || {});
    if (!isObj(base.ai)) base.ai = {};
    if (!isObj(base.ai.claude)) base.ai.claude = {};
    if (!isObj(base.ai.openai)) base.ai.openai = {};
    if (!isObj(base.ai.kimi)) base.ai.kimi = {};
    if (!isObj(base.ai.local)) base.ai.local = {};
    if (!isObj(base.server)) base.server = {};
    if (!isObj(base.evidence)) base.evidence = {};
    if (!isObj(base.analysis)) base.analysis = {};

    const provider = toBackendProvider(el.setProvider ? el.setProvider.value : "openai");
    base.ai.provider = provider;
    if (!isObj(base.ai[provider])) base.ai[provider] = {};
    base.ai[provider].model = val(el.setModel) || "";

    if (provider === "local") {
      const url = val(el.setLocalUrl);
      base.ai.local.base_url = url || base.ai.local.base_url || "http://localhost:11434/v1";
      const existingLocalApiKey = String(base.ai.local.api_key || "").trim();
      base.ai.local.api_key = existingLocalApiKey || "not-needed";
    } else if (provider === "kimi") {
      const url = val(el.setLocalUrl);
      base.ai.kimi.base_url = url || base.ai.kimi.base_url || "https://api.moonshot.ai/v1";
      base.ai.kimi.api_key = val(el.setApiKey) || "";
    } else {
      base.ai[provider].api_key = val(el.setApiKey) || "";
    }

    const port = num(val(el.setPort), null);
    if (typeof port === "number" && Number.isFinite(port) && port > 0) base.server.port = port;

    const gb = num(val(el.setSize), null);
    if (typeof gb === "number" && Number.isFinite(gb) && gb > 0) base.evidence.large_file_threshold_mb = Math.round(gb * 1024);
    if (el.setCsvOutputDir) base.evidence.csv_output_dir = val(el.setCsvOutputDir);

    base.analysis.ai_max_tokens = readIntInput(el.setAiMaxTokens, 128000, 1);
    base.analysis.connection_test_max_tokens = readIntInput(el.setConnectionMaxTokens, 256, 1);
    base.analysis.date_buffer_days = readIntInput(el.setDateBufferDays, 7, 0);
    base.analysis.citation_spot_check_limit = readIntInput(el.setCitationSpotCheckLimit, 20, 1);
    if (el.setArtifactDeduplicationEnabled) {
      base.analysis.artifact_deduplication_enabled = !!el.setArtifactDeduplicationEnabled.checked;
    }

    if (el.setAttachClaude) base.ai.claude.attach_csv_as_file = !!el.setAttachClaude.checked;
    if (el.setAttachOpenAI) base.ai.openai.attach_csv_as_file = !!el.setAttachOpenAI.checked;
    if (el.setAttachKimi) base.ai.kimi.attach_csv_as_file = !!el.setAttachKimi.checked;
    if (el.setAttachLocal) base.ai.local.attach_csv_as_file = !!el.setAttachLocal.checked;

    return base;
  }

  function readIntInput(input, fallback, minValue = 1) {
    const parsed = num(val(input), null);
    if (typeof parsed !== "number" || !Number.isFinite(parsed)) return fallback;
    return Math.max(minValue, Math.round(parsed));
  }

  async function testConnection() {
    clearMsg(el.settingsMsg);
    if (st.analysis.run) return setMsg(el.settingsMsg, "Stop active analysis before running connection test.", "error");
    const stopProgressFeedback = startConnectionTestFeedback();
    if (el.testBtn) {
      el.testBtn.disabled = true;
      el.testBtn.setAttribute("aria-busy", "true");
    }
    try {
      const ok = await saveSettings({ silent: true });
      if (!ok) return;
      const result = await apiJson("/api/settings/test-connection", { method: "POST" });
      const modelInfo = isObj(result && result.model_info) ? result.model_info : {};
      const provider = prettyProvider(String(modelInfo.provider || ""));
      const model = String(modelInfo.model || "").trim();
      const providerText = model ? `${provider} (${model})` : provider;
      const suffix = providerText && providerText !== "Unknown" ? `: ${providerText}` : "";
      setMsg(el.settingsMsg, `Connection test succeeded${suffix}.`, "success");
    } catch (e) {
      setMsg(el.settingsMsg, `Connection test failed: ${e.message}`, "error");
    } finally {
      stopProgressFeedback();
      if (el.testBtn) {
        el.testBtn.disabled = false;
        el.testBtn.removeAttribute("aria-busy");
        el.testBtn.textContent = "Test Connection";
      }
    }
  }

  function startConnectionTestFeedback() {
    const startedAt = Date.now();
    let frame = 0;
    let ticker = 0;

    const tick = () => {
      const elapsedSeconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
      const minutes = String(Math.floor(elapsedSeconds / 60)).padStart(2, "0");
      const seconds = String(elapsedSeconds % 60).padStart(2, "0");
      const dots = ".".repeat((frame % 3) + 1);
      frame += 1;
      if (el.testBtn) el.testBtn.textContent = `Testing${dots}`;
      setMsg(el.settingsMsg, `Testing provider connection${dots} (${minutes}:${seconds})`, "info");
    };

    tick();
    ticker = window.setInterval(tick, 1000);

    return () => {
      if (ticker) {
        window.clearInterval(ticker);
        ticker = 0;
      }
    };
  }

  function updateProviderFromSettings(s) {
    const ai = obj(s.ai);
    const p = normProvider(String(ai.provider || ""));
    const model = String(obj(ai[p]).model || "");
    if (!p) return setProvider("Not configured");
    const label = prettyProvider(p);
    setProvider(model ? `${label} (${model})` : label);
  }

  function setProvider(text) {
    if (el.providerName) el.providerName.textContent = text || "Not configured";
  }

  function resetCaseUi() {
    closeParseSse();
    closeAnalysisSse();
    stopTimer("parse");
    stopTimer("analysis");

    setCaseId("");
    st.caseName = "";
    st.artifacts = [];
    st.artifactNames = {};
    st.selected = [];
    st.selectedAi = [];
    st.pendingFiles = [];

    resetParseState();
    resetAnalysisState();

    if (el.evidenceForm) el.evidenceForm.reset();
    if (el.modeUpload) el.modeUpload.checked = true;
    syncMode();
    setPendingFiles([]);
    if (el.analysisDateStart) el.analysisDateStart.value = "";
    if (el.analysisDateEnd) el.analysisDateEnd.value = "";
    if (el.profileName) el.profileName.value = "";
    if (el.profileSelect) el.profileSelect.value = RECOMMENDED_PROFILE;

    if (el.summaryCard) el.summaryCard.hidden = true;
    if (el.sumHost) el.sumHost.textContent = "-";
    if (el.sumOs) el.sumOs.textContent = "-";
    if (el.sumDomain) el.sumDomain.textContent = "-";
    if (el.sumIps) el.sumIps.textContent = "-";
    if (el.sumSha) el.sumSha.textContent = "-";

    artifactBoxes().forEach((cb) => {
      cb.checked = false;
      cb.disabled = true;
      const select = ensureArtifactModeControl(cb, MODE_PARSE_AND_AI);
      if (select) select.value = MODE_PARSE_AND_AI;
      syncArtifactModeControl(cb, select);
      const li = cb.closest("li");
      if (li) {
        li.classList.add("artifact-unavailable");
        li.dataset.available = "false";
        li.title = "Load evidence to detect availability";
      }
    });
    clearDynamicArtifacts();
    if (el.parseBtn) el.parseBtn.disabled = true;
    if (el.evidenceProgWrap) el.evidenceProgWrap.hidden = true;
    if (el.evidenceProg) el.evidenceProg.value = 0;

    [el.evidenceMsg, el.artifactsMsg, el.parseErr, el.analysisMsg, el.resultsMsg].forEach(clearMsg);
    renderParsePlaceholder();
    renderAnalysis();
    renderExecSummary();
    renderFindings();

    if (el.runBtn) el.runBtn.disabled = false;
    updateCsvOutputHelp();
    updateNav();
  }

  async function apiJson(url, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    const init = { method: opts.method || "GET", headers };
    if (Object.prototype.hasOwnProperty.call(opts, "json")) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.json);
    } else if (Object.prototype.hasOwnProperty.call(opts, "body")) {
      init.body = opts.body;
      if (init.body instanceof FormData) delete headers["Content-Type"];
    }
    let r;
    try {
      r = await fetch(url, init);
    } catch (e) {
      throw new Error(`Network error while calling ${url}: ${e.message}`);
    }
    const ct = r.headers.get("content-type") || "";
    const payload = ct.includes("application/json")
      ? await r.json().catch(() => null)
      : ((await r.text().catch(() => "")) || "");
    if (!r.ok) {
      const m = payload && typeof payload === "object"
        ? (payload.error || payload.message)
        : payload;
      throw new Error(m || `Request failed with status ${r.status}.`);
    }
    return payload;
  }

  async function readErr(r) {
    const ct = r.headers.get("content-type") || "";
    if (ct.includes("application/json")) {
      const p = await r.json().catch(() => null);
      if (p && typeof p === "object") return p.error || p.message || "";
      return "";
    }
    return r.text().catch(() => "");
  }

  function startTimer(kind) {
    const node = kind === "parse" ? el.parseElapsed : el.analysisElapsed;
    const tgt = kind === "parse" ? st.parse : st.analysis;
    stopTimer(kind);
    if (!node || !tgt) return;
    tgt.started = Date.now();
    node.hidden = false;
    const tick = () => {
      const s = Math.max(0, Math.floor((Date.now() - tgt.started) / 1000));
      node.textContent = `Elapsed: ${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
    };
    tick();
    tgt.timer = window.setInterval(tick, 1000);
  }

  function stopTimer(kind) {
    const tgt = kind === "parse" ? st.parse : st.analysis;
    if (tgt && tgt.timer) {
      window.clearInterval(tgt.timer);
      tgt.timer = null;
    }
  }

  function artifactName(k) {
    return st.artifactNames[k] || k;
  }

  function fmtBytes(b) {
    if (!Number.isFinite(b) || b < 0) return "0 B";
    if (b < 1024) return `${b} B`;
    const units = ["KB", "MB", "GB", "TB"];
    let v = b / 1024;
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return `${v.toFixed(v >= 10 ? 0 : 1)} ${units[i]}`;
  }

  function fmtNumber(v, max = 3) {
    return Number.isFinite(v)
      ? v.toLocaleString(undefined, { maximumFractionDigits: max, minimumFractionDigits: 0, useGrouping: false })
      : "";
  }

  function safeJson(t) {
    if (typeof t !== "string" || !t) return null;
    try {
      return JSON.parse(t);
    } catch (_e) {
      return null;
    }
  }

  function escapeHtml(value) {
    return String(value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  function val(input) {
    return input ? String(input.value || "").trim() : "";
  }

  function num(v, fallback) {
    if (v === null || v === undefined || v === "") return fallback;
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  }

  function isObj(v) {
    return v !== null && typeof v === "object" && !Array.isArray(v);
  }

  function obj(v) {
    return isObj(v) ? v : {};
  }

  function clone(v) {
    if (typeof structuredClone === "function") return structuredClone(v);
    try {
      return JSON.parse(JSON.stringify(v));
    } catch (_e) {
      return {};
    }
  }

  function toBackendProvider(ui) {
    if (ui === "anthropic") return "claude";
    if (ui === "kimi") return "kimi";
    if (ui === "local") return "local";
    return "openai";
  }

  function toUiProvider(back) {
    if (back === "claude") return "anthropic";
    if (back === "kimi") return "kimi";
    if (back === "local") return "local";
    return "openai";
  }

  function normProvider(p) {
    const x = String(p || "").trim().toLowerCase();
    if (x === "anthropic") return "claude";
    if (x === "claude" || x === "openai" || x === "kimi" || x === "local") return x;
    return "";
  }

  function prettyProvider(p) {
    const x = normProvider(p);
    if (x === "claude") return "Claude";
    if (x === "openai") return "OpenAI";
    if (x === "kimi") return "Kimi";
    if (x === "local") return "Local";
    return p || "Unknown";
  }

  function stripLeadingReasoningBlocks(text) {
    const raw = String(text || "").trim();
    if (!raw) return "";
    const cleaned = raw.replace(
      /^(?:\s*(?:<\s*(?:think|thinking|reasoning)\b[^>]*>[\s\S]*?<\s*\/\s*(?:think|thinking|reasoning)\s*>|```(?:think|thinking|reasoning)[^\n]*\n[\s\S]*?```)\s*)+/i,
      "",
    );
    return cleaned.trim();
  }

  function finalizeAnyThinkingArtifacts() {
    st.analysis.order.forEach((key) => {
      const current = st.analysis.byKey[key];
      if (!current || !current.isThinking) return;
      const rawResolvedText = String(current.text || current.partialText || current.thinkingText || "");
      const resolvedText = stripLeadingReasoningBlocks(rawResolvedText) || rawResolvedText.trim();
      st.analysis.byKey[key] = {
        ...current,
        text: resolvedText,
        isThinking: false,
      };
    });
  }
})();
