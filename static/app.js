/**
 * AIFT main application orchestrator.
 *
 * Initializes the UI, caches DOM elements, wires up the wizard
 * navigation, and coordinates module setup. This file must be loaded
 * last, after all modules under static/js/ have been loaded.
 *
 * Depends on: AIFT (utils.js, markdown.js, evidence.js, parsing.js,
 *             analysis.js, chat.js, settings.js)
 */
"use strict";

(() => {
  const A = window.AIFT;
  const { st, el, q } = A;

  document.addEventListener("DOMContentLoaded", init);

  /** Initialise the application: cache DOM, wire wizard, set up all modules. */
  function init() {
    cache();
    if (!el.wizard) return;
    addMessages();
    addTimers();
    setupWizard();
    A.setupEvidence();
    A.setupArtifacts();
    A.setupAnalysis();
    A.setupResults();
    A.setupSettings();
    resetCaseUi();
    showStep(1);
    A.fetchCsrfToken().catch(() => {});
    A.loadSettings().catch((e) => A.setMsg(el.settingsMsg, `Unable to load settings: ${e.message}`, "error"));
    A.loadArtifactProfiles().catch((e) => A.setMsg(el.artifactsMsg, `Unable to load profiles: ${e.message}`, "error"));
  }

  // ── DOM cache ──────────────────────────────────────────────────────────────

  /** Look up and cache all DOM element references used across the application. */
  function cache() {
    el.wizard = q("wizard");
    el.steps = Array.from(document.querySelectorAll(".wizard-step"));
    el.indicators = Array.from(document.querySelectorAll(".step-indicator li"));

    el.evidenceForm = q("evidence-form");
    el.evidenceLoadedBanner = q("evidence-loaded-banner");
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
    el.cancelParse = q("cancel-parse");
    el.parseErr = q("parse-error-message");
    el.parseRows = q("parse-progress-rows");

    el.analysisForm = q("analysis-form");
    el.prompt = q("investigation-context");
    el.runBtn = q("run-analysis");
    el.cancelAnalysis = q("cancel-analysis");
    el.providerName = q("provider-name");
    el.settingsLink = q("provider-settings-link");
    el.analysisList = q("analysis-results-list");
    el.analysisStatusBanner = q("analysis-status-banner");
    el.analysisStatusText = q("analysis-status-text");

    el.summaryOut = q("executive-summary-content");
    el.findings = q("artifact-findings");
    el.downloadReport = q("download-report");
    el.downloadCsvs = q("download-csvs");
    el.newAnalysis = q("new-analysis");
    el.chatSection = q("chat-section");
    el.chatToggle = q("chat-toggle");
    el.chatClear = q("clear-chat");
    el.chatPanel = q("chat-panel");
    el.chatThread = q("chat-thread");
    el.chatEmptyState = q("chat-empty-state");
    el.chatForm = q("chat-form");
    el.chatInput = q("chat-input");
    el.chatSend = q("chat-send");

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
    el.setAiMaxTokensWarning = q("setting-ai-max-tokens-warning");
    el.setShortenedPromptCutoffTokens = q("setting-shortened-prompt-cutoff-tokens");
    el.setConnectionMaxTokens = q("setting-connection-max-tokens");
    el.setDateBufferDays = q("setting-date-buffer-days");
    el.setCitationSpotCheckLimit = q("setting-citation-spot-check-limit");
    el.setLocalRequestTimeoutSeconds = q("setting-local-request-timeout-seconds");
    el.setMaxMergeRounds = q("setting-max-merge-rounds");
    el.setArtifactDeduplicationEnabled = q("setting-artifact-deduplication-enabled");

    el.setAttachClaude = q("setting-attach-claude");
    el.setAttachOpenAI = q("setting-attach-openai");
    el.setAttachKimi = q("setting-attach-kimi");
    el.setAttachLocal = q("setting-attach-local");
  }

  // ── Messages & timers ──────────────────────────────────────────────────────

  /** Create status-message elements for each wizard step and settings panel. */
  function addMessages() {
    el.evidenceMsg = A.ensureMsg(el.evidenceForm, "evidence-message");
    el.artifactsMsg = A.ensureMsg(el.artifactsForm, "artifacts-message");
    el.analysisMsg = A.ensureMsg(el.analysisForm, "analysis-message");
    el.resultsMsg = A.ensureMsg(q("step-results"), "results-message");
    el.settingsMsg = A.ensureMsg(el.settingsForm, "settings-message");
    if (el.parseErr) el.parseErr.hidden = true;
  }

  /** Create elapsed-time display elements for parse and analysis steps. */
  function addTimers() {
    el.parseElapsed = A.ensureTimer(q("step-parsing"), "parse-elapsed");
    el.analysisElapsed = A.ensureTimer(q("step-analysis"), "analysis-elapsed");
  }

  // ── Wizard navigation ─────────────────────────────────────────────────────

  /** Set up wizard navigation buttons and step-indicator click handlers. */
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

  /** Inject Back/Next buttons and hint paragraphs into each wizard step. */
  function addNavButtons() {
    const total = A.STEP_IDS.length;
    const stepLabels = ["Evidence", "Artifact Selection", "Parsing", "Analysis", "Results"];
    el.steps.forEach((s) => {
      if (!s || s.querySelector(".wizard-nav")) return;
      const n = Number(s.dataset.step || 1);
      const wrap = document.createElement("div");
      wrap.className = "wizard-nav";
      if (n > 1) {
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = "Back";
        b.setAttribute("aria-label", `Back: ${stepLabels[n - 2] || "Previous"}`);
        b.addEventListener("click", () => showStep(n - 1));
        wrap.appendChild(b);
      }
      if (n < total) {
        const b = document.createElement("button");
        b.type = "button";
        b.textContent = "Next";
        b.setAttribute("aria-label", `Next: ${stepLabels[n] || "Next"}`);
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

  /** Refresh the enabled/disabled state of all Next buttons and step indicators. */
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
    el.indicators.forEach((i) => {
      const t = i.dataset.stepTarget ? q(i.dataset.stepTarget) : null;
      const n = t ? Number(t.dataset.step || 1) : 1;
      const isActive = i.classList.contains("is-active");
      const blocked = !isActive && !canGo(n);
      i.classList.toggle("is-disabled", blocked);
      i.classList.toggle("is-visited", !blocked && !isActive);
      if (blocked) i.title = navBlockReason(n);
      else i.removeAttribute("title");
    });
  }

  /**
   * Navigate to a wizard step by number (1-based).
   *
   * Updates visibility, indicator highlights, navigation state, and
   * triggers side effects (e.g. loading chat history when entering Step 5).
   *
   * @param {number} n - Target step number.
   */
  function showStep(n) {
    const priorStep = st.step;
    const rawStep = Number(n);
    const normalizedStep = Number.isFinite(rawStep) ? Math.trunc(rawStep) : 1;
    st.step = Math.max(1, Math.min(A.STEP_IDS.length, normalizedStep));
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
    syncEvidenceBanner();
    if (st.step === 5 && priorStep !== 5) {
      A.loadChatHistory().catch((e) => A.setMsg(el.resultsMsg, `Unable to load chat history: ${e.message}`, "error"));
    }
  }

  /** Show or hide the evidence-loaded banner based on whether a case is active. */
  function syncEvidenceBanner() {
    if (!el.evidenceLoadedBanner) return;
    el.evidenceLoadedBanner.hidden = !A.activeCaseId();
  }

  /** Return true if the user can navigate to step n. @param {number} n */
  function canGo(n) {
    return !navBlockReason(n);
  }

  /**
   * Return a human-readable reason why step n is blocked, or "" if accessible.
   *
   * @param {number} n - Target step number.
   * @returns {string} Blocking reason, or empty string.
   */
  function navBlockReason(n) {
    const rawStep = Number(n);
    if (!Number.isFinite(rawStep)) return "";
    const step = Math.trunc(rawStep);
    if (step <= 1) return "";
    if (step === 2) return A.activeCaseId() ? "" : "Submit evidence first.";
    if (step === 3) return st.selected.length > 0 ? "" : "Select artifacts and click Parse Selected first.";
    if (step === 4) {
      if (st.parse.done && st.selectedAi.length > 0) return "";
      if (st.parse.done && st.selectedAi.length === 0) return "No artifacts are set to \u201cParse and use in AI.\u201d Re-parse with AI-enabled artifacts to unlock analysis.";
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

  /** Display the navigation-blocked reason as an error in the relevant step. */
  function blockedMsg(n) {
    const reason = navBlockReason(n);
    if (!reason) return;
    if (n === 2) return A.setMsg(el.evidenceMsg, reason, "error");
    if (n === 3) return A.setMsg(el.artifactsMsg, reason, "error");
    if (n === 4) return A.setMsg(el.parseErr, reason, "error");
    if (n === 5) return A.setMsg(el.analysisMsg, reason, "error");
  }

  // ── Full case reset ────────────────────────────────────────────────────────

  /** Reset the entire application UI to its initial state (no active case). */
  function resetCaseUi() {
    A.closeParseSse();
    A.closeAnalysisSse();
    A.closeChatSse();
    A.stopTimer("parse");
    A.stopTimer("analysis");

    A.setCaseId("");
    st.caseName = "";
    st.artifacts = [];
    st.artifactNames = {};
    st.selected = [];
    st.selectedAi = [];
    st.pendingFiles = [];

    A.resetParseState();
    A.resetAnalysisState();
    A.resetChatState();

    if (el.evidenceForm) el.evidenceForm.reset();
    if (el.modePath) el.modePath.checked = true;
    A.syncMode();
    A.setPendingFiles([]);
    if (el.analysisDateStart) el.analysisDateStart.value = "";
    if (el.analysisDateEnd) el.analysisDateEnd.value = "";
    if (el.profileName) el.profileName.value = "";
    if (el.profileSelect) el.profileSelect.value = A.RECOMMENDED_PROFILE;

    if (el.summaryCard) el.summaryCard.hidden = true;
    if (el.sumHost) el.sumHost.textContent = "-";
    if (el.sumOs) el.sumOs.textContent = "-";
    if (el.sumDomain) el.sumDomain.textContent = "-";
    if (el.sumIps) el.sumIps.textContent = "-";
    if (el.sumSha) el.sumSha.textContent = "-";

    A.artifactBoxes().forEach((cb) => {
      cb.checked = false;
      cb.disabled = true;
      const select = A.ensureArtifactModeControl(cb, A.MODE_PARSE_AND_AI);
      if (select) select.value = A.MODE_PARSE_AND_AI;
      A.syncArtifactModeControl(cb, select);
      const li = cb.closest("li");
      if (li) {
        li.classList.add("artifact-unavailable");
        li.dataset.available = "false";
        li.title = "Load evidence to detect availability";
      }
    });
    A.clearDynamicArtifacts();
    if (el.parseBtn) el.parseBtn.disabled = true;
    if (el.evidenceProgWrap) el.evidenceProgWrap.hidden = true;
    if (el.evidenceProg) el.evidenceProg.value = 0;

    [el.evidenceMsg, el.artifactsMsg, el.parseErr, el.analysisMsg, el.resultsMsg].forEach(A.clearMsg);
    A.renderParsePlaceholder();
    A.renderAnalysis();
    A.renderExecSummary();
    A.renderFindings();

    if (el.runBtn) el.runBtn.disabled = false;
    A.updateCsvOutputHelp();
    updateNav();
    syncEvidenceBanner();
  }

  // ── Expose functions needed by other modules ───────────────────────────────
  A.showStep = showStep;
  A.updateNav = updateNav;
  A.resetCaseUi = resetCaseUi;
})();
