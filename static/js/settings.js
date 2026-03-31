/**
 * Settings panel, provider configuration, and connection testing for AIFT.
 *
 * Manages the settings overlay: loading/saving config, provider field
 * toggling, advanced settings, CSV output path help, and the
 * "Test Connection" button with progress feedback.
 *
 * Depends on: AIFT (utils.js)
 */
"use strict";

(() => {
  const A = window.AIFT;
  const { st, el, q } = A;

  // ── Setup ──────────────────────────────────────────────────────────────────

  /** Wire up the settings panel: tabs, open/close, provider, CSV help, form submit. */
  function setupSettings() {
    if (!el.settingsBtn || !el.settingsPanel || !el.settingsForm) return;
    ensureTestButton();
    if (el.settingsTabButtons.length) {
      el.settingsTabButtons.forEach((button) => {
        button.addEventListener("click", () => {
          showSettingsTab(String(button.dataset.settingsTab || "basic"));
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
    if (el.setAiMaxTokens) {
      el.setAiMaxTokens.addEventListener("input", updateAiMaxTokensWarning);
      el.setAiMaxTokens.addEventListener("change", updateAiMaxTokensWarning);
    }
    el.settingsForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await saveSettings();
    });
    document.addEventListener("keydown", (e) => {
      if (e.key === "Escape" && !el.settingsPanel.hidden) closeSettings();
    });
    const backdrop = q("settings-backdrop");
    if (backdrop) {
      backdrop.addEventListener("click", () => closeSettings());
    }
    syncProviderFields();
    showSettingsTab(st.settingsTab || "basic");
  }

  /** Create the "Test Connection" button if it doesn't exist yet. */
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

  /** Returns all focusable elements inside the settings panel. */
  function getFocusableElements() {
    if (!el.settingsPanel) return [];
    return Array.from(
      el.settingsPanel.querySelectorAll(
        'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
      )
    );
  }

  /** Traps Tab focus within the settings modal. */
  function handleFocusTrap(e) {
    if (e.key !== "Tab") return;
    const focusable = getFocusableElements();
    if (!focusable.length) return;
    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    if (e.shiftKey) {
      if (document.activeElement === first) { e.preventDefault(); last.focus(); }
    } else {
      if (document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  }

  /** Sets inert on main page content so background is non-interactive. */
  function setBackgroundInert(inert) {
    const main = document.querySelector("main#wizard");
    const header = document.querySelector(".app-header");
    const footer = document.querySelector(".app-footer");
    [main, header, footer].forEach((node) => {
      if (!node) return;
      if (inert) node.setAttribute("inert", "");
      else node.removeAttribute("inert");
    });
  }

  /** Open the settings modal, show backdrop, trap focus, and refresh data. */
  function openSettings() {
    if (!el.settingsPanel || !el.settingsBtn) return;
    const backdrop = q("settings-backdrop");
    if (backdrop) backdrop.hidden = false;
    el.settingsPanel.hidden = false;
    el.settingsBtn.setAttribute("aria-expanded", "true");
    setBackgroundInert(true);
    showSettingsTab(st.settingsTab || "basic");
    // Move focus into the dialog
    const focusable = getFocusableElements();
    if (focusable.length) focusable[0].focus();
    el.settingsPanel.addEventListener("keydown", handleFocusTrap);
    loadSettings().catch((e) => A.setMsg(el.settingsMsg, `Unable to refresh settings: ${e.message}`, "error"));
  }

  /** Close the settings modal, hide backdrop, and release focus trap. */
  function closeSettings() {
    if (!el.settingsPanel || !el.settingsBtn) return;
    el.settingsPanel.removeEventListener("keydown", handleFocusTrap);
    el.settingsPanel.hidden = true;
    const backdrop = q("settings-backdrop");
    if (backdrop) backdrop.hidden = true;
    setBackgroundInert(false);
    el.settingsBtn.setAttribute("aria-expanded", "false");
    el.settingsBtn.focus();
  }

  /**
   * Activate a settings tab ("basic" or "advanced") and show its panel.
   *
   * @param {string} tabName - "basic" or "advanced".
   */
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

  // ── Load / Apply / Save ────────────────────────────────────────────────────

  /** Fetch settings from the backend and apply them to the form. */
  async function loadSettings() {
    const s = await A.apiJson("/api/settings", { method: "GET" });
    st.settings = s;
    applySettings(s);
    updateProviderFromSettings(s);
    A.clearMsg(el.settingsMsg);
  }

  /** Populate all settings form fields from a settings object. @param {Object} s */
  function applySettings(s) {
    if (!A.isObj(s)) return;
    const ai = A.obj(s.ai);
    const backend = A.normProvider(String(ai.provider || "claude"));
    if (el.setProvider) el.setProvider.value = A.toUiProvider(backend);
    if (el.setPort) el.setPort.value = String(A.num(A.obj(s.server).port, 5000));
    if (el.setSize) {
      var threshMb = A.num(A.obj(s.evidence).large_file_threshold_mb, 0);
      el.setSize.value = threshMb === 0 ? "0" : A.fmtNumber(threshMb / 1024, 3);
    }
    if (el.setCsvOutputDir) el.setCsvOutputDir.value = String(A.obj(s.evidence).csv_output_dir || "");
    updateCsvOutputHelp();
    applyAdvancedSettings(s);
    fillProviderFields();
    syncProviderFields();
  }

  /** Populate the advanced-tab settings fields from a settings object. @param {Object} s */
  function applyAdvancedSettings(s) {
    if (!A.isObj(s)) return;
    const analysis = A.obj(s.analysis);
    setNumberInput(el.setAiMaxTokens, A.num(analysis.ai_max_tokens, 128000), 128000);
    setNumberInput(
      el.setShortenedPromptCutoffTokens,
      A.num(analysis.shortened_prompt_cutoff_tokens, A.num(analysis.statistics_section_cutoff_tokens, 64000)),
      64000
    );
    setNumberInput(el.setConnectionMaxTokens, A.num(analysis.connection_test_max_tokens, 256), 256);
    setNumberInput(el.setCitationSpotCheckLimit, A.num(analysis.citation_spot_check_limit, 20), 20);
    setNumberInput(el.setIntakeTimeoutSeconds, A.num(A.obj(s.evidence).intake_timeout_seconds, 7200), 7200);
    setNumberInput(
      el.setLocalRequestTimeoutSeconds,
      A.num(A.obj(A.obj(s.ai).local).request_timeout_seconds, 3600),
      3600
    );
    setNumberInput(el.setMaxMergeRounds, A.num(analysis.max_merge_rounds, 5), 5);
    updateAiMaxTokensWarning();
    if (el.setArtifactDeduplicationEnabled) {
      el.setArtifactDeduplicationEnabled.checked = A.boolSetting(analysis.artifact_deduplication_enabled, true);
    }

    const ai = A.obj(s.ai);
    if (el.setAttachClaude) el.setAttachClaude.checked = A.boolSetting(A.obj(ai.claude).attach_csv_as_file, true);
    if (el.setAttachOpenAI) el.setAttachOpenAI.checked = A.boolSetting(A.obj(ai.openai).attach_csv_as_file, true);
    if (el.setAttachKimi) el.setAttachKimi.checked = A.boolSetting(A.obj(ai.kimi).attach_csv_as_file, true);
    if (el.setAttachLocal) el.setAttachLocal.checked = A.boolSetting(A.obj(ai.local).attach_csv_as_file, true);
  }

  /** Set a number input's value, falling back to a default if not finite. */
  function setNumberInput(input, value, fallback) {
    if (!input) return;
    const numeric = typeof value === "number" && Number.isFinite(value) ? value : fallback;
    input.value = String(numeric);
  }

  /** Show/hide the AI max-tokens warning based on the current input value. */
  function updateAiMaxTokensWarning() {
    if (!el.setAiMaxTokensWarning || !el.setAiMaxTokens) return;
    const parsed = A.num(A.val(el.setAiMaxTokens), null);
    const shouldWarn = typeof parsed === "number"
      && Number.isFinite(parsed)
      && parsed < A.AI_MAX_TOKENS_WARNING_THRESHOLD;
    el.setAiMaxTokensWarning.hidden = !shouldWarn;
  }

  /**
   * Build a settings payload from the form and save it to the backend.
   *
   * @param {Object} [opts={}] - Options.
   * @param {boolean} [opts.silent] - Suppress the success toast.
   * @returns {Promise<boolean>} True if saved successfully.
   */
  async function saveSettings(opts = {}) {
    const silent = !!opts.silent;
    A.clearMsg(el.settingsMsg);
    try {
      const payload = buildSettingsPayload();
      const saved = await A.apiJson("/api/settings", { method: "POST", json: payload });
      st.settings = saved;
      applySettings(saved);
      updateProviderFromSettings(saved);
      if (!silent) A.setMsg(el.settingsMsg, "Settings saved.", "success");
      return true;
    } catch (e) {
      A.setMsg(el.settingsMsg, `Failed to save settings: ${e.message}`, "error");
      return false;
    }
  }

  /** Construct the settings JSON payload from all form fields and current state. */
  function buildSettingsPayload() {
    const base = A.clone(st.settings || {});
    if (!A.isObj(base.ai)) base.ai = {};
    if (!A.isObj(base.ai.claude)) base.ai.claude = {};
    if (!A.isObj(base.ai.openai)) base.ai.openai = {};
    if (!A.isObj(base.ai.kimi)) base.ai.kimi = {};
    if (!A.isObj(base.ai.local)) base.ai.local = {};
    if (!A.isObj(base.server)) base.server = {};
    if (!A.isObj(base.evidence)) base.evidence = {};
    if (!A.isObj(base.analysis)) base.analysis = {};

    const provider = A.toBackendProvider(el.setProvider ? el.setProvider.value : "openai");
    base.ai.provider = provider;
    if (!A.isObj(base.ai[provider])) base.ai[provider] = {};
    base.ai[provider].model = A.val(el.setModel) || "";

    if (provider === "local") {
      const url = A.val(el.setLocalUrl);
      base.ai.local.base_url = url || base.ai.local.base_url || "http://localhost:11434/v1";
      const existingLocalApiKey = String(base.ai.local.api_key || "").trim();
      base.ai.local.api_key = existingLocalApiKey || "not-needed";
    } else if (provider === "kimi") {
      const url = A.val(el.setLocalUrl);
      base.ai.kimi.base_url = url || base.ai.kimi.base_url || "https://api.moonshot.ai/v1";
      base.ai.kimi.api_key = A.val(el.setApiKey) || "";
    } else {
      base.ai[provider].api_key = A.val(el.setApiKey) || "";
    }

    const port = A.num(A.val(el.setPort), null);
    if (typeof port === "number" && Number.isFinite(port) && port > 0) base.server.port = port;

    const gb = A.num(A.val(el.setSize), null);
    if (typeof gb === "number" && Number.isFinite(gb) && gb >= 0) base.evidence.large_file_threshold_mb = Math.round(gb * 1024);
    if (el.setCsvOutputDir) base.evidence.csv_output_dir = A.val(el.setCsvOutputDir);
    base.evidence.intake_timeout_seconds = readIntInput(el.setIntakeTimeoutSeconds, 7200, 60);

    base.analysis.ai_max_tokens = readIntInput(el.setAiMaxTokens, 128000, 1);
    base.analysis.shortened_prompt_cutoff_tokens = readIntInput(el.setShortenedPromptCutoffTokens, 64000, 1);
    base.analysis.connection_test_max_tokens = readIntInput(el.setConnectionMaxTokens, 256, 1);
    base.analysis.citation_spot_check_limit = readIntInput(el.setCitationSpotCheckLimit, 20, 1);
    base.analysis.max_merge_rounds = readIntInput(el.setMaxMergeRounds, 5, 1);
    base.ai.local.request_timeout_seconds = readIntInput(el.setLocalRequestTimeoutSeconds, 3600, 1);
    if (el.setArtifactDeduplicationEnabled) {
      base.analysis.artifact_deduplication_enabled = !!el.setArtifactDeduplicationEnabled.checked;
    }

    if (el.setAttachClaude) base.ai.claude.attach_csv_as_file = !!el.setAttachClaude.checked;
    if (el.setAttachOpenAI) base.ai.openai.attach_csv_as_file = !!el.setAttachOpenAI.checked;
    if (el.setAttachKimi) base.ai.kimi.attach_csv_as_file = !!el.setAttachKimi.checked;
    if (el.setAttachLocal) base.ai.local.attach_csv_as_file = !!el.setAttachLocal.checked;

    return base;
  }

  /**
   * Read an integer from a number input, clamped to a minimum.
   *
   * @param {HTMLInputElement|null} input - The input element.
   * @param {number} fallback - Default when the input is empty or invalid.
   * @param {number} [minValue=1] - Minimum allowed value.
   * @returns {number}
   */
  function readIntInput(input, fallback, minValue = 1) {
    const parsed = A.num(A.val(input), null);
    if (typeof parsed !== "number" || !Number.isFinite(parsed)) return fallback;
    return Math.max(minValue, Math.round(parsed));
  }

  // ── Provider fields ────────────────────────────────────────────────────────

  /** Fill API key, model, and endpoint URL fields from the stored settings for the selected provider. */
  function fillProviderFields() {
    if (!A.isObj(st.settings) || !el.setProvider) return;
    const provider = A.toBackendProvider(el.setProvider.value);
    const ai = A.obj(st.settings.ai);
    const pc = A.obj(ai[provider]);
    if (el.setApiKey) el.setApiKey.value = String(pc.api_key || "");
    if (el.setModel) el.setModel.value = String(pc.model || "");
    if (el.setLocalUrl) {
      if (provider === "local" || provider === "kimi") {
        el.setLocalUrl.value = String(pc.base_url || "");
      } else {
        el.setLocalUrl.value = String(A.obj(ai.local).base_url || "");
      }
    }
  }

  /** Show/hide and relabel provider-specific form rows based on the selected provider. */
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
      else if (p === "openai") el.setModel.placeholder = "gpt-5.4";
      else if (p === "kimi") el.setModel.placeholder = "kimi-k2-turbo-preview";
      else el.setModel.placeholder = "llama3.1:70b";
    }
  }

  /** Update the analysis step's provider name display from a settings object. */
  function updateProviderFromSettings(s) {
    const ai = A.obj(s.ai);
    const p = A.normProvider(String(ai.provider || ""));
    const model = String(A.obj(ai[p]).model || "");
    if (!p) return A.setProvider("Not configured");
    const label = A.prettyProvider(p);
    A.setProvider(model ? `${label} (${model})` : label);
  }

  // ── CSV output path help ───────────────────────────────────────────────────

  /** Return the default CSV output path for the active case. */
  function defaultCsvOutputForCurrentCase() {
    const caseId = A.activeCaseId();
    if (caseId) return `cases/${caseId}/parsed`;
    return "cases/<case_id>/parsed";
  }

  /** Build the effective CSV output path from a configured root directory. */
  function configuredCsvOutputForCurrentCase(rootPath) {
    const text = String(rootPath || "").trim();
    if (!text) return "";
    const trimmed = text.replace(/[\\/]+$/, "");
    const sep = trimmed.includes("\\") ? "\\" : "/";
    const caseToken = A.activeCaseId() || "<case_id>";
    return `${trimmed}${sep}${caseToken}${sep}parsed`;
  }

  /** Update the CSV output path help text below the input field. */
  function updateCsvOutputHelp() {
    if (!el.setCsvOutputHelp) return;
    const configuredPath = A.val(el.setCsvOutputDir);
    const defaultPath = defaultCsvOutputForCurrentCase();
    if (configuredPath) {
      const effectivePath = configuredCsvOutputForCurrentCase(configuredPath);
      el.setCsvOutputHelp.textContent = `Currently using: ${effectivePath}`;
      return;
    }
    el.setCsvOutputHelp.textContent = `Currently using: ${defaultPath}`;
  }

  // ── Connection test ────────────────────────────────────────────────────────

  /** Save current settings, then test the AI provider connection. */
  async function testConnection() {
    A.clearMsg(el.settingsMsg);
    if (st.analysis.run) return A.setMsg(el.settingsMsg, "Stop active analysis before running connection test.", "error");
    const stopProgressFeedback = startConnectionTestFeedback();
    if (el.testBtn) {
      el.testBtn.disabled = true;
      el.testBtn.setAttribute("aria-busy", "true");
    }
    try {
      const ok = await saveSettings({ silent: true });
      if (!ok) return;
      const result = await A.apiJson("/api/settings/test-connection", { method: "POST" });
      const modelInfo = A.isObj(result && result.model_info) ? result.model_info : {};
      const provider = A.prettyProvider(String(modelInfo.provider || ""));
      const model = String(modelInfo.model || "").trim();
      const providerText = model ? `${provider} (${model})` : provider;
      const suffix = providerText && providerText !== "Unknown" ? `: ${providerText}` : "";
      A.setMsg(el.settingsMsg, `Connection test succeeded${suffix}.`, "success");
    } catch (e) {
      A.setMsg(el.settingsMsg, `Connection test failed: ${e.message}`, "error");
    } finally {
      stopProgressFeedback();
      if (el.testBtn) {
        el.testBtn.disabled = false;
        el.testBtn.removeAttribute("aria-busy");
        el.testBtn.textContent = "Test Connection";
      }
    }
  }

  /**
   * Start a visual feedback ticker for the connection test.
   *
   * @returns {function} Stop function — call to clear the interval.
   */
  function startConnectionTestFeedback() {
    const startedAt = Date.now();
    let frame = 0;
    let ticker = 0;
    const tick = () => {
      const dots = ".".repeat((frame % 3) + 1);
      frame += 1;
      if (el.testBtn) el.testBtn.textContent = `Testing${dots}`;
      A.setMsg(el.settingsMsg, `Testing provider connection${dots} (${A.fmtElapsed(startedAt)})`, "info");
    };
    tick();
    ticker = window.setInterval(tick, 1000);
    return () => {
      if (ticker) { window.clearInterval(ticker); ticker = 0; }
    };
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  A.setupSettings = setupSettings;
  A.openSettings = openSettings;
  A.loadSettings = loadSettings;
  A.updateCsvOutputHelp = updateCsvOutputHelp;
})();
