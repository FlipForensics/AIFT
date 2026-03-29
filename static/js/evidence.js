/**
 * Evidence intake and artifact selection / profile management for AIFT.
 *
 * Handles file upload, dropzone, evidence submission, artifact checkboxes,
 * artifact mode controls (parse-only vs parse+AI), and artifact profiles.
 *
 * Depends on: AIFT (utils.js)
 */
"use strict";

(() => {
  const A = window.AIFT;
  const { st, el, q } = A;

  // ── Evidence intake ────────────────────────────────────────────────────────

  /** Wire up the evidence form: mode toggle, file input, dropzone, and submit handler. */
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

  /** Show/hide upload vs. path panels based on the selected intake mode radio. */
  function syncMode() {
    const pathMode = !!(el.modePath && el.modePath.checked);
    if (el.uploadPanel) el.uploadPanel.hidden = pathMode;
    if (el.pathPanel) el.pathPanel.hidden = !pathMode;
  }

  /** Initialise drag-and-drop event listeners on the dropzone element. */
  function initDropzone() {
    if (!el.drop) return;
    const prevent = (e) => { e.preventDefault(); e.stopPropagation(); };
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
      } catch (_err) { /* fallback: use st.pendingFiles */ }
    });
  }

  /**
   * Store pending evidence files and update the dropzone help text.
   *
   * @param {File[]} files - Array of File objects selected by the user.
   */
  function setPendingFiles(files) {
    st.pendingFiles = Array.isArray(files) ? files.filter(Boolean) : [];
    if (!el.dropHelp) return;
    if (!st.pendingFiles.length) {
      el.dropHelp.textContent = A.DROP_HELP;
      return;
    }
    if (st.pendingFiles.length === 1) {
      const file = st.pendingFiles[0];
      el.dropHelp.textContent = `${file.name}${Number.isFinite(file.size) ? ` (${A.fmtBytes(file.size)})` : ""}`;
      return;
    }
    const totalSize = st.pendingFiles.reduce((sum, file) => sum + (Number.isFinite(file.size) ? file.size : 0), 0);
    el.dropHelp.textContent = `${st.pendingFiles.length} files selected (${A.fmtBytes(totalSize)})`;
  }

  /** Return the files to upload from either the file input or pending state. */
  function selectedFiles() {
    if (el.file && el.file.files && el.file.files.length) return Array.from(el.file.files);
    return Array.from(st.pendingFiles || []);
  }

  /** Strip curly/smart quotes and whitespace from a user-supplied evidence path. */
  function sanitizeEvidencePath(raw) {
    return String(raw || "").replace(/["\u201c\u201d]/g, "").trim();
  }

  /**
   * Submit evidence to the backend: create a case, upload/link evidence,
   * populate artifacts, and advance to Step 2.
   */
  async function submitEvidence() {
    A.clearMsg(el.evidenceMsg);
    A.clearMsg(el.artifactsMsg);
    A.clearMsg(el.parseErr);

    const uploadMode = !!(el.modeUpload && el.modeUpload.checked);
    const files = selectedFiles();
    const path = sanitizeEvidencePath(A.val(el.path));
    if (uploadMode && files.length === 0) return A.setMsg(el.evidenceMsg, "Choose one or more evidence files first.", "error");
    if (!uploadMode && !path) return A.setMsg(el.evidenceMsg, "Enter a local evidence path.", "error");
    if (!uploadMode && el.path && el.path.value !== path) el.path.value = path;

    setEvidenceBusy(true);
    const intakeProgress = createIntakeProgressTracker();
    try {
      const c = await A.apiJson("/api/cases", { method: "POST", json: { case_name: A.val(el.caseName) } });
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
        ev = await A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/evidence`, { method: "POST", body: fd, timeout: A.FETCH_TIMEOUT_UPLOAD_MS });
      } else {
        ev = await A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/evidence`, { method: "POST", json: { path }, timeout: A.FETCH_TIMEOUT_UPLOAD_MS });
      }
      intakeProgress.complete();
      A.setCaseId(caseId);
      A.updateCsvOutputHelp();
      applyEvidence(ev);
      A.setMsg(el.evidenceMsg, "Evidence intake complete.", "success");
      A.showStep(2);
    } catch (e) {
      A.setMsg(el.evidenceMsg, `Evidence intake failed: ${e.message}`, "error");
    } finally {
      intakeProgress.stop();
      setEvidenceBusy(false);
      A.updateNav();
    }
  }

  /**
   * Create a progress tracker for the evidence intake operation.
   *
   * Returns an object with setPhase/complete/stop methods that drive the
   * progress bar and elapsed-time message during upload.
   *
   * @returns {{setPhase: function, complete: function, stop: function}}
   */
  function createIntakeProgressTracker() {
    if (!el.evidenceProg) return { setPhase: () => {}, complete: () => {}, stop: () => {} };
    let cap = 30;
    let barTicker = 0;
    let msgTicker = 0;
    const startedAt = Date.now();

    const updateMessage = () => {
      A.setMsg(el.evidenceMsg, `Intake in progress... (${A.fmtElapsed(startedAt)})`, "info");
    };

    const tickProgress = () => {
      const current = A.num(el.evidenceProg.value, 0);
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
      complete: () => { cap = 100; el.evidenceProg.value = 100; },
      stop: () => {
        if (barTicker) { window.clearInterval(barTicker); barTicker = 0; }
        if (msgTicker) { window.clearInterval(msgTicker); msgTicker = 0; }
      },
    };
  }

  /** Toggle the evidence submit button and progress bar visibility. @param {boolean} on */
  function setEvidenceBusy(on) {
    if (el.submitEvidence) el.submitEvidence.disabled = on;
    if (el.evidenceProgWrap) el.evidenceProgWrap.hidden = !on;
  }

  /**
   * Apply evidence intake response data to the UI.
   *
   * Populates artifact checkboxes, renders the evidence summary card, and
   * handles the unsupported-evidence error state.
   *
   * @param {Object} data - Backend response from the evidence endpoint.
   */
  function applyEvidence(data) {
    st.artifacts = Array.isArray(data.available_artifacts) ? data.available_artifacts : [];
    st.artifactNames = {};
    st.artifacts.forEach((a) => {
      if (a && a.key) st.artifactNames[String(a.key)] = String(a.name || a.key);
    });

    A.resetParseState();
    A.resetAnalysisState();
    st.selected = [];
    st.selectedAi = [];

    renderSummary(data.metadata || {}, data.hashes || {}, data.os_type || "");

    /* Log OS detection warning when the backend could not determine the OS.
       The unsupported-evidence error box below handles the visual feedback. */
    if (data.os_warning) {
      console.warn("[AIFT] OS detection warning:", data.os_warning);
    }

    const osVersion = String((data.metadata || {}).os_version || "").trim().toLowerCase();
    const isUnsupported = !osVersion || osVersion === "unknown" || osVersion === "-";
    const errorBox = document.getElementById("unsupported-evidence-error");
    const hintEl = document.getElementById("unsupported-evidence-hint");
    const artifactContent = document.getElementById("artifact-selection-content");

    if (isUnsupported && errorBox) {
      errorBox.hidden = false;
      if (hintEl) {
        const wasUpload = !!(el.modeUpload && el.modeUpload.checked);
        hintEl.hidden = !wasUpload;
      }
      if (artifactContent) artifactContent.hidden = true;
    } else {
      if (errorBox) errorBox.hidden = true;
      if (artifactContent) artifactContent.hidden = false;
      populateArtifacts(st.artifacts);
    }

    A.renderParsePlaceholder();
    A.renderAnalysis();
    A.renderExecSummary();
    A.renderFindings();
    updateParseButton();
  }

  /**
   * Populate the evidence summary card with metadata and hashes.
   *
   * @param {Object} m - Metadata object (hostname, os_version, domain, ips).
   * @param {Object} h - Hashes object (sha256).
   * @param {string} osType - Detected OS type ("windows", "linux", etc.).
   */
  function renderSummary(m, h, osType) {
    if (el.sumHost) el.sumHost.textContent = String(m.hostname || "-");

    /* Build the OS display string: include the OS type label when it
       differs meaningfully from the version string (e.g. "Linux" prefix
       for a version like "Ubuntu 22.04"). */
    var osVersion = String(m.os_version || "-");
    var osLabel = String(osType || "").trim().toLowerCase();
    if (osLabel && osLabel !== "unknown" && osVersion !== "-") {
      var versionLower = osVersion.toLowerCase();
      /* Only prepend the type if it is not already part of the version. */
      if (versionLower.indexOf(osLabel) === -1) {
        var capitalized = osLabel.charAt(0).toUpperCase() + osLabel.slice(1);
        osVersion = capitalized + " \u2014 " + osVersion;
      }
    }
    if (el.sumOs) el.sumOs.textContent = osVersion;

    if (el.sumDomain) el.sumDomain.textContent = String(m.domain || "-");
    if (el.sumIps) el.sumIps.textContent = String(m.ips || "-");
    if (el.sumSha) el.sumSha.textContent = String(h.sha256 || "-");
    if (el.summaryCard) el.summaryCard.hidden = false;
  }

  // ── Artifact checkboxes & mode controls ────────────────────────────────────

  /** Return all artifact checkbox `<input>` elements in the artifacts form. */
  function artifactBoxes() {
    return el.artifactsForm
      ? Array.from(el.artifactsForm.querySelectorAll("input[type='checkbox'][data-artifact-key]"))
      : [];
  }

  /**
   * Find the `<select>` mode dropdown for a given artifact key.
   *
   * @param {string} artifactKey - The artifact key to look up.
   * @returns {HTMLSelectElement|null}
   */
  function artifactModeSelectForKey(artifactKey) {
    if (!el.artifactsForm) return null;
    const key = String(artifactKey || "");
    if (!key) return null;
    const selects = Array.from(el.artifactsForm.querySelectorAll("select.artifact-mode-select[data-artifact-key]"));
    return selects.find((select) => String(select.dataset.artifactKey || "") === key) || null;
  }

  /** Normalise a mode string to MODE_PARSE_ONLY or MODE_PARSE_AND_AI. */
  function artifactModeValue(rawMode) {
    return String(rawMode || "").trim().toLowerCase() === A.MODE_PARSE_ONLY ? A.MODE_PARSE_ONLY : A.MODE_PARSE_AND_AI;
  }

  /**
   * Synchronise a mode `<select>` with its parent checkbox's state.
   *
   * Disables the select when the checkbox is unchecked or disabled.
   *
   * @param {HTMLInputElement} cb - The artifact checkbox.
   * @param {HTMLSelectElement|null} [modeSelect] - Override for the select element.
   */
  function syncArtifactModeControl(cb, modeSelect = null) {
    if (!(cb instanceof HTMLInputElement)) return;
    const select = modeSelect || artifactModeSelectForKey(cb.dataset.artifactKey || "");
    if (!select) return;
    select.disabled = cb.disabled || !cb.checked;
    if (!select.disabled) select.value = artifactModeValue(select.value);
  }

  /**
   * Ensure a mode `<select>` dropdown exists for an artifact checkbox,
   * creating one if necessary.
   *
   * @param {HTMLInputElement} cb - The artifact checkbox element.
   * @param {string} [preferredMode=MODE_PARSE_AND_AI] - Initial mode value.
   * @returns {HTMLSelectElement|null} The mode select element.
   */
  function ensureArtifactModeControl(cb, preferredMode = A.MODE_PARSE_AND_AI) {
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
      const artifactName = st.artifactNames[key] || key;
      select.setAttribute("aria-label", `Analysis mode for ${artifactName}`);

      const parseAiOption = document.createElement("option");
      parseAiOption.value = A.MODE_PARSE_AND_AI;
      parseAiOption.textContent = "Parse and use in AI";
      select.appendChild(parseAiOption);

      const parseOnlyOption = document.createElement("option");
      parseOnlyOption.value = A.MODE_PARSE_ONLY;
      parseOnlyOption.textContent = "Parse only";
      select.appendChild(parseOnlyOption);

      li.appendChild(select);
    }
    select.value = artifactModeValue(preferredMode);
    syncArtifactModeControl(cb, select);
    return select;
  }

  /** Ensure all artifact checkboxes have an associated mode `<select>`. */
  function ensureArtifactModeControls() {
    artifactBoxes().forEach((cb) => {
      const select = ensureArtifactModeControl(cb, A.MODE_PARSE_AND_AI);
      syncArtifactModeControl(cb, select);
    });
  }

  /** Update the visible text of a checkbox's parent `<label>`. */
  function setLabelText(cb, text) {
    const label = cb.closest("label");
    if (!label) return;
    const txt = Array.from(label.childNodes).find((n) => n.nodeType === Node.TEXT_NODE);
    if (txt) txt.textContent = ` ${text}`;
    else label.appendChild(document.createTextNode(` ${text}`));
  }

  /** Remove the dynamically-created "Additional" artifact category from the DOM. */
  function clearDynamicArtifacts() {
    const d = q("dynamic-artifact-category");
    if (d) d.remove();
  }

  /**
   * Populate the artifact selection UI from the backend's available-artifact list.
   *
   * Updates existing checkboxes (enabling available ones) and creates a
   * dynamic "Additional" category for any artifacts not in the static HTML.
   *
   * @param {Object[]} list - Array of artifact descriptors with key, name, available.
   */
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
      const modeSelect = ensureArtifactModeControl(cb, A.MODE_PARSE_AND_AI);
      if (modeSelect) modeSelect.value = A.MODE_PARSE_AND_AI;
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

  // ── Selection helpers ──────────────────────────────────────────────────────

  /**
   * Collect the selected artifact options (key + mode) from all checked checkboxes.
   *
   * @returns {{artifact_key: string, mode: string}[]}
   */
  function selectedArtifactOptions() {
    return artifactBoxes()
      .filter((cb) => cb.checked && !cb.disabled && cb.dataset.artifactKey)
      .map((cb) => {
        const key = String(cb.dataset.artifactKey || "");
        const select = artifactModeSelectForKey(key);
        return { artifact_key: key, mode: artifactModeValue(select ? select.value : A.MODE_PARSE_AND_AI) };
      });
  }

  /** Return an array of selected artifact keys (all modes). */
  function selectedArtifacts() {
    return selectedArtifactOptions().map((option) => option.artifact_key);
  }

  /**
   * Return artifact keys that are set to "Parse and use in AI" mode.
   *
   * @param {Object[]|null} [options] - Pre-computed options array; defaults to
   *     selectedArtifactOptions().
   * @returns {string[]}
   */
  function selectedAiArtifacts(options = null) {
    const artifactOptions = Array.isArray(options) ? options : selectedArtifactOptions();
    return artifactOptions
      .filter((option) => artifactModeValue(option.mode) === A.MODE_PARSE_AND_AI)
      .map((option) => String(option.artifact_key || ""))
      .filter(Boolean);
  }

  // ── Date range ─────────────────────────────────────────────────────────────

  /** Read start and end date strings from the analysis date-range inputs. */
  function readAnalysisDateRangeInputs() {
    return { start: A.val(el.analysisDateStart), end: A.val(el.analysisDateEnd) };
  }

  /**
   * Validate the analysis date-range inputs.
   *
   * @returns {{ok: boolean, message?: string, range?: {start_date: string, end_date: string}|null}}
   */
  function validateAnalysisDateRange() {
    const { start, end } = readAnalysisDateRangeInputs();
    if (!start && !end) return { ok: true, range: null };
    if (!start || !end) return { ok: false, message: "Provide both begin and end dates." };
    if (start > end) return { ok: false, message: "Begin date must be earlier than or equal to end date." };
    return { ok: true, range: { start_date: start, end_date: end } };
  }

  // ── Artifact profiles ──────────────────────────────────────────────────────

  /**
   * Normalise a raw profile object from the backend into a consistent shape.
   *
   * @param {Object} rawProfile - Raw profile descriptor.
   * @returns {{name: string, builtin: boolean, artifact_options: Object[]}|null}
   */
  function normalizeArtifactProfile(rawProfile) {
    if (!A.isObj(rawProfile)) return null;
    const name = String(rawProfile.name || "").trim();
    if (!name) return null;
    const options = Array.isArray(rawProfile.artifact_options) ? rawProfile.artifact_options : [];
    const artifactOptions = options
      .map((option) => (A.isObj(option) ? option : null))
      .filter(Boolean)
      .map((option) => ({
        artifact_key: String(option.artifact_key || option.key || "").trim(),
        mode: artifactModeValue(option.mode),
      }))
      .filter((option) => option.artifact_key);
    return { name, builtin: !!rawProfile.builtin, artifact_options: artifactOptions };
  }

  /** Find a profile in st.profiles by case-insensitive name match. */
  function findProfileByName(name) {
    const wanted = String(name || "").trim().toLowerCase();
    if (!wanted) return null;
    return st.profiles.find((profile) => String(profile.name || "").trim().toLowerCase() === wanted) || null;
  }

  /**
   * Rebuild the profile `<select>` dropdown options from st.profiles.
   *
   * @param {string} [preferredName=""] - Profile name to select after render.
   */
  function renderArtifactProfileOptions(preferredName = "") {
    if (!el.profileSelect) return;
    const currentValue = String(preferredName || el.profileSelect.value || A.RECOMMENDED_PROFILE).trim().toLowerCase();
    el.profileSelect.innerHTML = "";
    st.profiles.forEach((profile) => {
      const name = String(profile.name || "").trim();
      if (!name) return;
      const opt = document.createElement("option");
      opt.value = name;
      opt.textContent = profile.builtin ? `${name} (built-in)` : name;
      el.profileSelect.appendChild(opt);
    });
    const fallback = findProfileByName(A.RECOMMENDED_PROFILE);
    const selected = findProfileByName(currentValue) || fallback || (st.profiles.length ? st.profiles[0] : null);
    if (selected) el.profileSelect.value = selected.name;
  }

  /**
   * Fetch artifact profiles from the backend and populate the dropdown.
   *
   * @param {string} [preferredName=""] - Profile name to select after loading.
   */
  async function loadArtifactProfiles(preferredName = "") {
    const response = await A.apiJson("/api/artifact-profiles", { method: "GET" });
    const profilesRaw = Array.isArray(response && response.profiles) ? response.profiles : [];
    st.profiles = profilesRaw.map((profile) => normalizeArtifactProfile(profile)).filter(Boolean);
    if (!st.profiles.length) {
      st.profiles = [{ name: A.RECOMMENDED_PROFILE, builtin: true, artifact_options: [] }];
    }
    renderArtifactProfileOptions(preferredName);
  }

  /**
   * Apply a profile to the artifact checkboxes and mode selects.
   *
   * @param {Object} profile - Normalised profile object.
   * @param {Object} [opts={}] - Options.
   * @param {boolean} [opts.silent] - Suppress the success toast.
   * @returns {boolean} True if the profile was applied.
   */
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
      const mode = optionMap.get(key) || A.MODE_PARSE_AND_AI;
      const modeSelect = ensureArtifactModeControl(cb, mode);
      if (cb.disabled || !optionMap.has(key)) cb.checked = false;
      else cb.checked = true;
      if (modeSelect) modeSelect.value = mode;
      syncArtifactModeControl(cb, modeSelect);
    });
    updateParseButton();
    if (!silent) A.setMsg(el.artifactsMsg, `Loaded profile: ${profile.name}`, "success");
    return true;
  }

  /** Load and apply the currently selected profile from the dropdown. */
  function applySelectedProfile() {
    A.clearMsg(el.artifactsMsg);
    const selectedName = el.profileSelect ? el.profileSelect.value : A.RECOMMENDED_PROFILE;
    const profile = findProfileByName(selectedName);
    if (!profile) return A.setMsg(el.artifactsMsg, "Selected profile is not available.", "error");
    applyArtifactProfile(profile);
  }

  /** Save the current artifact selection as a named profile on the backend. */
  async function saveCurrentProfile() {
    A.clearMsg(el.artifactsMsg);
    const profileName = A.val(el.profileName);
    if (!profileName) return A.setMsg(el.artifactsMsg, "Enter a profile name before saving.", "error");
    if (profileName.toLowerCase() === A.RECOMMENDED_PROFILE) {
      return A.setMsg(el.artifactsMsg, "`recommended` is reserved. Pick a different name.", "error");
    }
    const options = selectedArtifactOptions();
    if (!options.length) return A.setMsg(el.artifactsMsg, "Select at least one artifact before saving a profile.", "error");
    try {
      const response = await A.apiJson("/api/artifact-profiles", { method: "POST", json: { name: profileName, artifact_options: options } });
      const profilesRaw = Array.isArray(response && response.profiles) ? response.profiles : [];
      st.profiles = profilesRaw.map((profile) => normalizeArtifactProfile(profile)).filter(Boolean);
      renderArtifactProfileOptions(profileName);
      if (el.profileName) el.profileName.value = "";
      A.setMsg(el.artifactsMsg, `Profile saved: ${profileName}`, "success");
    } catch (e) {
      A.setMsg(el.artifactsMsg, `Failed to save profile: ${e.message}`, "error");
    }
  }

  // ── Artifact step wiring ───────────────────────────────────────────────────

  /** Wire up event listeners for the artifact selection step (Step 2). */
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
        const recommendedProfile = findProfileByName(A.RECOMMENDED_PROFILE);
        if (recommendedProfile) return applyArtifactProfile(recommendedProfile);
        return applyPreset("recommended");
      });
    }
    if (el.clearBtn) el.clearBtn.addEventListener("click", () => applyPreset("clear"));
    if (el.profileLoadBtn) el.profileLoadBtn.addEventListener("click", () => applySelectedProfile());
    if (el.profileSaveBtn) el.profileSaveBtn.addEventListener("click", async () => saveCurrentProfile());
    el.artifactsForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await A.submitParse();
    });
    if (el.cancelParse) el.cancelParse.addEventListener("click", A.cancelParse);
  }

  /**
   * Apply a checkbox preset ("recommended" selects most, "clear" unchecks all).
   *
   * @param {string} mode - "recommended" or "clear".
   */
  function applyPreset(mode) {
    artifactBoxes().forEach((cb) => {
      const select = ensureArtifactModeControl(cb, A.MODE_PARSE_AND_AI);
      if (cb.disabled) {
        cb.checked = false;
        if (select) select.value = A.MODE_PARSE_AND_AI;
        return syncArtifactModeControl(cb, select);
      }
      if (mode === "clear") cb.checked = false;
      else cb.checked = !A.RECOMMENDED_PRESET_EXCLUDED_ARTIFACTS.has(String(cb.dataset.artifactKey || "").trim().toLowerCase());
      if (select) select.value = A.MODE_PARSE_AND_AI;
      syncArtifactModeControl(cb, select);
    });
    updateParseButton();
  }

  /** Update the parse button's disabled state, label, and cancel button visibility. */
  function updateParseButton() {
    const options = selectedArtifactOptions();
    const parseArtifacts = options.map((option) => option.artifact_key);
    const dateRangeValidation = validateAnalysisDateRange();
    const disabled = !A.activeCaseId() || parseArtifacts.length === 0 || !dateRangeValidation.ok;
    if (el.parseBtn) {
      el.parseBtn.disabled = disabled;
      el.parseBtn.textContent = (st.parse.run || st.parse.done) ? "Restart Parsing" : "Parse Selected";
    }
    if (el.cancelParse) el.cancelParse.hidden = !st.parse.run;
    A.updateNav();
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  A.setupEvidence = setupEvidence;
  A.setupArtifacts = setupArtifacts;
  A.loadArtifactProfiles = loadArtifactProfiles;
  A.setPendingFiles = setPendingFiles;
  A.updateParseButton = updateParseButton;
  A.selectedArtifactOptions = selectedArtifactOptions;
  A.selectedArtifacts = selectedArtifacts;
  A.selectedAiArtifacts = selectedAiArtifacts;
  A.validateAnalysisDateRange = validateAnalysisDateRange;
  A.artifactBoxes = artifactBoxes;
  A.ensureArtifactModeControl = ensureArtifactModeControl;
  A.syncArtifactModeControl = syncArtifactModeControl;
  A.clearDynamicArtifacts = clearDynamicArtifacts;
  A.syncMode = syncMode;
})();
