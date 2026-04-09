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

  // ── Multi-image state ──────────────────────────────────────────────────────

  /** Array of image intake entries. Each entry: {index, image_id, label, metadata, available_artifacts, pendingFiles} */
  st.images = [];

  /** Counter for generating unique image form indices. */
  let imageFormCounter = 0;

  // ── Evidence intake ────────────────────────────────────────────────────────

  /** Wire up the evidence form: mode toggle, file input, dropzone, and submit handler. */
  function setupEvidence() {
    if (!el.evidenceForm) return;
    /* Legacy single-image elements are no longer used directly.
       Mode toggling and dropzone init are handled per image card. */
    initImageForm(getImageForms()[0]);
    el.evidenceForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await submitEvidence();
    });
    const addBtn = q("add-image-btn");
    if (addBtn) addBtn.addEventListener("click", addImageForm);
  }

  /**
   * Batch-sync upload/path panels for every image form card.
   *
   * Called from app.js when restoring wizard state.  Per-image sync is
   * handled by syncImageFormMode(); this is the convenience wrapper that
   * iterates all cards.
   */
  function syncMode() {
    getImageForms().forEach(syncImageFormMode);
  }

  /**
   * Sync upload/path panels for a single image form card.
   *
   * @param {HTMLElement} card - The .image-form-card element.
   */
  function syncImageFormMode(card) {
    if (!card) return;
    const pathRadio = card.querySelector(".image-mode-path");
    const pathMode = !!(pathRadio && pathRadio.checked);
    const uploadPanel = card.querySelector(".image-upload-panel");
    const pathPanel = card.querySelector(".image-path-panel");
    if (uploadPanel) uploadPanel.hidden = pathMode;
    if (pathPanel) pathPanel.hidden = !pathMode;
  }

  /**
   * Initialise event listeners for a single image form card.
   *
   * @param {HTMLElement|null} card - The .image-form-card element.
   */
  function initImageForm(card) {
    if (!card) return;
    const modeUpload = card.querySelector(".image-mode-upload");
    const modePath = card.querySelector(".image-mode-path");
    if (modeUpload) modeUpload.addEventListener("change", () => syncImageFormMode(card));
    if (modePath) modePath.addEventListener("change", () => syncImageFormMode(card));

    const fileInput = card.querySelector(".image-file-input");
    const dropzoneHelp = card.querySelector(".image-dropzone-help");
    if (fileInput) {
      fileInput.addEventListener("change", () => {
        updateDropzoneHelp(fileInput, dropzoneHelp);
      });
    }
    initImageDropzone(card);
    syncImageFormMode(card);

    const removeBtn = card.querySelector(".image-remove-btn");
    if (removeBtn) {
      removeBtn.addEventListener("click", () => removeImageForm(card));
    }
  }

  /**
   * Initialise drag-and-drop for an image form card's dropzone.
   *
   * @param {HTMLElement} card - The .image-form-card element.
   */
  function initImageDropzone(card) {
    const drop = card.querySelector(".image-dropzone");
    if (!drop) return;
    const prevent = (e) => { e.preventDefault(); e.stopPropagation(); };
    ["dragenter", "dragover"].forEach((t) => drop.addEventListener(t, (e) => {
      prevent(e);
      drop.classList.add("is-dragover");
    }));
    ["dragleave", "dragend", "drop"].forEach((t) => drop.addEventListener(t, (e) => {
      prevent(e);
      drop.classList.remove("is-dragover");
    }));
    drop.addEventListener("drop", (e) => {
      const files = e.dataTransfer && e.dataTransfer.files ? e.dataTransfer.files : null;
      if (!files || !files.length) return;
      const dropped = Array.from(files);
      const fileInput = card.querySelector(".image-file-input");
      if (fileInput) {
        try {
          const dt = new DataTransfer();
          dropped.forEach((file) => dt.items.add(file));
          fileInput.files = dt.files;
        } catch (_err) { /* fallback */ }
      }
      const helpEl = card.querySelector(".image-dropzone-help");
      updateDropzoneHelp(fileInput, helpEl);
    });
  }

  /**
   * Update a dropzone help text element based on selected files.
   *
   * @param {HTMLInputElement|null} fileInput - The file input element.
   * @param {HTMLElement|null} helpEl - The dropzone help text element.
   */
  function updateDropzoneHelp(fileInput, helpEl) {
    if (!helpEl) return;
    const files = fileInput && fileInput.files ? Array.from(fileInput.files) : [];
    if (!files.length) {
      helpEl.textContent = A.DROP_HELP;
      return;
    }
    if (files.length === 1) {
      const file = files[0];
      helpEl.textContent = `${file.name}${Number.isFinite(file.size) ? ` (${A.fmtBytes(file.size)})` : ""}`;
      return;
    }
    const totalSize = files.reduce((sum, file) => sum + (Number.isFinite(file.size) ? file.size : 0), 0);
    helpEl.textContent = `${files.length} files selected (${A.fmtBytes(totalSize)})`;
  }

  /**
   * Store pending evidence files and update the dropzone help text (legacy).
   *
   * @param {File[]} files - Array of File objects selected by the user.
   */
  function setPendingFiles(files) {
    st.pendingFiles = Array.isArray(files) ? files.filter(Boolean) : [];
  }

  /** Strip curly/smart quotes and whitespace from a user-supplied evidence path. */
  function sanitizeEvidencePath(raw) {
    return String(raw || "").replace(/["\u201c\u201d]/g, "").trim();
  }

  // ── Image form management ─────────────────────────────────────────────────

  /** Return all image form card elements from the DOM. */
  function getImageForms() {
    const container = q("image-forms-container");
    return container ? Array.from(container.querySelectorAll(".image-form-card")) : [];
  }

  /** Add a new image intake form to the container. */
  function addImageForm() {
    const container = q("image-forms-container");
    if (!container) return;
    imageFormCounter += 1;
    const idx = imageFormCounter;
    const card = document.createElement("div");
    card.className = "image-form-card";
    card.dataset.imageIndex = String(idx);
    card.innerHTML = `
      <div class="image-form-header">
        <h3 class="image-form-title">Image ${getImageForms().length + 1}</h3>
        <button type="button" class="image-remove-btn" data-image-index="${idx}">Remove</button>
      </div>
      <div class="form-row">
        <label>Label (optional)</label>
        <input class="image-label-input" type="text" placeholder="e.g. Workstation-PC01" autocomplete="off" spellcheck="false">
      </div>
      <fieldset class="mode-toggle">
        <legend>Evidence source</legend>
        <label>
          <input class="image-mode-upload" name="evidence_mode_${idx}" type="radio" value="upload">
          Upload File
        </label>
        <label>
          <input class="image-mode-path" name="evidence_mode_${idx}" type="radio" value="path" checked>
          Local Path
        </label>
      </fieldset>
      <section class="image-upload-panel" data-mode="upload" hidden>
        <h4>Upload File</h4>
        <label class="image-dropzone">
          <span class="image-dropzone-help">${A.DROP_HELP}</span>
          <input class="image-file-input" type="file" multiple accept=".e01,.e02,.e03,.e04,.e05,.e06,.e07,.e08,.e09,.ex01,.s01,.l01,.dd,.img,.raw,.bin,.iso,.000,.001,.vmdk,.vhd,.vhdx,.vdi,.qcow2,.hdd,.hds,.vmx,.vmwarevm,.vbox,.vmcx,.ovf,.ova,.pvm,.pvs,.utm,.xva,.vma,.vbk,.asdf,.asif,.ad1,.tar,.gz,.tgz,.zip,.7z">
        </label>
      </section>
      <section class="image-path-panel" data-mode="path">
        <h4>Local Path</h4>
        <label>Filesystem path</label>
        <input
          class="image-path-input"
          type="text"
          placeholder="C:\\Evidence\\disk-image.E01 (or .dd, .vmdk, .vhd, .qcow2, folder, ...)"
          autocomplete="off"
          spellcheck="false"
        >
        <p class="path-mode-hint">Evidence files (E01, VMDK, VHD, DD, etc.) are read in-place (read-only) &mdash; nothing is copied. Archives (ZIP, 7z, tar) are copied and extracted into the case folder first.</p>
      </section>
      <article class="image-metadata-card summary-card" hidden>
        <h4>Evidence Summary</h4>
        <dl>
          <dt>Hostname</dt>
          <dd class="image-sum-hostname">-</dd>
          <dt>OS</dt>
          <dd class="image-sum-os">-</dd>
          <dt>Domain</dt>
          <dd class="image-sum-domain">-</dd>
          <dt>IPs</dt>
          <dd class="image-sum-ips">-</dd>
          <dt>SHA-256</dt>
          <dd class="image-sum-sha256">-</dd>
        </dl>
      </article>
      <p class="image-status-msg" role="alert" hidden></p>
    `;
    container.appendChild(card);
    initImageForm(card);
    renumberImageForms();
  }

  /**
   * Remove an image form card from the container.
   *
   * @param {HTMLElement} card - The .image-form-card element to remove.
   */
  function removeImageForm(card) {
    if (!card) return;
    const forms = getImageForms();
    /* Don't allow removing the last remaining image form. */
    if (forms.length <= 1) return;
    card.remove();
    renumberImageForms();
  }

  /** Re-number image form titles after add/remove. */
  function renumberImageForms() {
    getImageForms().forEach((card, i) => {
      const title = card.querySelector(".image-form-title");
      if (title) title.textContent = `Image ${i + 1}`;
      /* Show remove button on all except the first if there are multiple. */
      const removeBtn = card.querySelector(".image-remove-btn");
      if (removeBtn) removeBtn.hidden = (i === 0 && getImageForms().length === 1);
    });
    /* Update first card's remove button visibility. */
    const forms = getImageForms();
    if (forms.length > 0) {
      const firstRemoveBtn = forms[0].querySelector(".image-remove-btn");
      if (firstRemoveBtn) firstRemoveBtn.hidden = forms.length <= 1;
    }
  }

  /**
   * Gather the evidence data from a single image form card.
   *
   * @param {HTMLElement} card - The .image-form-card element.
   * @returns {{uploadMode: boolean, files: File[], path: string, label: string}|null}
   *     Null if validation fails (sets error message on card).
   */
  function gatherImageFormData(card) {
    const modeUpload = card.querySelector(".image-mode-upload");
    const uploadMode = !!(modeUpload && modeUpload.checked);
    const labelInput = card.querySelector(".image-label-input");
    const label = labelInput ? String(labelInput.value || "").trim() : "";
    const statusMsg = card.querySelector(".image-status-msg");

    if (uploadMode) {
      const fileInput = card.querySelector(".image-file-input");
      const files = fileInput && fileInput.files ? Array.from(fileInput.files) : [];
      if (files.length === 0) {
        setImageStatusMsg(statusMsg, "Choose one or more evidence files first.", "error");
        return null;
      }
      return { uploadMode: true, files, path: "", label };
    }

    const pathInput = card.querySelector(".image-path-input");
    const path = sanitizeEvidencePath(pathInput ? pathInput.value : "");
    if (!path) {
      setImageStatusMsg(statusMsg, "Enter a local evidence path.", "error");
      return null;
    }
    return { uploadMode: false, files: [], path, label };
  }

  /**
   * Set the status message on an image card.
   *
   * @param {HTMLElement|null} node - The .image-status-msg element.
   * @param {string} text - Message text.
   * @param {string} [kind="info"] - "info", "error", or "success".
   */
  function setImageStatusMsg(node, text, kind) {
    if (!node) return;
    if (!text) {
      node.hidden = true;
      node.textContent = "";
      delete node.dataset.status;
      return;
    }
    node.hidden = false;
    node.textContent = text;
    node.dataset.status = kind === "error" ? "failed" : kind === "success" ? "success" : "in-progress";
  }

  /**
   * Submit evidence to the backend: create a case, then for each image form
   * call the multi-image endpoints sequentially.
   */
  async function submitEvidence() {
    A.clearMsg(el.evidenceMsg);
    A.clearMsg(el.artifactsMsg);
    A.clearMsg(el.parseErr);

    const imageForms = getImageForms();
    if (!imageForms.length) return A.setMsg(el.evidenceMsg, "No image forms found.", "error");

    /* Gather and validate all image form data upfront. */
    const imageDataList = [];
    for (const card of imageForms) {
      const statusMsg = card.querySelector(".image-status-msg");
      setImageStatusMsg(statusMsg, "", "info");
      const data = gatherImageFormData(card);
      if (!data) return; /* Validation error already shown on the card. */
      imageDataList.push({ card, data });
    }

    /* Check upload size thresholds. */
    const threshMb = A.num(A.obj(A.obj(st.settings).evidence).large_file_threshold_mb, 0);
    if (threshMb > 0) {
      for (const { data } of imageDataList) {
        if (!data.uploadMode) continue;
        const totalBytes = data.files.reduce(function(sum, f) { return sum + (f.size || 0); }, 0);
        const threshBytes = threshMb * 1024 * 1024;
        if (totalBytes > threshBytes) {
          const limitGb = (threshMb / 1024).toFixed(1);
          const sizeGb = (totalBytes / (1024 * 1024 * 1024)).toFixed(1);
          return A.setMsg(el.evidenceMsg,
            "File size (" + sizeGb + " GB) exceeds the Evidence Size Threshold (" + limitGb + " GB). " +
            "Use path mode instead, or increase the threshold in Settings \u2192 Advanced.",
            "error");
        }
      }
    }

    setEvidenceBusy(true);
    const intakeProgress = createIntakeProgressTracker();
    const intakeStatusEl = q("evidence-intake-status");

    try {
      /* Step 1: Create the case. */
      const c = await A.apiJson("/api/cases", { method: "POST", json: { case_name: A.val(el.caseName) } });
      const caseId = String(c.case_id || "").trim();
      st.caseName = String(c.case_name || "");
      if (!caseId) throw new Error("Case ID missing from create response.");
      intakeProgress.setPhase("case-created");

      const intakeTimeoutMs = A.num(A.obj(A.obj(A.obj(st.settings).evidence).intake_timeout_seconds), 7200) * 1000;
      const skipHashing = !A.boolSetting(A.obj(A.obj(st.settings).evidence).compute_hashes, true);

      /* Step 2: Process each image sequentially. */
      st.images = [];
      const allArtifacts = [];
      let firstOsType = "";
      const totalImages = imageDataList.length;

      for (let i = 0; i < totalImages; i++) {
        const { card, data } = imageDataList[i];
        const statusMsg = card.querySelector(".image-status-msg");

        if (intakeStatusEl) {
          intakeStatusEl.hidden = false;
          intakeStatusEl.textContent = `Processing image ${i + 1} of ${totalImages}...`;
        }
        setImageStatusMsg(statusMsg, "Processing...", "info");

        /* Create image slot. */
        const imgResp = await A.apiJson(
          `/api/cases/${encodeURIComponent(caseId)}/images`,
          { method: "POST", json: { label: data.label || `Image ${i + 1}` } },
        );
        const imageId = String(imgResp.image_id || "").trim();
        if (!imageId) throw new Error(`Image ID missing from response for image ${i + 1}.`);

        /* Upload/link evidence for this image. */
        let ev;
        if (data.uploadMode) {
          const fd = new FormData();
          data.files.forEach((file, index) => {
            fd.append("evidence_file", file, file.name || `evidence_${index + 1}.bin`);
          });
          if (skipHashing) fd.append("skip_hashing", "1");
          ev = await A.apiJson(
            `/api/cases/${encodeURIComponent(caseId)}/images/${encodeURIComponent(imageId)}/evidence`,
            { method: "POST", body: fd, timeout: intakeTimeoutMs },
          );
        } else {
          ev = await A.apiJson(
            `/api/cases/${encodeURIComponent(caseId)}/images/${encodeURIComponent(imageId)}/evidence`,
            { method: "POST", json: { path: data.path, skip_hashing: skipHashing }, timeout: intakeTimeoutMs },
          );
        }

        /* Show metadata on this card. */
        renderImageMetadataCard(card, ev.metadata || {}, ev.hashes || {}, ev.os_type || "");
        setImageStatusMsg(statusMsg, "Evidence loaded.", "success");

        /* Track this image. */
        const imageEntry = {
          image_id: imageId,
          label: data.label || imgResp.label || `Image ${i + 1}`,
          metadata: ev.metadata || {},
          hashes: ev.hashes || {},
          os_type: ev.os_type || "",
          available_artifacts: Array.isArray(ev.available_artifacts) ? ev.available_artifacts : [],
        };
        st.images.push(imageEntry);

        /* Merge available artifacts. */
        if (Array.isArray(ev.available_artifacts)) {
          ev.available_artifacts.forEach((a) => {
            if (!a || !a.key) return;
            const existing = allArtifacts.find((x) => x.key === a.key);
            if (!existing) allArtifacts.push(Object.assign({}, a));
            else if (a.available && !existing.available) existing.available = true;
          });
        }

        if (i === 0) firstOsType = ev.os_type || "";
      }

      intakeProgress.complete();
      if (intakeStatusEl) intakeStatusEl.hidden = true;

      A.setCaseId(caseId);
      A.updateCsvOutputHelp();

      /* Build a combined evidence response for applyEvidence. */
      const combinedEv = {
        available_artifacts: allArtifacts,
        os_type: firstOsType,
        metadata: st.images.length === 1 ? st.images[0].metadata : buildCombinedMetadata(st.images),
        hashes: st.images.length === 1 ? st.images[0].hashes : {},
      };
      applyEvidence(combinedEv);

      /* Build per-image summaries in Step 2. */
      renderImageSummaries(st.images);

      const imageCountLabel = totalImages === 1 ? "1 image" : `${totalImages} images`;
      A.setMsg(el.evidenceMsg, `Evidence intake complete (${imageCountLabel}).`, "success");
      A.showStep(2);
    } catch (e) {
      A.setMsg(el.evidenceMsg, `Evidence intake failed: ${e.message}`, "error");
      if (intakeStatusEl) intakeStatusEl.hidden = true;
    } finally {
      intakeProgress.stop();
      setEvidenceBusy(false);
      A.updateNav();
    }
  }

  /**
   * Build combined metadata from multiple images for display.
   *
   * @param {Object[]} images - Array of image entry objects.
   * @returns {Object} Combined metadata.
   */
  function buildCombinedMetadata(images) {
    if (!images.length) return { hostname: "-", os_version: "-", domain: "-" };
    if (images.length === 1) return images[0].metadata;
    const hostnames = images.map((img) => String((img.metadata || {}).hostname || "Unknown")).join(", ");
    return {
      hostname: hostnames,
      os_version: String((images[0].metadata || {}).os_version || "-"),
      domain: String((images[0].metadata || {}).domain || "-"),
    };
  }

  /**
   * Format an OS version string, prepending the OS type label when it is
   * not already contained in the version text.
   *
   * @param {string} rawVersion - Raw os_version value (may be empty/"-").
   * @param {string} osType - Detected OS type label (e.g. "windows").
   * @returns {string} Formatted OS version string.
   */
  function formatOsVersion(rawVersion, osType) {
    let osVersion = String(rawVersion || "-");
    const osLabel = String(osType || "").trim().toLowerCase();
    if (osLabel && osLabel !== "unknown" && osVersion !== "-") {
      if (osVersion.toLowerCase().indexOf(osLabel) === -1) {
        const capitalized = osLabel.charAt(0).toUpperCase() + osLabel.slice(1);
        osVersion = capitalized + " \u2014 " + osVersion;
      }
    }
    return osVersion;
  }

  /**
   * Render per-image metadata on a card in Step 1.
   *
   * @param {HTMLElement} card - The .image-form-card element.
   * @param {Object} metadata - Evidence metadata.
   * @param {Object} hashes - Hash information.
   * @param {string} osType - Detected OS type.
   */
  function renderImageMetadataCard(card, metadata, hashes, osType) {
    const metaCard = card.querySelector(".image-metadata-card");
    if (!metaCard) return;
    const setText = (cls, val) => {
      const el = metaCard.querySelector(`.${cls}`);
      if (el) el.textContent = val;
    };
    setText("image-sum-hostname", String(metadata.hostname || "-"));
    setText("image-sum-os", formatOsVersion(metadata.os_version, osType));
    setText("image-sum-domain", String(metadata.domain || "-"));
    setText("image-sum-ips", String(metadata.ips || "-"));
    setText("image-sum-sha256", String(hashes.sha256 || "-"));
    metaCard.hidden = false;
  }

  /**
   * Render per-image summaries in the Step 2 evidence summaries container.
   *
   * @param {Object[]} images - Array of image entry objects.
   */
  function renderImageSummaries(images) {
    const container = q("evidence-summaries-container");
    const list = q("evidence-summaries-list");
    if (!container || !list) return;

    /* For single image, use the legacy summary card instead. */
    if (images.length <= 1) {
      container.hidden = true;
      list.innerHTML = "";
      return;
    }

    /* Hide the legacy single summary card. */
    if (el.summaryCard) el.summaryCard.hidden = true;

    list.innerHTML = "";
    images.forEach((img) => {
      const article = document.createElement("article");
      article.className = "summary-card";
      const m = img.metadata || {};
      const h = img.hashes || {};
      const osVersion = formatOsVersion(m.os_version, img.os_type);
      article.innerHTML = `
        <h4>${A.escapeHtml(img.label || "Image")}</h4>
        <dl>
          <dt>Hostname</dt><dd>${A.escapeHtml(m.hostname || "-")}</dd>
          <dt>OS</dt><dd>${A.escapeHtml(osVersion)}</dd>
          <dt>Domain</dt><dd>${A.escapeHtml(m.domain || "-")}</dd>
          <dt>IPs</dt><dd>${A.escapeHtml(m.ips || "-")}</dd>
          <dt>SHA-256</dt><dd>${A.escapeHtml(h.sha256 || "-")}</dd>
        </dl>
      `;
      list.appendChild(article);
    });
    container.hidden = false;
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

    /**
     * Tick the progress bar forward.
     *
     * Uses a time-based curve so the bar advances steadily over a long
     * period instead of racing to the cap and stalling.  The position is
     * interpolated as:  cap * (1 - 1/(1 + t/T))  where t is elapsed
     * seconds and T is a half-life constant (seconds to reach ~50% of cap).
     */
    const tickProgress = () => {
      const current = A.num(el.evidenceProg.value, 0);
      if (current >= cap) return;
      const elapsed = (Date.now() - startedAt) / 1000;
      /* Half-life: 30s means bar reaches ~50% of cap after 30s,
         ~75% after 90s, ~90% after 270s — stays well below cap. */
      const halfLife = 30;
      const target = cap * (1 - 1 / (1 + elapsed / halfLife));
      /* Only move forward, never backward, and cap at the limit. */
      el.evidenceProg.value = Math.min(cap, Math.max(current, target));
    };

    el.evidenceProg.value = 2;
    updateMessage();
    barTicker = window.setInterval(tickProgress, 500);
    msgTicker = window.setInterval(updateMessage, 1000);

    return {
      setPhase: (phase) => {
        if (phase === "case-created") {
          cap = 90;
          if (el.evidenceProg.value < 15) el.evidenceProg.value = 15;
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

    const detectedOs = String(data.os_type || "").trim().toLowerCase();
    st.detectedOs = detectedOs;

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
        const firstCard = getImageForms()[0];
        const firstUploadRadio = firstCard ? firstCard.querySelector(".image-mode-upload") : null;
        const wasUpload = !!(firstUploadRadio && firstUploadRadio.checked);
        hintEl.hidden = !wasUpload;
      }
      if (artifactContent) artifactContent.hidden = true;
    } else {
      if (errorBox) errorBox.hidden = true;
      if (artifactContent) artifactContent.hidden = false;
      populateArtifacts(st.artifacts);
      showOsArtifactFieldsets(detectedOs);
    }

    A.renderParsePlaceholder();
    A.renderAnalysis();
    A.renderExecSummary();
    A.renderFindings();
    buildMultiImageArtifactTabs();
    updateParseButton();
  }

  /**
   * Show/hide OS-specific artifact fieldsets based on the detected OS.
   *
   * Windows fieldsets (no data-os attribute) are shown for Windows images.
   * Linux fieldsets (data-os="linux") are shown for Linux images.
   *
   * @param {string} osType - Detected OS type ("windows", "linux", etc.).
   */
  function showOsArtifactFieldsets(osType) {
    if (!el.artifactsForm) return;
    const isLinux = osType === "linux";
    const fieldsets = el.artifactsForm.querySelectorAll("fieldset.artifact-category");
    fieldsets.forEach((fs) => {
      const fsOs = String(fs.dataset.os || "").trim().toLowerCase();
      var hide;
      if (fsOs === "linux") {
        hide = !isLinux;
      } else if (!fsOs) {
        /* Windows fieldsets have no data-os attribute */
        hide = isLinux;
      } else {
        return;
      }
      fs.hidden = hide;
      /* Force-disable checkboxes in hidden fieldsets so they cannot be
         selected by profiles or presets (prevents duplicate keys like
         'services' from being selected in the wrong OS context). */
      fs.querySelectorAll("input[type='checkbox']").forEach((cb) => {
        if (hide) {
          cb.disabled = true;
          cb.checked = false;
        }
      });
    });
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
    const li = cb.closest("li");
    const select = modeSelect || (li ? li.querySelector("select.artifact-mode-select") : null);
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

    /* Search within the parent <li> to avoid collisions when duplicate
       artifact keys exist across OS-specific fieldsets (e.g. "services"). */
    let select = li.querySelector("select.artifact-mode-select");
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
        const li = cb.closest("li");
        const select = li ? li.querySelector("select.artifact-mode-select") : null;
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
        if (isMultiImage()) return applyPresetMultiAware("recommended");
        const recommendedProfile = findProfileByName(A.RECOMMENDED_PROFILE);
        if (recommendedProfile) return applyArtifactProfile(recommendedProfile);
        return applyPreset("recommended");
      });
    }
    if (el.clearBtn) el.clearBtn.addEventListener("click", () => {
      if (isMultiImage()) return applyPresetMultiAware("clear");
      return applyPreset("clear");
    });
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
    let hasArtifacts = false;
    if (isMultiImage()) {
      /* In multi-image mode, at least one image must have selections. */
      const selections = allImageArtifactSelections();
      hasArtifacts = selections.some((s) => s.artifact_options.length > 0);
    } else {
      /* Ensure the main artifact form is visible and its state is current
         before reading selections (avoids stale state when switching back
         from multi-image mode). */
      if (el.artifactsForm && el.artifactsForm.hidden) {
        el.artifactsForm.hidden = false;
      }
      const options = selectedArtifactOptions();
      hasArtifacts = options.length > 0;
    }
    const dateRangeValidation = validateAnalysisDateRange();
    const disabled = !A.activeCaseId() || !hasArtifacts || !dateRangeValidation.ok;
    if (el.parseBtn) {
      el.parseBtn.disabled = disabled;
      el.parseBtn.textContent = (st.parse.run || st.parse.done) ? "Restart Parsing" : "Parse Selected";
    }
    if (el.cancelParse) el.cancelParse.hidden = !st.parse.run;
    A.updateNav();
  }

  // ── Version update check ───────────────────────────────────────────────────

  /**
   * Query the backend for the latest GitHub release and show an update banner
   * in Step 1 when the running version differs, or a warning when offline.
   */
  async function checkForUpdate() {
    const banner = q("update-banner");
    const text = q("update-banner-text");
    const closeBtn = q("update-banner-close");
    if (!banner || !text) return;

    if (closeBtn) {
      closeBtn.addEventListener("click", () => { banner.hidden = true; });
    }

    try {
      const r = await A.fetchWithTimeout("/api/version/check", { method: "GET" }, 8000);
      if (r.ok) {
        const data = await r.json();
        if (data.update_available) {
          text.textContent = `A new version of AIFT is available (v${data.latest}). You are running v${data.current}.`;
          banner.dataset.kind = "update";
          banner.hidden = false;
        }
      } else {
        text.textContent = "Unable to check for updates. Please verify manually that you are running the latest version of AIFT.";
        banner.dataset.kind = "warning";
        banner.hidden = false;
      }
    } catch (_e) {
      text.textContent = "Unable to check for updates. Please verify manually that you are running the latest version of AIFT.";
      banner.dataset.kind = "warning";
      banner.hidden = false;
    }
  }

  // ── Multi-image artifact tabs ──────────────────────────────────────────────

  /**
   * Build per-image artifact tabs when multiple images are present.
   *
   * Clones the main artifact form fieldsets into per-image panels, each with
   * its own checkboxes filtered to that image's available artifacts.  The
   * main form is hidden and the tab interface is shown instead.
   */
  /** AbortController used to remove prior change listeners from the panels container. */
  let _panelsChangeAC = null;

  function buildMultiImageArtifactTabs() {
    const tabContainer = q("artifact-image-tabs");
    const panelsContainer = q("artifact-image-panels");
    if (!tabContainer || !panelsContainer) return;

    /* Abort the previous change listener so we don't accumulate handlers. */
    if (_panelsChangeAC) _panelsChangeAC.abort();
    _panelsChangeAC = new AbortController();

    /* Clean up any prior tabs. */
    const tabBar = tabContainer.querySelector(".artifact-tab-bar");
    if (tabBar) tabBar.innerHTML = "";
    panelsContainer.innerHTML = "";

    if (st.images.length <= 1) {
      tabContainer.hidden = true;
      panelsContainer.innerHTML = "";
      /* Show the main artifact form for single-image. */
      if (el.artifactsForm) el.artifactsForm.hidden = false;
      return;
    }

    /* Hide the main artifact form — each tab has its own copy. */
    if (el.artifactsForm) el.artifactsForm.hidden = true;
    tabContainer.hidden = false;

    st.images.forEach((img, idx) => {
      const imgId = img.image_id;
      const label = img.label || `Image ${idx + 1}`;
      const availSet = new Set(
        (img.available_artifacts || [])
          .filter((a) => a && a.available)
          .map((a) => String(a.key)),
      );

      /* Create tab button. */
      const tabBtn = document.createElement("button");
      tabBtn.type = "button";
      tabBtn.role = "tab";
      tabBtn.textContent = label;
      tabBtn.dataset.imageId = imgId;
      tabBtn.dataset.tabIndex = String(idx);
      if (idx === 0) tabBtn.classList.add("is-active");
      tabBtn.addEventListener("click", () => switchArtifactTab(imgId));
      if (tabBar) tabBar.appendChild(tabBtn);

      /* Create panel. */
      const panel = document.createElement("div");
      panel.className = "artifact-image-panel";
      panel.dataset.imageId = imgId;
      panel.role = "tabpanel";
      if (idx === 0) panel.classList.add("is-active");

      /* Clone artifact fieldsets from the main form into this panel. */
      if (el.artifactsForm) {
        const fieldsets = el.artifactsForm.querySelectorAll("fieldset.artifact-category");
        fieldsets.forEach((fs) => {
          /* Skip hidden OS-specific fieldsets. */
          if (fs.hidden) return;
          const clone = fs.cloneNode(true);
          /* Update checkboxes for this image's availability. */
          clone.querySelectorAll("input[type='checkbox'][data-artifact-key]").forEach((cb) => {
            const key = String(cb.dataset.artifactKey || "");
            /* Prefix with image ID to avoid name collisions. */
            cb.name = `${imgId}__${key}`;
            cb.dataset.imageId = imgId;
            const available = availSet.has(key);
            cb.disabled = !available;
            cb.checked = false;
            const li = cb.closest("li");
            if (li) {
              li.dataset.available = String(available);
              li.classList.toggle("artifact-unavailable", !available);
              li.title = available ? "" : "Not found in this image";
            }
            /* Remove any existing mode select clones — we'll rebuild. */
            const existingSelect = li ? li.querySelector("select.artifact-mode-select") : null;
            if (existingSelect) existingSelect.remove();
          });
          panel.appendChild(clone);
        });
      }

      /* Ensure mode controls are created for all checkboxes in this panel. */
      panel.querySelectorAll("input[type='checkbox'][data-artifact-key]").forEach((cb) => {
        ensureArtifactModeControl(cb, A.MODE_PARSE_AND_AI);
      });

      panelsContainer.appendChild(panel);
    });

    /* Wire change events on the panels container (with abort signal to prevent accumulation). */
    panelsContainer.addEventListener("change", (e) => {
      const t = e.target;
      if (t instanceof HTMLInputElement && t.type === "checkbox" && t.dataset.artifactKey) {
        syncArtifactModeControl(t);
        return updateParseButton();
      }
      if (t instanceof HTMLSelectElement && t.classList.contains("artifact-mode-select") && t.dataset.artifactKey) {
        t.value = artifactModeValue(t.value);
        return updateParseButton();
      }
    }, { signal: _panelsChangeAC.signal });
  }

  /**
   * Switch the active artifact tab to the given image.
   *
   * @param {string} imageId - The image_id to activate.
   */
  function switchArtifactTab(imageId) {
    const tabContainer = q("artifact-image-tabs");
    const panelsContainer = q("artifact-image-panels");
    if (!tabContainer || !panelsContainer) return;

    tabContainer.querySelectorAll(".artifact-tab-bar button").forEach((btn) => {
      btn.classList.toggle("is-active", btn.dataset.imageId === imageId);
    });
    panelsContainer.querySelectorAll(".artifact-image-panel").forEach((panel) => {
      panel.classList.toggle("is-active", panel.dataset.imageId === imageId);
    });
  }

  /**
   * Return the image_id of the currently active artifact tab, or null.
   *
   * @returns {string|null}
   */
  function activeArtifactTabImageId() {
    const tabContainer = q("artifact-image-tabs");
    if (!tabContainer || tabContainer.hidden) return null;
    const active = tabContainer.querySelector(".artifact-tab-bar button.is-active");
    return active ? active.dataset.imageId || null : null;
  }

  /**
   * Collect selected artifact options for a specific image from its tab panel.
   *
   * @param {string} imageId - Image ID.
   * @returns {{artifact_key: string, mode: string}[]}
   */
  function selectedArtifactOptionsForImage(imageId) {
    if (!imageId) return [];
    const panelsContainer = q("artifact-image-panels");
    if (!panelsContainer) return [];
    const panel = panelsContainer.querySelector(`.artifact-image-panel[data-image-id="${imageId}"]`);
    if (!panel) return [];
    return Array.from(panel.querySelectorAll("input[type='checkbox'][data-artifact-key]"))
      .filter((cb) => cb.checked && !cb.disabled && cb.dataset.artifactKey)
      .map((cb) => {
        const key = String(cb.dataset.artifactKey || "");
        const li = cb.closest("li");
        const select = li ? li.querySelector("select.artifact-mode-select") : null;
        return { artifact_key: key, mode: artifactModeValue(select ? select.value : A.MODE_PARSE_AND_AI) };
      });
  }

  /**
   * Collect per-image artifact selections for all images.
   *
   * @returns {{image_id: string, label: string, artifact_options: Object[]}[]}
   */
  function allImageArtifactSelections() {
    if (st.images.length <= 1) return [];
    return st.images.map((img) => ({
      image_id: img.image_id,
      label: img.label || img.image_id,
      artifact_options: selectedArtifactOptionsForImage(img.image_id),
    }));
  }

  /**
   * Check whether multi-image mode is active (more than one image loaded).
   *
   * @returns {boolean}
   */
  function isMultiImage() {
    return st.images.length > 1;
  }

  /**
   * Apply a preset to the active tab panel in multi-image mode,
   * or to the main form in single-image mode.
   *
   * @param {string} mode - "recommended" or "clear".
   */
  function applyPresetMultiAware(mode) {
    if (!isMultiImage()) return applyPreset(mode);
    const activeId = activeArtifactTabImageId();
    if (!activeId) return applyPreset(mode);
    const panelsContainer = q("artifact-image-panels");
    if (!panelsContainer) return;
    const panel = panelsContainer.querySelector(`.artifact-image-panel[data-image-id="${activeId}"]`);
    if (!panel) return;
    panel.querySelectorAll("input[type='checkbox'][data-artifact-key]").forEach((cb) => {
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
  A.checkForUpdate = checkForUpdate;
  A.getImageForms = getImageForms;
  A.addImageForm = addImageForm;
  A.removeImageForm = removeImageForm;
  A.renderImageSummaries = renderImageSummaries;
  A.buildMultiImageArtifactTabs = buildMultiImageArtifactTabs;
  A.switchArtifactTab = switchArtifactTab;
  A.activeArtifactTabImageId = activeArtifactTabImageId;
  A.selectedArtifactOptionsForImage = selectedArtifactOptionsForImage;
  A.allImageArtifactSelections = allImageArtifactSelections;
  A.isMultiImage = isMultiImage;
  A.applyPresetMultiAware = applyPresetMultiAware;
})();
