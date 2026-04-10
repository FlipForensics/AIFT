/**
 * Multi-image evidence intake, submission, and per-image artifact tab management.
 *
 * Handles adding/removing image form cards, multi-image evidence submission,
 * per-image metadata rendering, and per-image artifact selection tabs.
 *
 * Depends on: AIFT (utils.js), evidence.js (must be loaded first)
 */
"use strict";

(() => {
  const A = window.AIFT;
  const { st, el, q } = A;

  // ── Multi-image form management ─────────────────────────────────────────

  /** Counter for generating unique image form indices. */
  let imageFormCounter = 0;

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
        <h3 class="image-form-title">Image ${A.getImageForms().length + 1}</h3>
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
    A.initImageForm(card);
    renumberImageForms();
  }

  /**
   * Remove an image form card from the container.
   *
   * @param {HTMLElement} card - The .image-form-card element to remove.
   */
  function removeImageForm(card) {
    if (!card) return;
    const forms = A.getImageForms();
    /* Don't allow removing the last remaining image form. */
    if (forms.length <= 1) return;
    card.remove();
    renumberImageForms();
  }

  /** Re-number image form titles after add/remove. */
  function renumberImageForms() {
    const forms = A.getImageForms();
    const totalForms = forms.length;
    forms.forEach((card, i) => {
      const title = card.querySelector(".image-form-title");
      if (title) title.textContent = `Image ${i + 1}`;
      /* Show remove button only when there are multiple forms. */
      const removeBtn = card.querySelector(".image-remove-btn");
      if (removeBtn) removeBtn.hidden = totalForms <= 1;
    });
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
    const path = A.sanitizeEvidencePath(pathInput ? pathInput.value : "");
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

  // ── Multi-image submission ──────────────────────────────────────────────

  /**
   * Submit evidence to the backend: create a case, then for each image form
   * call the multi-image endpoints sequentially.
   */
  async function submitEvidence() {
    A.clearMsg(el.evidenceMsg);
    A.clearMsg(el.artifactsMsg);
    A.clearMsg(el.parseErr);

    const imageForms = A.getImageForms();
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
      A.applyEvidence(combinedEv);

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

  // ── Multi-image metadata helpers ────────────────────────────────────────

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
    /* Collect unique OS versions and domains across all images so
       multi-image cases do not silently drop info from images 2+. */
    const osVersions = Array.from(new Set(
      images.map((img) => String((img.metadata || {}).os_version || "")).filter(Boolean)
    ));
    const domains = Array.from(new Set(
      images.map((img) => String((img.metadata || {}).domain || "")).filter(Boolean)
    ));
    return {
      hostname: hostnames,
      os_version: osVersions.length ? osVersions.join(", ") : "-",
      domain: domains.length ? domains.join(", ") : "-",
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

  // ── Intake progress & busy state ────────────────────────────────────────

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

  // ── Multi-image artifact tabs ──────────────────────────────────────────

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
        A.ensureArtifactModeControl(cb, A.MODE_PARSE_AND_AI);
      });

      panelsContainer.appendChild(panel);
    });

    /* Wire change events on the panels container (with abort signal to prevent accumulation). */
    panelsContainer.addEventListener("change", (e) => {
      const t = e.target;
      if (t instanceof HTMLInputElement && t.type === "checkbox" && t.dataset.artifactKey) {
        A.syncArtifactModeControl(t);
        return A.updateParseButton();
      }
      if (t instanceof HTMLSelectElement && t.classList.contains("artifact-mode-select") && t.dataset.artifactKey) {
        t.value = A.artifactModeValue(t.value);
        return A.updateParseButton();
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
    const panel = panelsContainer.querySelector(`.artifact-image-panel[data-image-id="${CSS.escape(imageId)}"]`);
    if (!panel) return [];
    return Array.from(panel.querySelectorAll("input[type='checkbox'][data-artifact-key]"))
      .filter((cb) => cb.checked && !cb.disabled && cb.dataset.artifactKey)
      .map((cb) => {
        const key = String(cb.dataset.artifactKey || "");
        const li = cb.closest("li");
        const select = li ? li.querySelector("select.artifact-mode-select") : null;
        return { artifact_key: key, mode: A.artifactModeValue(select ? select.value : A.MODE_PARSE_AND_AI) };
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
    if (!isMultiImage()) return A.applyPreset(mode);
    const activeId = activeArtifactTabImageId();
    if (!activeId) return A.applyPreset(mode);
    const panelsContainer = q("artifact-image-panels");
    if (!panelsContainer) return;
    const panel = panelsContainer.querySelector(`.artifact-image-panel[data-image-id="${CSS.escape(activeId)}"]`);
    if (!panel) return;
    panel.querySelectorAll("input[type='checkbox'][data-artifact-key]").forEach((cb) => {
      const select = A.ensureArtifactModeControl(cb, A.MODE_PARSE_AND_AI);
      if (cb.disabled) {
        cb.checked = false;
        if (select) select.value = A.MODE_PARSE_AND_AI;
        return A.syncArtifactModeControl(cb, select);
      }
      if (mode === "clear") cb.checked = false;
      else cb.checked = !A.RECOMMENDED_PRESET_EXCLUDED_ARTIFACTS.has(String(cb.dataset.artifactKey || "").trim().toLowerCase());
      if (select) select.value = A.MODE_PARSE_AND_AI;
      A.syncArtifactModeControl(cb, select);
    });
    A.updateParseButton();
  }

  // ── Public API ─────────────────────────────────────────────────────────
  A.submitEvidence = submitEvidence;
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
