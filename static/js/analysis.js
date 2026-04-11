/**
 * Analysis SSE, result rendering, and findings display for AIFT.
 *
 * Manages the analysis lifecycle: submit, track via SSE, render
 * per-artifact results, executive summary, and collapsible findings.
 * Supports both single-image (V1) and multi-image analysis flows.
 *
 * Depends on: AIFT (utils.js, markdown.js)
 */
"use strict";

(() => {
  const A = window.AIFT;
  const { st, el } = A;

  // ── Analysis submission ────────────────────────────────────────────────────

  /** Wire up the analysis form: submit, cancel, and settings link handlers. */
  function setupAnalysis() {
    if (!el.analysisForm) return;
    el.analysisForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      await submitAnalysis();
    });
    if (el.cancelAnalysis) el.cancelAnalysis.addEventListener("click", cancelAnalysis);
    if (el.settingsLink) {
      el.settingsLink.addEventListener("click", (e) => {
        e.preventDefault();
        A.openSettings();
      });
    }
  }

  /**
   * Submit the analysis request.
   *
   * Validates preconditions (case exists, parse complete, AI artifacts selected),
   * posts to the analyze endpoint, and opens the SSE progress stream.
   * For multi-image cases, sends per-image artifact selections.
   */
  async function submitAnalysis() {
    A.clearMsg(el.analysisMsg);
    const caseId = A.activeCaseId();
    if (!caseId) {
      A.setMsg(el.analysisMsg, "No active case. Intake evidence first.", "error");
      A.showStep(1);
      return;
    }
    if (!st.parse.done) {
      A.setMsg(el.analysisMsg, "Parsing must complete before analysis.", "error");
      A.showStep(3);
      return;
    }
    if (!st.selectedAi.length) {
      A.setMsg(el.analysisMsg, "No artifacts are set to `Parse and use in AI`. Update artifact options and parse again.", "error");
      A.showStep(2);
      return;
    }
    if (st.analysis.run) return A.setMsg(el.analysisMsg, "Analysis is already running.", "error");

    if (st.analysis.cancelPending) {
      await st.analysis.cancelPending;
    }
    resetAnalysisState();
    st.analysis.run = true;
    const abortCtrl = new AbortController();
    st.analysis.abort = abortCtrl;
    A.clearMsg(el.resultsMsg);
    if (el.runBtn) el.runBtn.disabled = true;
    if (el.cancelAnalysis) el.cancelAnalysis.hidden = false;

    // Build the request body.
    const body = { prompt: A.val(el.prompt) };
    const isMulti = A.isMultiImage && A.isMultiImage();
    if (isMulti) {
      const selections = A.allImageArtifactSelections();
      if (selections && selections.length) {
        // Backend expects body.images as an array of {image_id: string,
        // artifacts: string[]} where each artifact entry is a key string
        // (e.g. "evtx", "prefetch").  See analysis.py start_analysis().
        body.images = selections.map(function(sel) {
          return {
            image_id: sel.image_id,
            artifacts: sel.artifact_options
              .filter(function(opt) { return opt.mode !== A.MODE_PARSE_ONLY; })
              .map(function(opt) { return opt.artifact_key; }),
          };
        }).filter(function(img) { return img.artifacts.length > 0; });
        st.analysis.multiImage = true;
        st.analysis.imageResults = {};
      }
    }

    try {
      A.startTimer("analysis");
      await A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/analyze`, { method: "POST", json: body, signal: abortCtrl.signal });
      startAnalysisSse();
      A.showStep(4);
    } catch (e) {
      st.analysis.abort = null;
      if (e.name === "AbortError") return;
      st.analysis.run = false;
      A.stopTimer("analysis");
      if (el.runBtn) el.runBtn.disabled = false;
      if (el.cancelAnalysis) el.cancelAnalysis.hidden = true;
      A.setMsg(el.analysisMsg, `Failed to start analysis: ${e.message}`, "error");
    } finally {
      A.updateNav();
    }
  }

  // ── Analysis SSE ───────────────────────────────────────────────────────────

  /** Open the analysis-progress SSE stream for the active case. */
  function startAnalysisSse() {
    const caseId = A.activeCaseId();
    if (!caseId) return A.setMsg(el.analysisMsg, "No case ID for analysis stream.", "error");
    A.openSseStream(
      `/api/cases/${encodeURIComponent(caseId)}/analyze/progress`,
      st.analysis,
      {
        onEvent: (p) => onAnalysisEvent(p),
        onError: () => {
          if (!st.analysis.done && !st.analysis.fail && st.analysis.run) retryAnalysisSse();
        },
      },
    );
  }

  /** Dispatch a single analysis SSE event to the appropriate UI handler. */
  function onAnalysisEvent(p) {
    const t = String(p.type || "");
    if (t === "analysis_started") {
      A.clearMsg(el.analysisMsg);
      st.analysis.totalArtifacts = Number(p.analysis_artifact_count) || 0;
      if (p.multi_image) st.analysis.multiImage = true;
      setAnalysisStatus("Preparing analysis\u2026");
      renderAnalysis();
      renderFindings();
      return;
    }
    if (t === "artifact_analysis_started") {
      const r = A.isObj(p.result) ? p.result : p;
      upsertAnalysisStarted(r);
      const name = String(r.artifact_name || A.artifactName(String(r.artifact_key || "")));
      const idx = st.analysis.order.length;
      const total = st.analysis.totalArtifacts || idx;
      const imageLabel = String(r.image_label || "");
      const statusPrefix = imageLabel ? `[${imageLabel}] ` : "";
      setAnalysisStatus(`${statusPrefix}Analysing (${idx}/${total}): ${name}`);
      renderAnalysis();
      renderFindings();
      return;
    }
    if (t === "artifact_analysis_thinking") {
      upsertAnalysisThinking(A.isObj(p.result) ? p.result : p);
      renderAnalysis();
      renderFindings();
      return;
    }
    if (t === "artifact_analysis_completed") {
      upsertAnalysis(A.isObj(p.result) ? p.result : p);
      renderAnalysis();
      renderFindings();
      return;
    }
    if (t === "analysis_summary") {
      st.analysis.summary = String(p.summary || "");
      st.analysis.model = A.isObj(p.model_info) ? p.model_info : {};
      // Store multi-image data if present.
      if (p.multi_image && A.isObj(p.images)) {
        st.analysis.multiImage = true;
        st.analysis.imageResults = p.images;
        st.analysis.crossImageSummary = String(p.cross_image_summary || "");
      }
      renderExecSummary();
      if (st.analysis.model.provider || st.analysis.model.model) {
        const display = st.analysis.model.model
          ? `${A.prettyProvider(String(st.analysis.model.provider || ""))} (${String(st.analysis.model.model || "")})`
          : A.prettyProvider(String(st.analysis.model.provider || ""));
        setProvider(display || "Not configured");
      }
      return;
    }
    if (t === "analysis_completed") {
      // Handle multi-image completed payload.
      if (p.multi_image && A.isObj(p.images)) {
        st.analysis.multiImage = true;
        st.analysis.imageResults = p.images;
        st.analysis.crossImageSummary = String(p.cross_image_summary || "");
      }
      const finalArtifacts = Array.isArray(p.per_artifact) ? p.per_artifact : [];
      finalArtifacts.forEach((entry) => {
        if (A.isObj(entry)) upsertAnalysis(entry);
      });
      finalizeAnyThinkingArtifacts();
      renderAnalysis();
      renderFindings();
      st.analysis.run = false;
      st.analysis.done = true;
      st.analysis.fail = false;
      A.stopTimer("analysis");
      closeAnalysisSse();
      setAnalysisStatus(null);
      if (el.runBtn) el.runBtn.disabled = false;
      if (el.cancelAnalysis) el.cancelAnalysis.hidden = true;
      A.clearMsg(el.analysisMsg);
      A.updateNav();
      return A.showStep(5);
    }
    if (t === "analysis_failed") {
      st.analysis.run = false;
      st.analysis.done = false;
      st.analysis.fail = true;
      A.stopTimer("analysis");
      closeAnalysisSse();
      setAnalysisStatus(null);
      if (el.runBtn) el.runBtn.disabled = false;
      if (el.cancelAnalysis) el.cancelAnalysis.hidden = true;
      A.setMsg(el.analysisMsg, String(p.error || "Analysis failed."), "error");
      A.updateNav();
      return;
    }
    if (t === "complete" || t === "idle") {
      // Synthetic events from the backend indicating the operation already
      // finished (reconnect after completion) or timed out idle.  Finalize
      // the UI so it does not stay stuck on "in progress".
      if (!st.analysis.done && !st.analysis.fail) {
        st.analysis.run = false;
        st.analysis.done = true;
        st.analysis.fail = false;
        A.stopTimer("analysis");
      }
      closeAnalysisSse();
      setAnalysisStatus(null);
      if (el.runBtn) el.runBtn.disabled = false;
      if (el.cancelAnalysis) el.cancelAnalysis.hidden = true;
      A.clearMsg(el.analysisMsg);
      A.updateNav();
      return A.showStep(5);
    }
    if (t === "error") A.setMsg(el.analysisMsg, String(p.message || "Analysis stream error."), "error");
  }

  // ── Analysis data upserts ──────────────────────────────────────────────────

  /**
   * Extract the common key, name, and model from an analysis SSE payload,
   * and ensure the key is tracked in st.analysis.order.
   *
   * @param {Object} r - Raw event payload.
   * @returns {{key: string, name: string, model: string, current: Object, imageId: string, imageLabel: string}}
   */
  function extractAnalysisIdentifiers(r) {
    const rawKey = String(r.artifact_key || r.key || `artifact_${st.analysis.order.length + 1}`);
    const name = String(r.artifact_name || A.artifactName(rawKey));
    const model = String(r.model || "");
    const imageId = String(r.image_id || "");
    const imageLabel = String(r.image_label || "");
    /* Use a composite key when image_id is present so that the same
       artifact from different images does not collide in byKey/order. */
    const key = imageId ? `${imageId}::${rawKey}` : rawKey;
    if (!st.analysis.byKey[key]) st.analysis.order.push(key);
    const current = st.analysis.byKey[key] || {};
    return { key, name, model, current, imageId, imageLabel };
  }

  /** Record a completed artifact analysis result. */
  function upsertAnalysis(r) {
    const { key, name, model, imageId, imageLabel } = extractAnalysisIdentifiers(r);
    const rawText = String(r.analysis || r.result || "");
    const text = A.stripLeadingReasoningBlocks(rawText) || rawText;
    st.analysis.byKey[key] = {
      key, name, text, model, imageId, imageLabel,
      thinkingText: "", partialText: "", isThinking: false,
    };
  }

  /** Record that artifact analysis has started (sets thinking state). */
  function upsertAnalysisStarted(r) {
    const { key, name, model, current, imageId, imageLabel } = extractAnalysisIdentifiers(r);
    st.analysis.byKey[key] = {
      key, name, imageId, imageLabel,
      text: String(current.text || ""),
      model: model || String(current.model || ""),
      thinkingText: String(current.thinkingText || "Model is thinking..."),
      partialText: String(current.partialText || ""),
      isThinking: true,
    };
  }

  /** Update thinking/partial text for an in-progress artifact analysis. */
  function upsertAnalysisThinking(r) {
    const { key, name, model, current, imageId, imageLabel } = extractAnalysisIdentifiers(r);
    st.analysis.byKey[key] = {
      key, name, imageId, imageLabel,
      text: String(current.text || ""),
      model: model || String(current.model || ""),
      thinkingText: String(r.thinking_text || current.thinkingText || ""),
      partialText: String(r.partial_text || current.partialText || ""),
      isThinking: true,
    };
  }

  /** Resolve all still-thinking artifacts to their best available text. */
  function finalizeAnyThinkingArtifacts() {
    st.analysis.order.forEach((key) => {
      const current = st.analysis.byKey[key];
      if (!current || !current.isThinking) return;
      const rawResolvedText = String(current.text || current.partialText || current.thinkingText || "");
      const resolvedText = A.stripLeadingReasoningBlocks(rawResolvedText) || rawResolvedText.trim();
      st.analysis.byKey[key] = { ...current, text: resolvedText, isThinking: false };
    });
  }

  // ── Status banner ─────────────────────────────────────────────────────

  /**
   * Show or update the analysis status banner with the given message.
   * Pass null/empty to hide.
   */
  function setAnalysisStatus(msg) {
    if (!el.analysisStatusBanner) return;
    if (!msg) {
      el.analysisStatusBanner.hidden = true;
      return;
    }
    el.analysisStatusBanner.hidden = false;
    if (el.analysisStatusText) el.analysisStatusText.textContent = msg;
  }

  // ── Rendering helpers ──────────────────────────────────────────────────────

  /** Return the best display text for an analysis entry (thinking placeholder or final). */
  function resolveAnalysisText(r) {
    if (r.isThinking && !String(r.text || "").trim()) {
      return String(r.thinkingText || r.partialText || "Model is thinking...");
    }
    return r.text;
  }

  /** Render all per-artifact analysis cards into the analysis results list. */
  function renderAnalysis() {
    if (!el.analysisList) return;
    el.analysisList.innerHTML = "";
    if (!st.analysis.order.length) {
      const p = document.createElement("p");
      p.textContent = "No analysis output yet.";
      el.analysisList.appendChild(p);
      return;
    }

    // In multi-image mode, group artifacts by image.
    if (st.analysis.multiImage) {
      renderMultiImageAnalysis();
      return;
    }

    st.analysis.order.forEach((k) => {
      const r = st.analysis.byKey[k];
      if (!r) return;
      el.analysisList.appendChild(buildAnalysisCard(r));
    });
  }

  /**
   * Render multi-image analysis cards grouped by image.
   * Each image gets a collapsible section with its artifacts inside.
   */
  function renderMultiImageAnalysis() {
    if (!el.analysisList) return;
    // Group artifacts by imageId.
    const groups = {};
    const groupOrder = [];
    st.analysis.order.forEach(function(k) {
      const r = st.analysis.byKey[k];
      if (!r) return;
      const imgId = r.imageId || "__single__";
      if (!groups[imgId]) {
        groups[imgId] = [];
        groupOrder.push(imgId);
      }
      groups[imgId].push(r);
    });

    groupOrder.forEach(function(imgId) {
      const items = groups[imgId];
      if (!items || !items.length) return;
      const label = items[0].imageLabel || imgId;

      const section = document.createElement("div");
      section.className = "analysis-image-group";

      const header = document.createElement("h4");
      header.className = "analysis-image-group-header";
      header.textContent = label;
      section.appendChild(header);

      items.forEach(function(r) {
        section.appendChild(buildAnalysisCard(r));
      });
      el.analysisList.appendChild(section);
    });
  }

  /**
   * Build a single analysis card DOM element.
   *
   * @param {Object} r - Analysis entry from st.analysis.byKey.
   * @returns {HTMLElement} The article element.
   */
  function buildAnalysisCard(r) {
    const a = document.createElement("article");
    a.className = "analysis-card";
    const h = document.createElement("h4");
    h.textContent = r.name;
    const m = document.createElement("p");
    m.className = "mono";
    const metaParts = [r.key];
    if (r.model) metaParts.push("model: " + r.model);
    if (r.imageLabel) metaParts.push("image: " + r.imageLabel);
    m.textContent = metaParts.join(" | ");
    const b = document.createElement("div");
    b.className = "markdown-output";
    const displayText = resolveAnalysisText(r);
    const emptyLabel = r.isThinking ? "Model is thinking..." : "(No analysis text returned.)";
    A.renderMarkdownInto(b, displayText, emptyLabel);
    a.appendChild(h);
    a.appendChild(m);
    a.appendChild(b);
    return a;
  }

  /** Render the executive summary markdown into the results page. */
  function renderExecSummary() {
    if (!el.summaryOut) return;

    // Multi-image: show cross-image summary and per-image summaries.
    if (st.analysis.multiImage && st.analysis.crossImageSummary) {
      renderMultiImageExecSummary();
      return;
    }

    A.renderMarkdownInto(el.summaryOut, st.analysis.summary, "Summary is generated after analysis completes.");
  }

  /**
   * Render multi-image executive summary: cross-image summary at top,
   * then per-image summaries in collapsible sections.
   */
  function renderMultiImageExecSummary() {
    if (!el.summaryOut) return;
    el.summaryOut.innerHTML = "";

    // Remove any previously appended per-image summary containers so
    // repeated calls (e.g. SSE reconnects) do not create duplicates.
    document.querySelectorAll(".per-image-summaries").forEach(function(node) { node.remove(); });

    // Cross-image summary section.
    const crossSection = document.getElementById("cross-system-analysis");
    if (crossSection) {
      const crossContent = crossSection.querySelector(".cross-system-content");
      if (crossContent) {
        A.renderMarkdownInto(crossContent, st.analysis.crossImageSummary, "No cross-system analysis available.");
      }
      crossSection.hidden = false;
    }

    // Overall summary.
    A.renderMarkdownInto(el.summaryOut, st.analysis.summary, "Summary is generated after analysis completes.");

    // Per-image summaries below the main summary.
    const imageResults = st.analysis.imageResults || {};
    const imageIds = Object.keys(imageResults);
    if (imageIds.length > 0) {
      const perImageContainer = document.createElement("div");
      perImageContainer.className = "per-image-summaries";

      imageIds.forEach(function(imgId) {
        const imgData = imageResults[imgId];
        if (!imgData) return;
        const label = String(imgData.label || imgId);
        const summary = String(imgData.summary || "");

        const details = document.createElement("details");
        details.className = "per-image-summary-section";
        details.open = true;
        const summaryEl = document.createElement("summary");
        summaryEl.className = "per-image-summary-header";
        summaryEl.textContent = label;
        const bodyDiv = document.createElement("div");
        bodyDiv.className = "markdown-output per-image-summary-body";
        A.renderMarkdownInto(bodyDiv, summary, "(No summary for this image.)");
        details.appendChild(summaryEl);
        details.appendChild(bodyDiv);
        perImageContainer.appendChild(details);
      });

      el.summaryOut.appendChild(perImageContainer);
    }
  }

  /** Render collapsible per-artifact findings `<details>` elements. */
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

    // Multi-image: group findings by image.
    if (st.analysis.multiImage) {
      renderMultiImageFindings();
      return;
    }

    st.analysis.order.forEach((k, i) => {
      const r = st.analysis.byKey[k];
      if (!r) return;
      el.findings.appendChild(buildFindingsDetails(r, i === 0));
    });
  }

  /**
   * Render multi-image findings grouped by image in collapsible sections.
   */
  function renderMultiImageFindings() {
    if (!el.findings) return;

    // Group by image.
    const groups = {};
    const groupOrder = [];
    st.analysis.order.forEach(function(k) {
      const r = st.analysis.byKey[k];
      if (!r) return;
      const imgId = r.imageId || "__single__";
      if (!groups[imgId]) {
        groups[imgId] = [];
        groupOrder.push(imgId);
      }
      groups[imgId].push(r);
    });

    groupOrder.forEach(function(imgId, gi) {
      const items = groups[imgId];
      if (!items || !items.length) return;
      const label = items[0].imageLabel || imgId;

      const imageSection = document.createElement("details");
      imageSection.className = "findings-image-group";
      imageSection.open = gi === 0;
      const imageSummary = document.createElement("summary");
      imageSummary.className = "findings-image-group-header";
      imageSummary.textContent = label;
      imageSection.appendChild(imageSummary);

      items.forEach(function(r, i) {
        imageSection.appendChild(buildFindingsDetails(r, gi === 0 && i === 0));
      });

      el.findings.appendChild(imageSection);
    });
  }

  /**
   * Build a collapsible findings details element.
   *
   * @param {Object} r - Analysis entry.
   * @param {boolean} isOpen - Whether to start open.
   * @returns {HTMLDetailsElement}
   */
  function buildFindingsDetails(r, isOpen) {
    const d = document.createElement("details");
    d.open = isOpen;
    const s = document.createElement("summary");
    s.textContent = r.name;
    const p = document.createElement("div");
    p.className = "markdown-output";
    const displayText = resolveAnalysisText(r);
    const emptyLabel = r.isThinking ? "Model is thinking..." : "(No analysis text returned.)";
    A.renderMarkdownInto(p, displayText, emptyLabel);
    d.appendChild(s);
    d.appendChild(p);
    return d;
  }

  /** Update the provider name display in the analysis step header. */
  function setProvider(text) {
    if (el.providerName) el.providerName.textContent = text || "Not configured";
  }

  // ── SSE retry / close / cancel ─────────────────────────────────────────────

  /** Attempt to reconnect the analysis SSE stream with exponential backoff. */
  function retryAnalysisSse() {
    if (st.analysis.done || st.analysis.fail || !st.analysis.run) return;
    A.retrySseStream(st.analysis, {
      reconnect: () => {
        if (!st.analysis.done && !st.analysis.fail && st.analysis.run) startAnalysisSse();
      },
      onRetryScheduled: (attempt, delaySec) => {
        A.setMsg(el.analysisMsg, `Analysis progress connection dropped. Reconnecting (${attempt}/${A.SSE_MAX_RETRIES}) in ${delaySec}s...`, "error");
      },
      onMaxRetries: () => {
        st.analysis.run = false;
        st.analysis.done = false;
        st.analysis.fail = true;
        st.analysis.retryCount = 0;
        A.stopTimer("analysis");
        closeAnalysisSse();
        if (el.runBtn) el.runBtn.disabled = false;
        A.setMsg(el.analysisMsg, `Analysis progress connection lost after ${A.SSE_MAX_RETRIES} retries. Run analysis again.`, "error");
        A.updateNav();
      },
    });
  }

  /** Close the analysis SSE EventSource and clear pending retries. */
  function closeAnalysisSse() {
    A.closeSseChannel(st.analysis);
  }

  /** Cancel any in-progress analysis: abort HTTP, close SSE, notify backend. */
  function cancelAnalysis() {
    if (st.analysis.abort) {
      st.analysis.abort.abort();
      st.analysis.abort = null;
    }
    closeAnalysisSse();
    const wasRunning = st.analysis.run;
    if (!wasRunning) return;
    st.analysis.run = false;
    st.analysis.done = false;
    st.analysis.fail = false;
    A.stopTimer("analysis");
    if (el.runBtn) el.runBtn.disabled = false;
    if (el.cancelAnalysis) el.cancelAnalysis.hidden = true;
    setAnalysisStatus(null);
    A.setMsg(el.analysisMsg, "Analysis cancelled.", "info");
    A.updateNav();
    const caseId = A.activeCaseId();
    if (caseId) {
      st.analysis.cancelPending = A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/analyze/cancel`, { method: "POST" })
        .catch(() => {})
        .finally(() => { st.analysis.cancelPending = null; });
    }
  }

  /** Reset all analysis state, close SSE, and clear rendered results. */
  function resetAnalysisState() {
    closeAnalysisSse();
    A.stopTimer("analysis");
    st.analysis.run = false;
    st.analysis.done = false;
    st.analysis.fail = false;
    st.analysis.retryCount = 0;
    st.analysis.seq = -1;
    st.analysis.order = [];
    st.analysis.byKey = {};
    st.analysis.totalArtifacts = 0;
    st.analysis.summary = "";
    st.analysis.model = {};
    st.analysis.multiImage = false;
    st.analysis.imageResults = {};
    st.analysis.crossImageSummary = "";
    A.clearMsg(el.analysisMsg);
    setAnalysisStatus(null);
    if (el.runBtn) el.runBtn.disabled = false;
    if (el.cancelAnalysis) el.cancelAnalysis.hidden = true;

    // Hide and clear cross-system analysis section so stale content from a
    // prior multi-image run does not persist into a subsequent single-image run.
    const crossSection = document.getElementById("cross-system-analysis");
    if (crossSection) {
      crossSection.hidden = true;
      const crossContent = crossSection.querySelector(".cross-system-content");
      if (crossContent) crossContent.innerHTML = "";
    }

    // Remove any per-image summary sections from previous runs.
    document.querySelectorAll(".per-image-summaries").forEach(function(node) { node.remove(); });

    renderAnalysis();
    renderExecSummary();
    renderFindings();
    A.updateNav();
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  A.setupAnalysis = setupAnalysis;
  A.cancelAnalysis = cancelAnalysis;
  A.closeAnalysisSse = closeAnalysisSse;
  A.resetAnalysisState = resetAnalysisState;
  A.renderAnalysis = renderAnalysis;
  A.renderExecSummary = renderExecSummary;
  A.renderFindings = renderFindings;
  A.setProvider = setProvider;
  A._onAnalysisEvent = onAnalysisEvent;
})();
