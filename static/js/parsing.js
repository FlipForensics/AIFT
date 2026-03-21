/**
 * Parse submission and SSE progress tracking for AIFT.
 *
 * Manages the parse lifecycle: submit, track progress via SSE,
 * handle retries, cancellation, and state reset.
 *
 * Depends on: AIFT (utils.js), evidence.js
 */
"use strict";

(() => {
  const A = window.AIFT;
  const { st, el } = A;

  // ── Parse submission ───────────────────────────────────────────────────────

  /**
   * Submit selected artifacts for parsing.
   *
   * Validates selection and date range, cancels any running parse, posts
   * the parse request, and opens the SSE progress stream.
   */
  async function submitParse() {
    A.clearMsg(el.artifactsMsg);
    A.clearMsg(el.parseErr);
    const caseId = A.activeCaseId();
    if (!caseId) {
      A.setMsg(el.artifactsMsg, "Create and intake a case first.", "error");
      A.showStep(1);
      return;
    }
    const artifactOptions = A.selectedArtifactOptions();
    const arts = artifactOptions.map((option) => option.artifact_key);
    const aiArtifacts = A.selectedAiArtifacts(artifactOptions);
    if (!arts.length) return A.setMsg(el.artifactsMsg, "Select at least one artifact.", "error");
    const dateRangeValidation = A.validateAnalysisDateRange();
    if (!dateRangeValidation.ok) return A.setMsg(el.artifactsMsg, dateRangeValidation.message, "error");

    if (st.parse.run) cancelParse();
    if (st.parse.cancelPending) {
      await st.parse.cancelPending;
    }
    st.selected = arts;
    st.selectedAi = aiArtifacts;
    resetParseState();
    st.parse.run = true;
    const abortCtrl = new AbortController();
    st.parse.abort = abortCtrl;
    initParseRows(arts);
    updateParseProgress();
    A.updateParseButton();

    try {
      const parsePayload = { artifacts: arts, ai_artifacts: aiArtifacts, artifact_options: artifactOptions };
      if (dateRangeValidation.range) parsePayload.analysis_date_range = dateRangeValidation.range;
      A.startTimer("parse");
      await A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/parse`, { method: "POST", json: parsePayload, signal: abortCtrl.signal });
      startParseSse();
      A.showStep(3);
    } catch (e) {
      st.parse.abort = null;
      if (e.name === "AbortError") return;
      st.parse.run = false;
      A.stopTimer("parse");
      A.setMsg(el.artifactsMsg, `Failed to start parsing: ${e.message}`, "error");
      A.updateParseButton();
    } finally {
      A.updateNav();
    }
  }

  // ── Parse progress rows ────────────────────────────────────────────────────

  /**
   * Create the initial progress table rows for each artifact being parsed.
   *
   * @param {string[]} keys - Artifact keys to track.
   */
  function initParseRows(keys) {
    if (!el.parseRows) return;
    st.parse.rows = {};
    st.parse.status = {};
    el.parseRows.innerHTML = "";
    keys.forEach((k) => {
      const tr = document.createElement("tr");
      tr.dataset.artifactKey = k;
      const tdA = document.createElement("td");
      tdA.textContent = A.artifactName(k);
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

  /** Reset the parse table to a single "Awaiting selection" placeholder row. */
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

  /**
   * Update (or create) a parse progress row for the given artifact.
   *
   * @param {string} key - Artifact key.
   * @param {string} status - Status label (e.g. "waiting", "parsing", "completed", "failed").
   * @param {number|null} count - Record count to display.
   * @param {string} [err] - Optional error message shown as a tooltip.
   */
  function setParseRow(key, status, count, err) {
    if (!key) return;
    let row = st.parse.rows[key];
    if (!row && el.parseRows) {
      const tr = document.createElement("tr");
      tr.dataset.artifactKey = key;
      const tdA = document.createElement("td");
      tdA.textContent = A.artifactName(key);
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

  /**
   * Recompute and set the overall parse progress bar value (0–100).
   *
   * @param {boolean} [force=false] - When true, immediately set to 100%.
   */
  function updateParseProgress(force = false) {
    if (!el.parseProgress) return;
    if (force) return (el.parseProgress.value = 100);
    const keys = st.selected.length ? st.selected : Object.keys(st.parse.status);
    if (!keys.length) return (el.parseProgress.value = 0);
    const done = keys.filter((k) => st.parse.status[k] === "completed" || st.parse.status[k] === "failed").length;
    el.parseProgress.value = Math.max(0, Math.min(100, Math.round((done / keys.length) * 100)));
  }

  // ── Parse SSE ──────────────────────────────────────────────────────────────

  /** Open the parse-progress SSE stream for the active case. */
  function startParseSse() {
    A.clearMsg(el.parseErr);
    const caseId = A.activeCaseId();
    if (!caseId) return A.setMsg(el.parseErr, "No active case for parse stream.", "error");
    A.openSseStream(
      `/api/cases/${encodeURIComponent(caseId)}/parse/progress`,
      st.parse,
      {
        onEvent: (p) => onParseEvent(p),
        onError: () => {
          if (!st.parse.done && !st.parse.fail && st.parse.run) retryParseSse();
        },
      },
    );
  }

  /** Dispatch a single parse SSE event to the appropriate UI handler. */
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
    if (t === "artifact_started") return (setParseRow(String(p.artifact_key || ""), "parsing", A.num(p.record_count, null)), updateParseProgress());
    if (t === "artifact_progress") return setParseRow(String(p.artifact_key || ""), "parsing", A.num(p.record_count, 0));
    if (t === "artifact_completed") return (setParseRow(String(p.artifact_key || ""), "completed", A.num(p.record_count, 0)), updateParseProgress());
    if (t === "artifact_failed") {
      const key = String(p.artifact_key || "");
      setParseRow(key, "failed", A.num(p.record_count, 0), String(p.error || "Unknown parser error."));
      updateParseProgress();
      return A.setMsg(el.parseErr, `Parse failed for ${A.artifactName(key)}: ${String(p.error || "Unknown parser error.")}`, "error");
    }
    if (t === "parse_completed") {
      st.parse.run = false;
      st.parse.done = true;
      st.parse.fail = false;
      updateParseProgress(true);
      A.stopTimer("parse");
      closeParseSse();
      A.clearMsg(el.parseErr);
      A.updateParseButton();
      A.updateNav();
      if (st.selectedAi.length > 0) return A.showStep(4);
      A.setMsg(el.parseErr, "Parsing complete. No artifacts were set to \u201cParse and use in AI,\u201d so analysis is not available. You can review parsed CSVs in the case folder or go back and re-parse with AI-enabled artifacts.", "success");
      return;
    }
    if (t === "parse_failed") {
      st.parse.run = false;
      st.parse.done = false;
      st.parse.fail = true;
      A.stopTimer("parse");
      closeParseSse();
      A.setMsg(el.parseErr, String(p.error || "Parsing failed."), "error");
      A.updateParseButton();
      A.updateNav();
      return A.showStep(3);
    }
    if (t === "error") A.setMsg(el.parseErr, String(p.message || "Parse stream error."), "error");
  }

  // ── SSE retry / close / cancel ─────────────────────────────────────────────

  /** Attempt to reconnect the parse SSE stream with exponential backoff. */
  function retryParseSse() {
    if (st.parse.done || st.parse.fail || !st.parse.run) return;
    A.retrySseStream(st.parse, {
      reconnect: () => {
        if (!st.parse.done && !st.parse.fail && st.parse.run) startParseSse();
      },
      onRetryScheduled: (attempt, delaySec) => {
        A.setMsg(el.parseErr, `Parse progress connection dropped. Reconnecting (${attempt}/${A.SSE_MAX_RETRIES}) in ${delaySec}s...`, "error");
      },
      onMaxRetries: () => {
        st.parse.run = false;
        st.parse.done = false;
        st.parse.fail = true;
        st.parse.retryCount = 0;
        A.stopTimer("parse");
        closeParseSse();
        A.setMsg(el.parseErr, `Parse progress connection lost after ${A.SSE_MAX_RETRIES} retries. Start parsing again.`, "error");
        A.updateParseButton();
        A.updateNav();
      },
    });
  }

  /** Close the parse SSE EventSource and clear pending retries. */
  function closeParseSse() {
    A.closeSseChannel(st.parse);
  }

  /** Cancel any in-progress parse: abort HTTP, close SSE, notify backend. */
  function cancelParse() {
    if (st.parse.abort) {
      st.parse.abort.abort();
      st.parse.abort = null;
    }
    closeParseSse();
    const wasRunning = st.parse.run;
    if (!wasRunning) return;
    st.parse.run = false;
    st.parse.done = false;
    st.parse.fail = false;
    A.stopTimer("parse");
    A.setMsg(el.parseErr, "Parsing cancelled.", "info");
    A.updateParseButton();
    A.updateNav();
    const caseId = A.activeCaseId();
    if (caseId) {
      st.parse.cancelPending = A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/parse/cancel`, { method: "POST" })
        .catch(() => {})
        .finally(() => { st.parse.cancelPending = null; });
    }
  }

  /** Reset all parse state, close SSE, clear UI, and cascade to analysis reset. */
  function resetParseState() {
    closeParseSse();
    A.stopTimer("parse");
    st.parse.run = false;
    st.parse.done = false;
    st.parse.fail = false;
    st.parse.retryCount = 0;
    st.parse.seq = -1;
    st.parse.rows = {};
    st.parse.status = {};
    A.clearMsg(el.parseErr);
    renderParsePlaceholder();
    // Old analysis results depend on old parsed data — clear them.
    A.resetAnalysisState();
    A.updateParseButton();
    A.updateNav();
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  A.submitParse = submitParse;
  A.cancelParse = cancelParse;
  A.closeParseSse = closeParseSse;
  A.resetParseState = resetParseState;
  A.renderParsePlaceholder = renderParsePlaceholder;
})();
