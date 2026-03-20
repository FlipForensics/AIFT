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

    st.selected = arts;
    st.selectedAi = aiArtifacts;
    resetParseState();
    st.parse.run = true;
    const abortCtrl = new AbortController();
    st.parse.abort = abortCtrl;
    initParseRows(arts);
    updateParseProgress();
    if (el.parseBtn) el.parseBtn.disabled = true;

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

  function updateParseProgress(force = false) {
    if (!el.parseProgress) return;
    if (force) return (el.parseProgress.value = 100);
    const keys = st.selected.length ? st.selected : Object.keys(st.parse.status);
    if (!keys.length) return (el.parseProgress.value = 0);
    const done = keys.filter((k) => st.parse.status[k] === "completed" || st.parse.status[k] === "failed").length;
    el.parseProgress.value = Math.max(0, Math.min(100, Math.round((done / keys.length) * 100)));
  }

  // ── Parse SSE ──────────────────────────────────────────────────────────────

  function startParseSse() {
    closeParseSse();
    A.clearMsg(el.parseErr);
    const caseId = A.activeCaseId();
    if (!caseId) return A.setMsg(el.parseErr, "No active case for parse stream.", "error");
    const es = new EventSource(`/api/cases/${encodeURIComponent(caseId)}/parse/progress`);
    st.parse.es = es;
    es.onopen = () => { st.parse.retryCount = 0; };
    es.onmessage = (ev) => {
      st.parse.retryCount = 0;
      const p = A.safeJson(ev.data);
      if (!p) return;
      const seq = A.num(p.sequence, -1);
      if (seq >= 0) {
        if (seq <= st.parse.seq) return;
        st.parse.seq = seq;
      }
      onParseEvent(p);
    };
    es.onerror = () => {
      if (st.parse.done || st.parse.fail || !st.parse.run) return;
      retryParseSse();
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
      return A.showStep(4);
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

  function retryParseSse() {
    if (st.parse.retry || st.parse.done || st.parse.fail || !st.parse.run) return;
    const attempt = st.parse.retryCount + 1;
    if (attempt > A.SSE_MAX_RETRIES) return failParseSseReconnect();
    st.parse.retryCount = attempt;
    const delay = A.sseRetryDelayMs(attempt);
    closeParseSse();
    A.setMsg(el.parseErr, `Parse progress connection dropped. Reconnecting (${attempt}/${A.SSE_MAX_RETRIES}) in ${Math.ceil(delay / 1000)}s...`, "error");
    st.parse.retry = window.setTimeout(() => {
      st.parse.retry = null;
      if (!st.parse.done && !st.parse.fail && st.parse.run) startParseSse();
    }, delay);
  }

  function failParseSseReconnect() {
    st.parse.run = false;
    st.parse.done = false;
    st.parse.fail = true;
    st.parse.retryCount = 0;
    A.stopTimer("parse");
    closeParseSse();
    A.setMsg(el.parseErr, `Parse progress connection lost after ${A.SSE_MAX_RETRIES} retries. Start parsing again.`, "error");
    A.updateParseButton();
    A.updateNav();
  }

  function closeParseSse() {
    A.closeSseChannel(st.parse);
  }

  function cancelParse() {
    if (st.parse.abort) {
      st.parse.abort.abort();
      st.parse.abort = null;
    }
    closeParseSse();
    if (!st.parse.run) return;
    st.parse.run = false;
    st.parse.done = false;
    st.parse.fail = true;
    A.stopTimer("parse");
    A.setMsg(el.parseErr, "Parsing cancelled.", "info");
    A.updateParseButton();
    A.updateNav();
  }

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
