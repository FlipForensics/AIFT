/**
 * Analysis SSE, result rendering, and findings display for AIFT.
 *
 * Manages the analysis lifecycle: submit, track via SSE, render
 * per-artifact results, executive summary, and collapsible findings.
 *
 * Depends on: AIFT (utils.js, markdown.js)
 */
"use strict";

(() => {
  const A = window.AIFT;
  const { st, el } = A;

  // ── Analysis submission ────────────────────────────────────────────────────

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

    resetAnalysisState();
    st.analysis.run = true;
    const abortCtrl = new AbortController();
    st.analysis.abort = abortCtrl;
    A.clearMsg(el.resultsMsg);
    if (el.runBtn) el.runBtn.disabled = true;
    if (el.cancelAnalysis) el.cancelAnalysis.hidden = false;

    try {
      A.startTimer("analysis");
      await A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/analyze`, { method: "POST", json: { prompt: A.val(el.prompt) }, signal: abortCtrl.signal });
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

  function startAnalysisSse() {
    closeAnalysisSse();
    const caseId = A.activeCaseId();
    if (!caseId) return A.setMsg(el.analysisMsg, "No case ID for analysis stream.", "error");
    const es = new EventSource(`/api/cases/${encodeURIComponent(caseId)}/analyze/progress`);
    st.analysis.es = es;
    es.onopen = () => { st.analysis.retryCount = 0; };
    es.onmessage = (ev) => {
      st.analysis.retryCount = 0;
      const p = A.safeJson(ev.data);
      if (!p) return;
      const seq = A.num(p.sequence, -1);
      if (seq >= 0) {
        if (seq <= st.analysis.seq) return;
        st.analysis.seq = seq;
      }
      onAnalysisEvent(p);
    };
    es.onerror = () => {
      if (st.analysis.done || st.analysis.fail || !st.analysis.run) return;
      retryAnalysisSse();
    };
  }

  function onAnalysisEvent(p) {
    const t = String(p.type || "");
    if (t === "analysis_started") {
      A.clearMsg(el.analysisMsg);
      renderAnalysis();
      renderFindings();
      return;
    }
    if (t === "artifact_analysis_started") {
      upsertAnalysisStarted(A.isObj(p.result) ? p.result : p);
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
      if (el.runBtn) el.runBtn.disabled = false;
      if (el.cancelAnalysis) el.cancelAnalysis.hidden = true;
      A.setMsg(el.analysisMsg, String(p.error || "Analysis failed."), "error");
      A.updateNav();
      return;
    }
    if (t === "error") A.setMsg(el.analysisMsg, String(p.message || "Analysis stream error."), "error");
  }

  // ── Analysis data upserts ──────────────────────────────────────────────────

  function upsertAnalysis(r) {
    const key = String(r.artifact_key || r.key || `artifact_${st.analysis.order.length + 1}`);
    const name = String(r.artifact_name || A.artifactName(key));
    const rawText = String(r.analysis || r.result || "");
    const text = A.stripLeadingReasoningBlocks(rawText) || rawText;
    const model = String(r.model || "");
    if (!st.analysis.byKey[key]) st.analysis.order.push(key);
    st.analysis.byKey[key] = { key, name, text, model, thinkingText: "", partialText: "", isThinking: false };
  }

  function upsertAnalysisStarted(r) {
    const key = String(r.artifact_key || r.key || `artifact_${st.analysis.order.length + 1}`);
    const name = String(r.artifact_name || A.artifactName(key));
    const model = String(r.model || "");
    if (!st.analysis.byKey[key]) st.analysis.order.push(key);
    const current = st.analysis.byKey[key] || {};
    st.analysis.byKey[key] = {
      key, name,
      text: String(current.text || ""),
      model: model || String(current.model || ""),
      thinkingText: String(current.thinkingText || "Model is thinking..."),
      partialText: String(current.partialText || ""),
      isThinking: true,
    };
  }

  function upsertAnalysisThinking(r) {
    const key = String(r.artifact_key || r.key || `artifact_${st.analysis.order.length + 1}`);
    const name = String(r.artifact_name || A.artifactName(key));
    const model = String(r.model || "");
    if (!st.analysis.byKey[key]) st.analysis.order.push(key);
    const current = st.analysis.byKey[key] || {};
    st.analysis.byKey[key] = {
      key, name,
      text: String(current.text || ""),
      model: model || String(current.model || ""),
      thinkingText: String(r.thinking_text || current.thinkingText || ""),
      partialText: String(r.partial_text || current.partialText || ""),
      isThinking: true,
    };
  }

  function finalizeAnyThinkingArtifacts() {
    st.analysis.order.forEach((key) => {
      const current = st.analysis.byKey[key];
      if (!current || !current.isThinking) return;
      const rawResolvedText = String(current.text || current.partialText || current.thinkingText || "");
      const resolvedText = A.stripLeadingReasoningBlocks(rawResolvedText) || rawResolvedText.trim();
      st.analysis.byKey[key] = { ...current, text: resolvedText, isThinking: false };
    });
  }

  // ── Rendering helpers ──────────────────────────────────────────────────────

  function resolveAnalysisText(r) {
    if (r.isThinking && !String(r.text || "").trim()) {
      return String(r.thinkingText || r.partialText || "Model is thinking...");
    }
    return r.text;
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
      const displayText = resolveAnalysisText(r);
      const emptyLabel = r.isThinking ? "Model is thinking..." : "(No analysis text returned.)";
      A.renderMarkdownInto(b, displayText, emptyLabel);
      a.appendChild(h);
      a.appendChild(m);
      a.appendChild(b);
      el.analysisList.appendChild(a);
    });
  }

  function renderExecSummary() {
    if (!el.summaryOut) return;
    A.renderMarkdownInto(el.summaryOut, st.analysis.summary, "Summary is generated after analysis completes.");
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
      const displayText = resolveAnalysisText(r);
      const emptyLabel = r.isThinking ? "Model is thinking..." : "(No analysis text returned.)";
      A.renderMarkdownInto(p, displayText, emptyLabel);
      d.appendChild(s);
      d.appendChild(p);
      el.findings.appendChild(d);
    });
  }

  function setProvider(text) {
    if (el.providerName) el.providerName.textContent = text || "Not configured";
  }

  // ── SSE retry / close / cancel ─────────────────────────────────────────────

  function retryAnalysisSse() {
    if (st.analysis.retry || st.analysis.done || st.analysis.fail || !st.analysis.run) return;
    const attempt = st.analysis.retryCount + 1;
    if (attempt > A.SSE_MAX_RETRIES) return failAnalysisSseReconnect();
    st.analysis.retryCount = attempt;
    const delay = A.sseRetryDelayMs(attempt);
    closeAnalysisSse();
    A.setMsg(el.analysisMsg, `Analysis progress connection dropped. Reconnecting (${attempt}/${A.SSE_MAX_RETRIES}) in ${Math.ceil(delay / 1000)}s...`, "error");
    st.analysis.retry = window.setTimeout(() => {
      st.analysis.retry = null;
      if (!st.analysis.done && !st.analysis.fail && st.analysis.run) startAnalysisSse();
    }, delay);
  }

  function failAnalysisSseReconnect() {
    st.analysis.run = false;
    st.analysis.done = false;
    st.analysis.fail = true;
    st.analysis.retryCount = 0;
    A.stopTimer("analysis");
    closeAnalysisSse();
    if (el.runBtn) el.runBtn.disabled = false;
    A.setMsg(el.analysisMsg, `Analysis progress connection lost after ${A.SSE_MAX_RETRIES} retries. Run analysis again.`, "error");
    A.updateNav();
  }

  function closeAnalysisSse() {
    A.closeSseChannel(st.analysis);
  }

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
    A.setMsg(el.analysisMsg, "Analysis cancelled.", "info");
    A.updateNav();
    const caseId = A.activeCaseId();
    if (caseId) {
      fetch(`/api/cases/${caseId}/analyze/cancel`, { method: "POST" }).catch(() => {});
    }
  }

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
    st.analysis.summary = "";
    st.analysis.model = {};
    A.clearMsg(el.analysisMsg);
    if (el.runBtn) el.runBtn.disabled = false;
    if (el.cancelAnalysis) el.cancelAnalysis.hidden = true;
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
})();
