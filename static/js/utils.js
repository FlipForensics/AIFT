/**
 * AIFT shared namespace, application state, and utility functions.
 *
 * Loaded first — every other module depends on window.AIFT.
 */
"use strict";

window.AIFT = (() => {
  // ── Constants ──────────────────────────────────────────────────────────────
  const STEP_IDS = ["step-evidence", "step-artifacts", "step-parsing", "step-analysis", "step-results"];
  const RECOMMENDED_PRESET_EXCLUDED_ARTIFACTS = new Set(["mft", "usnjrnl", "evtx", "defender.evtx"]);
  const MODE_PARSE_AND_AI = "parse_and_ai";
  const MODE_PARSE_ONLY = "parse_only";
  const RECOMMENDED_PROFILE = "recommended";
  const DROP_HELP = "Drag and drop evidence here (.E01, .dd, .raw, .vmdk, .vhd, .vhdx, .vdi, .qcow2, .zip, .7z, .tar, ...)";
  const CONFIDENCE_TOKEN_PATTERN = /\b(CRITICAL|HIGH|MEDIUM|LOW)\b/gi;
  const AI_MAX_TOKENS_WARNING_THRESHOLD = 32000;
  const CONFIDENCE_CLASS_MAP = {
    CRITICAL: "confidence-critical",
    HIGH: "confidence-high",
    MEDIUM: "confidence-medium",
    LOW: "confidence-low",
  };
  const SSE_MAX_RETRIES = 10;
  const SSE_RETRY_BASE_DELAY_MS = 1000;
  const SSE_RETRY_MAX_DELAY_MS = 30000;
  const FETCH_TIMEOUT_API_MS = 60000;
  const FETCH_TIMEOUT_UPLOAD_MS = 240000;

  // ── Application state ──────────────────────────────────────────────────────
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
    parse: { run: false, done: false, fail: false, es: null, retry: null, retryCount: 0, seq: -1, rows: {}, status: {}, timer: null, started: 0, abort: null, cancelPending: null },
    analysis: { run: false, done: false, fail: false, es: null, retry: null, retryCount: 0, seq: -1, order: [], byKey: {}, summary: "", model: {}, timer: null, started: 0, abort: null, cancelPending: null },
    chat: {
      run: false,
      es: null,
      retry: null,
      retryCount: 0,
      seq: -1,
      pending: null,
      historyLoadedCaseId: "",
    },
  };

  let csrfToken = "";

  const el = {};
  const q = (id) => document.getElementById(id);

  // ── Fetch with timeout ─────────────────────────────────────────────────────
  async function fetchWithTimeout(url, init = {}, timeoutMs = FETCH_TIMEOUT_API_MS) {
    const controller = new AbortController();
    let timedOut = false;

    if (init.signal) {
      if (init.signal.aborted) {
        controller.abort(init.signal.reason);
      } else {
        init.signal.addEventListener("abort", () => controller.abort(init.signal.reason), { once: true });
      }
    }

    const timer = timeoutMs > 0
      ? window.setTimeout(() => { timedOut = true; controller.abort(); }, timeoutMs)
      : null;

    try {
      return await fetch(url, Object.assign({}, init, { signal: controller.signal }));
    } catch (e) {
      if (e.name === "AbortError" && timedOut) {
        const err = new Error(`Request timed out after ${Math.round(timeoutMs / 1000)}s.`);
        err.name = "TimeoutError";
        throw err;
      }
      throw e;
    } finally {
      if (timer) window.clearTimeout(timer);
    }
  }

  function handleFetchError(error, url) {
    if (error.name === "TimeoutError") {
      return `Request to ${url} timed out. The server may be busy \u2014 please try again.`;
    }
    if (error.name === "AbortError") {
      return "Request was cancelled.";
    }
    if (error instanceof TypeError || /network|failed to fetch/i.test(error.message)) {
      return "Network error: unable to reach the server. Check your connection and ensure AIFT is running.";
    }
    return error.message || `Request to ${url} failed.`;
  }

  // ── CSRF ───────────────────────────────────────────────────────────────────
  async function fetchCsrfToken() {
    try {
      const r = await fetchWithTimeout("/api/csrf-token", { method: "GET" });
      if (r.ok) {
        const data = await r.json();
        csrfToken = data.csrf_token || "";
      }
    } catch (_e) { /* CSRF fetch is best-effort */ }
  }

  // ── Case ID helpers ────────────────────────────────────────────────────────
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

  // ── Message helpers ────────────────────────────────────────────────────────
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

  // ── Timer helpers ──────────────────────────────────────────────────────────
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

  // ── SSE helpers (shared across parse / analysis / chat) ────────────────────
  function sseRetryDelayMs(attempt) {
    const normalizedAttempt = Number.isFinite(attempt) ? Math.max(1, Math.floor(attempt)) : 1;
    const backoff = SSE_RETRY_BASE_DELAY_MS * (2 ** (normalizedAttempt - 1));
    return Math.min(SSE_RETRY_MAX_DELAY_MS, backoff);
  }

  function closeSseChannel(channel) {
    if (channel.abort) {
      channel.abort.abort();
      channel.abort = null;
    }
    if (channel.retry) {
      window.clearTimeout(channel.retry);
      channel.retry = null;
    }
    if (channel.es) {
      channel.es.close();
      channel.es = null;
    }
  }

  // ── Network ────────────────────────────────────────────────────────────────
  async function apiJson(url, opts = {}) {
    const headers = Object.assign({}, opts.headers || {});
    const method = opts.method || "GET";
    if (csrfToken && method !== "GET" && method !== "HEAD") {
      headers["X-CSRF-Token"] = csrfToken;
    }
    const init = { method, headers };
    if (opts.signal) init.signal = opts.signal;
    if (Object.prototype.hasOwnProperty.call(opts, "json")) {
      headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(opts.json);
    } else if (Object.prototype.hasOwnProperty.call(opts, "body")) {
      init.body = opts.body;
      if (init.body instanceof FormData) delete headers["Content-Type"];
    }
    const timeoutMs = typeof opts.timeout === "number" ? opts.timeout : FETCH_TIMEOUT_API_MS;
    let r;
    try {
      r = await fetchWithTimeout(url, init, timeoutMs);
    } catch (e) {
      if (e.name === "AbortError") throw e;
      throw new Error(handleFetchError(e, url));
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

  // ── Pure utilities ─────────────────────────────────────────────────────────
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

  function boolSetting(value, fallback = false) {
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
      if (normalized === "false" || normalized === "0" || normalized === "no") return false;
    }
    return fallback;
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  return {
    // Constants
    STEP_IDS, RECOMMENDED_PRESET_EXCLUDED_ARTIFACTS, MODE_PARSE_AND_AI, MODE_PARSE_ONLY,
    RECOMMENDED_PROFILE, DROP_HELP, CONFIDENCE_TOKEN_PATTERN, AI_MAX_TOKENS_WARNING_THRESHOLD,
    CONFIDENCE_CLASS_MAP, SSE_MAX_RETRIES, SSE_RETRY_BASE_DELAY_MS, SSE_RETRY_MAX_DELAY_MS,
    FETCH_TIMEOUT_API_MS, FETCH_TIMEOUT_UPLOAD_MS,
    // State & DOM
    st, el, q,
    // CSRF
    fetchCsrfToken,
    // Case ID
    setCaseId, activeCaseId,
    // Messages & timers
    ensureMsg, setMsg, clearMsg, ensureTimer, startTimer, stopTimer,
    // SSE
    sseRetryDelayMs, closeSseChannel,
    // Network
    fetchWithTimeout, handleFetchError, apiJson, readErr,
    // Utilities
    artifactName, fmtBytes, fmtNumber, safeJson, escapeHtml, val, num,
    isObj, obj, clone,
    toBackendProvider, toUiProvider, normProvider, prettyProvider,
    stripLeadingReasoningBlocks, getFilename, boolSetting,
  };
})();
