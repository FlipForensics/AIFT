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

  /**
   * Perform a fetch request with an automatic timeout.
   *
   * Wraps the native `fetch` with an AbortController that fires after
   * `timeoutMs` milliseconds.  If an external signal is supplied via
   * `init.signal`, it is chained so that either signal can abort the request.
   *
   * @param {string} url - Request URL.
   * @param {RequestInit} [init={}] - Standard fetch init options.
   * @param {number} [timeoutMs=FETCH_TIMEOUT_API_MS] - Timeout in ms; 0 disables.
   * @returns {Promise<Response>} The fetch Response.
   * @throws {Error} With name "TimeoutError" when the timeout fires.
   */
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

  /**
   * Derive a user-friendly error message from a failed fetch.
   *
   * @param {Error} error - The caught error from fetchWithTimeout.
   * @param {string} url - The URL that was being fetched (for context).
   * @returns {string} Human-readable error description.
   */
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

  /** Fetch the CSRF token from the server and cache it (best-effort). */
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

  /**
   * Persist a case ID into application state and the wizard DOM element.
   *
   * @param {string} rawCaseId - The raw case identifier to store.
   * @returns {string} The trimmed case ID that was set.
   */
  function setCaseId(rawCaseId) {
    const caseId = String(rawCaseId || "").trim();
    st.caseId = caseId;
    if (el.wizard) {
      if (caseId) el.wizard.dataset.caseId = caseId;
      else delete el.wizard.dataset.caseId;
    }
    return st.caseId;
  }

  /**
   * Return the current case ID from state, falling back to the DOM attribute.
   *
   * @returns {string} The active case ID, or empty string if none is set.
   */
  function activeCaseId() {
    if (st.caseId) return st.caseId;
    const domCaseId = el.wizard ? String(el.wizard.dataset.caseId || "").trim() : "";
    if (domCaseId) return setCaseId(domCaseId);
    return "";
  }

  // ── Message helpers ────────────────────────────────────────────────────────

  /**
   * Ensure a status-message paragraph element exists inside a parent.
   *
   * If an element with the given `id` already exists in the DOM it is
   * returned as-is; otherwise a new hidden `<p>` is created and appended.
   *
   * @param {HTMLElement} parent - Container to append the element into.
   * @param {string} id - DOM id for the message element.
   * @returns {HTMLElement} The message paragraph node.
   */
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

  /**
   * Display a status message in a message node.
   *
   * @param {HTMLElement|null} node - The message element (from ensureMsg).
   * @param {string} text - Message content; falsy clears the message.
   * @param {string} [kind="info"] - One of "info", "error", or "success".
   */
  function setMsg(node, text, kind = "info") {
    if (!node) return;
    if (!text) return clearMsg(node);
    node.hidden = false;
    node.textContent = text;
    node.dataset.status = kind === "error" ? "failed" : kind === "success" ? "success" : "in-progress";
  }

  /** Hide and clear a status-message node. @param {HTMLElement|null} node */
  function clearMsg(node) {
    if (!node) return;
    node.hidden = true;
    node.textContent = "";
    delete node.dataset.status;
  }

  // ── Timer helpers ──────────────────────────────────────────────────────────

  /**
   * Ensure an elapsed-time paragraph element exists in a step container.
   *
   * @param {HTMLElement|null} container - Wizard step element.
   * @param {string} id - DOM id for the timer element.
   * @returns {HTMLElement} The timer paragraph node (initially hidden).
   */
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

  /**
   * Start an elapsed-time ticker for parse or analysis.
   *
   * @param {string} kind - Either "parse" or "analysis".
   */
  function startTimer(kind) {
    const node = kind === "parse" ? el.parseElapsed : el.analysisElapsed;
    const tgt = kind === "parse" ? st.parse : st.analysis;
    stopTimer(kind);
    if (!node || !tgt) return;
    tgt.started = Date.now();
    node.hidden = false;
    const tick = () => { node.textContent = `Elapsed: ${fmtElapsed(tgt.started)}`; };
    tick();
    tgt.timer = window.setInterval(tick, 1000);
  }

  /** Stop the elapsed-time ticker for parse or analysis. @param {string} kind */
  function stopTimer(kind) {
    const tgt = kind === "parse" ? st.parse : st.analysis;
    if (tgt && tgt.timer) {
      window.clearInterval(tgt.timer);
      tgt.timer = null;
    }
  }

  // ── SSE helpers (shared across parse / analysis / chat) ────────────────────

  /**
   * Compute exponential-backoff delay for an SSE reconnection attempt.
   *
   * @param {number} attempt - 1-based attempt counter.
   * @returns {number} Delay in milliseconds, capped at SSE_RETRY_MAX_DELAY_MS.
   */
  function sseRetryDelayMs(attempt) {
    const normalizedAttempt = Number.isFinite(attempt) ? Math.max(1, Math.floor(attempt)) : 1;
    const backoff = SSE_RETRY_BASE_DELAY_MS * (2 ** (normalizedAttempt - 1));
    return Math.min(SSE_RETRY_MAX_DELAY_MS, backoff);
  }

  /**
   * Close an SSE channel, aborting any pending request and clearing timers.
   *
   * @param {Object} channel - State object with optional abort, retry, and es
   *     properties.
   */
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

  /**
   * Make a JSON-capable API request with CSRF, timeout, and error handling.
   *
   * Automatically attaches the CSRF token for mutating methods, serialises
   * a `json` option as JSON body, and parses the response.
   *
   * @param {string} url - API endpoint URL.
   * @param {Object} [opts={}] - Options.
   * @param {string} [opts.method="GET"] - HTTP method.
   * @param {Object} [opts.json] - Body to serialise as JSON.
   * @param {BodyInit} [opts.body] - Raw body (FormData, string, etc.).
   * @param {AbortSignal} [opts.signal] - Optional abort signal.
   * @param {number} [opts.timeout] - Override timeout in ms.
   * @param {Object} [opts.headers] - Additional request headers.
   * @returns {Promise<Object|string>} Parsed JSON object or response text.
   * @throws {Error} On non-2xx status or network failure.
   */
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

  /**
   * Extract an error message string from a non-ok Response.
   *
   * @param {Response} r - The fetch Response object.
   * @returns {Promise<string>} The extracted error text.
   */
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

  /** Return the display name for an artifact key. @param {string} k */
  function artifactName(k) {
    return st.artifactNames[k] || k;
  }

  /**
   * Format a byte count as a human-readable string (e.g. "1.5 MB").
   *
   * @param {number} b - Byte count.
   * @returns {string} Formatted size string.
   */
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

  /**
   * Format a number using locale conventions without grouping separators.
   *
   * @param {number} v - The value to format.
   * @param {number} [max=3] - Maximum fraction digits.
   * @returns {string} Formatted number string, or "" if not finite.
   */
  function fmtNumber(v, max = 3) {
    return Number.isFinite(v)
      ? v.toLocaleString(undefined, { maximumFractionDigits: max, minimumFractionDigits: 0, useGrouping: false })
      : "";
  }

  /** Parse a JSON string, returning null on failure. @param {string} t */
  function safeJson(t) {
    if (typeof t !== "string" || !t) return null;
    try {
      return JSON.parse(t);
    } catch (_e) {
      return null;
    }
  }

  /** Escape HTML special characters for safe insertion into markup. @param {*} value */
  function escapeHtml(value) {
    return String(value || "")
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#39;");
  }

  /** Return the trimmed value of a form input element. @param {HTMLInputElement|null} input */
  function val(input) {
    return input ? String(input.value || "").trim() : "";
  }

  /**
   * Coerce a value to a finite number, returning a fallback otherwise.
   *
   * @param {*} v - Value to coerce.
   * @param {*} fallback - Returned when `v` is null, undefined, empty, or NaN.
   * @returns {number|*} The parsed number, or `fallback`.
   */
  function num(v, fallback) {
    if (v === null || v === undefined || v === "") return fallback;
    const n = Number(v);
    return Number.isFinite(n) ? n : fallback;
  }

  /** Check if a value is a plain object (not null, not an array). @param {*} v */
  function isObj(v) {
    return v !== null && typeof v === "object" && !Array.isArray(v);
  }

  /** Return `v` if it is a plain object, otherwise an empty object. @param {*} v */
  function obj(v) {
    return isObj(v) ? v : {};
  }

  /** Deep-clone a value via structuredClone (with JSON fallback). @param {*} v */
  function clone(v) {
    if (typeof structuredClone === "function") return structuredClone(v);
    try {
      return JSON.parse(JSON.stringify(v));
    } catch (_e) {
      return {};
    }
  }

  /** Map a UI provider name (e.g. "anthropic") to the backend key (e.g. "claude"). */
  function toBackendProvider(ui) {
    if (ui === "anthropic") return "claude";
    if (ui === "kimi") return "kimi";
    if (ui === "local") return "local";
    return "openai";
  }

  /** Map a backend provider key (e.g. "claude") to the UI name (e.g. "anthropic"). */
  function toUiProvider(back) {
    if (back === "claude") return "anthropic";
    if (back === "kimi") return "kimi";
    if (back === "local") return "local";
    return "openai";
  }

  /** Normalise a provider string to one of "claude", "openai", "kimi", "local", or "". */
  function normProvider(p) {
    const x = String(p || "").trim().toLowerCase();
    if (x === "anthropic") return "claude";
    if (x === "claude" || x === "openai" || x === "kimi" || x === "local") return x;
    return "";
  }

  /** Return a human-readable label for a provider key (e.g. "Claude", "OpenAI"). */
  function prettyProvider(p) {
    const x = normProvider(p);
    if (x === "claude") return "Claude";
    if (x === "openai") return "OpenAI";
    if (x === "kimi") return "Kimi";
    if (x === "local") return "Local";
    return p || "Unknown";
  }

  /**
   * Strip leading `<think>`/`<reasoning>` XML blocks and code-fenced reasoning
   * from AI output so the user sees only the final answer.
   *
   * @param {string} text - Raw AI response text.
   * @returns {string} Cleaned text with reasoning blocks removed.
   */
  function stripLeadingReasoningBlocks(text) {
    const raw = String(text || "").trim();
    if (!raw) return "";
    const cleaned = raw.replace(
      /^(?:\s*(?:<\s*(?:think|thinking|reasoning)\b[^>]*>[\s\S]*?<\s*\/\s*(?:think|thinking|reasoning)\s*>|```(?:think|thinking|reasoning)[^\n]*\n[\s\S]*?```)\s*)+/i,
      "",
    );
    return cleaned.trim();
  }

  /**
   * Extract a filename from a Content-Disposition header.
   *
   * Supports both RFC 5987 `filename*=UTF-8''...` and the plain
   * `filename="..."` forms.
   *
   * @param {Headers} headers - Response headers object.
   * @returns {string} Extracted filename, or "".
   */
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

  /**
   * Coerce a value to boolean, accepting string representations like
   * "true"/"false", "1"/"0", "yes"/"no".
   *
   * @param {*} value - The value to coerce.
   * @param {boolean} [fallback=false] - Default when value is unrecognised.
   * @returns {boolean}
   */
  function boolSetting(value, fallback = false) {
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
      const normalized = value.trim().toLowerCase();
      if (normalized === "true" || normalized === "1" || normalized === "yes") return true;
      if (normalized === "false" || normalized === "0" || normalized === "no") return false;
    }
    return fallback;
  }

  /**
   * Format elapsed time since a given start timestamp as "MM:SS".
   *
   * @param {number} startedAt - Timestamp from Date.now() when the timer started.
   * @returns {string} Formatted elapsed time string (e.g. "01:23").
   */
  function fmtElapsed(startedAt) {
    const s = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    return `${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  }

  /**
   * Open an SSE EventSource with automatic sequence deduplication.
   *
   * Provides a standard pattern used by parse, analysis, and chat SSE
   * streams: open the EventSource, reset retry count on connection,
   * deduplicate by sequence number, and delegate events to a handler.
   *
   * @param {string} url - The SSE endpoint URL.
   * @param {Object} channel - State object (e.g. st.parse) with es, retryCount,
   *     and seq properties.
   * @param {Object} handlers - Callback map.
   * @param {function(Object): void} handlers.onEvent - Called for each
   *     deduplicated SSE payload.
   * @param {function(): void} handlers.onError - Called on EventSource error
   *     (typically triggers retry logic).
   */
  function openSseStream(url, channel, handlers) {
    closeSseChannel(channel);
    const es = new EventSource(url);
    channel.es = es;
    es.onopen = () => { channel.retryCount = 0; };
    es.onmessage = (ev) => {
      const payload = safeJson(ev.data);
      if (!payload) return;
      const seq = num(payload.sequence, -1);
      if (seq >= 0) {
        if (seq <= channel.seq) return;
        channel.seq = seq;
      }
      handlers.onEvent(payload);
    };
    es.onerror = () => {
      if (typeof handlers.onError === "function") handlers.onError();
    };
  }

  /**
   * Attempt to reconnect an SSE stream with exponential backoff.
   *
   * Increments the channel's retry counter, checks against
   * SSE_MAX_RETRIES, and schedules a reconnection via setTimeout.
   *
   * @param {Object} channel - State object with retry, retryCount, and run
   *     properties.
   * @param {Object} handlers - Callback map.
   * @param {function(): void} handlers.reconnect - Called after the delay to
   *     re-open the SSE stream.
   * @param {function(): void} handlers.onMaxRetries - Called when retries are
   *     exhausted.
   * @param {function(number, number): void} [handlers.onRetryScheduled] -
   *     Optional callback receiving (attempt, delaySec) for UI feedback.
   * @returns {boolean} True if a retry was scheduled, false if max retries
   *     exceeded.
   */
  function retrySseStream(channel, handlers) {
    if (channel.retry) return true;
    const attempt = channel.retryCount + 1;
    if (attempt > SSE_MAX_RETRIES) {
      handlers.onMaxRetries();
      return false;
    }
    channel.retryCount = attempt;
    const delay = sseRetryDelayMs(attempt);
    closeSseChannel(channel);
    if (typeof handlers.onRetryScheduled === "function") {
      handlers.onRetryScheduled(attempt, Math.ceil(delay / 1000));
    }
    channel.retry = window.setTimeout(() => {
      channel.retry = null;
      if (typeof handlers.reconnect === "function") handlers.reconnect();
    }, delay);
    return true;
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
    stripLeadingReasoningBlocks, getFilename, boolSetting, fmtElapsed,
    openSseStream, retrySseStream,
  };
})();
