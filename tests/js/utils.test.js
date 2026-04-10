/**
 * Unit tests for AIFT utility functions (utils.js).
 *
 * Covers:
 *  - fmtBytes formatting
 *  - fmtNumber locale-independent formatting
 *  - escapeHtml XSS prevention
 *  - safeJson robust JSON parsing
 *  - num coercion with fallback
 *  - isObj / obj plain-object checks
 *  - clone deep copy
 *  - val input trimming
 *  - boolSetting boolean coercion
 *  - fmtElapsed timer formatting
 *  - sseRetryDelayMs exponential backoff
 *  - Provider mapping (toBackendProvider, toUiProvider, normProvider, prettyProvider)
 *  - stripLeadingReasoningBlocks AI output cleanup
 *  - getFilename Content-Disposition parsing
 *  - handleFetchError user-friendly messages
 *  - ensureMsg / setMsg / clearMsg DOM helpers
 *  - setCaseId / activeCaseId state management
 *  - closeSseChannel cleanup
 *  - Constants sanity checks
 *
 * @jest-environment jsdom
 */

"use strict";

const fs = require("fs");
const path = require("path");

const STATIC = path.resolve(__dirname, "..", "..", "static");
const TEMPLATES = path.resolve(__dirname, "..", "..", "templates");

function readJs(relPath) {
  return fs.readFileSync(path.join(STATIC, relPath), "utf-8");
}

function setup() {
  const indexHtml = fs.readFileSync(path.join(TEMPLATES, "index.html"), "utf-8");
  document.documentElement.innerHTML = "";
  document.write(indexHtml);
  document.close();

  global.fetch = () => Promise.reject(new Error("fetch not available in tests"));
  global.EventSource = class { close() {} };

  const scripts = [
    "js/utils.js",
    "js/markdown.js",
    "js/evidence.js",
    "js/evidence_multi.js",
    "js/parsing.js",
    "js/analysis.js",
    "js/chat.js",
    "js/settings.js",
    "app.js",
  ];
  for (const s of scripts) {
    const code = readJs(s);
    try {
      const fn = new Function(code);
      fn.call(window);
    } catch (e) {
      throw new Error(`Failed to evaluate ${s}: ${e.message}`);
    }
  }

  document.dispatchEvent(new Event("DOMContentLoaded"));
  return window.AIFT;
}

let A;

beforeEach(() => {
  A = setup();
});

// ── fmtBytes ────────────────────────────────────────────────────────────────

describe("fmtBytes", () => {
  test("formats 0 bytes", () => {
    expect(A.fmtBytes(0)).toBe("0 B");
  });

  test("formats small byte values without conversion", () => {
    expect(A.fmtBytes(512)).toBe("512 B");
    expect(A.fmtBytes(1023)).toBe("1023 B");
  });

  test("formats kilobytes", () => {
    expect(A.fmtBytes(1024)).toBe("1.0 KB");
    expect(A.fmtBytes(1536)).toBe("1.5 KB");
  });

  test("formats megabytes", () => {
    expect(A.fmtBytes(1048576)).toBe("1.0 MB");
    expect(A.fmtBytes(10 * 1024 * 1024)).toBe("10 MB");
  });

  test("formats gigabytes", () => {
    expect(A.fmtBytes(1073741824)).toBe("1.0 GB");
  });

  test("handles negative values", () => {
    expect(A.fmtBytes(-1)).toBe("0 B");
  });

  test("handles NaN and Infinity", () => {
    expect(A.fmtBytes(NaN)).toBe("0 B");
    expect(A.fmtBytes(Infinity)).toBe("0 B");
  });
});

// ── fmtNumber ───────────────────────────────────────────────────────────────

describe("fmtNumber", () => {
  test("formats integers without decimals", () => {
    expect(A.fmtNumber(42)).toBe("42");
  });

  test("formats decimals up to max fraction digits", () => {
    const result = A.fmtNumber(3.14159, 2);
    // Locale-dependent decimal separator (. or ,)
    expect(result).toMatch(/^3[.,]14$/);
  });

  test("returns empty string for non-finite values", () => {
    expect(A.fmtNumber(NaN)).toBe("");
    expect(A.fmtNumber(Infinity)).toBe("");
  });
});

// ── escapeHtml ──────────────────────────────────────────────────────────────

describe("escapeHtml", () => {
  test("escapes all HTML special characters", () => {
    expect(A.escapeHtml('<script>alert("xss")&</script>')).toBe(
      "&lt;script&gt;alert(&quot;xss&quot;)&amp;&lt;/script&gt;"
    );
  });

  test("escapes single quotes", () => {
    expect(A.escapeHtml("it's")).toBe("it&#39;s");
  });

  test("handles null and undefined", () => {
    expect(A.escapeHtml(null)).toBe("");
    expect(A.escapeHtml(undefined)).toBe("");
  });

  test("handles empty string", () => {
    expect(A.escapeHtml("")).toBe("");
  });

  test("passes through safe text unchanged", () => {
    expect(A.escapeHtml("Hello World")).toBe("Hello World");
  });
});

// ── safeJson ────────────────────────────────────────────────────────────────

describe("safeJson", () => {
  test("parses valid JSON", () => {
    expect(A.safeJson('{"a":1}')).toEqual({ a: 1 });
  });

  test("parses JSON arrays", () => {
    expect(A.safeJson("[1,2,3]")).toEqual([1, 2, 3]);
  });

  test("returns null for invalid JSON", () => {
    expect(A.safeJson("{bad}")).toBeNull();
  });

  test("returns null for non-string input", () => {
    expect(A.safeJson(123)).toBeNull();
    expect(A.safeJson(null)).toBeNull();
    expect(A.safeJson(undefined)).toBeNull();
  });

  test("returns null for empty string", () => {
    expect(A.safeJson("")).toBeNull();
  });
});

// ── num ─────────────────────────────────────────────────────────────────────

describe("num", () => {
  test("returns number for valid numeric input", () => {
    expect(A.num(42, 0)).toBe(42);
    expect(A.num("3.14", 0)).toBe(3.14);
  });

  test("returns fallback for null, undefined, empty string", () => {
    expect(A.num(null, -1)).toBe(-1);
    expect(A.num(undefined, -1)).toBe(-1);
    expect(A.num("", -1)).toBe(-1);
  });

  test("returns fallback for NaN-producing values", () => {
    expect(A.num("abc", 99)).toBe(99);
    expect(A.num(NaN, 99)).toBe(99);
  });

  test("returns fallback for Infinity", () => {
    expect(A.num(Infinity, 0)).toBe(0);
  });

  test("handles zero correctly", () => {
    expect(A.num(0, 99)).toBe(0);
    expect(A.num("0", 99)).toBe(0);
  });
});

// ── isObj / obj ─────────────────────────────────────────────────────────────

describe("isObj and obj", () => {
  test("isObj returns true for plain objects", () => {
    expect(A.isObj({})).toBe(true);
    expect(A.isObj({ a: 1 })).toBe(true);
  });

  test("isObj returns false for non-objects", () => {
    expect(A.isObj(null)).toBe(false);
    expect(A.isObj(undefined)).toBe(false);
    expect(A.isObj(42)).toBe(false);
    expect(A.isObj("str")).toBe(false);
    expect(A.isObj([1, 2])).toBe(false);
  });

  test("obj returns the object if plain", () => {
    const o = { a: 1 };
    expect(A.obj(o)).toBe(o);
  });

  test("obj returns empty object for non-objects", () => {
    expect(A.obj(null)).toEqual({});
    expect(A.obj([1, 2])).toEqual({});
    expect(A.obj("str")).toEqual({});
  });
});

// ── clone ───────────────────────────────────────────────────────────────────

describe("clone", () => {
  test("deep clones an object", () => {
    const original = { a: { b: 1 }, c: [1, 2] };
    const cloned = A.clone(original);
    expect(cloned).toEqual(original);
    expect(cloned).not.toBe(original);
    expect(cloned.a).not.toBe(original.a);
    expect(cloned.c).not.toBe(original.c);
  });

  test("clones arrays", () => {
    const arr = [1, { x: 2 }];
    const cloned = A.clone(arr);
    expect(cloned).toEqual(arr);
    expect(cloned[1]).not.toBe(arr[1]);
  });
});

// ── val ─────────────────────────────────────────────────────────────────────

describe("val", () => {
  test("returns trimmed value from input element", () => {
    const input = document.createElement("input");
    input.value = "  hello  ";
    expect(A.val(input)).toBe("hello");
  });

  test("returns empty string for null input", () => {
    expect(A.val(null)).toBe("");
  });

  test("returns empty string for input with no value", () => {
    const input = document.createElement("input");
    expect(A.val(input)).toBe("");
  });
});

// ── boolSetting ─────────────────────────────────────────────────────────────

describe("boolSetting", () => {
  test("returns boolean values as-is", () => {
    expect(A.boolSetting(true)).toBe(true);
    expect(A.boolSetting(false)).toBe(false);
  });

  test("parses truthy strings", () => {
    expect(A.boolSetting("true")).toBe(true);
    expect(A.boolSetting("1")).toBe(true);
    expect(A.boolSetting("yes")).toBe(true);
    expect(A.boolSetting("TRUE")).toBe(true);
    expect(A.boolSetting("  Yes  ")).toBe(true);
  });

  test("parses falsy strings", () => {
    expect(A.boolSetting("false")).toBe(false);
    expect(A.boolSetting("0")).toBe(false);
    expect(A.boolSetting("no")).toBe(false);
  });

  test("returns fallback for unrecognised values", () => {
    expect(A.boolSetting("maybe", true)).toBe(true);
    expect(A.boolSetting(42, false)).toBe(false);
    expect(A.boolSetting(null, true)).toBe(true);
  });
});

// ── fmtElapsed ──────────────────────────────────────────────────────────────

describe("fmtElapsed", () => {
  test("formats zero elapsed time", () => {
    expect(A.fmtElapsed(Date.now())).toBe("00:00");
  });

  test("formats elapsed seconds", () => {
    const thirtySecsAgo = Date.now() - 30000;
    expect(A.fmtElapsed(thirtySecsAgo)).toBe("00:30");
  });

  test("formats elapsed minutes and seconds", () => {
    const fiveMinAgo = Date.now() - 305000;
    expect(A.fmtElapsed(fiveMinAgo)).toBe("05:05");
  });

  test("handles future timestamps (clamps to 00:00)", () => {
    expect(A.fmtElapsed(Date.now() + 10000)).toBe("00:00");
  });
});

// ── sseRetryDelayMs ─────────────────────────────────────────────────────────

describe("sseRetryDelayMs", () => {
  test("first attempt returns base delay", () => {
    expect(A.sseRetryDelayMs(1)).toBe(A.SSE_RETRY_BASE_DELAY_MS);
  });

  test("doubles on each subsequent attempt", () => {
    expect(A.sseRetryDelayMs(2)).toBe(A.SSE_RETRY_BASE_DELAY_MS * 2);
    expect(A.sseRetryDelayMs(3)).toBe(A.SSE_RETRY_BASE_DELAY_MS * 4);
  });

  test("caps at SSE_RETRY_MAX_DELAY_MS", () => {
    expect(A.sseRetryDelayMs(100)).toBe(A.SSE_RETRY_MAX_DELAY_MS);
  });

  test("handles non-finite input by defaulting to attempt 1", () => {
    expect(A.sseRetryDelayMs(NaN)).toBe(A.SSE_RETRY_BASE_DELAY_MS);
    expect(A.sseRetryDelayMs(-5)).toBe(A.SSE_RETRY_BASE_DELAY_MS);
  });
});

// ── Provider mapping ────────────────────────────────────────────────────────

describe("provider mapping", () => {
  test("toBackendProvider maps UI names to backend keys", () => {
    expect(A.toBackendProvider("anthropic")).toBe("claude");
    expect(A.toBackendProvider("kimi")).toBe("kimi");
    expect(A.toBackendProvider("local")).toBe("local");
    expect(A.toBackendProvider("openai")).toBe("openai");
    expect(A.toBackendProvider("unknown")).toBe("openai");
  });

  test("toUiProvider maps backend keys to UI names", () => {
    expect(A.toUiProvider("claude")).toBe("anthropic");
    expect(A.toUiProvider("kimi")).toBe("kimi");
    expect(A.toUiProvider("local")).toBe("local");
    expect(A.toUiProvider("openai")).toBe("openai");
    expect(A.toUiProvider("unknown")).toBe("openai");
  });

  test("normProvider normalises provider strings", () => {
    expect(A.normProvider("Claude")).toBe("claude");
    expect(A.normProvider("Anthropic")).toBe("claude");
    expect(A.normProvider("OPENAI")).toBe("openai");
    expect(A.normProvider("kimi")).toBe("kimi");
    expect(A.normProvider("local")).toBe("local");
    expect(A.normProvider("")).toBe("");
    expect(A.normProvider(null)).toBe("");
  });

  test("prettyProvider returns display labels", () => {
    expect(A.prettyProvider("claude")).toBe("Claude");
    expect(A.prettyProvider("openai")).toBe("OpenAI");
    expect(A.prettyProvider("kimi")).toBe("Kimi");
    expect(A.prettyProvider("local")).toBe("Local");
    expect(A.prettyProvider("anthropic")).toBe("Claude");
    expect(A.prettyProvider("")).toBe("Unknown");
  });
});

// ── stripLeadingReasoningBlocks ─────────────────────────────────────────────

describe("stripLeadingReasoningBlocks", () => {
  test("strips <think> blocks from the beginning", () => {
    const input = "<think>some reasoning</think>Final answer here.";
    expect(A.stripLeadingReasoningBlocks(input)).toBe("Final answer here.");
  });

  test("strips <reasoning> blocks", () => {
    const input = "<reasoning>internal thoughts</reasoning>The result.";
    expect(A.stripLeadingReasoningBlocks(input)).toBe("The result.");
  });

  test("strips code-fenced reasoning blocks", () => {
    const input = "```thinking\nsome thoughts\n```\nThe answer.";
    expect(A.stripLeadingReasoningBlocks(input)).toBe("The answer.");
  });

  test("returns text unchanged if no reasoning blocks", () => {
    const input = "Just a normal response.";
    expect(A.stripLeadingReasoningBlocks(input)).toBe("Just a normal response.");
  });

  test("handles empty or null input", () => {
    expect(A.stripLeadingReasoningBlocks("")).toBe("");
    expect(A.stripLeadingReasoningBlocks(null)).toBe("");
  });

  test("does not strip reasoning blocks in the middle of text", () => {
    const input = "Start text. <think>middle</think> End text.";
    expect(A.stripLeadingReasoningBlocks(input)).toBe(input.trim());
  });
});

// ── getFilename ─────────────────────────────────────────────────────────────

describe("getFilename", () => {
  test("extracts plain filename", () => {
    const headers = new Headers({ "content-disposition": 'attachment; filename="report.html"' });
    expect(A.getFilename(headers)).toBe("report.html");
  });

  test("extracts filename without quotes", () => {
    const headers = new Headers({ "content-disposition": "attachment; filename=report.html" });
    expect(A.getFilename(headers)).toBe("report.html");
  });

  test("extracts UTF-8 encoded filename", () => {
    const headers = new Headers({ "content-disposition": "attachment; filename*=UTF-8''report%20final.html" });
    expect(A.getFilename(headers)).toBe("report final.html");
  });

  test("returns empty string when no content-disposition", () => {
    const headers = new Headers({});
    expect(A.getFilename(headers)).toBe("");
  });
});

// ── handleFetchError ────────────────────────────────────────────────────────

describe("handleFetchError", () => {
  test("returns timeout message for TimeoutError", () => {
    const err = new Error("timed out");
    err.name = "TimeoutError";
    expect(A.handleFetchError(err, "/api/test")).toContain("timed out");
  });

  test("returns cancelled message for AbortError", () => {
    const err = new Error("aborted");
    err.name = "AbortError";
    expect(A.handleFetchError(err, "/api/test")).toBe("Request was cancelled.");
  });

  test("returns network error for TypeError", () => {
    const err = new TypeError("Failed to fetch");
    expect(A.handleFetchError(err, "/api/test")).toContain("Network error");
  });

  test("returns the error message for other errors", () => {
    const err = new Error("Something went wrong");
    expect(A.handleFetchError(err, "/api/test")).toBe("Something went wrong");
  });
});

// ── ensureMsg / setMsg / clearMsg ───────────────────────────────────────────

describe("message helpers", () => {
  test("ensureMsg creates a new hidden message element", () => {
    const parent = document.createElement("div");
    const node = A.ensureMsg(parent, "test-msg-1");
    expect(node.id).toBe("test-msg-1");
    expect(node.hidden).toBe(true);
    expect(node.getAttribute("role")).toBe("alert");
    expect(parent.contains(node)).toBe(true);
  });

  test("ensureMsg returns existing element if already present", () => {
    // Append parent to document so getElementById can find the child
    const parent = document.createElement("div");
    document.body.appendChild(parent);
    const first = A.ensureMsg(parent, "test-msg-2");
    const second = A.ensureMsg(parent, "test-msg-2");
    expect(first).toBe(second);
    parent.remove();
  });

  test("setMsg shows the message with correct status", () => {
    const node = document.createElement("p");
    node.hidden = true;
    A.setMsg(node, "Hello", "info");
    expect(node.hidden).toBe(false);
    expect(node.textContent).toBe("Hello");
    expect(node.dataset.status).toBe("in-progress");
  });

  test("setMsg sets error status", () => {
    const node = document.createElement("p");
    A.setMsg(node, "Error!", "error");
    expect(node.dataset.status).toBe("failed");
  });

  test("setMsg sets success status", () => {
    const node = document.createElement("p");
    A.setMsg(node, "Done!", "success");
    expect(node.dataset.status).toBe("success");
  });

  test("setMsg with falsy text clears the message", () => {
    const node = document.createElement("p");
    node.hidden = false;
    node.textContent = "Old";
    A.setMsg(node, "", "info");
    expect(node.hidden).toBe(true);
    expect(node.textContent).toBe("");
  });

  test("clearMsg hides and clears the node", () => {
    const node = document.createElement("p");
    node.hidden = false;
    node.textContent = "Message";
    node.dataset.status = "in-progress";
    A.clearMsg(node);
    expect(node.hidden).toBe(true);
    expect(node.textContent).toBe("");
    expect(node.dataset.status).toBeUndefined();
  });

  test("setMsg and clearMsg handle null gracefully", () => {
    expect(() => A.setMsg(null, "test")).not.toThrow();
    expect(() => A.clearMsg(null)).not.toThrow();
  });
});

// ── setCaseId / activeCaseId ────────────────────────────────────────────────

describe("setCaseId and activeCaseId", () => {
  test("setCaseId stores and returns trimmed ID", () => {
    expect(A.setCaseId("  abc-123  ")).toBe("abc-123");
    expect(A.st.caseId).toBe("abc-123");
  });

  test("setCaseId sets wizard dataset", () => {
    A.setCaseId("case-1");
    expect(A.el.wizard.dataset.caseId).toBe("case-1");
  });

  test("setCaseId with empty string removes dataset", () => {
    A.setCaseId("case-1");
    A.setCaseId("");
    expect(A.el.wizard.dataset.caseId).toBeUndefined();
  });

  test("activeCaseId returns st.caseId when set", () => {
    A.setCaseId("active-case");
    expect(A.activeCaseId()).toBe("active-case");
  });

  test("activeCaseId falls back to DOM attribute", () => {
    A.st.caseId = "";
    A.el.wizard.dataset.caseId = "dom-case";
    expect(A.activeCaseId()).toBe("dom-case");
  });

  test("activeCaseId returns empty when nothing is set", () => {
    A.setCaseId("");
    expect(A.activeCaseId()).toBe("");
  });
});

// ── closeSseChannel ─────────────────────────────────────────────────────────

describe("closeSseChannel", () => {
  test("closes EventSource and clears abort and retry", () => {
    const esClosed = jest.fn();
    const abortCalled = jest.fn();
    const channel = {
      es: { close: esClosed },
      abort: { abort: abortCalled },
      retry: setTimeout(() => {}, 10000),
    };
    A.closeSseChannel(channel);
    expect(esClosed).toHaveBeenCalled();
    expect(abortCalled).toHaveBeenCalled();
    expect(channel.es).toBeNull();
    expect(channel.abort).toBeNull();
    expect(channel.retry).toBeNull();
  });

  test("handles channel with no es/abort/retry", () => {
    const channel = { es: null, abort: null, retry: null };
    expect(() => A.closeSseChannel(channel)).not.toThrow();
  });
});

// ── Constants ───────────────────────────────────────────────────────────────

describe("constants", () => {
  test("STEP_IDS has 5 entries", () => {
    expect(A.STEP_IDS).toHaveLength(5);
  });

  test("MODE constants are strings", () => {
    expect(typeof A.MODE_PARSE_AND_AI).toBe("string");
    expect(typeof A.MODE_PARSE_ONLY).toBe("string");
    expect(A.MODE_PARSE_AND_AI).not.toBe(A.MODE_PARSE_ONLY);
  });

  test("CONFIDENCE_CLASS_MAP has all four levels", () => {
    expect(A.CONFIDENCE_CLASS_MAP).toHaveProperty("CRITICAL");
    expect(A.CONFIDENCE_CLASS_MAP).toHaveProperty("HIGH");
    expect(A.CONFIDENCE_CLASS_MAP).toHaveProperty("MEDIUM");
    expect(A.CONFIDENCE_CLASS_MAP).toHaveProperty("LOW");
  });

  test("SSE constants are positive numbers", () => {
    expect(A.SSE_MAX_RETRIES).toBeGreaterThan(0);
    expect(A.SSE_RETRY_BASE_DELAY_MS).toBeGreaterThan(0);
    expect(A.SSE_RETRY_MAX_DELAY_MS).toBeGreaterThan(A.SSE_RETRY_BASE_DELAY_MS);
  });

  test("FETCH timeout constants are positive", () => {
    expect(A.FETCH_TIMEOUT_API_MS).toBeGreaterThan(0);
    expect(A.FETCH_TIMEOUT_UPLOAD_MS).toBeGreaterThan(A.FETCH_TIMEOUT_API_MS);
  });
});
