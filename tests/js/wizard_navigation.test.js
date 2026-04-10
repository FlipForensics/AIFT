/**
 * Unit tests for wizard navigation behaviour.
 *
 * Covers:
 *  - Tab clickability and visual states (is-active, is-disabled, is-visited)
 *  - Evidence-loaded banner visibility when navigating back to step 1
 *  - Navigating back from step 2 to step 1 preserves case (canGo(2) stays true)
 *  - navBlockReason returns "" for unlocked steps (no fall-through to generic msg)
 *  - Parse button label switches between "Parse Selected" and "Restart Parsing"
 *  - Navigating away from step 3/4 does NOT cancel parsing/analysis
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

/**
 * Load the full index.html into jsdom's document, then evaluate
 * all JS modules so window.AIFT is initialised.
 */
function setup() {
  const indexHtml = fs.readFileSync(path.join(TEMPLATES, "index.html"), "utf-8");
  document.documentElement.innerHTML = "";
  document.write(indexHtml);
  document.close();

  // Stub fetch
  global.fetch = () => Promise.reject(new Error("fetch not available in tests"));
  // Stub EventSource
  global.EventSource = class { close() {} };
  if (!global.CSS) global.CSS = {};
  if (!global.CSS.escape) global.CSS.escape = (v) => String(v).replace(/([^\w-])/g, "\\$1");

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
    // Wrap in try/catch to surface errors clearly
    try {
      const fn = new Function(code);
      fn.call(window);
    } catch (e) {
      throw new Error(`Failed to evaluate ${s}: ${e.message}`);
    }
  }

  // Fire DOMContentLoaded so app.js init() runs
  document.dispatchEvent(new Event("DOMContentLoaded"));

  return window.AIFT;
}

let A;

beforeEach(() => {
  A = setup();
});

// ── Tab visual states ──────────────────────────────────────────────────────

describe("tab indicator visual states", () => {
  test("step 1 indicator is active on initial load", () => {
    expect(A.el.indicators[0].classList.contains("is-active")).toBe(true);
    expect(A.el.indicators[1].classList.contains("is-active")).toBe(false);
  });

  test("navigating to step 2 moves is-active to step 2 indicator", () => {
    A.setCaseId("test-case-123");
    A.showStep(2);
    expect(A.el.indicators[0].classList.contains("is-active")).toBe(false);
    expect(A.el.indicators[1].classList.contains("is-active")).toBe(true);
  });

  test("unavailable tabs have is-disabled class", () => {
    // On initial load with no case, steps 2-5 should be disabled
    expect(A.el.indicators[0].classList.contains("is-disabled")).toBe(false);
    expect(A.el.indicators[1].classList.contains("is-disabled")).toBe(true);
    expect(A.el.indicators[2].classList.contains("is-disabled")).toBe(true);
    expect(A.el.indicators[3].classList.contains("is-disabled")).toBe(true);
    expect(A.el.indicators[4].classList.contains("is-disabled")).toBe(true);
  });

  test("step 2 tab loses is-disabled after case is created", () => {
    A.setCaseId("test-case-123");
    A.updateNav();
    expect(A.el.indicators[1].classList.contains("is-disabled")).toBe(false);
  });

  test("available non-active tabs have is-visited class", () => {
    A.setCaseId("test-case-123");
    A.showStep(2);
    // Step 1 is available but not active → is-visited
    expect(A.el.indicators[0].classList.contains("is-visited")).toBe(true);
    expect(A.el.indicators[0].classList.contains("is-active")).toBe(false);
    // Step 2 is active → not is-visited
    expect(A.el.indicators[1].classList.contains("is-visited")).toBe(false);
    expect(A.el.indicators[1].classList.contains("is-active")).toBe(true);
  });
});

// ── Evidence banner ────────────────────────────────────────────────────────

describe("evidence-loaded banner", () => {
  test("banner is hidden when no case exists", () => {
    const banner = document.getElementById("evidence-loaded-banner");
    expect(banner.hidden).toBe(true);
  });

  test("banner is visible when navigating back to step 1 with active case", () => {
    A.setCaseId("test-case-123");
    A.showStep(2);
    A.showStep(1);
    const banner = document.getElementById("evidence-loaded-banner");
    expect(banner.hidden).toBe(false);
  });

  test("evidence form remains visible when banner is shown", () => {
    A.setCaseId("test-case-123");
    A.showStep(2);
    A.showStep(1);
    const form = document.getElementById("evidence-form");
    expect(form.hidden).toBeFalsy();
  });

  test("banner hides after resetCaseUi clears the case", () => {
    A.setCaseId("test-case-123");
    A.showStep(2);
    A.showStep(1);
    A.resetCaseUi();
    const banner = document.getElementById("evidence-loaded-banner");
    expect(banner.hidden).toBe(true);
  });
});

// ── Step navigation preservation ───────────────────────────────────────────

describe("navigating back preserves state", () => {
  test("going back from step 2 to step 1 keeps case ID, step 2 remains reachable", () => {
    A.setCaseId("test-case-123");
    A.showStep(2);
    A.showStep(1);
    expect(A.activeCaseId()).toBe("test-case-123");
    expect(A.el.indicators[1].classList.contains("is-disabled")).toBe(false);
  });

  test("showStep does NOT cancel parsing when leaving step 3", () => {
    A.setCaseId("test-case-123");
    A.st.selected = ["evtx"];
    A.st.selectedAi = ["evtx"];
    A.st.parse.run = true;
    A.showStep(3);
    A.showStep(2);
    expect(A.st.parse.run).toBe(true);
  });

  test("showStep does NOT cancel analysis when leaving step 4", () => {
    A.setCaseId("test-case-123");
    A.st.selected = ["evtx"];
    A.st.selectedAi = ["evtx"];
    A.st.parse.done = true;
    A.st.analysis.run = true;
    A.showStep(4);
    A.showStep(2);
    expect(A.st.analysis.run).toBe(true);
  });
});

// ── navBlockReason explicit returns ────────────────────────────────────────

describe("navBlockReason does not fall through to generic message", () => {
  test("step 2 tab has no blocked title when case exists", () => {
    A.setCaseId("test-case-123");
    A.updateNav();
    expect(A.el.indicators[1].title).toBe("");
    expect(A.el.indicators[1].classList.contains("is-disabled")).toBe(false);
  });

  test("step 3 tab has no blocked title when artifacts are selected", () => {
    A.setCaseId("test-case-123");
    A.st.selected = ["evtx"];
    A.updateNav();
    expect(A.el.indicators[2].title).toBe("");
    expect(A.el.indicators[2].classList.contains("is-disabled")).toBe(false);
  });

  test("step 2 tab shows 'Submit evidence first.' when no case", () => {
    A.updateNav();
    expect(A.el.indicators[1].title).toBe("Submit evidence first.");
    expect(A.el.indicators[1].classList.contains("is-disabled")).toBe(true);
  });

  test("step 3 tab blocked when no artifacts selected", () => {
    A.setCaseId("test-case-123");
    A.st.selected = [];
    A.updateNav();
    expect(A.el.indicators[2].classList.contains("is-disabled")).toBe(true);
    expect(A.el.indicators[2].title).toContain("Select artifacts");
  });
});

// ── Parse button label ─────────────────────────────────────────────────────

describe("parse button label", () => {
  test("shows 'Parse Selected' when no parse has been done", () => {
    A.setCaseId("test-case-123");
    A.updateParseButton();
    const btn = document.getElementById("parse-selected");
    expect(btn.textContent).toBe("Parse Selected");
  });

  test("shows 'Restart Parsing' when parsing is running", () => {
    A.setCaseId("test-case-123");
    A.st.parse.run = true;
    A.updateParseButton();
    const btn = document.getElementById("parse-selected");
    expect(btn.textContent).toBe("Restart Parsing");
  });

  test("shows 'Restart Parsing' when parsing is done", () => {
    A.setCaseId("test-case-123");
    A.st.parse.done = true;
    A.updateParseButton();
    const btn = document.getElementById("parse-selected");
    expect(btn.textContent).toBe("Restart Parsing");
  });

  test("shows 'Restart Parsing' when both run and done are true", () => {
    A.setCaseId("test-case-123");
    A.st.parse.run = true;
    A.st.parse.done = true;
    A.updateParseButton();
    const btn = document.getElementById("parse-selected");
    expect(btn.textContent).toBe("Restart Parsing");
  });

  test("shows 'Parse Selected' after resetCaseUi", () => {
    A.setCaseId("test-case-123");
    A.st.parse.done = true;
    A.updateParseButton();
    expect(document.getElementById("parse-selected").textContent).toBe("Restart Parsing");
    A.resetCaseUi();
    expect(document.getElementById("parse-selected").textContent).toBe("Parse Selected");
  });
});

// ── Re-parse state cleanup ─────────────────────────────────────────────────

describe("re-parse clears stale frontend state", () => {
  test("resetParseState clears analysis state", () => {
    A.setCaseId("test-case-123");
    // Simulate completed parse and analysis
    A.st.parse.done = true;
    A.st.parse.run = false;
    A.st.analysis.done = true;
    A.st.analysis.run = false;
    A.st.analysis.order = ["runkeys"];
    A.st.analysis.byKey = { runkeys: { analysis: "old" } };
    A.st.analysis.summary = "old summary";

    // resetParseState should also reset analysis
    A.resetParseState();

    expect(A.st.parse.done).toBe(false);
    expect(A.st.parse.run).toBe(false);
    expect(A.st.parse.rows).toEqual({});
    expect(A.st.parse.status).toEqual({});
    expect(A.st.analysis.done).toBe(false);
    expect(A.st.analysis.run).toBe(false);
    expect(A.st.analysis.order).toEqual([]);
    expect(A.st.analysis.byKey).toEqual({});
    expect(A.st.analysis.summary).toBe("");
  });

  test("resetParseState resets parse button to 'Parse Selected'", () => {
    A.setCaseId("test-case-123");
    A.st.parse.done = true;
    A.updateParseButton();
    expect(document.getElementById("parse-selected").textContent).toBe("Restart Parsing");

    A.resetParseState();
    expect(document.getElementById("parse-selected").textContent).toBe("Parse Selected");
  });

  test("resetParseState updates nav so analysis step becomes blocked", () => {
    A.setCaseId("test-case-123");
    A.st.selected = ["evtx"];
    A.st.selectedAi = ["evtx"];
    A.st.parse.done = true;

    A.updateNav();
    // Step 4 (analysis) should be reachable when parse is done
    expect(A.el.indicators[3].classList.contains("is-disabled")).toBe(false);

    A.resetParseState();
    // After reset, step 4 should be blocked again
    expect(A.el.indicators[3].classList.contains("is-disabled")).toBe(true);
  });
});
