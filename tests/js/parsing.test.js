/**
 * Unit tests for AIFT parse submission and progress tracking (parsing.js).
 *
 * Covers:
 *  - resetParseState clears all parse and analysis state
 *  - renderParsePlaceholder creates placeholder row
 *  - closeParseSse closes the SSE channel
 *  - Parse state lifecycle (run, done, fail flags)
 *  - Parse progress bar updates
 *  - Parse row creation and status updates
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

// ── resetParseState ─────────────────────────────────────────────────────────

describe("resetParseState", () => {
  test("resets all parse flags to initial state", () => {
    A.st.parse.run = true;
    A.st.parse.done = true;
    A.st.parse.fail = true;
    A.st.parse.retryCount = 5;
    A.st.parse.seq = 42;

    A.resetParseState();

    expect(A.st.parse.run).toBe(false);
    expect(A.st.parse.done).toBe(false);
    expect(A.st.parse.fail).toBe(false);
    expect(A.st.parse.retryCount).toBe(0);
    expect(A.st.parse.seq).toBe(-1);
  });

  test("clears parse rows and status", () => {
    A.st.parse.rows = { evtx: {} };
    A.st.parse.status = { evtx: "completed" };

    A.resetParseState();

    expect(A.st.parse.rows).toEqual({});
    expect(A.st.parse.status).toEqual({});
  });

  test("cascades reset to analysis state", () => {
    A.st.analysis.done = true;
    A.st.analysis.run = true;
    A.st.analysis.order = ["evtx"];
    A.st.analysis.byKey = { evtx: { text: "result" } };
    A.st.analysis.summary = "summary";

    A.resetParseState();

    expect(A.st.analysis.done).toBe(false);
    expect(A.st.analysis.run).toBe(false);
    expect(A.st.analysis.order).toEqual([]);
    expect(A.st.analysis.byKey).toEqual({});
    expect(A.st.analysis.summary).toBe("");
  });

  test("resets parse button to 'Parse Selected'", () => {
    A.setCaseId("test-case");
    A.st.parse.done = true;
    A.updateParseButton();
    expect(document.getElementById("parse-selected").textContent).toBe("Restart Parsing");

    A.resetParseState();
    expect(document.getElementById("parse-selected").textContent).toBe("Parse Selected");
  });

  test("updates navigation so analysis step becomes blocked", () => {
    A.setCaseId("test-case");
    A.st.selected = ["evtx"];
    A.st.selectedAi = ["evtx"];
    A.st.parse.done = true;

    A.updateNav();
    expect(A.el.indicators[3].classList.contains("is-disabled")).toBe(false);

    A.resetParseState();
    expect(A.el.indicators[3].classList.contains("is-disabled")).toBe(true);
  });

  test("clears parse error message", () => {
    if (A.el.parseErr) {
      A.setMsg(A.el.parseErr, "Some error", "error");
      expect(A.el.parseErr.hidden).toBe(false);

      A.resetParseState();
      expect(A.el.parseErr.hidden).toBe(true);
    }
  });
});

// ── renderParsePlaceholder ──────────────────────────────────────────────────

describe("renderParsePlaceholder", () => {
  test("creates placeholder row in parse table", () => {
    A.renderParsePlaceholder();
    if (A.el.parseRows) {
      const rows = A.el.parseRows.querySelectorAll("tr");
      expect(rows).toHaveLength(1);
      expect(rows[0].textContent).toContain("Awaiting selection");
    }
  });

  test("resets progress bar to 0", () => {
    if (A.el.parseProgress) {
      A.el.parseProgress.value = 75;
      A.renderParsePlaceholder();
      expect(A.el.parseProgress.value).toBe(0);
    }
  });

  test("clears rows and status state", () => {
    A.st.parse.rows = { evtx: {} };
    A.st.parse.status = { evtx: "completed" };
    A.renderParsePlaceholder();
    expect(A.st.parse.rows).toEqual({});
    expect(A.st.parse.status).toEqual({});
  });
});

// ── closeParseSse ───────────────────────────────────────────────────────────

describe("closeParseSse", () => {
  test("closes the parse SSE channel", () => {
    const mockEs = { close: jest.fn() };
    A.st.parse.es = mockEs;
    A.st.parse.retry = setTimeout(() => {}, 10000);

    A.closeParseSse();

    expect(mockEs.close).toHaveBeenCalled();
    expect(A.st.parse.es).toBeNull();
    expect(A.st.parse.retry).toBeNull();
  });

  test("handles already-closed channel gracefully", () => {
    A.st.parse.es = null;
    A.st.parse.retry = null;
    expect(() => A.closeParseSse()).not.toThrow();
  });
});

// ── Parse state lifecycle ───────────────────────────────────────────────────

describe("parse state lifecycle", () => {
  test("initial parse state has all flags false", () => {
    A.resetParseState();
    expect(A.st.parse.run).toBe(false);
    expect(A.st.parse.done).toBe(false);
    expect(A.st.parse.fail).toBe(false);
  });

  test("parse completion enables analysis step navigation", () => {
    A.setCaseId("test-case");
    A.st.selected = ["evtx"];
    A.st.selectedAi = ["evtx"];
    A.st.parse.done = true;
    A.updateNav();
    expect(A.el.indicators[3].classList.contains("is-disabled")).toBe(false);
  });

  test("parse running blocks analysis step", () => {
    A.setCaseId("test-case");
    A.st.selected = ["evtx"];
    A.st.selectedAi = ["evtx"];
    A.st.parse.run = true;
    A.st.parse.done = false;
    A.updateNav();
    expect(A.el.indicators[3].classList.contains("is-disabled")).toBe(true);
  });

  test("parse failure blocks analysis step", () => {
    A.setCaseId("test-case");
    A.st.selected = ["evtx"];
    A.st.selectedAi = ["evtx"];
    A.st.parse.fail = true;
    A.st.parse.done = false;
    A.updateNav();
    expect(A.el.indicators[3].classList.contains("is-disabled")).toBe(true);
  });
});

// ── Parse button states ─────────────────────────────────────────────────────

describe("parse button states", () => {
  test("button says 'Parse Selected' initially", () => {
    A.setCaseId("test-case");
    A.st.parse.run = false;
    A.st.parse.done = false;
    A.updateParseButton();
    const btn = document.getElementById("parse-selected");
    expect(btn.textContent).toBe("Parse Selected");
  });

  test("button says 'Restart Parsing' when running", () => {
    A.setCaseId("test-case");
    A.st.parse.run = true;
    A.updateParseButton();
    const btn = document.getElementById("parse-selected");
    expect(btn.textContent).toBe("Restart Parsing");
  });

  test("button says 'Restart Parsing' when done", () => {
    A.setCaseId("test-case");
    A.st.parse.done = true;
    A.updateParseButton();
    const btn = document.getElementById("parse-selected");
    expect(btn.textContent).toBe("Restart Parsing");
  });
});

// ── Multi-image parse state ────────────────────────────────────────────────

describe("multi-image parse state", () => {
  test("st.imageParse is initialised as empty object", () => {
    expect(A.st.imageParse).toBeDefined();
    expect(typeof A.st.imageParse).toBe("object");
  });

  test("resetParseState clears imageParse", () => {
    A.st.imageParse = { img1: { run: true, done: false } };
    A.resetParseState();
    expect(A.st.imageParse).toEqual({});
  });

  test("isMultiImage returns false for zero or one image", () => {
    A.st.images = [];
    expect(A.isMultiImage()).toBe(false);
    A.st.images = [{ image_id: "img1" }];
    expect(A.isMultiImage()).toBe(false);
  });

  test("isMultiImage returns true for multiple images", () => {
    A.st.images = [{ image_id: "img1" }, { image_id: "img2" }];
    expect(A.isMultiImage()).toBe(true);
    A.st.images = [];
  });
});

// ── Multi-image: showSingleImageParseTable ─────────────────────────────────

describe("showSingleImageParseTable", () => {
  test("parse-single-table is visible by default after reset", () => {
    A.renderParsePlaceholder();
    const table = document.getElementById("parse-single-table");
    if (table) {
      expect(table.hidden).toBe(false);
    }
  });
});

// ── Multi-image: allImageArtifactSelections ────────────────────────────────

describe("allImageArtifactSelections", () => {
  test("returns empty array when one or zero images loaded", () => {
    A.st.images = [];
    expect(A.allImageArtifactSelections()).toEqual([]);
    A.st.images = [{ image_id: "img1" }];
    expect(A.allImageArtifactSelections()).toEqual([]);
    A.st.images = [];
  });

  test("returns per-image entries for multiple images", () => {
    A.st.images = [
      { image_id: "img1", label: "Image 1", available_artifacts: [] },
      { image_id: "img2", label: "Image 2", available_artifacts: [] },
    ];
    const selections = A.allImageArtifactSelections();
    expect(selections).toHaveLength(2);
    expect(selections[0].image_id).toBe("img1");
    expect(selections[1].image_id).toBe("img2");
    expect(Array.isArray(selections[0].artifact_options)).toBe(true);
    A.st.images = [];
  });
});

// ── Multi-image: selectedArtifactOptionsForImage ──────────────────────────

describe("selectedArtifactOptionsForImage", () => {
  test("returns empty array for nonexistent image panel", () => {
    expect(A.selectedArtifactOptionsForImage("nonexistent")).toEqual([]);
  });

  test("returns empty array for null/empty imageId", () => {
    expect(A.selectedArtifactOptionsForImage("")).toEqual([]);
    expect(A.selectedArtifactOptionsForImage(null)).toEqual([]);
  });
});

// ── Multi-image: activeArtifactTabImageId ─────────────────────────────────

describe("activeArtifactTabImageId", () => {
  test("returns null when tab container is hidden", () => {
    const tabContainer = document.getElementById("artifact-image-tabs");
    if (tabContainer) tabContainer.hidden = true;
    expect(A.activeArtifactTabImageId()).toBeNull();
  });

  test("returns null when no tabs exist", () => {
    expect(A.activeArtifactTabImageId()).toBeNull();
  });
});

// ── Multi-image: buildMultiImageArtifactTabs ──────────────────────────────

describe("buildMultiImageArtifactTabs", () => {
  test("hides tab container for single image", () => {
    A.st.images = [{ image_id: "img1", label: "Image 1" }];
    A.buildMultiImageArtifactTabs();
    const tabContainer = document.getElementById("artifact-image-tabs");
    if (tabContainer) {
      expect(tabContainer.hidden).toBe(true);
    }
    A.st.images = [];
  });

  test("shows tab container for multiple images", () => {
    A.st.images = [
      { image_id: "img1", label: "Image 1", available_artifacts: [{ key: "evtx", available: true }] },
      { image_id: "img2", label: "Image 2", available_artifacts: [{ key: "evtx", available: true }] },
    ];
    A.buildMultiImageArtifactTabs();
    const tabContainer = document.getElementById("artifact-image-tabs");
    if (tabContainer) {
      expect(tabContainer.hidden).toBe(false);
      const buttons = tabContainer.querySelectorAll(".artifact-tab-bar button");
      expect(buttons.length).toBe(2);
      expect(buttons[0].textContent).toBe("Image 1");
      expect(buttons[1].textContent).toBe("Image 2");
      expect(buttons[0].classList.contains("is-active")).toBe(true);
      expect(buttons[1].classList.contains("is-active")).toBe(false);
    }
    A.st.images = [];
  });

  test("creates per-image panels with correct data-image-id", () => {
    A.st.images = [
      { image_id: "img1", label: "Image 1", available_artifacts: [] },
      { image_id: "img2", label: "Image 2", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
    const panels = document.getElementById("artifact-image-panels");
    if (panels) {
      const panelDivs = panels.querySelectorAll(".artifact-image-panel");
      expect(panelDivs.length).toBe(2);
      expect(panelDivs[0].dataset.imageId).toBe("img1");
      expect(panelDivs[1].dataset.imageId).toBe("img2");
      expect(panelDivs[0].classList.contains("is-active")).toBe(true);
      expect(panelDivs[1].classList.contains("is-active")).toBe(false);
    }
    A.st.images = [];
  });

  test("hides main artifact form for multi-image", () => {
    A.st.images = [
      { image_id: "img1", label: "Image 1", available_artifacts: [] },
      { image_id: "img2", label: "Image 2", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
    const form = document.getElementById("artifact-form");
    if (form) {
      expect(form.hidden).toBe(true);
    }
    A.st.images = [];
  });
});

// ── Multi-image: switchArtifactTab ────────────────────────────────────────

describe("switchArtifactTab", () => {
  beforeEach(() => {
    A.st.images = [
      { image_id: "img1", label: "Image 1", available_artifacts: [] },
      { image_id: "img2", label: "Image 2", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
  });

  afterEach(() => {
    A.st.images = [];
  });

  test("switches active tab button", () => {
    A.switchArtifactTab("img2");
    const tabContainer = document.getElementById("artifact-image-tabs");
    if (tabContainer) {
      const buttons = tabContainer.querySelectorAll(".artifact-tab-bar button");
      expect(buttons[0].classList.contains("is-active")).toBe(false);
      expect(buttons[1].classList.contains("is-active")).toBe(true);
    }
  });

  test("switches active panel", () => {
    A.switchArtifactTab("img2");
    const panels = document.getElementById("artifact-image-panels");
    if (panels) {
      const panelDivs = panels.querySelectorAll(".artifact-image-panel");
      expect(panelDivs[0].classList.contains("is-active")).toBe(false);
      expect(panelDivs[1].classList.contains("is-active")).toBe(true);
    }
  });

  test("activeArtifactTabImageId returns switched tab id", () => {
    A.switchArtifactTab("img2");
    expect(A.activeArtifactTabImageId()).toBe("img2");
  });
});
