/**
 * Unit tests for AIFT evidence intake and artifact selection (evidence.js).
 *
 * Covers:
 *  - setPendingFiles updates dropzone help text
 *  - syncMode toggles upload vs. path panels
 *  - artifactBoxes returns checkbox elements
 *  - selectedArtifactOptions / selectedArtifacts / selectedAiArtifacts
 *  - ensureArtifactModeControl creates and reuses mode selects
 *  - syncArtifactModeControl enables/disables selects
 *  - validateAnalysisDateRange validation logic
 *  - updateParseButton button state and label
 *  - clearDynamicArtifacts removes dynamic category
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

// ── setPendingFiles ─────────────────────────────────────────────────────────

describe("setPendingFiles", () => {
  test("sets empty files and restores default help text", () => {
    A.setPendingFiles([]);
    expect(A.st.pendingFiles).toEqual([]);
    if (A.el.dropHelp) {
      expect(A.el.dropHelp.textContent).toBe(A.DROP_HELP);
    }
  });

  test("sets single file and shows filename", () => {
    const file = { name: "evidence.E01", size: 2048 };
    A.setPendingFiles([file]);
    expect(A.st.pendingFiles).toHaveLength(1);
    if (A.el.dropHelp) {
      expect(A.el.dropHelp.textContent).toContain("evidence.E01");
    }
  });

  test("sets multiple files and shows count", () => {
    const files = [
      { name: "file1.E01", size: 1024 },
      { name: "file2.E02", size: 2048 },
    ];
    A.setPendingFiles(files);
    expect(A.st.pendingFiles).toHaveLength(2);
    if (A.el.dropHelp) {
      expect(A.el.dropHelp.textContent).toContain("2 files selected");
    }
  });

  test("filters out falsy entries", () => {
    A.setPendingFiles([null, undefined, { name: "real.E01", size: 100 }]);
    expect(A.st.pendingFiles).toHaveLength(1);
  });
});

// ── syncMode ────────────────────────────────────────────────────────────────

describe("syncMode", () => {
  test("shows upload panel when upload mode is selected", () => {
    if (!A.el.modeUpload || !A.el.uploadPanel) return;
    A.el.modeUpload.checked = true;
    A.el.modePath.checked = false;
    A.syncMode();
    expect(A.el.uploadPanel.hidden).toBe(false);
    expect(A.el.pathPanel.hidden).toBe(true);
  });

  test("shows path panel when path mode is selected", () => {
    if (!A.el.modePath || !A.el.pathPanel) return;
    A.el.modePath.checked = true;
    A.el.modeUpload.checked = false;
    A.syncMode();
    expect(A.el.pathPanel.hidden).toBe(false);
    expect(A.el.uploadPanel.hidden).toBe(true);
  });
});

// ── artifactBoxes ───────────────────────────────────────────────────────────

describe("artifactBoxes", () => {
  test("returns an array of checkbox elements", () => {
    const boxes = A.artifactBoxes();
    expect(Array.isArray(boxes)).toBe(true);
    boxes.forEach((cb) => {
      expect(cb.type).toBe("checkbox");
      expect(cb.dataset.artifactKey).toBeTruthy();
    });
  });
});

// ── ensureArtifactModeControl ───────────────────────────────────────────────

describe("ensureArtifactModeControl", () => {
  test("creates a mode select for a checkbox", () => {
    const boxes = A.artifactBoxes();
    if (!boxes.length) return;
    const cb = boxes[0];
    const select = A.ensureArtifactModeControl(cb, A.MODE_PARSE_AND_AI);
    expect(select).not.toBeNull();
    expect(select.tagName).toBe("SELECT");
    expect(select.dataset.artifactKey).toBe(cb.dataset.artifactKey);
  });

  test("returns existing select on second call", () => {
    const boxes = A.artifactBoxes();
    if (!boxes.length) return;
    const cb = boxes[0];
    const first = A.ensureArtifactModeControl(cb, A.MODE_PARSE_AND_AI);
    const second = A.ensureArtifactModeControl(cb, A.MODE_PARSE_ONLY);
    expect(first).toBe(second);
  });

  test("returns null for non-input element", () => {
    expect(A.ensureArtifactModeControl(document.createElement("div"))).toBeNull();
  });
});

// ── syncArtifactModeControl ─────────────────────────────────────────────────

describe("syncArtifactModeControl", () => {
  test("disables select when checkbox is unchecked", () => {
    const boxes = A.artifactBoxes();
    if (!boxes.length) return;
    const cb = boxes[0];
    const select = A.ensureArtifactModeControl(cb);
    cb.checked = false;
    cb.disabled = false;
    A.syncArtifactModeControl(cb, select);
    expect(select.disabled).toBe(true);
  });

  test("enables select when checkbox is checked and not disabled", () => {
    const boxes = A.artifactBoxes();
    if (!boxes.length) return;
    const cb = boxes[0];
    const select = A.ensureArtifactModeControl(cb);
    cb.checked = true;
    cb.disabled = false;
    A.syncArtifactModeControl(cb, select);
    expect(select.disabled).toBe(false);
  });

  test("disables select when checkbox is disabled", () => {
    const boxes = A.artifactBoxes();
    if (!boxes.length) return;
    const cb = boxes[0];
    const select = A.ensureArtifactModeControl(cb);
    cb.checked = true;
    cb.disabled = true;
    A.syncArtifactModeControl(cb, select);
    expect(select.disabled).toBe(true);
  });
});

// ── selectedArtifactOptions / selectedArtifacts / selectedAiArtifacts ──────

describe("artifact selection helpers", () => {
  test("selectedArtifactOptions returns empty when nothing checked", () => {
    A.artifactBoxes().forEach((cb) => { cb.checked = false; });
    expect(A.selectedArtifactOptions()).toEqual([]);
  });

  test("selectedArtifactOptions returns checked, non-disabled artifacts", () => {
    const boxes = A.artifactBoxes();
    if (!boxes.length) return;
    boxes[0].checked = true;
    boxes[0].disabled = false;
    const options = A.selectedArtifactOptions();
    expect(options.length).toBeGreaterThanOrEqual(1);
    expect(options[0]).toHaveProperty("artifact_key");
    expect(options[0]).toHaveProperty("mode");
  });

  test("selectedArtifacts returns array of keys", () => {
    const boxes = A.artifactBoxes();
    if (!boxes.length) return;
    boxes[0].checked = true;
    boxes[0].disabled = false;
    const keys = A.selectedArtifacts();
    expect(keys.length).toBeGreaterThanOrEqual(1);
    expect(typeof keys[0]).toBe("string");
  });

  test("selectedAiArtifacts filters to parse_and_ai mode only", () => {
    const boxes = A.artifactBoxes();
    if (boxes.length < 2) return;
    // Set first checkbox to parse_and_ai, second to parse_only
    boxes[0].checked = true;
    boxes[0].disabled = false;
    const select0 = A.ensureArtifactModeControl(boxes[0], A.MODE_PARSE_AND_AI);
    if (select0) select0.value = A.MODE_PARSE_AND_AI;

    boxes[1].checked = true;
    boxes[1].disabled = false;
    const select1 = A.ensureArtifactModeControl(boxes[1], A.MODE_PARSE_ONLY);
    if (select1) select1.value = A.MODE_PARSE_ONLY;

    const aiArts = A.selectedAiArtifacts();
    expect(aiArts).toContain(boxes[0].dataset.artifactKey);
    expect(aiArts).not.toContain(boxes[1].dataset.artifactKey);
  });

  test("does not include disabled checkboxes even if checked", () => {
    const boxes = A.artifactBoxes();
    if (!boxes.length) return;
    boxes[0].checked = true;
    boxes[0].disabled = true;
    expect(A.selectedArtifactOptions()).toEqual([]);
  });
});

// ── validateAnalysisDateRange ───────────────────────────────────────────────

describe("validateAnalysisDateRange", () => {
  test("returns ok with null range when both dates are empty", () => {
    if (A.el.analysisDateStart) A.el.analysisDateStart.value = "";
    if (A.el.analysisDateEnd) A.el.analysisDateEnd.value = "";
    const result = A.validateAnalysisDateRange();
    expect(result.ok).toBe(true);
    expect(result.range).toBeNull();
  });

  test("returns error when only start date is provided", () => {
    if (!A.el.analysisDateStart || !A.el.analysisDateEnd) return;
    A.el.analysisDateStart.value = "2024-01-01";
    A.el.analysisDateEnd.value = "";
    const result = A.validateAnalysisDateRange();
    expect(result.ok).toBe(false);
    expect(result.message).toContain("both");
  });

  test("returns error when only end date is provided", () => {
    if (!A.el.analysisDateStart || !A.el.analysisDateEnd) return;
    A.el.analysisDateStart.value = "";
    A.el.analysisDateEnd.value = "2024-12-31";
    const result = A.validateAnalysisDateRange();
    expect(result.ok).toBe(false);
  });

  test("returns error when start is after end", () => {
    if (!A.el.analysisDateStart || !A.el.analysisDateEnd) return;
    A.el.analysisDateStart.value = "2024-12-31";
    A.el.analysisDateEnd.value = "2024-01-01";
    const result = A.validateAnalysisDateRange();
    expect(result.ok).toBe(false);
    expect(result.message).toContain("earlier");
  });

  test("returns ok with range when both dates are valid", () => {
    if (!A.el.analysisDateStart || !A.el.analysisDateEnd) return;
    A.el.analysisDateStart.value = "2024-01-01";
    A.el.analysisDateEnd.value = "2024-12-31";
    const result = A.validateAnalysisDateRange();
    expect(result.ok).toBe(true);
    expect(result.range).toEqual({ start_date: "2024-01-01", end_date: "2024-12-31" });
  });
});

// ── updateParseButton ───────────────────────────────────────────────────────

describe("updateParseButton", () => {
  test("disables parse button when no case exists", () => {
    A.setCaseId("");
    A.updateParseButton();
    if (A.el.parseBtn) {
      expect(A.el.parseBtn.disabled).toBe(true);
    }
  });

  test("disables parse button when no artifacts selected", () => {
    A.setCaseId("test-case");
    A.artifactBoxes().forEach((cb) => { cb.checked = false; });
    A.updateParseButton();
    if (A.el.parseBtn) {
      expect(A.el.parseBtn.disabled).toBe(true);
    }
  });

  test("enables parse button when case exists and artifact selected", () => {
    A.setCaseId("test-case");
    const boxes = A.artifactBoxes();
    if (!boxes.length || !A.el.parseBtn) return;
    boxes[0].checked = true;
    boxes[0].disabled = false;
    A.updateParseButton();
    expect(A.el.parseBtn.disabled).toBe(false);
  });

  test("hides cancel button when parse is not running", () => {
    A.st.parse.run = false;
    A.updateParseButton();
    if (A.el.cancelParse) {
      expect(A.el.cancelParse.hidden).toBe(true);
    }
  });

  test("shows cancel button when parse is running", () => {
    A.st.parse.run = true;
    A.updateParseButton();
    if (A.el.cancelParse) {
      expect(A.el.cancelParse.hidden).toBe(false);
    }
  });
});

// ── clearDynamicArtifacts ───────────────────────────────────────────────────

describe("clearDynamicArtifacts", () => {
  test("removes dynamic artifact category from DOM", () => {
    // Create a fake dynamic category
    const fs = document.createElement("fieldset");
    fs.id = "dynamic-artifact-category";
    document.body.appendChild(fs);
    expect(document.getElementById("dynamic-artifact-category")).not.toBeNull();

    A.clearDynamicArtifacts();
    expect(document.getElementById("dynamic-artifact-category")).toBeNull();
  });

  test("does nothing when no dynamic category exists", () => {
    expect(() => A.clearDynamicArtifacts()).not.toThrow();
  });
});
