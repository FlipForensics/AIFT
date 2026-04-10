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

// ── syncMode (per-card) ─────────────────────────────────────────────────────

describe("syncMode", () => {
  test("shows upload panel when upload mode is selected on first card", () => {
    const cards = A.getImageForms();
    if (!cards.length) return;
    const card = cards[0];
    const modeUpload = card.querySelector(".image-mode-upload");
    const modePath = card.querySelector(".image-mode-path");
    const uploadPanel = card.querySelector(".image-upload-panel");
    const pathPanel = card.querySelector(".image-path-panel");
    if (!modeUpload || !modePath || !uploadPanel || !pathPanel) return;
    modeUpload.checked = true;
    modePath.checked = false;
    A.syncMode();
    expect(uploadPanel.hidden).toBe(false);
    expect(pathPanel.hidden).toBe(true);
  });

  test("shows path panel when path mode is selected on first card", () => {
    const cards = A.getImageForms();
    if (!cards.length) return;
    const card = cards[0];
    const modeUpload = card.querySelector(".image-mode-upload");
    const modePath = card.querySelector(".image-mode-path");
    const uploadPanel = card.querySelector(".image-upload-panel");
    const pathPanel = card.querySelector(".image-path-panel");
    if (!modeUpload || !modePath || !uploadPanel || !pathPanel) return;
    modePath.checked = true;
    modeUpload.checked = false;
    A.syncMode();
    expect(pathPanel.hidden).toBe(false);
    expect(uploadPanel.hidden).toBe(true);
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

// ── Multi-image: getImageForms ──────────────────────────────────────────────

describe("getImageForms", () => {
  test("returns at least one image form card from the template", () => {
    const forms = A.getImageForms();
    expect(Array.isArray(forms)).toBe(true);
    expect(forms.length).toBeGreaterThanOrEqual(1);
    expect(forms[0].classList.contains("image-form-card")).toBe(true);
  });
});

// ── Multi-image: addImageForm / removeImageForm ─────────────────────────────

describe("addImageForm", () => {
  test("adds a new image form card to the container", () => {
    const before = A.getImageForms().length;
    A.addImageForm();
    const after = A.getImageForms().length;
    expect(after).toBe(before + 1);
  });

  test("new card has the expected UI elements", () => {
    A.addImageForm();
    const forms = A.getImageForms();
    const card = forms[forms.length - 1];
    expect(card.querySelector(".image-label-input")).not.toBeNull();
    expect(card.querySelector(".image-mode-upload")).not.toBeNull();
    expect(card.querySelector(".image-mode-path")).not.toBeNull();
    expect(card.querySelector(".image-upload-panel")).not.toBeNull();
    expect(card.querySelector(".image-path-panel")).not.toBeNull();
    expect(card.querySelector(".image-dropzone")).not.toBeNull();
    expect(card.querySelector(".image-file-input")).not.toBeNull();
    expect(card.querySelector(".image-path-input")).not.toBeNull();
    expect(card.querySelector(".image-metadata-card")).not.toBeNull();
    expect(card.querySelector(".image-status-msg")).not.toBeNull();
    expect(card.querySelector(".image-remove-btn")).not.toBeNull();
  });

  test("renumbers titles after adding", () => {
    A.addImageForm();
    const forms = A.getImageForms();
    forms.forEach((card, i) => {
      const title = card.querySelector(".image-form-title");
      expect(title.textContent).toBe(`Image ${i + 1}`);
    });
  });

  test("shows remove button on all cards when multiple exist", () => {
    A.addImageForm();
    const forms = A.getImageForms();
    expect(forms.length).toBeGreaterThan(1);
    forms.forEach((card) => {
      const removeBtn = card.querySelector(".image-remove-btn");
      expect(removeBtn.hidden).toBe(false);
    });
  });

  test("new card defaults to path mode", () => {
    A.addImageForm();
    const forms = A.getImageForms();
    const card = forms[forms.length - 1];
    const modePath = card.querySelector(".image-mode-path");
    expect(modePath.checked).toBe(true);
    const uploadPanel = card.querySelector(".image-upload-panel");
    expect(uploadPanel.hidden).toBe(true);
    const pathPanel = card.querySelector(".image-path-panel");
    expect(pathPanel.hidden).toBe(false);
  });
});

describe("removeImageForm", () => {
  test("removes a card when multiple exist", () => {
    A.addImageForm();
    const forms = A.getImageForms();
    const count = forms.length;
    expect(count).toBeGreaterThan(1);
    A.removeImageForm(forms[forms.length - 1]);
    expect(A.getImageForms().length).toBe(count - 1);
  });

  test("does not remove the last remaining card", () => {
    const forms = A.getImageForms();
    expect(forms.length).toBe(1);
    A.removeImageForm(forms[0]);
    expect(A.getImageForms().length).toBe(1);
  });

  test("renumbers titles after removing", () => {
    A.addImageForm();
    A.addImageForm();
    const forms = A.getImageForms();
    expect(forms.length).toBe(3);
    A.removeImageForm(forms[1]);
    const remaining = A.getImageForms();
    expect(remaining.length).toBe(2);
    remaining.forEach((card, i) => {
      const title = card.querySelector(".image-form-title");
      expect(title.textContent).toBe(`Image ${i + 1}`);
    });
  });

  test("hides remove button when only one card remains", () => {
    A.addImageForm();
    expect(A.getImageForms().length).toBe(2);
    A.removeImageForm(A.getImageForms()[1]);
    const forms = A.getImageForms();
    expect(forms.length).toBe(1);
    const removeBtn = forms[0].querySelector(".image-remove-btn");
    expect(removeBtn.hidden).toBe(true);
  });

  test("does nothing when passed null", () => {
    expect(() => A.removeImageForm(null)).not.toThrow();
  });
});

// ── Multi-image: renderImageSummaries ───────────────────────────────────────

describe("renderImageSummaries", () => {
  test("hides container for single image", () => {
    const singleImage = [{ image_id: "img1", label: "Test", metadata: {}, hashes: {} }];
    A.renderImageSummaries(singleImage);
    const container = document.getElementById("evidence-summaries-container");
    if (container) {
      expect(container.hidden).toBe(true);
    }
  });

  test("renders summary cards for multiple images", () => {
    const images = [
      { image_id: "img1", label: "Image A", metadata: { hostname: "PC1" }, hashes: { sha256: "abc" }, os_type: "windows" },
      { image_id: "img2", label: "Image B", metadata: { hostname: "PC2" }, hashes: { sha256: "def" }, os_type: "linux" },
    ];
    A.renderImageSummaries(images);
    const container = document.getElementById("evidence-summaries-container");
    const list = document.getElementById("evidence-summaries-list");
    if (container && list) {
      expect(container.hidden).toBe(false);
      const cards = list.querySelectorAll(".summary-card");
      expect(cards.length).toBe(2);
      expect(cards[0].textContent).toContain("PC1");
      expect(cards[1].textContent).toContain("PC2");
    }
  });

  test("escapes HTML in labels and metadata", () => {
    const images = [
      { image_id: "img1", label: "<script>alert(1)</script>", metadata: { hostname: "<b>evil</b>" }, hashes: {} },
      { image_id: "img2", label: "Normal", metadata: { hostname: "PC2" }, hashes: {} },
    ];
    A.renderImageSummaries(images);
    const list = document.getElementById("evidence-summaries-list");
    if (list) {
      expect(list.innerHTML).not.toContain("<script>");
      expect(list.innerHTML).not.toContain("<b>evil");
      expect(list.innerHTML).toContain("&lt;script&gt;");
    }
  });
});

// ── Multi-image: isMultiImage ─────────────────────────────────────────────

describe("isMultiImage", () => {
  test("returns false when no images loaded", () => {
    A.st.images = [];
    expect(A.isMultiImage()).toBe(false);
  });

  test("returns false when single image loaded", () => {
    A.st.images = [{ image_id: "img1", label: "Image 1" }];
    expect(A.isMultiImage()).toBe(false);
  });

  test("returns true when multiple images loaded", () => {
    A.st.images = [
      { image_id: "img1", label: "Image 1" },
      { image_id: "img2", label: "Image 2" },
    ];
    expect(A.isMultiImage()).toBe(true);
  });
});

// ── Multi-image: allImageArtifactSelections ────────────────────────────────

describe("allImageArtifactSelections", () => {
  test("returns empty array when single image loaded", () => {
    A.st.images = [{ image_id: "img1", label: "Image 1" }];
    expect(A.allImageArtifactSelections()).toEqual([]);
  });

  test("returns per-image entries when multiple images loaded", () => {
    A.st.images = [
      { image_id: "img1", label: "Image A", available_artifacts: [] },
      { image_id: "img2", label: "Image B", available_artifacts: [] },
    ];
    const selections = A.allImageArtifactSelections();
    expect(selections.length).toBe(2);
    expect(selections[0].image_id).toBe("img1");
    expect(selections[1].image_id).toBe("img2");
    expect(Array.isArray(selections[0].artifact_options)).toBe(true);
  });

  test("returns empty array when no images loaded", () => {
    A.st.images = [];
    expect(A.allImageArtifactSelections()).toEqual([]);
  });
});

// ── Multi-image: buildMultiImageArtifactTabs ──────────────────────────────

describe("buildMultiImageArtifactTabs", () => {
  afterEach(() => {
    A.st.images = [];
  });

  test("hides tab container when single image loaded", () => {
    A.st.images = [{ image_id: "img1", label: "Image 1", available_artifacts: [] }];
    A.buildMultiImageArtifactTabs();
    const tabContainer = document.getElementById("artifact-image-tabs");
    if (tabContainer) {
      expect(tabContainer.hidden).toBe(true);
    }
  });

  test("shows tab container with buttons for multiple images", () => {
    A.st.images = [
      { image_id: "img1", label: "Image A", available_artifacts: [{ key: "evtx", available: true }] },
      { image_id: "img2", label: "Image B", available_artifacts: [{ key: "evtx", available: true }] },
    ];
    A.buildMultiImageArtifactTabs();
    const tabContainer = document.getElementById("artifact-image-tabs");
    if (tabContainer) {
      expect(tabContainer.hidden).toBe(false);
      const buttons = tabContainer.querySelectorAll(".artifact-tab-bar button");
      expect(buttons.length).toBe(2);
      expect(buttons[0].textContent).toBe("Image A");
      expect(buttons[1].textContent).toBe("Image B");
    }
  });

  test("first tab is active by default", () => {
    A.st.images = [
      { image_id: "img1", label: "Image A", available_artifacts: [] },
      { image_id: "img2", label: "Image B", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
    const tabContainer = document.getElementById("artifact-image-tabs");
    if (tabContainer) {
      const buttons = tabContainer.querySelectorAll(".artifact-tab-bar button");
      expect(buttons[0].classList.contains("is-active")).toBe(true);
      expect(buttons[1].classList.contains("is-active")).toBe(false);
    }
  });

  test("creates panels for each image", () => {
    A.st.images = [
      { image_id: "img1", label: "Image A", available_artifacts: [] },
      { image_id: "img2", label: "Image B", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
    const panelsContainer = document.getElementById("artifact-image-panels");
    if (panelsContainer) {
      const panels = panelsContainer.querySelectorAll(".artifact-image-panel");
      expect(panels.length).toBe(2);
      expect(panels[0].dataset.imageId).toBe("img1");
      expect(panels[1].dataset.imageId).toBe("img2");
    }
  });

  test("hides main artifact form when multi-image", () => {
    A.st.images = [
      { image_id: "img1", label: "Image A", available_artifacts: [] },
      { image_id: "img2", label: "Image B", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
    if (A.el.artifactsForm) {
      expect(A.el.artifactsForm.hidden).toBe(true);
    }
  });

  test("shows main artifact form when reverting to single image", () => {
    /* First build multi tabs, then revert. */
    A.st.images = [
      { image_id: "img1", label: "A", available_artifacts: [] },
      { image_id: "img2", label: "B", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
    A.st.images = [{ image_id: "img1", label: "A", available_artifacts: [] }];
    A.buildMultiImageArtifactTabs();
    if (A.el.artifactsForm) {
      expect(A.el.artifactsForm.hidden).toBe(false);
    }
  });
});

// ── Multi-image: switchArtifactTab ────────────────────────────────────────

describe("switchArtifactTab", () => {
  afterEach(() => {
    A.st.images = [];
  });

  test("switches active tab and panel", () => {
    A.st.images = [
      { image_id: "img1", label: "Image A", available_artifacts: [] },
      { image_id: "img2", label: "Image B", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
    A.switchArtifactTab("img2");

    const tabContainer = document.getElementById("artifact-image-tabs");
    const panelsContainer = document.getElementById("artifact-image-panels");
    if (tabContainer && panelsContainer) {
      const buttons = tabContainer.querySelectorAll(".artifact-tab-bar button");
      expect(buttons[0].classList.contains("is-active")).toBe(false);
      expect(buttons[1].classList.contains("is-active")).toBe(true);

      const panels = panelsContainer.querySelectorAll(".artifact-image-panel");
      expect(panels[0].classList.contains("is-active")).toBe(false);
      expect(panels[1].classList.contains("is-active")).toBe(true);
    }
  });
});

// ── Multi-image: activeArtifactTabImageId ─────────────────────────────────

describe("activeArtifactTabImageId", () => {
  afterEach(() => {
    A.st.images = [];
  });

  test("returns null when no tabs exist", () => {
    A.st.images = [];
    A.buildMultiImageArtifactTabs();
    expect(A.activeArtifactTabImageId()).toBeNull();
  });

  test("returns first image ID by default", () => {
    A.st.images = [
      { image_id: "img1", label: "A", available_artifacts: [] },
      { image_id: "img2", label: "B", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
    expect(A.activeArtifactTabImageId()).toBe("img1");
  });

  test("returns switched image ID after tab switch", () => {
    A.st.images = [
      { image_id: "img1", label: "A", available_artifacts: [] },
      { image_id: "img2", label: "B", available_artifacts: [] },
    ];
    A.buildMultiImageArtifactTabs();
    A.switchArtifactTab("img2");
    expect(A.activeArtifactTabImageId()).toBe("img2");
  });
});

// ── Multi-image: applyPresetMultiAware ────────────────────────────────────

describe("applyPresetMultiAware", () => {
  afterEach(() => {
    A.st.images = [];
  });

  test("falls back to applyPreset when single image", () => {
    A.st.images = [{ image_id: "img1", label: "A", available_artifacts: [] }];
    /* Should not throw. */
    expect(() => A.applyPresetMultiAware("clear")).not.toThrow();
  });

  test("clears checkboxes in active tab when mode is clear", () => {
    A.st.images = [
      { image_id: "img1", label: "A", available_artifacts: [{ key: "evtx", available: true }] },
      { image_id: "img2", label: "B", available_artifacts: [{ key: "evtx", available: true }] },
    ];
    A.buildMultiImageArtifactTabs();

    /* Check some boxes in the first tab panel. */
    const panelsContainer = document.getElementById("artifact-image-panels");
    if (!panelsContainer) return;
    const panel = panelsContainer.querySelector('.artifact-image-panel[data-image-id="img1"]');
    if (!panel) return;
    const checkboxes = panel.querySelectorAll("input[type='checkbox'][data-artifact-key]");
    checkboxes.forEach((cb) => { if (!cb.disabled) cb.checked = true; });

    A.applyPresetMultiAware("clear");
    checkboxes.forEach((cb) => {
      if (!cb.disabled) expect(cb.checked).toBe(false);
    });
  });
});

// ── Multi-image: sanitizeEvidencePath ───────────────────────────────────────

describe("sanitizeEvidencePath", () => {
  test("trims whitespace", () => {
    expect(A.sanitizeEvidencePath("  C:\\path  ")).toBe("C:\\path");
  });

  test("removes curly quotes", () => {
    expect(A.sanitizeEvidencePath("\u201CC:\\path\u201D")).toBe("C:\\path");
  });

  test("removes straight double quotes", () => {
    expect(A.sanitizeEvidencePath('"C:\\path"')).toBe("C:\\path");
  });

  test("returns empty string for null/undefined", () => {
    expect(A.sanitizeEvidencePath(null)).toBe("");
    expect(A.sanitizeEvidencePath(undefined)).toBe("");
  });
});
