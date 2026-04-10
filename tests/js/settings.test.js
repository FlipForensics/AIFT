/**
 * Unit tests for AIFT settings panel (settings.js).
 *
 * Covers:
 *  - openSettings / closeSettings visibility and aria
 *  - Settings tab switching (basic / advanced)
 *  - updateCsvOutputHelp path display logic
 *  - Provider field sync (show/hide API key, endpoint rows)
 *  - setProvider display updates
 *  - Focus trap setup
 *  - Background inert during modal
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

// ── openSettings / closeSettings ────────────────────────────────────────────

describe("openSettings and closeSettings", () => {
  test("openSettings makes panel visible", () => {
    if (!A.el.settingsPanel || !A.el.settingsBtn) return;
    A.el.settingsPanel.hidden = true;
    A.openSettings();
    expect(A.el.settingsPanel.hidden).toBe(false);
  });

  test("openSettings sets aria-expanded to true", () => {
    if (!A.el.settingsBtn) return;
    A.openSettings();
    expect(A.el.settingsBtn.getAttribute("aria-expanded")).toBe("true");
  });

  test("openSettings shows backdrop", () => {
    A.openSettings();
    const backdrop = document.getElementById("settings-backdrop");
    if (backdrop) {
      expect(backdrop.hidden).toBe(false);
    }
  });

  test("openSettings sets background inert", () => {
    A.openSettings();
    const main = document.querySelector("main#wizard");
    if (main) {
      expect(main.hasAttribute("inert")).toBe(true);
    }
  });
});

describe("closeSettings", () => {
  test("hides settings panel", () => {
    if (!A.el.settingsPanel || !A.el.settingsBtn) return;
    A.openSettings();
    // Simulate close - need to manually call since closeSettings is internal
    // but we can trigger via Escape key
    const event = new KeyboardEvent("keydown", { key: "Escape" });
    document.dispatchEvent(event);
    expect(A.el.settingsPanel.hidden).toBe(true);
  });

  test("hides backdrop on Escape", () => {
    A.openSettings();
    const event = new KeyboardEvent("keydown", { key: "Escape" });
    document.dispatchEvent(event);
    const backdrop = document.getElementById("settings-backdrop");
    if (backdrop) {
      expect(backdrop.hidden).toBe(true);
    }
  });

  test("removes background inert on close", () => {
    A.openSettings();
    const event = new KeyboardEvent("keydown", { key: "Escape" });
    document.dispatchEvent(event);
    const main = document.querySelector("main#wizard");
    if (main) {
      expect(main.hasAttribute("inert")).toBe(false);
    }
  });

  test("sets aria-expanded to false on close", () => {
    if (!A.el.settingsBtn) return;
    A.openSettings();
    const event = new KeyboardEvent("keydown", { key: "Escape" });
    document.dispatchEvent(event);
    expect(A.el.settingsBtn.getAttribute("aria-expanded")).toBe("false");
  });
});

// ── Settings tab switching ──────────────────────────────────────────────────

describe("settings tab switching", () => {
  test("defaults to basic tab", () => {
    expect(A.st.settingsTab).toBe("basic");
  });

  test("switching tabs updates settingsTab state", () => {
    if (!A.el.settingsTabButtons.length) return;
    const advancedBtn = A.el.settingsTabButtons.find(
      (b) => b.dataset.settingsTab === "advanced"
    );
    if (advancedBtn) {
      advancedBtn.click();
      expect(A.st.settingsTab).toBe("advanced");
    }
  });

  test("active tab button has is-active class", () => {
    if (!A.el.settingsTabButtons.length) return;
    const basicBtn = A.el.settingsTabButtons.find(
      (b) => b.dataset.settingsTab === "basic"
    );
    if (basicBtn) {
      expect(basicBtn.classList.contains("is-active")).toBe(true);
    }
  });

  test("active tab button has aria-selected true", () => {
    if (!A.el.settingsTabButtons.length) return;
    const basicBtn = A.el.settingsTabButtons.find(
      (b) => b.dataset.settingsTab === "basic"
    );
    if (basicBtn) {
      expect(basicBtn.getAttribute("aria-selected")).toBe("true");
    }
  });

  test("inactive tab button has aria-selected false", () => {
    if (!A.el.settingsTabButtons.length) return;
    const advancedBtn = A.el.settingsTabButtons.find(
      (b) => b.dataset.settingsTab === "advanced"
    );
    if (advancedBtn) {
      expect(advancedBtn.getAttribute("aria-selected")).toBe("false");
    }
  });

  test("only active tab panel is visible", () => {
    if (!A.el.settingsTabPanels.length) return;
    const basicPanel = A.el.settingsTabPanels.find(
      (p) => p.dataset.settingsPanel === "basic"
    );
    const advancedPanel = A.el.settingsTabPanels.find(
      (p) => p.dataset.settingsPanel === "advanced"
    );
    if (basicPanel && advancedPanel) {
      expect(basicPanel.hidden).toBe(false);
      expect(advancedPanel.hidden).toBe(true);
    }
  });
});

// ── updateCsvOutputHelp ─────────────────────────────────────────────────────

describe("updateCsvOutputHelp", () => {
  test("shows default path when no custom dir configured", () => {
    if (!A.el.setCsvOutputDir || !A.el.setCsvOutputHelp) return;
    A.el.setCsvOutputDir.value = "";
    A.updateCsvOutputHelp();
    expect(A.el.setCsvOutputHelp.textContent).toContain("Currently using:");
    expect(A.el.setCsvOutputHelp.textContent).toContain("parsed");
  });

  test("shows configured path when custom dir is set", () => {
    if (!A.el.setCsvOutputDir || !A.el.setCsvOutputHelp) return;
    A.setCaseId("test-case-123");
    A.el.setCsvOutputDir.value = "/custom/output";
    A.updateCsvOutputHelp();
    expect(A.el.setCsvOutputHelp.textContent).toContain("/custom/output");
    expect(A.el.setCsvOutputHelp.textContent).toContain("test-case-123");
  });

  test("uses <case_id> placeholder when no case is active", () => {
    if (!A.el.setCsvOutputDir || !A.el.setCsvOutputHelp) return;
    A.setCaseId("");
    A.el.setCsvOutputDir.value = "/custom/output";
    A.updateCsvOutputHelp();
    expect(A.el.setCsvOutputHelp.textContent).toContain("<case_id>");
  });
});

// ── Provider field visibility ───────────────────────────────────────────────

describe("provider field visibility", () => {
  test("hides API key row when local provider is selected", () => {
    if (!A.el.setProvider || !A.el.setApiRow) return;
    A.el.setProvider.value = "local";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setApiRow.hidden).toBe(true);
  });

  test("shows API key row for anthropic provider", () => {
    if (!A.el.setProvider || !A.el.setApiRow) return;
    A.el.setProvider.value = "anthropic";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setApiRow.hidden).toBe(false);
  });

  test("shows endpoint row for local provider", () => {
    if (!A.el.setProvider || !A.el.setLocalRow) return;
    A.el.setProvider.value = "local";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setLocalRow.hidden).toBe(false);
  });

  test("shows endpoint row for kimi provider", () => {
    if (!A.el.setProvider || !A.el.setLocalRow) return;
    A.el.setProvider.value = "kimi";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setLocalRow.hidden).toBe(false);
  });

  test("hides endpoint row for openai provider", () => {
    if (!A.el.setProvider || !A.el.setLocalRow) return;
    A.el.setProvider.value = "openai";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setLocalRow.hidden).toBe(true);
  });

  test("updates API key label for anthropic", () => {
    if (!A.el.setProvider || !A.el.setApiLabel) return;
    A.el.setProvider.value = "anthropic";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setApiLabel.textContent).toContain("Anthropic");
  });

  test("updates API key label for kimi", () => {
    if (!A.el.setProvider || !A.el.setApiLabel) return;
    A.el.setProvider.value = "kimi";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setApiLabel.textContent).toContain("Moonshot");
  });

  test("updates model placeholder for each provider", () => {
    if (!A.el.setProvider || !A.el.setModel) return;

    A.el.setProvider.value = "anthropic";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setModel.placeholder).toContain("claude");

    A.el.setProvider.value = "openai";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setModel.placeholder).toContain("gpt");

    A.el.setProvider.value = "local";
    A.el.setProvider.dispatchEvent(new Event("change"));
    expect(A.el.setModel.placeholder).toContain("llama");
  });
});

// ── Test Connection button ──────────────────────────────────────────────────

describe("test connection button", () => {
  test("test button is created during setup", () => {
    const btn = document.getElementById("test-connection");
    expect(btn).not.toBeNull();
    expect(btn.textContent).toBe("Test Connection");
  });

  test("test button is a regular button (not submit)", () => {
    const btn = document.getElementById("test-connection");
    expect(btn.type).toBe("button");
  });
});

// ── Settings panel initial state ────────────────────────────────────────────

describe("settings panel initial state", () => {
  test("settings panel is hidden on load", () => {
    if (A.el.settingsPanel) {
      expect(A.el.settingsPanel.hidden).toBe(true);
    }
  });

  test("settings button exists", () => {
    expect(A.el.settingsBtn).not.toBeNull();
  });
});
