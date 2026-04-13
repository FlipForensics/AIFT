/**
 * Unit tests for AIFT multi-image evidence intake and per-image artifact
 * tab management (evidence_multi.js).
 *
 * Covers:
 *  - addImageForm / removeImageForm card management
 *  - renderImageSummaries display for single and multiple images
 *  - buildMultiImageArtifactTabs with single and multiple images
 *  - OS-aware fieldset cloning (Windows-only, Linux-only, mixed)
 *  - switchArtifactTab tab activation
 *  - activeArtifactTabImageId returns correct ID
 *  - selectedArtifactOptionsForImage collects checked artifacts
 *  - allImageArtifactSelections aggregates per-image selections
 *  - isMultiImage reflects image count
 *  - applyRecommendedToAllImages applies preset across all panels
 *  - applyCurrentSelectionToAllImages mirrors active tab to others
 *  - applyPresetMultiAware dispatches to correct handler
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

/**
 * Helper: populate st.images with the given image entries and build tabs.
 *
 * @param {Object[]} images - Array of image entry objects.
 */
function setImagesAndBuildTabs(images) {
  A.st.images = images;
  /* Populate artifacts so the main form is aware of all artifact keys. */
  const allArts = [];
  for (const img of images) {
    for (const a of img.available_artifacts || []) {
      if (!allArts.find((x) => x.key === a.key)) allArts.push(Object.assign({}, a));
    }
  }
  A.st.artifacts = allArts;
  A.buildMultiImageArtifactTabs();
}

/**
 * Helper: create a standard two-image Windows+Linux setup.
 *
 * @returns {Object[]} Array of two image entries.
 */
function makeWindowsLinuxImages() {
  return [
    {
      image_id: "img-win",
      label: "Windows PC",
      os_type: "windows",
      metadata: { hostname: "WIN-PC", os_version: "Windows 10" },
      hashes: { sha256: "abc123" },
      available_artifacts: [
        { key: "runkeys", name: "Run/RunOnce Keys", available: true },
        { key: "shimcache", name: "Shimcache", available: true },
        { key: "evtx", name: "Event Logs", available: true },
        { key: "mft", name: "MFT", available: true },
      ],
    },
    {
      image_id: "img-linux",
      label: "Linux Server",
      os_type: "linux",
      metadata: { hostname: "SRV-01", os_version: "Ubuntu 22.04" },
      hashes: { sha256: "def456" },
      available_artifacts: [
        { key: "cronjobs", name: "Cron Jobs", available: true },
        { key: "bash_history", name: "Bash History", available: true },
        { key: "services", name: "Systemd Services", available: true },
      ],
    },
  ];
}

/**
 * Helper: create a two-Windows-image setup.
 *
 * @returns {Object[]} Array of two image entries.
 */
function makeTwoWindowsImages() {
  return [
    {
      image_id: "img-w1",
      label: "Workstation 1",
      os_type: "windows",
      metadata: { hostname: "WS-01" },
      hashes: {},
      available_artifacts: [
        { key: "runkeys", name: "Run/RunOnce Keys", available: true },
        { key: "shimcache", name: "Shimcache", available: true },
        { key: "prefetch", name: "Prefetch", available: false },
      ],
    },
    {
      image_id: "img-w2",
      label: "Workstation 2",
      os_type: "windows",
      metadata: { hostname: "WS-02" },
      hashes: {},
      available_artifacts: [
        { key: "runkeys", name: "Run/RunOnce Keys", available: true },
        { key: "shimcache", name: "Shimcache", available: false },
        { key: "prefetch", name: "Prefetch", available: true },
      ],
    },
  ];
}

// ── addImageForm / removeImageForm ──────────────────────────────────────────

describe("addImageForm", () => {
  test("adds a new image form card to the container", () => {
    const before = A.getImageForms().length;
    A.addImageForm();
    expect(A.getImageForms().length).toBe(before + 1);
  });

  test("each added card has the required child elements", () => {
    A.addImageForm();
    const cards = A.getImageForms();
    const last = cards[cards.length - 1];
    expect(last.querySelector(".image-form-title")).not.toBeNull();
    expect(last.querySelector(".image-label-input")).not.toBeNull();
    expect(last.querySelector(".image-mode-upload")).not.toBeNull();
    expect(last.querySelector(".image-mode-path")).not.toBeNull();
    expect(last.querySelector(".image-path-input")).not.toBeNull();
    expect(last.querySelector(".image-file-input")).not.toBeNull();
    expect(last.querySelector(".image-metadata-card")).not.toBeNull();
  });

  test("renumbers titles after adding", () => {
    A.addImageForm();
    A.addImageForm();
    const cards = A.getImageForms();
    const titles = Array.from(cards).map((c) => c.querySelector(".image-form-title").textContent);
    titles.forEach((t, i) => {
      expect(t).toBe(`Image ${i + 1}`);
    });
  });
});

describe("removeImageForm", () => {
  test("removes a card when multiple exist", () => {
    A.addImageForm();
    const cards = A.getImageForms();
    const countBefore = cards.length;
    expect(countBefore).toBeGreaterThanOrEqual(2);
    A.removeImageForm(cards[cards.length - 1]);
    expect(A.getImageForms().length).toBe(countBefore - 1);
  });

  test("does not remove the last remaining card", () => {
    const cards = A.getImageForms();
    /* Remove extras until only one remains. */
    while (A.getImageForms().length > 1) {
      A.removeImageForm(A.getImageForms()[A.getImageForms().length - 1]);
    }
    expect(A.getImageForms().length).toBe(1);
    A.removeImageForm(A.getImageForms()[0]);
    expect(A.getImageForms().length).toBe(1);
  });

  test("renumbers titles after removing", () => {
    A.addImageForm();
    A.addImageForm();
    const cards = A.getImageForms();
    /* Remove the middle card. */
    A.removeImageForm(cards[1]);
    const remaining = A.getImageForms();
    remaining.forEach((c, i) => {
      expect(c.querySelector(".image-form-title").textContent).toBe(`Image ${i + 1}`);
    });
  });
});

// ── isMultiImage ────────────────────────────────────────────────────────────

describe("isMultiImage", () => {
  test("returns false when no images loaded", () => {
    A.st.images = [];
    expect(A.isMultiImage()).toBe(false);
  });

  test("returns false for a single image", () => {
    A.st.images = [{ image_id: "x" }];
    expect(A.isMultiImage()).toBe(false);
  });

  test("returns true for multiple images", () => {
    A.st.images = [{ image_id: "a" }, { image_id: "b" }];
    expect(A.isMultiImage()).toBe(true);
  });
});

// ── buildMultiImageArtifactTabs ─────────────────────────────────────────────

describe("buildMultiImageArtifactTabs", () => {
  test("hides tabs and shows main form for single image", () => {
    A.st.images = [{ image_id: "solo", label: "Solo", os_type: "windows", available_artifacts: [] }];
    A.buildMultiImageArtifactTabs();

    const tabContainer = document.getElementById("artifact-image-tabs");
    expect(tabContainer.hidden).toBe(true);
    if (A.el.artifactsForm) expect(A.el.artifactsForm.hidden).toBe(false);
  });

  test("shows tabs and hides main form for multiple images", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    const tabContainer = document.getElementById("artifact-image-tabs");
    expect(tabContainer.hidden).toBe(false);
    if (A.el.artifactsForm) expect(A.el.artifactsForm.hidden).toBe(true);
  });

  test("creates one tab button per image", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    const tabBar = document.querySelector(".artifact-tab-bar");
    const buttons = tabBar.querySelectorAll("button");
    expect(buttons.length).toBe(2);
    expect(buttons[0].textContent).toBe("Workstation 1");
    expect(buttons[1].textContent).toBe("Workstation 2");
  });

  test("creates one panel per image", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    const panels = document.querySelectorAll(".artifact-image-panel");
    expect(panels.length).toBe(2);
    expect(panels[0].dataset.imageId).toBe("img-w1");
    expect(panels[1].dataset.imageId).toBe("img-w2");
  });

  test("first tab and panel are active by default", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    const buttons = document.querySelectorAll(".artifact-tab-bar button");
    expect(buttons[0].classList.contains("is-active")).toBe(true);
    expect(buttons[1].classList.contains("is-active")).toBe(false);

    const panels = document.querySelectorAll(".artifact-image-panel");
    expect(panels[0].classList.contains("is-active")).toBe(true);
    expect(panels[1].classList.contains("is-active")).toBe(false);
  });

  test("shows multi-image buttons when multiple images present", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    if (A.el.applyRecommendedAllBtn) {
      expect(A.el.applyRecommendedAllBtn.hidden).toBe(false);
    }
    if (A.el.applySelectionAllBtn) {
      expect(A.el.applySelectionAllBtn.hidden).toBe(false);
    }
  });

  test("hides multi-image buttons for single image", () => {
    A.st.images = [{ image_id: "solo", label: "Solo", os_type: "windows", available_artifacts: [] }];
    A.buildMultiImageArtifactTabs();

    if (A.el.applyRecommendedAllBtn) {
      expect(A.el.applyRecommendedAllBtn.hidden).toBe(true);
    }
    if (A.el.applySelectionAllBtn) {
      expect(A.el.applySelectionAllBtn.hidden).toBe(true);
    }
  });

  test("disables unavailable artifacts per image", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    const panels = document.querySelectorAll(".artifact-image-panel");
    /* Image 1: prefetch unavailable. */
    const panel1Prefetch = panels[0].querySelector("input[data-artifact-key='prefetch']");
    if (panel1Prefetch) {
      expect(panel1Prefetch.disabled).toBe(true);
    }
    /* Image 2: shimcache unavailable. */
    const panel2Shim = panels[1].querySelector("input[data-artifact-key='shimcache']");
    if (panel2Shim) {
      expect(panel2Shim.disabled).toBe(true);
    }
    /* Image 2: prefetch available. */
    const panel2Prefetch = panels[1].querySelector("input[data-artifact-key='prefetch']");
    if (panel2Prefetch) {
      expect(panel2Prefetch.disabled).toBe(false);
    }
  });
});

// ── OS-aware fieldset cloning ───────────────────────────────────────────────

describe("OS-aware fieldset cloning", () => {
  test("Windows image panel contains Windows fieldsets only", () => {
    setImagesAndBuildTabs(makeWindowsLinuxImages());

    const winPanel = document.querySelector(".artifact-image-panel[data-image-id='img-win']");
    expect(winPanel).not.toBeNull();

    /* Should have Windows artifacts (no data-os). */
    const winCheckbox = winPanel.querySelector("input[data-artifact-key='runkeys']");
    expect(winCheckbox).not.toBeNull();

    /* Should NOT have Linux artifacts. */
    const linuxCheckbox = winPanel.querySelector("input[data-artifact-key='cronjobs']");
    expect(linuxCheckbox).toBeNull();
  });

  test("Linux image panel contains Linux fieldsets only", () => {
    setImagesAndBuildTabs(makeWindowsLinuxImages());

    const linuxPanel = document.querySelector(".artifact-image-panel[data-image-id='img-linux']");
    expect(linuxPanel).not.toBeNull();

    /* Should have Linux artifacts. */
    const linuxCheckbox = linuxPanel.querySelector("input[data-artifact-key='cronjobs']");
    expect(linuxCheckbox).not.toBeNull();

    /* Should NOT have Windows-only artifacts. */
    const winCheckbox = linuxPanel.querySelector("input[data-artifact-key='runkeys']");
    expect(winCheckbox).toBeNull();
  });

  test("Linux fieldsets are visible (not hidden) in Linux panel", () => {
    setImagesAndBuildTabs(makeWindowsLinuxImages());

    const linuxPanel = document.querySelector(".artifact-image-panel[data-image-id='img-linux']");
    const fieldsets = linuxPanel.querySelectorAll("fieldset.artifact-category");
    fieldsets.forEach((fs) => {
      expect(fs.hidden).toBe(false);
    });
  });

  test("available Linux artifacts are enabled in Linux panel", () => {
    setImagesAndBuildTabs(makeWindowsLinuxImages());

    const linuxPanel = document.querySelector(".artifact-image-panel[data-image-id='img-linux']");
    const cronCb = linuxPanel.querySelector("input[data-artifact-key='cronjobs']");
    expect(cronCb).not.toBeNull();
    expect(cronCb.disabled).toBe(false);

    const bashCb = linuxPanel.querySelector("input[data-artifact-key='bash_history']");
    expect(bashCb).not.toBeNull();
    expect(bashCb.disabled).toBe(false);
  });

  test("two Windows images both get Windows fieldsets", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    const panels = document.querySelectorAll(".artifact-image-panel");
    panels.forEach((panel) => {
      const runkeys = panel.querySelector("input[data-artifact-key='runkeys']");
      expect(runkeys).not.toBeNull();

      /* Should not have Linux fieldsets. */
      const cronjobs = panel.querySelector("input[data-artifact-key='cronjobs']");
      expect(cronjobs).toBeNull();
    });
  });

  test("checkbox names are prefixed with image ID to avoid collisions", () => {
    setImagesAndBuildTabs(makeWindowsLinuxImages());

    const winPanel = document.querySelector(".artifact-image-panel[data-image-id='img-win']");
    const runkeys = winPanel.querySelector("input[data-artifact-key='runkeys']");
    if (runkeys) {
      expect(runkeys.name).toBe("img-win__runkeys");
      expect(runkeys.dataset.imageId).toBe("img-win");
    }

    const linuxPanel = document.querySelector(".artifact-image-panel[data-image-id='img-linux']");
    const cron = linuxPanel.querySelector("input[data-artifact-key='cronjobs']");
    if (cron) {
      expect(cron.name).toBe("img-linux__cronjobs");
      expect(cron.dataset.imageId).toBe("img-linux");
    }
  });
});

// ── switchArtifactTab ───────────────────────────────────────────────────────

describe("switchArtifactTab", () => {
  test("activates the selected tab and panel", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    A.switchArtifactTab("img-w2");

    const buttons = document.querySelectorAll(".artifact-tab-bar button");
    expect(buttons[0].classList.contains("is-active")).toBe(false);
    expect(buttons[1].classList.contains("is-active")).toBe(true);

    const panels = document.querySelectorAll(".artifact-image-panel");
    expect(panels[0].classList.contains("is-active")).toBe(false);
    expect(panels[1].classList.contains("is-active")).toBe(true);
  });

  test("switching back to first tab restores activation", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    A.switchArtifactTab("img-w2");
    A.switchArtifactTab("img-w1");

    const buttons = document.querySelectorAll(".artifact-tab-bar button");
    expect(buttons[0].classList.contains("is-active")).toBe(true);
    expect(buttons[1].classList.contains("is-active")).toBe(false);
  });
});

// ── activeArtifactTabImageId ────────────────────────────────────────────────

describe("activeArtifactTabImageId", () => {
  test("returns null when tabs are hidden (single image)", () => {
    A.st.images = [{ image_id: "solo", os_type: "windows", available_artifacts: [] }];
    A.buildMultiImageArtifactTabs();
    expect(A.activeArtifactTabImageId()).toBeNull();
  });

  test("returns first image ID by default in multi-image mode", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());
    expect(A.activeArtifactTabImageId()).toBe("img-w1");
  });

  test("returns switched tab's image ID", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());
    A.switchArtifactTab("img-w2");
    expect(A.activeArtifactTabImageId()).toBe("img-w2");
  });
});

// ── selectedArtifactOptionsForImage ─────────────────────────────────────────

describe("selectedArtifactOptionsForImage", () => {
  test("returns empty array when no artifacts checked", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());
    expect(A.selectedArtifactOptionsForImage("img-w1")).toEqual([]);
  });

  test("returns checked artifacts for a specific image", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    /* Check runkeys on image 1. */
    const panel = document.querySelector(".artifact-image-panel[data-image-id='img-w1']");
    const cb = panel.querySelector("input[data-artifact-key='runkeys']");
    if (cb) {
      cb.checked = true;
      const result = A.selectedArtifactOptionsForImage("img-w1");
      expect(result.length).toBe(1);
      expect(result[0].artifact_key).toBe("runkeys");
    }
  });

  test("does not include disabled (unavailable) checked artifacts", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    /* Image 1: prefetch is unavailable. Force-check it. */
    const panel = document.querySelector(".artifact-image-panel[data-image-id='img-w1']");
    const cb = panel.querySelector("input[data-artifact-key='prefetch']");
    if (cb) {
      cb.checked = true; /* Still disabled. */
      const result = A.selectedArtifactOptionsForImage("img-w1");
      const prefetchEntry = result.find((r) => r.artifact_key === "prefetch");
      expect(prefetchEntry).toBeUndefined();
    }
  });

  test("returns empty array for null/empty imageId", () => {
    expect(A.selectedArtifactOptionsForImage(null)).toEqual([]);
    expect(A.selectedArtifactOptionsForImage("")).toEqual([]);
  });

  test("returns Linux artifacts for Linux image", () => {
    setImagesAndBuildTabs(makeWindowsLinuxImages());

    const panel = document.querySelector(".artifact-image-panel[data-image-id='img-linux']");
    const cb = panel.querySelector("input[data-artifact-key='cronjobs']");
    if (cb) {
      cb.checked = true;
      const result = A.selectedArtifactOptionsForImage("img-linux");
      expect(result.length).toBe(1);
      expect(result[0].artifact_key).toBe("cronjobs");
    }
  });
});

// ── allImageArtifactSelections ──────────────────────────────────────────────

describe("allImageArtifactSelections", () => {
  test("returns empty array for single image", () => {
    A.st.images = [{ image_id: "solo", os_type: "windows", available_artifacts: [] }];
    A.buildMultiImageArtifactTabs();
    expect(A.allImageArtifactSelections()).toEqual([]);
  });

  test("returns per-image entries for multiple images", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    const result = A.allImageArtifactSelections();
    expect(result.length).toBe(2);
    expect(result[0].image_id).toBe("img-w1");
    expect(result[0].label).toBe("Workstation 1");
    expect(result[1].image_id).toBe("img-w2");
    expect(result[1].label).toBe("Workstation 2");
  });

  test("includes checked artifacts in each image entry", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    /* Check runkeys on image 1. */
    const panel1 = document.querySelector(".artifact-image-panel[data-image-id='img-w1']");
    const cb1 = panel1.querySelector("input[data-artifact-key='runkeys']");
    if (cb1) cb1.checked = true;

    const result = A.allImageArtifactSelections();
    expect(result[0].artifact_options.length).toBe(1);
    expect(result[0].artifact_options[0].artifact_key).toBe("runkeys");
    /* Image 2 has nothing checked. */
    expect(result[1].artifact_options.length).toBe(0);
  });
});

// ── applyRecommendedToAllImages ─────────────────────────────────────────────

describe("applyRecommendedToAllImages", () => {
  test("checks available non-excluded artifacts on all Windows panels", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());
    A.applyRecommendedToAllImages();

    const panels = document.querySelectorAll(".artifact-image-panel");
    panels.forEach((panel) => {
      panel.querySelectorAll("input[type='checkbox'][data-artifact-key]").forEach((cb) => {
        const key = String(cb.dataset.artifactKey || "").toLowerCase();
        if (cb.disabled) {
          expect(cb.checked).toBe(false);
        } else if (A.RECOMMENDED_PRESET_EXCLUDED_ARTIFACTS.has(key)) {
          expect(cb.checked).toBe(false);
        } else {
          expect(cb.checked).toBe(true);
        }
      });
    });
  });

  test("checks available Linux artifacts in Linux panel", () => {
    setImagesAndBuildTabs(makeWindowsLinuxImages());
    A.applyRecommendedToAllImages();

    const linuxPanel = document.querySelector(".artifact-image-panel[data-image-id='img-linux']");
    const cronCb = linuxPanel.querySelector("input[data-artifact-key='cronjobs']");
    if (cronCb) {
      /* cronjobs is available and not in the excluded set. */
      expect(cronCb.disabled).toBe(false);
      expect(cronCb.checked).toBe(true);
    }

    const bashCb = linuxPanel.querySelector("input[data-artifact-key='bash_history']");
    if (bashCb) {
      expect(bashCb.disabled).toBe(false);
      expect(bashCb.checked).toBe(true);
    }
  });

  test("does not check excluded artifacts (evtx, mft)", () => {
    setImagesAndBuildTabs(makeWindowsLinuxImages());
    A.applyRecommendedToAllImages();

    const winPanel = document.querySelector(".artifact-image-panel[data-image-id='img-win']");
    const evtxCb = winPanel.querySelector("input[data-artifact-key='evtx']");
    if (evtxCb && !evtxCb.disabled) {
      expect(evtxCb.checked).toBe(false);
    }
    const mftCb = winPanel.querySelector("input[data-artifact-key='mft']");
    if (mftCb && !mftCb.disabled) {
      expect(mftCb.checked).toBe(false);
    }
  });

  test("does nothing when not in multi-image mode", () => {
    A.st.images = [{ image_id: "solo", os_type: "windows", available_artifacts: [] }];
    A.buildMultiImageArtifactTabs();
    /* Should not throw. */
    expect(() => A.applyRecommendedToAllImages()).not.toThrow();
  });
});

// ── applyCurrentSelectionToAllImages ────────────────────────────────────────

describe("applyCurrentSelectionToAllImages", () => {
  test("mirrors active tab selection to other panels", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    /* Check runkeys on image 1 (active tab). */
    const panel1 = document.querySelector(".artifact-image-panel[data-image-id='img-w1']");
    const cb1 = panel1.querySelector("input[data-artifact-key='runkeys']");
    if (cb1) cb1.checked = true;

    A.applyCurrentSelectionToAllImages();

    /* Image 2 should now have runkeys checked too. */
    const panel2 = document.querySelector(".artifact-image-panel[data-image-id='img-w2']");
    const cb2 = panel2.querySelector("input[data-artifact-key='runkeys']");
    if (cb2 && !cb2.disabled) {
      expect(cb2.checked).toBe(true);
    }
  });

  test("does not enable disabled artifacts on target panel", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    /* Check shimcache on image 1 (available). */
    const panel1 = document.querySelector(".artifact-image-panel[data-image-id='img-w1']");
    const cb1 = panel1.querySelector("input[data-artifact-key='shimcache']");
    if (cb1) cb1.checked = true;

    A.applyCurrentSelectionToAllImages();

    /* Image 2: shimcache is unavailable (disabled). Should not be checked. */
    const panel2 = document.querySelector(".artifact-image-panel[data-image-id='img-w2']");
    const cb2 = panel2.querySelector("input[data-artifact-key='shimcache']");
    if (cb2 && cb2.disabled) {
      expect(cb2.checked).toBe(false);
    }
  });

  test("leaves OS-specific artifacts untouched when not in source panel", () => {
    setImagesAndBuildTabs(makeWindowsLinuxImages());

    /* Active tab is Windows (img-win). Check runkeys. */
    const winPanel = document.querySelector(".artifact-image-panel[data-image-id='img-win']");
    const runkeys = winPanel.querySelector("input[data-artifact-key='runkeys']");
    if (runkeys) runkeys.checked = true;

    /* Pre-check cronjobs on Linux panel. */
    const linuxPanel = document.querySelector(".artifact-image-panel[data-image-id='img-linux']");
    const cronCb = linuxPanel.querySelector("input[data-artifact-key='cronjobs']");
    if (cronCb) cronCb.checked = true;

    A.applyCurrentSelectionToAllImages();

    /* runkeys does not exist in Linux panel — cronjobs should remain checked. */
    if (cronCb) {
      expect(cronCb.checked).toBe(true);
    }
  });
});

// ── applyPresetMultiAware ───────────────────────────────────────────────────

describe("applyPresetMultiAware", () => {
  test("applies recommended preset to active multi-image panel", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());
    A.applyPresetMultiAware("recommended");

    /* Only the active panel (img-w1) should be affected. */
    const panel1 = document.querySelector(".artifact-image-panel[data-image-id='img-w1']");
    const available1 = panel1.querySelectorAll("input[type='checkbox'][data-artifact-key]:not(:disabled)");
    let anyChecked = false;
    available1.forEach((cb) => {
      const key = String(cb.dataset.artifactKey || "").toLowerCase();
      if (!A.RECOMMENDED_PRESET_EXCLUDED_ARTIFACTS.has(key)) {
        if (cb.checked) anyChecked = true;
      }
    });
    /* At least some available non-excluded artifacts should be checked. */
    if (available1.length > 0) {
      expect(anyChecked).toBe(true);
    }

    /* Panel 2 should remain unchecked (not affected by per-tab preset). */
    const panel2 = document.querySelector(".artifact-image-panel[data-image-id='img-w2']");
    const checked2 = panel2.querySelectorAll("input[type='checkbox'][data-artifact-key]:checked");
    expect(checked2.length).toBe(0);
  });

  test("clear preset unchecks all in active panel", () => {
    setImagesAndBuildTabs(makeTwoWindowsImages());

    /* First apply recommended, then clear. */
    A.applyPresetMultiAware("recommended");
    A.applyPresetMultiAware("clear");

    const panel1 = document.querySelector(".artifact-image-panel[data-image-id='img-w1']");
    const checked = panel1.querySelectorAll("input[type='checkbox'][data-artifact-key]:checked");
    expect(checked.length).toBe(0);
  });
});

// ── renderImageSummaries ────────────────────────────────────────────────────

describe("renderImageSummaries", () => {
  test("hides multi-image summaries for single image", () => {
    A.renderImageSummaries([{ image_id: "solo", metadata: {}, hashes: {} }]);

    const container = document.getElementById("evidence-summaries-container");
    if (container) {
      expect(container.hidden).toBe(true);
    }
  });

  test("shows summary cards for multiple images", () => {
    const images = makeWindowsLinuxImages();
    A.renderImageSummaries(images);

    const container = document.getElementById("evidence-summaries-container");
    const list = document.getElementById("evidence-summaries-list");
    if (container && list) {
      expect(container.hidden).toBe(false);
      const cards = list.querySelectorAll(".summary-card");
      expect(cards.length).toBe(2);
    }
  });

  test("displays image labels and metadata", () => {
    const images = makeWindowsLinuxImages();
    A.renderImageSummaries(images);

    const list = document.getElementById("evidence-summaries-list");
    if (list) {
      const cards = list.querySelectorAll(".summary-card");
      expect(cards[0].querySelector("h4").textContent).toBe("Windows PC");
      expect(cards[1].querySelector("h4").textContent).toBe("Linux Server");
      expect(cards[0].textContent).toContain("WIN-PC");
      expect(cards[1].textContent).toContain("SRV-01");
    }
  });
});
