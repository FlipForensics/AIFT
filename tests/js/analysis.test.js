/**
 * Unit tests for AIFT analysis SSE and results rendering (analysis.js).
 *
 * Covers:
 *  - resetAnalysisState clears all analysis state
 *  - renderAnalysis renders placeholder and artifact cards
 *  - renderExecSummary renders summary markdown
 *  - renderFindings renders collapsible details elements
 *  - setProvider updates provider display text
 *  - closeAnalysisSse closes the SSE channel
 *  - Analysis state lifecycle flags
 *  - Analysis navigation prerequisites
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

// ── resetAnalysisState ──────────────────────────────────────────────────────

describe("resetAnalysisState", () => {
  test("resets all analysis flags", () => {
    A.st.analysis.run = true;
    A.st.analysis.done = true;
    A.st.analysis.fail = true;
    A.st.analysis.retryCount = 5;
    A.st.analysis.seq = 10;

    A.resetAnalysisState();

    expect(A.st.analysis.run).toBe(false);
    expect(A.st.analysis.done).toBe(false);
    expect(A.st.analysis.fail).toBe(false);
    expect(A.st.analysis.retryCount).toBe(0);
    expect(A.st.analysis.seq).toBe(-1);
  });

  test("clears analysis order and byKey data", () => {
    A.st.analysis.order = ["evtx", "mft"];
    A.st.analysis.byKey = {
      evtx: { key: "evtx", name: "Event Logs", text: "analysis" },
      mft: { key: "mft", name: "MFT", text: "analysis" },
    };
    A.st.analysis.summary = "Executive summary";
    A.st.analysis.model = { provider: "claude" };

    A.resetAnalysisState();

    expect(A.st.analysis.order).toEqual([]);
    expect(A.st.analysis.byKey).toEqual({});
    expect(A.st.analysis.summary).toBe("");
    expect(A.st.analysis.model).toEqual({});
  });

  test("re-enables run button", () => {
    if (A.el.runBtn) {
      A.el.runBtn.disabled = true;
      A.resetAnalysisState();
      expect(A.el.runBtn.disabled).toBe(false);
    }
  });

  test("hides cancel button", () => {
    if (A.el.cancelAnalysis) {
      A.el.cancelAnalysis.hidden = false;
      A.resetAnalysisState();
      expect(A.el.cancelAnalysis.hidden).toBe(true);
    }
  });
});

// ── renderAnalysis ──────────────────────────────────────────────────────────

describe("renderAnalysis", () => {
  test("renders empty placeholder when no analysis results exist", () => {
    A.st.analysis.order = [];
    A.st.analysis.byKey = {};
    A.renderAnalysis();
    if (A.el.analysisList) {
      expect(A.el.analysisList.textContent).toContain("No analysis output yet");
    }
  });

  test("renders analysis cards for completed artifacts", () => {
    A.st.analysis.order = ["evtx"];
    A.st.analysis.byKey = {
      evtx: { key: "evtx", name: "Event Logs", text: "Found suspicious events.", model: "claude-3", isThinking: false },
    };
    A.renderAnalysis();
    if (A.el.analysisList) {
      const cards = A.el.analysisList.querySelectorAll(".analysis-card");
      expect(cards).toHaveLength(1);
      expect(cards[0].querySelector("h4").textContent).toBe("Event Logs");
    }
  });

  test("renders multiple analysis cards in order", () => {
    A.st.analysis.order = ["evtx", "mft"];
    A.st.analysis.byKey = {
      evtx: { key: "evtx", name: "Event Logs", text: "Events analysis.", model: "", isThinking: false },
      mft: { key: "mft", name: "MFT", text: "MFT analysis.", model: "gpt-4", isThinking: false },
    };
    A.renderAnalysis();
    if (A.el.analysisList) {
      const cards = A.el.analysisList.querySelectorAll(".analysis-card");
      expect(cards).toHaveLength(2);
      expect(cards[0].querySelector("h4").textContent).toBe("Event Logs");
      expect(cards[1].querySelector("h4").textContent).toBe("MFT");
    }
  });

  test("renders thinking placeholder for in-progress analysis", () => {
    A.st.analysis.order = ["evtx"];
    A.st.analysis.byKey = {
      evtx: { key: "evtx", name: "Event Logs", text: "", model: "", isThinking: true, thinkingText: "Model is thinking..." },
    };
    A.renderAnalysis();
    if (A.el.analysisList) {
      expect(A.el.analysisList.textContent).toContain("Model is thinking");
    }
  });

  test("shows model info when available", () => {
    A.st.analysis.order = ["evtx"];
    A.st.analysis.byKey = {
      evtx: { key: "evtx", name: "Event Logs", text: "Result.", model: "claude-3-opus", isThinking: false },
    };
    A.renderAnalysis();
    if (A.el.analysisList) {
      const mono = A.el.analysisList.querySelector(".mono");
      expect(mono.textContent).toContain("claude-3-opus");
    }
  });
});

// ── renderExecSummary ───────────────────────────────────────────────────────

describe("renderExecSummary", () => {
  test("renders summary text as markdown", () => {
    A.st.analysis.summary = "## Summary\n\nKey finding: **malware detected**.";
    A.renderExecSummary();
    if (A.el.summaryOut) {
      expect(A.el.summaryOut.querySelector("h2")).not.toBeNull();
      expect(A.el.summaryOut.querySelector("strong")).not.toBeNull();
    }
  });

  test("renders placeholder when summary is empty", () => {
    A.st.analysis.summary = "";
    A.renderExecSummary();
    if (A.el.summaryOut) {
      expect(A.el.summaryOut.textContent).toContain("Summary is generated after analysis completes");
    }
  });
});

// ── renderFindings ──────────────────────────────────────────────────────────

describe("renderFindings", () => {
  test("renders placeholder when no findings exist", () => {
    A.st.analysis.order = [];
    A.renderFindings();
    if (A.el.findings) {
      expect(A.el.findings.textContent).toContain("Findings will appear here");
    }
  });

  test("renders collapsible details elements for each artifact", () => {
    A.st.analysis.order = ["evtx", "mft"];
    A.st.analysis.byKey = {
      evtx: { key: "evtx", name: "Event Logs", text: "Events finding.", isThinking: false },
      mft: { key: "mft", name: "MFT", text: "MFT finding.", isThinking: false },
    };
    A.renderFindings();
    if (A.el.findings) {
      const details = A.el.findings.querySelectorAll("details");
      expect(details).toHaveLength(2);
      expect(details[0].querySelector("summary").textContent).toBe("Event Logs");
      expect(details[1].querySelector("summary").textContent).toBe("MFT");
    }
  });

  test("first finding is open by default", () => {
    A.st.analysis.order = ["evtx"];
    A.st.analysis.byKey = {
      evtx: { key: "evtx", name: "Event Logs", text: "Finding.", isThinking: false },
    };
    A.renderFindings();
    if (A.el.findings) {
      const details = A.el.findings.querySelector("details");
      expect(details.open).toBe(true);
    }
  });

  test("subsequent findings are closed by default", () => {
    A.st.analysis.order = ["evtx", "mft"];
    A.st.analysis.byKey = {
      evtx: { key: "evtx", name: "Event Logs", text: "Finding 1.", isThinking: false },
      mft: { key: "mft", name: "MFT", text: "Finding 2.", isThinking: false },
    };
    A.renderFindings();
    if (A.el.findings) {
      const details = A.el.findings.querySelectorAll("details");
      expect(details[0].open).toBe(true);
      expect(details[1].open).toBe(false);
    }
  });
});

// ── setProvider ─────────────────────────────────────────────────────────────

describe("setProvider", () => {
  test("sets provider name text", () => {
    A.setProvider("Claude (claude-3-opus)");
    if (A.el.providerName) {
      expect(A.el.providerName.textContent).toBe("Claude (claude-3-opus)");
    }
  });

  test("shows 'Not configured' for empty input", () => {
    A.setProvider("");
    if (A.el.providerName) {
      expect(A.el.providerName.textContent).toBe("Not configured");
    }
  });

  test("shows 'Not configured' for null input", () => {
    A.setProvider(null);
    if (A.el.providerName) {
      expect(A.el.providerName.textContent).toBe("Not configured");
    }
  });
});

// ── closeAnalysisSse ────────────────────────────────────────────────────────

describe("closeAnalysisSse", () => {
  test("closes the analysis SSE channel", () => {
    const mockEs = { close: jest.fn() };
    A.st.analysis.es = mockEs;
    A.st.analysis.retry = setTimeout(() => {}, 10000);

    A.closeAnalysisSse();

    expect(mockEs.close).toHaveBeenCalled();
    expect(A.st.analysis.es).toBeNull();
    expect(A.st.analysis.retry).toBeNull();
  });
});

// ── Analysis navigation prerequisites ───────────────────────────────────────

describe("analysis navigation prerequisites", () => {
  test("step 5 is blocked when analysis not done", () => {
    A.setCaseId("test-case");
    A.st.selected = ["evtx"];
    A.st.selectedAi = ["evtx"];
    A.st.parse.done = true;
    A.st.analysis.done = false;
    A.updateNav();
    expect(A.el.indicators[4].classList.contains("is-disabled")).toBe(true);
  });

  test("step 5 is accessible when analysis is done", () => {
    A.setCaseId("test-case");
    A.st.selected = ["evtx"];
    A.st.selectedAi = ["evtx"];
    A.st.parse.done = true;
    A.st.analysis.done = true;
    A.updateNav();
    expect(A.el.indicators[4].classList.contains("is-disabled")).toBe(false);
  });

  test("step 4 blocked when parse done but no AI artifacts", () => {
    A.setCaseId("test-case");
    A.st.selected = ["evtx"];
    A.st.selectedAi = [];
    A.st.parse.done = true;
    A.updateNav();
    expect(A.el.indicators[3].classList.contains("is-disabled")).toBe(true);
    expect(A.el.indicators[3].title).toContain("Parse and use in AI");
  });
});
