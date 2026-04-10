/**
 * Unit tests for AIFT chat panel and history management (chat.js).
 *
 * Covers:
 *  - resetChatState clears all chat state and UI
 *  - toggleChat opens/closes the chat panel
 *  - closeChatSse closes the SSE channel
 *  - Chat panel visibility and aria attributes
 *  - Chat controls disabled state
 *  - Chat empty state rendering
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

// ── resetChatState ──────────────────────────────────────────────────────────

describe("resetChatState", () => {
  test("resets all chat flags to initial state", () => {
    A.st.chat.run = true;
    A.st.chat.retryCount = 5;
    A.st.chat.seq = 10;
    A.st.chat.pending = { bubble: {}, contentNode: {}, typingNode: {} };
    A.st.chat.historyLoadedCaseId = "old-case";

    A.resetChatState();

    expect(A.st.chat.run).toBe(false);
    expect(A.st.chat.retryCount).toBe(0);
    expect(A.st.chat.seq).toBe(-1);
    expect(A.st.chat.pending).toBeNull();
    expect(A.st.chat.historyLoadedCaseId).toBe("");
  });

  test("resets chat input to enabled and empty", () => {
    if (A.el.chatInput) {
      A.el.chatInput.disabled = true;
      A.el.chatInput.value = "old message";
    }

    A.resetChatState();

    if (A.el.chatInput) {
      expect(A.el.chatInput.disabled).toBe(false);
      expect(A.el.chatInput.value).toBe("");
    }
  });

  test("re-enables chat send button", () => {
    if (A.el.chatSend) {
      A.el.chatSend.disabled = true;
      A.resetChatState();
      expect(A.el.chatSend.disabled).toBe(false);
    }
  });

  test("shows chat panel after reset", () => {
    if (A.el.chatPanel) {
      A.el.chatPanel.hidden = true;
      A.resetChatState();
      // resetChatState opens the chat panel (hidden = false).
      expect(A.el.chatPanel.hidden).toBe(false);
    }
  });

  test("resets chat toggle to open state", () => {
    if (A.el.chatToggle) {
      A.el.chatToggle.textContent = "Show Chat";
      A.el.chatToggle.setAttribute("aria-expanded", "false");

      A.resetChatState();

      // resetChatState sets chat panel to open/visible.
      expect(A.el.chatToggle.textContent).toBe("Hide Chat");
      expect(A.el.chatToggle.getAttribute("aria-expanded")).toBe("true");
    }
  });

  test("renders empty state in chat thread", () => {
    A.resetChatState();
    if (A.el.chatThread) {
      const empty = A.el.chatThread.querySelector("#chat-empty-state");
      expect(empty).not.toBeNull();
      expect(empty.textContent).toContain("Chat history will appear here");
    }
  });
});

// ── toggleChat ──────────────────────────────────────────────────────────────

describe("toggleChat", () => {
  test("opens chat panel when forced open", () => {
    if (!A.el.chatPanel || !A.el.chatToggle) return;
    A.el.chatPanel.hidden = true;
    A.toggleChat(true);
    expect(A.el.chatPanel.hidden).toBe(false);
    expect(A.el.chatToggle.getAttribute("aria-expanded")).toBe("true");
    expect(A.el.chatToggle.textContent).toBe("Hide Chat");
  });

  test("closes chat panel when forced closed", () => {
    if (!A.el.chatPanel || !A.el.chatToggle) return;
    A.el.chatPanel.hidden = false;
    A.toggleChat(false);
    expect(A.el.chatPanel.hidden).toBe(true);
    expect(A.el.chatToggle.getAttribute("aria-expanded")).toBe("false");
    expect(A.el.chatToggle.textContent).toBe("Show Chat");
  });

  test("toggles chat panel when no force argument", () => {
    if (!A.el.chatPanel || !A.el.chatToggle) return;
    A.el.chatPanel.hidden = true;
    A.toggleChat();
    expect(A.el.chatPanel.hidden).toBe(false);

    A.toggleChat();
    expect(A.el.chatPanel.hidden).toBe(true);
  });

  test("does nothing when elements are missing", () => {
    const savedPanel = A.el.chatPanel;
    A.el.chatPanel = null;
    expect(() => A.toggleChat(true)).not.toThrow();
    A.el.chatPanel = savedPanel;
  });
});

// ── closeChatSse ────────────────────────────────────────────────────────────

describe("closeChatSse", () => {
  test("closes the chat SSE channel", () => {
    const mockEs = { close: jest.fn() };
    A.st.chat.es = mockEs;
    A.st.chat.retry = setTimeout(() => {}, 10000);

    A.closeChatSse();

    expect(mockEs.close).toHaveBeenCalled();
    expect(A.st.chat.es).toBeNull();
    expect(A.st.chat.retry).toBeNull();
  });

  test("handles already-closed channel gracefully", () => {
    A.st.chat.es = null;
    A.st.chat.retry = null;
    expect(() => A.closeChatSse()).not.toThrow();
  });
});

// ── Chat panel initial state ────────────────────────────────────────────────

describe("chat panel initial state", () => {
  test("chat panel is visible on initial load", () => {
    if (A.el.chatPanel) {
      // The HTML template renders the chat panel open by default.
      expect(A.el.chatPanel.hidden).toBe(false);
    }
  });

  test("chat toggle shows 'Hide Chat' initially", () => {
    if (A.el.chatToggle) {
      // The HTML template renders with aria-expanded="true" and "Hide Chat".
      expect(A.el.chatToggle.textContent).toBe("Hide Chat");
    }
  });

  test("chat is not running initially", () => {
    expect(A.st.chat.run).toBe(false);
  });

  test("chat input is enabled initially", () => {
    if (A.el.chatInput) {
      expect(A.el.chatInput.disabled).toBe(false);
    }
  });
});

// ── Chat allMessages / displayedCount state ─────────────────────────────────

describe("chat message state", () => {
  test("resetChatState clears allMessages and displayedCount", () => {
    A.st.chat.allMessages = [{ role: "user", content: "hi" }];
    A.st.chat.displayedCount = 1;

    A.resetChatState();

    expect(A.st.chat.allMessages).toEqual([]);
    expect(A.st.chat.displayedCount).toBe(0);
  });
});
