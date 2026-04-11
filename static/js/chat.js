/**
 * Chat panel, SSE streaming, and history management for AIFT.
 *
 * Handles the follow-up chat feature on the results step: sending
 * messages, streaming responses via SSE, rendering chat bubbles,
 * loading/clearing history, and the typing indicator.
 *
 * Depends on: AIFT (utils.js, markdown.js)
 */
"use strict";

(() => {
  const A = window.AIFT;
  const { st, el } = A;

  /** Number of messages to render per page (initial load + each "load more"). */
  const CHAT_PAGE_SIZE = 50;

  // ── Results step wiring ────────────────────────────────────────────────────

  /** Wire up results-step event listeners: downloads, new-analysis, chat UI. */
  function setupResults() {
    if (el.downloadReport) el.downloadReport.addEventListener("click", async () => downloadCaseFile("report"));
    if (el.downloadCsvs) el.downloadCsvs.addEventListener("click", async () => downloadCaseFile("csvs"));
    if (el.newAnalysis) el.newAnalysis.addEventListener("click", () => {
      A.resetCaseUi();
      A.showStep(1);
    });
    if (el.chatToggle) el.chatToggle.addEventListener("click", () => toggleChat());
    if (el.chatForm) {
      el.chatForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        await sendChatMessage();
      });
    }
    if (el.chatInput) {
      el.chatInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter" && !e.shiftKey) {
          e.preventDefault();
          if (el.chatForm) el.chatForm.requestSubmit();
        }
      });
    }
    if (el.chatClear) {
      el.chatClear.addEventListener("click", async () => { await clearChat(); });
    }
    syncChatControls();
  }

  // ── Downloads ──────────────────────────────────────────────────────────────

  /**
   * Download a case artifact (report HTML or parsed CSVs zip).
   *
   * @param {string} kind - "report" or "csvs".
   */
  async function downloadCaseFile(kind) {
    A.clearMsg(el.resultsMsg);
    const caseId = A.activeCaseId();
    if (!caseId) return A.setMsg(el.resultsMsg, "No active case to download from.", "error");
    const endpoint = kind === "report"
      ? `/api/cases/${encodeURIComponent(caseId)}/report`
      : `/api/cases/${encodeURIComponent(caseId)}/csvs`;
    const fallback = kind === "report" ? `${caseId}_report.html` : `${caseId}_parsed_csvs.zip`;
    try {
      const r = await A.fetchWithTimeout(endpoint, { method: "GET" }, A.FETCH_TIMEOUT_UPLOAD_MS);
      if (!r.ok) throw new Error((await A.readErr(r)) || `Download failed (${r.status}).`);
      const blob = await r.blob();
      const filename = A.getFilename(r.headers) || fallback;
      triggerDownload(blob, filename);
      A.setMsg(el.resultsMsg, `Download started: ${filename}`, "success");
    } catch (e) {
      A.setMsg(el.resultsMsg, `Download failed: ${A.handleFetchError(e, endpoint)}`, "error");
    }
  }

  /** Create a temporary anchor to trigger a browser download for the given blob. */
  function triggerDownload(blob, name) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 5000);
  }

  // ── Chat toggle & controls ─────────────────────────────────────────────────

  /**
   * Toggle the chat panel open/closed, optionally forcing a specific state.
   *
   * @param {boolean|null} [forceOpen=null] - True to open, false to close, null to toggle.
   */
  function toggleChat(forceOpen = null) {
    if (!el.chatPanel || !el.chatToggle) return;
    const open = typeof forceOpen === "boolean" ? forceOpen : !!el.chatPanel.hidden;
    el.chatPanel.hidden = !open;
    el.chatToggle.setAttribute("aria-expanded", open ? "true" : "false");
    el.chatToggle.textContent = open ? "Hide Chat" : "Show Chat";
    if (!open) return;
    if (!st.chat.run && st.chat.historyLoadedCaseId !== A.activeCaseId()) {
      loadChatHistory().catch((e) => A.setMsg(el.resultsMsg, `Unable to load chat history: ${e.message}`, "error"));
    }
    scrollChatToBottom();
    if (el.chatInput && !el.chatInput.disabled) el.chatInput.focus();
  }

  /** Update disabled state of chat input, send button, and clear button. */
  function syncChatControls() {
    const busy = !!st.chat.run;
    if (el.chatInput) el.chatInput.disabled = busy;
    if (el.chatSend) el.chatSend.disabled = busy;
    if (el.chatClear) el.chatClear.disabled = busy || !hasChatMessages();
  }

  /** Return true if the chat thread contains at least one message row. */
  function hasChatMessages() {
    return !!(el.chatThread && el.chatThread.querySelector(".chat-message-row"));
  }

  /** Scroll the chat thread container to the bottom. */
  function scrollChatToBottom() {
    if (!el.chatThread) return;
    el.chatThread.scrollTop = el.chatThread.scrollHeight;
  }

  /** Normalise a role value to "user", "assistant", or empty string. */
  function strRole(value) {
    const role = String(value || "").trim().toLowerCase();
    if (role === "assistant" || role === "user") return role;
    return "";
  }

  // ── Chat history ───────────────────────────────────────────────────────────

  /** Fetch and render chat history for the active case (no-op if already loaded). */
  async function loadChatHistory() {
    const caseId = A.activeCaseId();
    if (!caseId || !el.chatThread || st.chat.run) return;
    if (st.chat.historyLoadedCaseId === caseId) return;
    const history = await A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/chat/history`, { method: "GET" });
    // Discard stale history if the case changed or a send started while we were fetching.
    if (caseId !== A.activeCaseId() || st.chat.run) return;
    const messages = Array.isArray(history) ? history : (Array.isArray(history?.messages) ? history.messages : []);
    renderChatHistory(messages);
    st.chat.historyLoadedCaseId = caseId;
  }

  /**
   * Render a full chat history array, paginating to show the last page first.
   *
   * @param {Object[]} history - Array of {role, content, metadata} message objects.
   */
  function renderChatHistory(history) {
    if (!el.chatThread) return;
    el.chatThread.innerHTML = "";
    const messages = Array.isArray(history)
      ? history.filter((entry) => {
        const role = strRole(entry && entry.role);
        const content = String(entry && entry.content || "").trim();
        return (role === "user" || role === "assistant") && !!content;
      })
      : [];
    // Store full history for pagination; track how many are displayed.
    st.chat.allMessages = messages;
    st.chat.displayedCount = 0;
    if (!messages.length) {
      renderChatEmptyState();
      syncChatControls();
      return;
    }
    // Render only the last page initially.
    const startIndex = Math.max(0, messages.length - CHAT_PAGE_SIZE);
    renderMessagesSlice(startIndex, messages.length);
    if (startIndex > 0) insertLoadEarlierButton();
    scrollChatToBottom();
    syncChatControls();
  }

  /**
   * Render a slice of st.chat.allMessages into the chat thread.
   *
   * Messages are inserted *before* any existing chat-message rows so that
   * earlier messages appear above later ones when paging backwards.
   *
   * Args:
   *   from: Start index (inclusive) in allMessages.
   *   to:   End index (exclusive) in allMessages.
   */
  function renderMessagesSlice(from, to) {
    if (!el.chatThread) return;
    const messages = st.chat.allMessages;
    if (!messages || !messages.length) return;
    // Find the first existing chat-message row to insert before (for "load earlier").
    const firstRow = el.chatThread.querySelector(".chat-message-row");
    const frag = firstRow ? document.createDocumentFragment() : null;
    for (let i = from; i < to; i++) {
      const entry = messages[i];
      const role = strRole(entry.role);
      const content = String(entry.content || "");
      let retrieved = [];
      if (role === "assistant" && A.isObj(entry.metadata) && Array.isArray(entry.metadata.data_retrieved)) {
        retrieved = entry.metadata.data_retrieved.map((item) => String(item || "").trim()).filter(Boolean);
      }
      const nodes = buildChatMessageNodes(role, content, { dataRetrieved: retrieved });
      if (frag) {
        frag.appendChild(nodes.row);
      } else {
        el.chatThread.appendChild(nodes.row);
      }
    }
    if (frag) {
      el.chatThread.insertBefore(frag, firstRow);
    }
    st.chat.displayedCount = (st.chat.displayedCount || 0) + (to - from);
  }

  /**
   * Insert the "Load earlier messages" button at the top of the chat thread.
   */
  function insertLoadEarlierButton() {
    if (!el.chatThread || el.chatThread.querySelector(".chat-load-earlier")) return;
    const btn = document.createElement("button");
    btn.className = "chat-load-earlier";
    btn.type = "button";
    btn.textContent = "Load earlier messages";
    btn.addEventListener("click", () => loadEarlierMessages());
    el.chatThread.insertBefore(btn, el.chatThread.firstChild);
  }

  /**
   * Remove the "Load earlier messages" button from the chat thread.
   */
  function removeLoadEarlierButton() {
    if (!el.chatThread) return;
    const btn = el.chatThread.querySelector(".chat-load-earlier");
    if (btn) btn.remove();
  }

  /**
   * Load the next page of earlier messages into the chat thread.
   */
  function loadEarlierMessages() {
    const messages = st.chat.allMessages;
    if (!messages || !messages.length) return;
    const displayed = st.chat.displayedCount || 0;
    const totalAvailable = messages.length;
    if (displayed >= totalAvailable) return;
    // Calculate the slice to prepend.
    const currentStart = totalAvailable - displayed;
    const newStart = Math.max(0, currentStart - CHAT_PAGE_SIZE);
    // Remember scroll position so we can preserve the user's view.
    const prevScrollHeight = el.chatThread.scrollHeight;
    removeLoadEarlierButton();
    renderMessagesSlice(newStart, currentStart);
    if (newStart > 0) insertLoadEarlierButton();
    // Restore scroll position so the view doesn't jump.
    const addedHeight = el.chatThread.scrollHeight - prevScrollHeight;
    el.chatThread.scrollTop += addedHeight;
  }

  /** Replace the chat thread contents with a "no messages" placeholder. */
  function renderChatEmptyState() {
    if (!el.chatThread) return;
    el.chatThread.innerHTML = "";
    const empty = document.createElement("p");
    empty.id = "chat-empty-state";
    empty.textContent = "Chat history will appear here.";
    el.chatThread.appendChild(empty);
  }

  /** Remove the empty-state placeholder from the chat thread if present. */
  function removeChatEmptyState() {
    if (!el.chatThread) return;
    const empty = el.chatThread.querySelector("#chat-empty-state");
    if (empty) empty.remove();
  }

  // ── Chat message rendering ─────────────────────────────────────────────────

  /**
   * Build chat message DOM nodes without inserting them into the thread.
   *
   * Returns:
   *   Object with row, bubble, contentNode, typingNode properties.
   */
  function buildChatMessageNodes(role, content, opts = {}) {
    const normalizedRole = strRole(role);

    const row = document.createElement("div");
    row.className = `chat-message-row ${normalizedRole === "user" ? "chat-message-user" : "chat-message-ai"}`;

    const bubble = document.createElement("article");
    bubble.className = `chat-bubble ${normalizedRole === "user" ? "chat-bubble-user" : "chat-bubble-ai"}`;

    const contentNode = document.createElement("div");
    contentNode.className = "chat-message-content markdown-output";
    renderChatMessageText(contentNode, content);
    bubble.appendChild(contentNode);

    let typingNode = null;
    if (opts.typing) {
      bubble.classList.add("is-streaming");
      typingNode = createTypingIndicator();
      bubble.appendChild(typingNode);
    }

    const retrievedArtifacts = Array.isArray(opts.dataRetrieved)
      ? opts.dataRetrieved.map((item) => String(item || "").trim()).filter(Boolean)
      : [];
    if (retrievedArtifacts.length) {
      appendDataRetrievedIndicator(bubble, retrievedArtifacts);
    }

    row.appendChild(bubble);
    return { row, bubble, contentNode, typingNode };
  }

  /**
   * Append a chat message to the thread and scroll to bottom.
   *
   * @param {string} role - "user" or "assistant".
   * @param {string} content - Message text (Markdown).
   * @param {Object} [opts] - Options (typing indicator, data retrieved).
   * @returns {Object|null} The created DOM node references, or null.
   */
  function appendChatMessage(role, content, opts = {}) {
    if (!el.chatThread) return null;
    removeChatEmptyState();
    const nodes = buildChatMessageNodes(role, content, opts);
    el.chatThread.appendChild(nodes.row);
    scrollChatToBottom();
    syncChatControls();
    return nodes;
  }

  /** Render Markdown chat message text into a container element. */
  function renderChatMessageText(container, text) {
    if (!container) return;
    const value = String(text || "");
    if (!value.trim()) { container.innerHTML = ""; return; }
    A.renderMarkdownInto(container, value, "");
  }

  /** Create an animated typing indicator (three bouncing dots). */
  function createTypingIndicator() {
    const indicator = document.createElement("div");
    indicator.className = "chat-typing-indicator";
    indicator.setAttribute("aria-label", "AI is streaming a response");
    indicator.setAttribute("aria-live", "polite");
    for (let index = 0; index < 3; index += 1) {
      const dot = document.createElement("span");
      dot.className = "chat-typing-dot";
      dot.style.animationDelay = `${index * 0.15}s`;
      indicator.appendChild(dot);
    }
    return indicator;
  }

  /**
   * Append or update a "Referenced: ..." indicator below a chat bubble.
   *
   * @param {HTMLElement} target - The chat bubble element.
   * @param {string[]} artifacts - List of artifact names referenced.
   */
  function appendDataRetrievedIndicator(target, artifacts) {
    if (!target) return;
    const clean = Array.isArray(artifacts)
      ? artifacts.map((item) => String(item || "").trim()).filter(Boolean)
      : [];
    if (!clean.length) return;
    let indicator = target.querySelector(".chat-data-retrieved");
    if (!indicator) {
      indicator = document.createElement("p");
      indicator.className = "chat-data-retrieved";
      target.appendChild(indicator);
    }
    indicator.textContent = `📎 Referenced: ${clean.join(", ")}`;
  }

  // ── Send message & SSE ─────────────────────────────────────────────────────

  /** Validate, send the user's chat message, and open the response SSE stream. */
  async function sendChatMessage() {
    A.clearMsg(el.resultsMsg);
    const caseId = A.activeCaseId();
    if (!caseId) return A.setMsg(el.resultsMsg, "No active case for chat.", "error");
    if (st.chat.run) return A.setMsg(el.resultsMsg, "Wait for the current chat response to finish.", "error");
    st.chat.run = true;
    const message = A.val(el.chatInput);
    if (!message) { st.chat.run = false; return; }

    toggleChat(true);
    appendChatMessage("user", message);
    if (el.chatInput) el.chatInput.value = "";

    const pendingMessage = appendChatMessage("assistant", "", { typing: true });
    st.chat.pending = pendingMessage
      ? { bubble: pendingMessage.bubble, contentNode: pendingMessage.contentNode, typingNode: pendingMessage.typingNode, text: "" }
      : null;
    st.chat.seq = -1;
    st.chat.retryCount = 0;
    syncChatControls();

    try {
      await A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/chat`, { method: "POST", json: { message } });
      startChatSse(caseId);
    } catch (e) {
      finalizeChatError(`Failed to send chat message: ${e.message}`);
    }
  }

  /**
   * Open the chat response SSE stream for the given case.
   *
   * @param {string} caseId - Active case identifier.
   */
  function startChatSse(caseId) {
    A.openSseStream(
      `/api/cases/${encodeURIComponent(caseId)}/chat/stream`,
      st.chat,
      {
        onEvent: (payload) => onChatEvent(caseId, payload),
        onError: () => {
          if (st.chat.run) retryChatSse(caseId);
        },
      },
    );
  }

  /** Dispatch a single chat SSE event (token, done, error) to the UI. */
  function onChatEvent(caseId, payload) {
    if (caseId !== A.activeCaseId()) { finalizePendingChatMessage(); finalizeChatStream(); return; }
    const type = String(payload.type || "");
    if (type === "token") {
      const pending = ensurePendingChatMessage();
      pending.text += String(payload.content || "");
      renderChatMessageText(pending.contentNode, pending.text);
      scrollChatToBottom();
      return;
    }
    if (type === "done") {
      const pending = ensurePendingChatMessage();
      if (!String(pending.text || "").trim()) {
        renderChatMessageText(pending.contentNode, "No response text was returned.");
      }
      if (Array.isArray(payload.data_retrieved)) {
        const files = payload.data_retrieved.map((item) => String(item || "").trim()).filter(Boolean);
        appendDataRetrievedIndicator(pending.bubble, files);
      }
      finalizePendingChatMessage();
      finalizeChatStream();
      // Mark history as loaded so chat-panel toggles don't re-fetch
      // and overwrite the just-streamed messages.
      st.chat.historyLoadedCaseId = A.activeCaseId();
      return;
    }
    if (type === "error") {
      finalizeChatError(String(payload.message || "Chat stream failed."));
      return;
    }
  }

  /** Ensure a pending assistant chat bubble exists (create one if needed). */
  function ensurePendingChatMessage() {
    if (st.chat.pending && st.chat.pending.contentNode) return st.chat.pending;
    const created = appendChatMessage("assistant", "", { typing: true });
    st.chat.pending = created
      ? { bubble: created.bubble, contentNode: created.contentNode, typingNode: created.typingNode, text: "" }
      : { bubble: null, contentNode: null, typingNode: null, text: "" };
    return st.chat.pending;
  }

  /** Remove the typing indicator from the pending bubble and clear pending state. */
  function finalizePendingChatMessage() {
    if (!st.chat.pending) return;
    if (st.chat.pending.typingNode && st.chat.pending.typingNode.parentNode) {
      st.chat.pending.typingNode.parentNode.removeChild(st.chat.pending.typingNode);
    }
    if (st.chat.pending.bubble) st.chat.pending.bubble.classList.remove("is-streaming");
    st.chat.pending = null;
    syncChatControls();
  }

  // ── SSE retry / close ──────────────────────────────────────────────────────

  /**
   * Attempt to reconnect the chat SSE stream with exponential backoff.
   *
   * @param {string} caseId - Active case identifier.
   */
  function retryChatSse(caseId) {
    if (!st.chat.run) return;
    A.retrySseStream(st.chat, {
      reconnect: () => {
        if (st.chat.run) startChatSse(caseId);
      },
      onMaxRetries: () => {
        finalizeChatError(`Chat connection lost after ${A.SSE_MAX_RETRIES} retries.`);
      },
    });
  }

  /** Display an error in the pending chat bubble and finalise the stream. */
  function finalizeChatError(message) {
    const pending = ensurePendingChatMessage();
    const current = String(pending.text || "").trim();
    const rendered = current ? `${current}\n\n${message}` : message;
    renderChatMessageText(pending.contentNode, rendered);
    finalizePendingChatMessage();
    finalizeChatStream();
    A.setMsg(el.resultsMsg, message, "error");
  }

  /** Close the chat SSE EventSource and clear pending retries. */
  function closeChatSse() {
    A.closeSseChannel(st.chat);
  }

  /** Close SSE, mark chat as idle, and refresh controls. */
  function finalizeChatStream() {
    closeChatSse();
    st.chat.run = false;
    st.chat.retryCount = 0;
    st.chat.seq = -1;
    syncChatControls();
  }

  /** Reset all chat state, close SSE, clear UI, and restore the empty state. */
  function resetChatState() {
    closeChatSse();
    st.chat.run = false;
    st.chat.retryCount = 0;
    st.chat.seq = -1;
    st.chat.pending = null;
    st.chat.historyLoadedCaseId = "";
    st.chat.allMessages = [];
    st.chat.displayedCount = 0;
    if (el.chatInput) { el.chatInput.disabled = false; el.chatInput.value = ""; }
    if (el.chatSend) el.chatSend.disabled = false;
    if (el.chatPanel) el.chatPanel.hidden = true;
    if (el.chatToggle) {
      el.chatToggle.setAttribute("aria-expanded", "false");
      el.chatToggle.textContent = "Show Chat";
    }
    renderChatEmptyState();
    syncChatControls();
  }

  /** Confirm and delete chat history for the active case on the backend. */
  async function clearChat() {
    const caseId = A.activeCaseId();
    if (!caseId) return A.setMsg(el.resultsMsg, "No active case for chat.", "error");
    if (st.chat.run) return A.setMsg(el.resultsMsg, "Wait for the current chat response to finish.", "error");
    if (!hasChatMessages()) return;
    const confirmed = window.confirm("Clear chat history for this case?");
    if (!confirmed) return;
    A.clearMsg(el.resultsMsg);
    try {
      await A.apiJson(`/api/cases/${encodeURIComponent(caseId)}/chat/history`, { method: "DELETE" });
      renderChatEmptyState();
      st.chat.historyLoadedCaseId = caseId;
      A.setMsg(el.resultsMsg, "Chat history cleared.", "success");
      syncChatControls();
    } catch (e) {
      A.setMsg(el.resultsMsg, `Failed to clear chat history: ${e.message}`, "error");
    }
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  A.setupResults = setupResults;
  A.closeChatSse = closeChatSse;
  A.resetChatState = resetChatState;
  A.loadChatHistory = loadChatHistory;
  A.toggleChat = toggleChat;
})();
