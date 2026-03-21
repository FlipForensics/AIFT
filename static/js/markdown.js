/**
 * Markdown-to-DOM rendering for AIFT.
 *
 * Converts a subset of Markdown (headings, lists, tables, code fences,
 * inline bold/italic/code, and confidence tokens) into a DocumentFragment.
 *
 * Depends on: AIFT (utils.js)
 */
"use strict";

(() => {
  const A = window.AIFT;

  /**
   * Render a Markdown string into a DOM container, replacing its contents.
   *
   * @param {HTMLElement|null} container - Target DOM element.
   * @param {string} text - Markdown source text.
   * @param {string} emptyText - Placeholder shown when text is blank.
   */
  function renderMarkdownInto(container, text, emptyText) {
    if (!container) return;
    container.innerHTML = "";
    const raw = String(text || "");
    if (!raw.trim()) {
      const p = document.createElement("p");
      p.textContent = emptyText;
      container.appendChild(p);
      return;
    }
    container.appendChild(markdownToFragment(raw));
  }

  /**
   * Convert a Markdown string into a DocumentFragment.
   *
   * Supports headings, ordered/unordered lists, fenced code blocks,
   * tables, and inline formatting (bold, italic, code, confidence tokens).
   *
   * @param {string} text - Markdown source text.
   * @returns {DocumentFragment} Fragment ready for insertion into the DOM.
   */
  function markdownToFragment(text) {
    const fragment = document.createDocumentFragment();
    const lines = String(text || "").replace(/\r\n?/g, "\n").split("\n");
    let paragraphLines = [];
    let listNode = null;
    let listType = "";
    let inCodeFence = false;
    let codeFenceLines = [];

    /** Flush and append the current list node to the fragment. */
    const closeList = () => {
      if (!listNode) return;
      fragment.appendChild(listNode);
      listNode = null;
      listType = "";
    };

    /** Flush accumulated paragraph lines into a <p> element. */
    const flushParagraph = () => {
      if (!paragraphLines.length) return;
      const p = document.createElement("p");
      const html = renderInlineMarkdown(paragraphLines.join("\n")).replace(/\n/g, "<br>");
      p.innerHTML = html;
      fragment.appendChild(p);
      paragraphLines = [];
    };

    /** Flush accumulated code-fence lines into a <pre><code> block. */
    const flushCodeFence = () => {
      const pre = document.createElement("pre");
      const code = document.createElement("code");
      code.textContent = codeFenceLines.join("\n");
      pre.appendChild(code);
      fragment.appendChild(pre);
      codeFenceLines = [];
    };

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const trimmed = String(line || "").trim();

      if (inCodeFence) {
        if (trimmed.startsWith("```")) {
          inCodeFence = false;
          flushCodeFence();
          continue;
        }
        codeFenceLines.push(line);
        continue;
      }

      if (trimmed.startsWith("```")) {
        flushParagraph();
        closeList();
        inCodeFence = true;
        codeFenceLines = [];
        continue;
      }

      if (!trimmed) {
        flushParagraph();
        closeList();
        continue;
      }

      const headerCells = splitMarkdownTableRow(line);
      if (headerCells && index + 1 < lines.length) {
        const separatorCells = splitMarkdownTableRow(lines[index + 1]);
        if (
          separatorCells
          && headerCells.length === separatorCells.length
          && isMarkdownTableSeparatorRow(separatorCells)
        ) {
          flushParagraph();
          closeList();

          const expectedColumns = headerCells.length;
          const normalizedHeader = normalizeMarkdownTableCells(headerCells, expectedColumns);

          const table = document.createElement("table");
          const thead = document.createElement("thead");
          const headerRow = document.createElement("tr");
          normalizedHeader.forEach((cell) => {
            const th = document.createElement("th");
            th.innerHTML = renderInlineMarkdown(cell);
            headerRow.appendChild(th);
          });
          thead.appendChild(headerRow);
          table.appendChild(thead);

          const tbody = document.createElement("tbody");
          let hasBodyRows = false;
          index += 2;
          while (index < lines.length) {
            const bodyLine = lines[index];
            const bodyTrimmed = String(bodyLine || "").trim();
            if (!bodyTrimmed) break;

            const parsedBodyCells = splitMarkdownTableRow(bodyLine);
            if (!parsedBodyCells) break;

            const normalizedBody = normalizeMarkdownTableCells(parsedBodyCells, expectedColumns);
            const tr = document.createElement("tr");
            normalizedBody.forEach((cell) => {
              const td = document.createElement("td");
              td.innerHTML = renderInlineMarkdown(cell);
              tr.appendChild(td);
            });
            tbody.appendChild(tr);
            hasBodyRows = true;
            index += 1;
          }

          if (hasBodyRows) table.appendChild(tbody);
          fragment.appendChild(table);
          index -= 1;
          continue;
        }
      }

      const heading = trimmed.match(/^(#{1,6})\s+(.*)$/);
      if (heading) {
        flushParagraph();
        closeList();
        const level = heading[1].length;
        const content = heading[2] || "";
        const h = document.createElement(`h${level}`);
        h.innerHTML = renderInlineMarkdown(content);
        fragment.appendChild(h);
        continue;
      }

      const ordered = trimmed.match(/^\d+\.\s+(.*)$/);
      if (ordered) {
        flushParagraph();
        if (listType !== "ol") {
          closeList();
          listNode = document.createElement("ol");
          listType = "ol";
        }
        const li = document.createElement("li");
        li.innerHTML = renderInlineMarkdown(ordered[1] || "");
        listNode.appendChild(li);
        continue;
      }

      const unordered = trimmed.match(/^[-*]\s+(.*)$/);
      if (unordered) {
        flushParagraph();
        if (listType !== "ul") {
          closeList();
          listNode = document.createElement("ul");
          listType = "ul";
        }
        const li = document.createElement("li");
        li.innerHTML = renderInlineMarkdown(unordered[1] || "");
        listNode.appendChild(li);
        continue;
      }

      closeList();
      paragraphLines.push(trimmed);
    }

    if (inCodeFence) flushCodeFence();
    flushParagraph();
    closeList();
    return fragment;
  }

  /**
   * Split a Markdown table row into trimmed cell strings.
   *
   * @param {string} line - A single line of text.
   * @returns {string[]|null} Array of cell values, or null if not a table row.
   */
  function splitMarkdownTableRow(line) {
    const raw = String(line || "");
    if (!raw.includes("|")) return null;
    let trimmed = raw.trim();
    if (!trimmed || !trimmed.includes("|")) return null;
    if (trimmed.startsWith("|")) trimmed = trimmed.slice(1);
    if (trimmed.endsWith("|")) trimmed = trimmed.slice(0, -1);
    return trimmed.split("|").map((cell) => cell.trim());
  }

  /**
   * Check whether an array of cells forms a valid Markdown table separator
   * row (e.g. `| --- | :---: |`).
   *
   * @param {string[]} cells - Cell values from splitMarkdownTableRow.
   * @returns {boolean}
   */
  function isMarkdownTableSeparatorRow(cells) {
    if (!Array.isArray(cells) || !cells.length) return false;
    return cells.every((cell) => /^:?-{3,}:?$/.test(String(cell || "").trim()));
  }

  /**
   * Pad or trim an array of table cells to exactly `expectedCount` entries.
   *
   * @param {string[]} cells - Raw cells array.
   * @param {number} expectedCount - Target column count.
   * @returns {string[]} Normalised array of trimmed cell strings.
   */
  function normalizeMarkdownTableCells(cells, expectedCount) {
    const normalized = Array.isArray(cells)
      ? cells.slice(0, expectedCount).map((cell) => String(cell || "").trim())
      : [];
    while (normalized.length < expectedCount) normalized.push("");
    return normalized;
  }

  /**
   * Render inline Markdown (bold, italic, code, confidence tokens) to HTML.
   *
   * Code spans are extracted first so their content is not processed for
   * bold/italic, then the remaining text is HTML-escaped and formatted.
   *
   * @param {string} text - Inline Markdown source.
   * @returns {string} HTML string with inline formatting applied.
   */
  function renderInlineMarkdown(text) {
    const source = String(text || "");
    if (!source) return "";
    const parts = source.split(/(`[^`\n]*`)/g);
    return parts
      .map((part) => {
        if (part.startsWith("`") && part.endsWith("`")) {
          return `<code>${A.escapeHtml(part.slice(1, -1))}</code>`;
        }
        let out = A.escapeHtml(part);
        out = out.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
        out = out.replace(/__(.+?)__/g, "<strong>$1</strong>");
        out = out.replace(/\*(.+?)\*/g, "<em>$1</em>");
        out = out.replace(/_(.+?)_/g, "<em>$1</em>");
        out = highlightConfidenceTokens(out);
        return out;
      })
      .join("");
  }

  /**
   * Wrap confidence-level tokens (CRITICAL, HIGH, MEDIUM, LOW) in coloured
   * `<span>` badges using CONFIDENCE_CLASS_MAP.
   *
   * @param {string} text - HTML string (already escaped).
   * @returns {string} HTML with confidence tokens highlighted.
   */
  function highlightConfidenceTokens(text) {
    A.CONFIDENCE_TOKEN_PATTERN.lastIndex = 0;
    return String(text || "").replace(A.CONFIDENCE_TOKEN_PATTERN, (match, token) => {
      const normalized = String(token || match || "").toUpperCase();
      const cssClass = A.CONFIDENCE_CLASS_MAP[normalized] || "confidence-unknown";
      return `<span class="confidence-inline ${cssClass}">${normalized}</span>`;
    });
  }

  // ── Public API ─────────────────────────────────────────────────────────────
  A.renderMarkdownInto = renderMarkdownInto;
})();
