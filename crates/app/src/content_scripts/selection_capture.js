// A private script world, installed at document start in every frame.
// One parked request per frame; no timer, clipboard, privileged IPC or eval.
(() => {
  "use strict";
  const token = "__SELECTION_DOCUMENT_TOKEN__";
  const channels = window.webkit.messageHandlers;
  const limit = 512 * 1024;

  // A child document can leave without a top-level load event. This signal
  // carries no page data and revokes any native menu tied to that view.
  window.addEventListener("pagehide", event => {
    if (event.isTrusted) channels.selectionReply.postMessage(token + " end");
  }, true);

  function selectedText() {
    if (!document.hasFocus()) return null;
    const field = document.activeElement;
    // Only the focused leaf frame answers. Parent documents can retain an
    // old selection while a child owns the actual native menu invocation.
    if (field && /^(IFRAME|FRAME)$/.test(field.tagName)) return null;
    let text;
    if (field && /^(INPUT|TEXTAREA)$/.test(field.tagName)) {
      if (field.type === "password") return "";
      if (typeof field.selectionStart !== "number" || typeof field.selectionEnd !== "number") return "";
      text = field.value.slice(field.selectionStart, field.selectionEnd);
    } else {
      const selection = window.getSelection();
      text = selection ? selection.toString() : "";
    }
    // Check code units before allocating the bounded UTF-8 buffer.
    if (text.length > limit || new TextEncoder().encode(text).length > limit) return "";
    return text;
  }

  async function waitForMenu() {
    try {
      const request = await channels.selectionAsk.postMessage(token);
      if (typeof request !== "string" || !/^[a-f0-9]{32}$/.test(request)) return;
      let text;
      try { text = selectedText(); } catch (_) { text = ""; }
      if (text !== null) channels.selectionReply.postMessage(token + " " + request + " " + text);
      waitForMenu();
    } catch (_) { /* navigation or unavailable channel: no cached selection */ }
  }
  waitForMenu();
})();
