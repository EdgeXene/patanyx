/*
 * Injected into every CONTENT webview via `with_initialization_script`
 * (windows.rs, build_content) -- runs before the page's own scripts, in
 * every document the tab ever navigates to. This is untrusted-page
 * territory: no window.ipc exists here by design (see state.rs's own doc on
 * `evaluate_script` being chrome-only), and this file must never assume
 * anything about the page around it.
 *
 * TOP-LEVEL DOCUMENT ONLY. WebView2 runs an initialization script in every
 * frame, subframes included. A third-party iframe embedded on an unrelated
 * page is not this tab's own login form, and letting it participate in the
 * save/fill flow at all -- for either direction -- is unnecessary surface
 * this feature does not need. Out of scope for v1, not a gap: a legitimate
 * same-site login iframe is uncommon enough that excluding every iframe is
 * the safer default.
 *
 * TWO MESSAGE SHAPES, AND ONLY TWO.
 *   OUT (page -> Rust): {kind:"login_submit", origin, username, password},
 *   posted on a password-form submit, read by the WebMessageReceived handler
 *   windows.rs registers directly on the raw COM object.
 *   IN (Rust -> page): {kind:"fill_credential", username, password}, and
 *   this is the ONLY message this script ever acts on when receiving --
 *   there is no message shape that reads a field's value back out. A page
 *   cannot ask this script "what did the user type"; it can only ever be
 *   TOLD what to fill, after the user has explicitly clicked to fill it
 *   (chrome.js only posts this after an IPC round trip the user initiated).
 */
(function () {
  "use strict";

  if (window.top !== window) return;

  function ownForm(passwordField) {
    return passwordField.form || passwordField.closest("form");
  }

  // On screen and able to receive a value. A zero-area box is either a
  // staged field the page will use later or a decoy, and filling one looks
  // to the user exactly like nothing happening.
  function onScreen(el) {
    var r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  }

  function textLike(el) {
    var type = (el.getAttribute("type") || "text").toLowerCase();
    return (
      type !== "password" &&
      type !== "hidden" &&
      type !== "submit" &&
      type !== "button" &&
      type !== "checkbox" &&
      type !== "radio" &&
      type !== "file" &&
      type !== "image" &&
      type !== "reset"
    );
  }

  // Best-effort: a text-like input within `scope`, PREFERRING one the user
  // can actually see. Good enough for the common case; a page whose username
  // field this misses simply gets offered no username, not a wrong one -- the
  // password field itself is never guessed at, only read from where the user
  // actually typed it.
  //
  // Visible-first matters on real sign-in pages. Google's identifier step
  // carries a second, zero-area text input (`ca`) alongside the one you type
  // into; taking the first in document order is a coin toss between them.
  function usernameField(scope) {
    if (!scope) return null;
    var fields = scope.querySelectorAll("input");
    var offScreen = null;
    for (var i = 0; i < fields.length; i += 1) {
      var el = fields[i];
      if (!textLike(el)) continue;
      if (onScreen(el)) return el;
      if (!offScreen) offScreen = el;
    }
    return offScreen;
  }

  function fireInputEvents(el) {
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  document.addEventListener(
    "submit",
    function (ev) {
      var form = ev.target;
      if (!form || typeof form.querySelector !== "function") return;
      var pwField = form.querySelector('input[type="password"]');
      if (!pwField || !pwField.value) return;
      var userField = usernameField(form);
      try {
        window.chrome.webview.postMessage(
          JSON.stringify({
            kind: "login_submit",
            origin: location.origin,
            username: userField ? userField.value : "",
            password: pwField.value,
          }),
        );
      } catch (e) {
        // No window.chrome.webview (not actually a WebView2 document, or a
        // future engine change) -- fail silently. This is a convenience
        // feature; a page must never behave differently because it failed.
      }
    },
    true,
  );

  try {
    window.chrome.webview.addEventListener("message", function (ev) {
      var msg = ev.data;
      if (!msg || msg.kind !== "fill_credential") return;

      // THE PASSWORD FIELD IS NO LONGER THE GATE, AND THE FORM IS NO LONGER
      // THE SCOPE. Measured on accounts.google.com's identifier step, which
      // is where this feature is most wanted and where it did nothing at all:
      //
      //   * every input on that page has NO <form> -- not a different form,
      //     none. `ownForm` returned null, `usernameField(null)` returned
      //     null on its first line, and the username was never filled.
      //   * the only `input[type=password]` there is Google's own zero-area
      //     staged field, so the password went somewhere invisible.
      //
      // The net effect was a lit button that appeared to do nothing. Both
      // halves are fixed here: the scope falls back to the whole document
      // when there is genuinely no form, and a missing password field no
      // longer aborts the username fill.
      //
      // Not fixed by guessing: `.value = x` plus an input event was checked
      // against that same live page and the value sticks, so no native-setter
      // workaround is warranted. It is not added on suspicion.
      var pwFields = document.querySelectorAll('input[type="password"]');
      var pwField = null;
      for (var i = 0; i < pwFields.length; i += 1) {
        if (onScreen(pwFields[i])) {
          pwField = pwFields[i];
          break;
        }
      }
      // No visible one: a two-step flow's staged field is still the right
      // place for the password, and filling it is what it exists for.
      if (!pwField && pwFields.length) pwField = pwFields[0];

      // Form scope stays PREFERRED. Widening to the document only when the
      // page has no form at all keeps an ordinary login page from having its
      // username typed into some unrelated search box elsewhere on the page.
      var form = pwField ? ownForm(pwField) : null;
      var userField =
        usernameField(form) || (form ? null : usernameField(document));

      if (userField && typeof msg.username === "string") {
        userField.value = msg.username;
        fireInputEvents(userField);
      }
      if (pwField && typeof msg.password === "string") {
        pwField.value = msg.password;
        fireInputEvents(pwField);
      }
    });
  } catch (e) {
    // Same reasoning as the submit handler's own try/catch above.
  }
})();
