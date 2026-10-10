// YouTube video ads, removed from the page's own data before the player reads it.
//
// Registered at document start in every frame while the "Block YouTube video
// ads" switch is on. It acts only on YouTube's own hosts (checked first, below;
// WebView2 has no per-site registration) and does three things there:
//
//   1. ytInitialPlayerResponse / ytInitialData, the data the page embeds, are
//      cleaned as the page assigns them.
//   2. Replies from YouTube's own data endpoints (/youtubei/v1/player, next,
//      browse, search, ...) are cleaned before the page reads them, over both
//      fetch and XMLHttpRequest.
//   3. A style sheet hides any ad element that still arrives another way.
//
// "Cleaned" means: the player's ad keys are deleted wherever they appear, and
// list entries that ARE an ad (an ad slot, a promoted search result, a grid
// cell holding one) are dropped from their list. Nothing else changes.
//
// FAIL OPEN. Any shape this does not expect, any exception, any non-JSON reply:
// the original is passed through untouched. An ad that plays is a better
// outcome than a video that does not.
//
// No global is added, nothing here names the browser, and every built-in it
// relies on is captured before page script can replace it.
(() => {
  "use strict";
  const HOSTS = new Set([
    "www.youtube.com",
    "youtube.com",
    "m.youtube.com",
    "music.youtube.com",
    "www.youtube-nocookie.com",
    "youtube-nocookie.com",
  ]);
  let host;
  try {
    host = location.hostname;
  } catch (_) {
    return;
  }
  if (!HOSTS.has(host)) return;

  // ---- captured built-ins ----
  const defineProperty = Object.defineProperty;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const hasOwn = Object.prototype.hasOwnProperty;
  const isArray = Array.isArray;
  const isFrozen = Object.isFrozen;
  const isSealed = Object.isSealed;
  const deleteProperty = Reflect.deleteProperty;
  const jsonParse = JSON.parse;
  const jsonStringify = JSON.stringify;
  const call = Function.prototype.call;
  const Win = window;
  const nativeFetch = typeof Win.fetch === "function" ? Win.fetch : null;
  const NativeResponse =
    typeof Win.Response === "function" ? Win.Response : null;
  const responseClone = NativeResponse ? NativeResponse.prototype.clone : null;
  const responseText = NativeResponse ? NativeResponse.prototype.text : null;
  const NativeHeaders = typeof Win.Headers === "function" ? Win.Headers : null;
  const headersDelete = NativeHeaders ? NativeHeaders.prototype.delete : null;
  const XHR = Win.XMLHttpRequest;
  const xhrOpen = XHR && XHR.prototype.open;
  const xhrResponseText =
    XHR && getOwnPropertyDescriptor(XHR.prototype, "responseText");
  const xhrResponse =
    XHR && getOwnPropertyDescriptor(XHR.prototype, "response");
  const xhrResponseType =
    XHR && getOwnPropertyDescriptor(XHR.prototype, "responseType");
  const xhrReadyState =
    XHR && getOwnPropertyDescriptor(XHR.prototype, "readyState");
  const URLCtor = Win.URL;
  const createElement = Document.prototype.createElement;
  const appendChild = Node.prototype.appendChild;

  // ---- what an ad looks like in YouTube's data ----

  // Keys that only ever hold ads: the player's ad schedule, its ad renderers,
  // the heartbeat that times ad breaks, and the feed's ad bookkeeping.
  const AD_KEYS = [
    "adPlacements",
    "playerAds",
    "adSlots",
    "adBreakHeartbeatParams",
  ];
  // A list entry whose only renderer is one of these IS an ad.
  const AD_ENTRIES = new Set([
    "adSlotRenderer",
    "searchPyvRenderer",
    "promotedSparklesWebRenderer",
    "promotedVideoRenderer",
    "compactPromotedVideoRenderer",
    "bannerPromoRenderer",
    "adsControlFlowOpportunityReceivedCommand",
  ]);
  // Grid and section wrappers that hold exactly one item: drop the wrapper
  // when its item is an ad, or the page keeps an empty cell where it was.
  const WRAPPERS = ["richItemRenderer", "richSectionRenderer"];

  const MAX_NODES = 2000000;

  // Bookkeeping that rides beside a renderer and says nothing about what it is.
  const TRACKING = new Set(["clickTrackingParams", "trackingParams"]);

  // The single renderer key of an entry, or null. Tracking keys beside it do
  // not count: a feed command arrives as { clickTrackingParams, <command> }.
  function onlyKey(o) {
    let found = null;
    for (const k in o) {
      if (!hasOwn.call(o, k) || TRACKING.has(k)) continue;
      if (found !== null) return null;
      found = k;
    }
    return found;
  }

  function isAdEntry(item) {
    if (!item || typeof item !== "object" || isArray(item)) return false;
    const k = onlyKey(item);
    if (k === null) return false;
    if (AD_ENTRIES.has(k)) return true;
    if (WRAPPERS.indexOf(k) !== -1) {
      const inner = item[k];
      const content = inner && typeof inner === "object" ? inner.content : null;
      return !!content && typeof content === "object" && isAdEntry(content);
    }
    return false;
  }

  // Cleans `root` in place and returns how many things it removed; 0 means
  // the caller can pass the original through.
  //
  // TWO PHASES, so a failure changes nothing. The first walk only READS and
  // writes down every removal; anything unexpected there (a getter that
  // throws, a key that cannot be deleted, a frozen list, a structure too
  // large) throws before a single byte of the page's data has moved. Only a
  // complete plan is applied.
  function clean(root) {
    const deletions = []; // [object, key]
    const rebuilds = []; // [array, kept items]
    let visited = 0;
    const stack = [root];
    while (stack.length) {
      const node = stack.pop();
      if (++visited > MAX_NODES) throw new Error("too large");
      if (isArray(node)) {
        const kept = [];
        for (let i = 0; i < node.length; i++) {
          const item = node[i];
          if (isAdEntry(item)) continue;
          kept.push(item);
          if (item && typeof item === "object") stack.push(item);
        }
        if (kept.length !== node.length) {
          if (isFrozen(node) || isSealed(node)) throw new Error("fixed list");
          rebuilds.push([node, kept]);
        }
      } else if (node && typeof node === "object") {
        const skip = new Set();
        for (let i = 0; i < AD_KEYS.length; i++) {
          const key = AD_KEYS[i];
          if (!hasOwn.call(node, key)) continue;
          const d = getOwnPropertyDescriptor(node, key);
          if (!d || !d.configurable) throw new Error("fixed key");
          deletions.push([node, key]);
          skip.add(key);
        }
        for (const k in node) {
          if (!hasOwn.call(node, k) || skip.has(k)) continue;
          const v = node[k];
          if (v && typeof v === "object") stack.push(v);
        }
      }
    }
    for (let i = 0; i < deletions.length; i++) {
      deleteProperty(deletions[i][0], deletions[i][1]);
    }
    let removed = deletions.length;
    for (let i = 0; i < rebuilds.length; i++) {
      const [list, kept] = rebuilds[i];
      removed += list.length - kept.length;
      for (let j = 0; j < kept.length; j++) list[j] = kept[j];
      list.length = kept.length;
    }
    return removed;
  }

  // Cleans a JSON text; returns the cleaned text, or null to mean "unchanged,
  // use the original".
  function cleanText(text) {
    if (typeof text !== "string" || text.length < 2) return null;
    let data;
    try {
      data = jsonParse(text);
    } catch (_) {
      return null;
    }
    if (!data || typeof data !== "object") return null;
    try {
      return clean(data) > 0 ? jsonStringify(data) : null;
    } catch (_) {
      return null;
    }
  }

  // Only YouTube's own data endpoints, on this same host.
  const ENDPOINT =
    /^\/youtubei\/v1\/(?:player|next|browse|search|reel\/reel_item_watch|reel\/reel_watch_sequence|get_watch|guide)(?:$|[/?])/;
  function isDataEndpoint(raw) {
    try {
      const u = new URLCtor(String(raw), location.href);
      return HOSTS.has(u.hostname) && ENDPOINT.test(u.pathname);
    } catch (_) {
      return false;
    }
  }

  // ---- 1. data the page embeds ----
  function trap(name) {
    let value;
    let had = false;
    try {
      const existing = getOwnPropertyDescriptor(Win, name);
      if (existing) {
        if (!existing.configurable) return;
        if ("value" in existing) {
          value = existing.value;
          had = true;
        }
      }
      defineProperty(Win, name, {
        configurable: true,
        enumerable: true,
        get() {
          return value;
        },
        set(next) {
          if (next && typeof next === "object") {
            try {
              clean(next);
            } catch (_) {
              // fail open: keep what the page assigned
            }
          }
          value = next;
        },
      });
      if (had && value && typeof value === "object") {
        try {
          clean(value);
        } catch (_) {}
      }
    } catch (_) {
      // a property we cannot trap is left to the page
    }
  }
  trap("ytInitialPlayerResponse");
  trap("ytInitialData");

  // ---- 2a. fetch ----
  if (nativeFetch && NativeResponse && responseClone && responseText) {
    // The original's headers minus the two that describe ITS body bytes: the
    // cleaned body is shorter and already decoded.
    const bodyFreeHeaders = (headers) => {
      if (!NativeHeaders || !headersDelete) return headers;
      const copy = new NativeHeaders(headers);
      call.call(headersDelete, copy, "content-length");
      call.call(headersDelete, copy, "content-encoding");
      return copy;
    };
    // A constructed Response has an empty url and type "default"; the page
    // may read either, so they say what the original said -- on every clone
    // too, since a native clone would not carry these own properties.
    const disguise = (replacement, original) => {
      for (const key of ["url", "redirected", "type"]) {
        try {
          const v = original[key];
          defineProperty(replacement, key, { configurable: true, get: () => v });
        } catch (_) {}
      }
      try {
        defineProperty(replacement, "clone", {
          configurable: true,
          writable: true,
          value: function clone() {
            return disguise(call.call(responseClone, replacement), original);
          },
        });
      } catch (_) {}
      return replacement;
    };
    const cleanResponse = async (original) => {
      try {
        if (!original || original.bodyUsed || original.status === 204)
          return original;
        const text = await call.call(
          responseText,
          call.call(responseClone, original),
        );
        const cleaned = cleanText(text);
        if (cleaned === null) return original;
        return disguise(new NativeResponse(cleaned, {
          status: original.status,
          statusText: original.statusText,
          headers: bodyFreeHeaders(original.headers),
        }), original);
      } catch (_) {
        return original;
      }
    };
    const wrapped = function fetch(input, init) {
      let target;
      try {
        target =
          input && typeof input === "object" && "url" in input
            ? input.url
            : input;
      } catch (_) {
        target = "";
      }
      const pending = call.call(nativeFetch, Win, input, init);
      if (!isDataEndpoint(target)) return pending;
      return pending.then(cleanResponse);
    };
    try {
      defineProperty(wrapped, "name", { value: "fetch", configurable: true });
      defineProperty(wrapped, "length", { value: nativeFetch.length, configurable: true });
      defineProperty(Win, "fetch", {
        configurable: true,
        enumerable: true,
        writable: true,
        value: wrapped,
      });
    } catch (_) {}
  }

  // ---- 2b. XMLHttpRequest ----
  if (
    XHR &&
    xhrOpen &&
    xhrResponseText &&
    xhrResponseText.get &&
    xhrResponse &&
    xhrResponse.get
  ) {
    const tracked = new WeakMap(); // xhr -> { done: cleaned text or null }
    const readyStateOf = (xhr) => call.call(xhrReadyState.get, xhr);
    const typeOf = (xhr) =>
      xhrResponseType ? call.call(xhrResponseType.get, xhr) : "";
    const isTextType = (t) => t === "" || t === "text";
    // Text replies: the cleaned text, computed once per request; undefined
    // means "use the native value".
    const cleanedText = (xhr) => {
      const entry = tracked.get(xhr);
      if (!entry || readyStateOf(xhr) !== 4) return undefined;
      if (entry.text === undefined) {
        let cleaned = null;
        try {
          cleaned = cleanText(call.call(xhrResponseText.get, xhr));
        } catch (_) {}
        entry.text = cleaned;
      }
      return entry.text === null ? undefined : entry.text;
    };
    // JSON replies: the engine's own parsed object, cleaned in place once.
    // Same object on every read, as natively; clean() changes nothing unless
    // its whole plan succeeds.
    const cleanedJson = (xhr) => {
      const value = call.call(xhrResponse.get, xhr);
      const entry = tracked.get(xhr);
      if (entry && !entry.json && readyStateOf(xhr) === 4 && value && typeof value === "object") {
        entry.json = true;
        try {
          clean(value);
        } catch (_) {}
      }
      return value;
    };
    const openDescriptor = getOwnPropertyDescriptor(XHR.prototype, "open");
    try {
      defineProperty(XHR.prototype, "open", {
        configurable: true,
        enumerable: !!(openDescriptor && openDescriptor.enumerable),
        writable: true,
        value: function open(method, url) {
          try {
            if (isDataEndpoint(url)) tracked.set(this, {});
            else tracked.delete(this);
          } catch (_) {}
          return call.apply(xhrOpen, [this, ...arguments]);
        },
      });
      defineProperty(XHR.prototype, "responseText", {
        configurable: true,
        enumerable: !!xhrResponseText.enumerable,
        get: function responseText() {
          // Any other type goes to the native getter, which throws as the
          // standard says it must.
          if (isTextType(typeOf(this))) {
            const cleaned = cleanedText(this);
            if (cleaned !== undefined) return cleaned;
          }
          return call.call(xhrResponseText.get, this);
        },
      });
      defineProperty(XHR.prototype, "response", {
        configurable: true,
        enumerable: !!xhrResponse.enumerable,
        get: function response() {
          const t = typeOf(this);
          if (isTextType(t)) {
            const cleaned = cleanedText(this);
            if (cleaned !== undefined) return cleaned;
            return call.call(xhrResponse.get, this);
          }
          if (t === "json") return cleanedJson(this);
          return call.call(xhrResponse.get, this);
        },
      });
    } catch (_) {}
  }

  // ---- 3. anything that still arrives another way ----
  // The selectors are YouTube's own element names and ids, read from its
  // pages (2026-10-10); they are not taken from any filter list.
  const CSS =
    [
      "ytd-ad-slot-renderer",
      "ytd-in-feed-ad-layout-renderer",
      "ytd-search-pyv-renderer",
      "ytd-promoted-sparkles-web-renderer",
      "ytd-promoted-video-renderer",
      "ytd-compact-promoted-video-renderer",
      "ytd-banner-promo-renderer",
      "ytd-rich-item-renderer:has(> #content > ytd-ad-slot-renderer)",
      'ytd-engagement-panel-section-list-renderer[target-id="engagement-panel-ads"]',
      "#player-ads",
      "#masthead-ad",
      "ytm-promoted-sparkles-web-renderer",
      "ad-slot-renderer",
    ].join(",") + "{display:none!important}";
  const addStyle = () => {
    try {
      const root = document.documentElement;
      if (!root) return false;
      const style = call.call(createElement, document, "style");
      style.textContent = CSS;
      call.call(appendChild, root, style);
      return true;
    } catch (_) {
      return true;
    }
  };
  if (!addStyle()) {
    try {
      document.addEventListener("readystatechange", function once() {
        if (addStyle()) document.removeEventListener("readystatechange", once);
      });
    } catch (_) {}
  }
})();
