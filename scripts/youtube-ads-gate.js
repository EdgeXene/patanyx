// What youtube_ads.js does to YouTube's data, exercised end to end.
//
// WHY THIS EXISTS. The script edits replies the page asked for, in the page's
// own world. The two ways it can hurt someone are removing something that is
// not an ad, and breaking a reply it should have left alone. So this gate runs
// the REAL script in fresh vm realms (Node's own Response, a stub
// XMLHttpRequest) and asserts:
//
//   player    the four player ad keys go, wherever they sit; nothing else moves
//   lists     an entry that IS an ad (ad slot, promoted search result, a grid
//             cell holding one, a feed command carrying tracking beside it)
//             is dropped; ordinary entries keep their content and order
//   embedded  ytInitialPlayerResponse / ytInitialData are cleaned as assigned,
//             including a value the page set before the script ran
//   fetch     only YouTube's own data endpoints are touched; status, headers,
//             url, redirected, type survive; a reply with no ads, a non-JSON
//             reply and a failed fetch are passed through as the SAME object
//   xhr       responseText and json responses are cleaned once complete, and
//             only for data endpoints
//   hosts     on any other host nothing is installed at all
//   shape     no new globals; fetch keeps its name and length; the source
//             never names the browser
//
// Planted defects (PATANYX_YT_PLANT): each must make this gate fail, which the
// wrapper in chrome-js-gate.sh checks.
//
// NOT covered here, honestly: YouTube's live pages. Those are measured with
// the real browser (ads-notes P0 runs); this gate pins the behaviour so a
// change to the script cannot quietly undo it.
"use strict";
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const SRC_PATH = path.join(
  __dirname,
  "..",
  "crates/app/src/content_scripts/youtube_ads.js",
);
let SRC = fs.readFileSync(SRC_PATH, "utf8");

const PLANTS = {
  // Ads stay in the player data.
  "no-player-keys": ['"adPlacements",', ""],
  // The host check is gone: every site gets the hooks.
  "no-host-gate": ["if (!HOSTS.has(host)) return;", ""],
  // Every list entry with one key is treated as an ad.
  "greedy-lists": ["if (AD_ENTRIES.has(k)) return true;", "return true;"],
  // A reply with no ads is rebuilt instead of passed through.
  "rebuild-always": [
    "return clean(data) > 0 ? jsonStringify(data) : null;",
    "clean(data); return jsonStringify(data);",
  ],
  // The fetch wrapper drops the original's url.
  "lose-url": [
    'for (const key of ["url", "redirected", "type"])',
    "for (const key of [])",
  ],
  // A clone of a cleaned reply forgets its url again.
  "plain-clone": ['defineProperty(replacement, "clone", {', 'defineProperty(replacement, "notclone", {'],
  // Cleaning mutates as it walks (no plan first).
  "no-plan": ["deletions.push([node, key]);", "deleteProperty(node, key); deletions.push([node, key]);"],
  // JSON XHR replies re-parsed on each read.
  "reparse-json": ["if (t === \"json\") return cleanedJson(this);", "if (t === \"json\") return JSON.parse(JSON.stringify(cleanedJson(this)));"],
  // Body-length header kept on the rebuilt reply.
  "keep-length": ['call.call(headersDelete, copy, "content-length");', ""],
};
if (process.env.PATANYX_YT_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}
const plant = process.env.PATANYX_YT_PLANT;
if (plant) {
  const p = PLANTS[plant];
  if (!p || !SRC.includes(p[0])) {
    console.error(
      `plant ${plant}: anchor not found; the gate cannot prove anything`,
    );
    process.exit(2);
  }
  SRC = SRC.replace(p[0], p[1]);
}

// ---- a fresh realm per check ----
function realm(host, { preset } = {}) {
  const calls = [];
  class XMLHttpRequest {
    constructor() {
      this._state = 0;
      this._type = "";
      this._text = "";
    }
    open(method, url) {
      this._url = url;
      this._state = 1;
    }
    _finish(text) {
      this._text = text;
      this._state = 4;
    }
  }
  const proto = XMLHttpRequest.prototype;
  Object.defineProperty(proto, "readyState", {
    configurable: true,
    get() {
      return this._state;
    },
  });
  Object.defineProperty(proto, "responseType", {
    configurable: true,
    get() {
      return this._type;
    },
    set(v) {
      this._type = v;
    },
  });
  // As the standard says: responseText throws for any type but "" / "text",
  // and a json response is parsed ONCE and the same object returned after.
  Object.defineProperty(proto, "responseText", {
    configurable: true,
    enumerable: false,
    get() {
      if (this._type !== "" && this._type !== "text") {
        throw new Error("InvalidStateError");
      }
      return this._text;
    },
  });
  Object.defineProperty(proto, "response", {
    configurable: true,
    enumerable: false,
    get() {
      if (this._type !== "json") return this._text;
      if (this._state !== 4) return null;
      if (!("_parsed" in this)) this._parsed = JSON.parse(this._text);
      return this._parsed;
    },
  });
  const win = {
    location: { hostname: host, href: `https://${host}/watch?v=x` },
    URL,
    Response,
    Headers,
    XMLHttpRequest,
    __reply: null,
    __fail: false,
    fetch(input, init) {
      calls.push({ input, init });
      if (win.__fail) return Promise.reject(new TypeError("network"));
      const r = win.__reply;
      return Promise.resolve(typeof r === "function" ? r(input) : r);
    },
  };
  win.window = win;
  win.Document = function Document() {};
  win.Document.prototype.createElement = () => ({ textContent: "" });
  win.Node = function Node() {};
  win.Node.prototype.appendChild = function (child) {
    win.__styles = (win.__styles || 0) + 1;
    return child;
  };
  win.document = {
    documentElement: {},
    addEventListener() {},
    removeEventListener() {},
  };
  if (preset) Object.assign(win, preset);
  vm.createContext(win);
  const before = new Set(Object.getOwnPropertyNames(win));
  vm.runInContext(SRC, win);
  win.__added = Object.getOwnPropertyNames(win).filter((k) => !before.has(k));
  win.__calls = calls;
  return win;
}

const reply = (body, init = {}) => {
  const r = new Response(
    typeof body === "string" ? body : JSON.stringify(body),
    {
      status: 200,
      statusText: "OK",
      headers: {
        "content-type": "application/json; charset=UTF-8",
        "x-test": "kept",
      },
      ...init,
    },
  );
  Object.defineProperty(r, "url", {
    value: "https://www.youtube.com/youtubei/v1/player?prettyPrint=false",
  });
  return r;
};

// ---- fixtures: the shapes measured on live YouTube (P0, 2026-10-10) ----
const PLAYER = () => ({
  playabilityStatus: { status: "OK" },
  streamingData: { adaptiveFormats: [{ itag: 248 }] },
  videoDetails: { videoId: "v1", title: "A video" },
  adPlacements: [
    { adPlacementRenderer: { renderer: { adBreakServiceRenderer: {} } } },
  ],
  playerAds: [{ playerLegacyDesktopWatchAdsRenderer: {} }],
  adSlots: [{ adSlotRenderer: { fulfillmentContent: {} } }],
  adBreakHeartbeatParams: "Q0FB",
  playerConfig: { audioConfig: { loudnessDb: -3 } },
});
const VIDEO = (id) => ({
  videoRenderer: { videoId: id, title: { runs: [{ text: id }] } },
});
const DATA = () => ({
  contents: {
    twoColumnBrowseResultsRenderer: {
      tabs: [
        {
          tabRenderer: {
            content: {
              richGridRenderer: {
                contents: [
                  { richItemRenderer: { content: VIDEO("a") } },
                  {
                    richItemRenderer: {
                      content: { adSlotRenderer: { slotId: "s1" } },
                    },
                  },
                  { richItemRenderer: { content: VIDEO("b") } },
                  {
                    richSectionRenderer: {
                      content: { richShelfRenderer: { title: "Shorts" } },
                    },
                  },
                ],
              },
            },
          },
        },
      ],
    },
    twoColumnSearchResultsRenderer: {
      primaryContents: {
        sectionListRenderer: {
          contents: [
            {
              itemSectionRenderer: {
                contents: [
                  { searchPyvRenderer: { ads: [{ adSlotRenderer: {} }] } },
                  VIDEO("c"),
                  { adSlotRenderer: { slotId: "s2" } },
                  VIDEO("d"),
                  // Two real renderers: not a single ad entry, must stay.
                  { videoRenderer: { videoId: "e" }, adSlotRenderer: {} },
                ],
              },
            },
          ],
        },
      },
    },
  },
  onResponseReceivedActions: [
    {
      clickTrackingParams: "CA",
      adsControlFlowOpportunityReceivedCommand: { opportunityType: "x" },
    },
    {
      clickTrackingParams: "CB",
      appendContinuationItemsAction: { continuationItems: [VIDEO("f")] },
    },
  ],
});
const videoIds = (o) => JSON.stringify(o).match(/"videoId":"[^"]+"/g) || [];

// ---- checks ----
const checks = [];
const check = (name, fn) => checks.push([name, fn]);
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

check("player: the four ad keys go and nothing else changes", () => {
  const w = realm("www.youtube.com");
  w.ytInitialPlayerResponse = PLAYER();
  const got = w.ytInitialPlayerResponse;
  for (const k of [
    "adPlacements",
    "playerAds",
    "adSlots",
    "adBreakHeartbeatParams",
  ]) {
    assert(!(k in got), `${k} survived`);
  }
  const want = PLAYER();
  for (const k of [
    "adPlacements",
    "playerAds",
    "adSlots",
    "adBreakHeartbeatParams",
  ])
    delete want[k];
  assert(
    JSON.stringify(got) === JSON.stringify(want),
    `other fields changed: ${JSON.stringify(got)}`,
  );
});

check(
  "player keys are removed wherever they sit (get_watch nests the player)",
  () => {
    const w = realm("www.youtube.com");
    w.ytInitialData = [
      { playerResponse: PLAYER() },
      { response: { contents: {} } },
    ];
    const s = JSON.stringify(w.ytInitialData);
    assert(!/adPlacements|playerAds|adSlots|adBreakHeartbeat/.test(s), s);
    assert(/"videoId":"v1"/.test(s), "the video went with the ads");
  },
);

check(
  "lists: ad entries go, ordinary entries keep their content and order",
  () => {
    const w = realm("www.youtube.com");
    w.ytInitialData = DATA();
    const d = w.ytInitialData;
    const grid =
      d.contents.twoColumnBrowseResultsRenderer.tabs[0].tabRenderer.content
        .richGridRenderer.contents;
    assert(
      grid.length === 3,
      `grid has ${grid.length} cells, want 3 (ad cell dropped)`,
    );
    assert(grid[2].richSectionRenderer, "a non-ad section wrapper was dropped");
    const section =
      d.contents.twoColumnSearchResultsRenderer.primaryContents
        .sectionListRenderer.contents[0].itemSectionRenderer.contents;
    assert(
      JSON.stringify(section.map((e) => Object.keys(e).join("+"))) ===
        JSON.stringify([
          "videoRenderer",
          "videoRenderer",
          "videoRenderer+adSlotRenderer",
        ]),
      `search results: ${JSON.stringify(section.map((e) => Object.keys(e)))}`,
    );
    assert(
      d.onResponseReceivedActions.length === 1,
      "the feed's ad command survived",
    );
    assert(
      JSON.stringify(videoIds(d)) ===
        JSON.stringify([
          '"videoId":"a"',
          '"videoId":"b"',
          '"videoId":"c"',
          '"videoId":"d"',
          '"videoId":"e"',
          '"videoId":"f"',
        ]),
      `videos changed: ${videoIds(d)}`,
    );
  },
);

check(
  "embedded: a value the page set before the script ran is cleaned too",
  () => {
    const w = realm("www.youtube.com", {
      preset: { ytInitialPlayerResponse: PLAYER() },
    });
    assert(
      !("adPlacements" in w.ytInitialPlayerResponse),
      "pre-set value kept its ads",
    );
  },
);

check(
  "embedded: a value that throws while being read is kept as assigned (fail open)",
  () => {
    const w = realm("www.youtube.com");
    const odd = {};
    Object.defineProperty(odd, "boom", {
      enumerable: true,
      get() {
        throw new Error("x");
      },
    });
    w.ytInitialData = odd;
    assert(w.ytInitialData === odd, "the page's own value was replaced");
  },
);

check(
  "fetch: a data endpoint is cleaned and the reply keeps its metadata",
  async () => {
    const w = realm("www.youtube.com");
    w.__reply = reply(PLAYER(), { status: 200, statusText: "OK" });
    const r = await w.fetch("/youtubei/v1/player?prettyPrint=false", {
      method: "POST",
    });
    const again = r.clone();
    const body = await r.json();
    assert(
      !("adPlacements" in body) && body.videoDetails.videoId === "v1",
      JSON.stringify(body),
    );
    assert(
      r.status === 200 && r.statusText === "OK",
      `status ${r.status} ${r.statusText}`,
    );
    assert(r.headers.get("x-test") === "kept", "headers were dropped");
    assert(
      r.url === "https://www.youtube.com/youtubei/v1/player?prettyPrint=false",
      `url ${r.url}`,
    );
    assert(
      r.redirected === false && typeof r.type === "string",
      "redirected/type not carried",
    );
    assert(
      (await again.text()).length > 0,
      "clone of the cleaned reply has no body",
    );
    assert(
      w.__calls[0].init.method === "POST",
      "the request was not passed through as made",
    );
  },
);

check(
  "fetch: a Request object for a data endpoint is cleaned too",
  async () => {
    const w = realm("www.youtube.com");
    w.__reply = reply(PLAYER());
    const r = await w.fetch(
      new Request("https://www.youtube.com/youtubei/v1/next"),
    );
    assert(
      !("playerAds" in (await r.json())),
      "Request input was not recognised",
    );
  },
);

check("fetch: anything else is the SAME reply object, untouched", async () => {
  const w = realm("www.youtube.com");
  for (const [url, body] of [
    ["/youtubei/v1/log_event", PLAYER()], // not a data endpoint
    ["https://www.example.com/youtubei/v1/player", PLAYER()], // another host
    ["/youtubei/v1/player", "not json {"], // not JSON
    ["/youtubei/v1/player", { videoDetails: { videoId: "z" } }], // no ads
  ]) {
    const original = reply(body);
    w.__reply = original;
    const r = await w.fetch(url);
    assert(r === original, `${url}: the reply was replaced`);
    assert(!r.bodyUsed, `${url}: the original body was consumed`);
  }
});

check("fetch: a failed request still fails the same way", async () => {
  const w = realm("www.youtube.com");
  w.__fail = true;
  let err = null;
  try {
    await w.fetch("/youtubei/v1/player");
  } catch (e) {
    err = e;
  }
  assert(err && err.name === "TypeError", `got ${err}`);
});

check(
  "xhr: text and json replies are cleaned once complete, for data endpoints only",
  () => {
    const w = realm("www.youtube.com");
    const x = new w.XMLHttpRequest();
    x.open("POST", "/youtubei/v1/player");
    assert(x.responseText === "", "an unfinished request was given a body");
    x._finish(JSON.stringify(PLAYER()));
    assert(!/adPlacements/.test(x.responseText), "responseText kept the ads");
    const j = new w.XMLHttpRequest();
    j.open("POST", "/youtubei/v1/next");
    j.responseType = "json";
    j._finish(JSON.stringify(PLAYER()));
    assert(
      j.response &&
        !("adSlots" in j.response) &&
        j.response.videoDetails.videoId === "v1",
      "json kept the ads",
    );
    const other = new w.XMLHttpRequest();
    other.open("GET", "/api/stats/qoe");
    other._finish(JSON.stringify(PLAYER()));
    assert(
      /adPlacements/.test(other.responseText),
      "a non-data endpoint was edited",
    );
  },
);

check("fetch: a clone of a cleaned reply keeps the original's url", async () => {
  const w = realm("www.youtube.com");
  w.__reply = reply(PLAYER());
  const r = await w.fetch("/youtubei/v1/player");
  const c = r.clone();
  assert(c.url === "https://www.youtube.com/youtubei/v1/player?prettyPrint=false", `clone url ${c.url}`);
  assert(!("adPlacements" in (await c.json())), "the clone carries the ads");
});

check("fetch: headers that describe the original body are not carried over", async () => {
  const w = realm("www.youtube.com");
  w.__reply = reply(PLAYER(), {
    headers: { "content-type": "application/json", "content-length": "99999", "content-encoding": "gzip", "x-test": "kept" },
  });
  const r = await w.fetch("/youtubei/v1/player");
  assert(r.headers.get("content-length") === null, "content-length kept");
  assert(r.headers.get("content-encoding") === null, "content-encoding kept");
  assert(r.headers.get("x-test") === "kept", "other headers dropped");
});

check("xhr json: the same object on every read, cleaned in place; responseText still throws", () => {
  const w = realm("www.youtube.com");
  const x = new w.XMLHttpRequest();
  x.open("POST", "/youtubei/v1/player");
  x.responseType = "json";
  x._finish(JSON.stringify(PLAYER()));
  const a = x.response;
  const b = x.response;
  assert(a === b, "a json response must be the same object on every read");
  assert(!("adPlacements" in a) && a.videoDetails.videoId === "v1", "json kept the ads");
  let threw = false;
  try {
    void x.responseText;
  } catch (_) {
    threw = true;
  }
  assert(threw, "responseText must throw for a json request, as natively");
});

check("fail open: an unexpected value leaves the data exactly as it was", () => {
  const w = realm("www.youtube.com");
  const odd = { adPlacements: [1], videoDetails: { videoId: "v1" } };
  Object.defineProperty(odd, "later", { enumerable: true, get() { throw new Error("x"); } });
  w.ytInitialPlayerResponse = odd;
  assert("adPlacements" in odd, "a partial clean happened before the failure");
  const frozen = { contents: Object.freeze([{ adSlotRenderer: {} }, VIDEO("a")]), adSlots: [] };
  w.ytInitialData = frozen;
  assert("adSlots" in frozen && frozen.contents.length === 2, "a frozen list caused a partial clean");
});

check("hosts: on any other site nothing is installed", () => {
  for (const host of [
    "www.example.com",
    "youtube.com.evil.example",
    "notyoutube.com",
    "studio.youtube.com",
  ]) {
    const w = realm(host);
    const p = PLAYER();
    w.ytInitialPlayerResponse = p;
    assert(
      w.ytInitialPlayerResponse === p && "adPlacements" in p,
      `${host}: data was edited`,
    );
    assert(!w.__styles, `${host}: a style sheet was added`);
    assert(
      Object.getOwnPropertyDescriptor(w, "ytInitialPlayerResponse").writable ===
        true,
      `${host}: a trap was installed`,
    );
  }
});

check(
  "shape: no new globals, fetch keeps its name and length, a style is added",
  () => {
    const w = realm("www.youtube.com");
    // `__`-names are this harness's own counters, not the script's.
    const extra = w.__added.filter(
      (k) =>
        !k.startsWith("__") &&
        !["ytInitialPlayerResponse", "ytInitialData"].includes(k),
    );
    assert(extra.length === 0, `new globals: ${extra}`);
    assert(w.fetch.name === "fetch", `fetch.name ${w.fetch.name}`);
  // The stub fetch takes (input, init): the wrapper must report the same.
  assert(w.fetch.length === 2, `fetch.length ${w.fetch.length}, native is 2`);
  for (const key of ["open", "responseText", "response"]) {
    const d = Object.getOwnPropertyDescriptor(w.XMLHttpRequest.prototype, key);
    assert(d && d.enumerable === false, `${key} became enumerable`);
  }
    assert(w.__styles === 1, "the fallback style sheet was not added");
  },
);

check("source never names the browser", () => {
  assert(
    !/patanyx/i.test(fs.readFileSync(SRC_PATH, "utf8")),
    "the script names the product",
  );
});

(async () => {
  const failures = [];
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + "\n      " + e.message);
      console.log("  FAIL " + name);
    }
  }
  if (failures.length) {
    console.error("\nYOUTUBE ADS GATE FAILED:\n");
    for (const f of failures) console.error("  - " + f + "\n");
    process.exit(1);
  }
  console.log("\nYOUTUBE ADS SCRIPT OK");
})();
