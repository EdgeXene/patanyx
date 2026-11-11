// The feature videos: the video panel, its way back from About, and the
// retired one-time banner (chrome.js "feature videos", tutorial.rs).
//
// THE BANNER IS RETIRED IN 1.1.0 (deferred from 1.0.9 and 1.0.10). The
// "New in 1.0.5" and "New in 1.0.7" announcements never show, on any
// platform, whatever Rust's seen and keep_seen markers say: not at boot,
// not after the first-run tour, not after an update check, not after a
// language refill. The element, its strings and its BANNERS entry stay as
// dead markup for this release. The videos stay in About, and the Kept
// Sites topic still follows keep_video.
//
// WHAT IT PINS, each against a planted defect (chrome-js-gate.sh runs them):
//   - the banner is still in BANNERS, so a revival renders inside the
//     clipped strip (the lock-warning defect)                    [banners]
//   - its markup starts hidden                              [markup-shown]
//   - About always lists Reader View, Tab Groups and Side by Side
//                                                     [markup-topic-hidden]
//   - the old banner code, put back whole, is caught    [revive-old-banner]
//   - so is a banner raised for an unanswered 1.0.5 marker   [revive-seen]
//   - or, on Windows, for an unanswered 1.0.7 marker         [revive-keep]
//   - or when the first-run tour closes                [revive-after-tour]
//   - or by an update check, in any update state        [revive-on-update]
//   - or by a language refill                           [revive-on-refill]
//   - the Kept Sites topic only where its video is     [keep-button-linux]
//   - and always there on Windows                     [keep-button-windows]
//   - also after a Windows first run's tour              [keep-after-tour]
//   - a video reply for a topic already left is not shown          [stale]
//   - one request per topic while it is in flight                  [dedup]
//   - a failure for a topic already left stays out of sight    [abandoned]
//   - the error line stays with the video that failed       [sticky-error]
//   - a video that loads clears its own error                    [recover]
//   - a media error is blamed on the video playing          [attribution]
//   - switching to a video still loading resets the player         [reset]
//   - the player's controls are in the panel's focus cycle         [focus]
//   - closing the panel pauses the video                           [pause]
//
// Boots, each its own process because the markers are read once per boot
// (CASE): main (Linux, tour seen, neither marker answered), tour (Linux
// first run), seen (answered), requests; on Windows keep (the 1.0.5 marker
// answered, the 1.0.7 one not: the old upgrade path), keep-fresh, keep-seen
// and keep-tour. Then the retirement matrix, BOTH markers unset:
// retire-<linux|windows>-<none|offered|ready|dismissed|applied>, each
// followed by a language refill and every video played from About.
//
// "applied" is not a state the chrome ever receives. An applied update is
// a new process on the new version, so it is modeled as a fresh boot whose
// first check reports uptodate. Playback itself is not modeled (the DOM stub
// has no media engine): a video counts as playing when the panel asked Rust
// for it by name and its src is that reply's video/webm blob.
//
// Run: node scripts/tutorial-gate.js   (or via scripts/chrome-js-gate.sh)
const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const CASE = process.env.PATANYX_TUTORIAL_CASE || "main";
const PLANT = process.env.PATANYX_TUTORIAL_PLANT || "";

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

// The stub starts EVERY element hidden, whatever the markup says, so what the
// markup shows at load is read from the source here instead.
let htmlSrc = fs.readFileSync(process.env.HTML_PATH, "utf8");
let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
function plantIn(src, from, to) {
  if (src.split(from).length !== 2) {
    console.error("PLANT TARGET MISSING OR NOT UNIQUE: " + from);
    process.exit(2);
  }
  return src.replace(from, to);
}
function plant(from, to) {
  chromeJs = plantIn(chromeJs, from, to);
}
function plantHtml(from, to) {
  htmlSrc = plantIn(htmlSrc, from, to);
}
const KEEP_LINE = '        $("tutorial-topic-keep").hidden = !keepVideo;\n';
const TOUR_CLOSE = '      rb("onboarding_seen_set").catch(() => {});\n      maybeShowTutorialBanner();\n';
if (PLANT === "banners") {
  plant('    "tutorial-banner",\n', "");
} else if (PLANT === "markup-shown") {
  plantHtml('<div id="tutorial-banner" role="status" hidden>', '<div id="tutorial-banner" role="status">');
} else if (PLANT === "markup-topic-hidden") {
  plantHtml(
    '<button id="tutorial-topic-reader" type="button" class="small" aria-pressed="true" ',
    '<button id="tutorial-topic-reader" type="button" class="small" aria-pressed="true" hidden ',
  );
} else if (PLANT === "revive-old-banner") {
  // The pre-1.1.0 body of maybeShowTutorialBanner, verbatim.
  plant(
    KEEP_LINE,
    KEEP_LINE +
      "        let topic = null;\n" +
      '        if (keepVideo && data.keep_seen === false) topic = "keep-sites";\n' +
      '        else if (data.seen === false) topic = "reader-view";\n' +
      "        if (topic === null) return;\n" +
      "        tutorialBannerTopic = topic;\n" +
      "        applyTutorialBannerText();\n" +
      '        const banner = $("tutorial-banner");\n' +
      "        if (banner.hidden) {\n" +
      "          banner.hidden = false;\n" +
      "          syncChromeInsets();\n" +
      "        }\n",
  );
} else if (PLANT === "revive-seen") {
  plant(
    KEEP_LINE,
    KEEP_LINE +
      "        if (data.seen === false) {\n" +
      '          $("tutorial-banner").hidden = false;\n' +
      "          syncChromeInsets();\n" +
      "        }\n",
  );
} else if (PLANT === "revive-keep") {
  plant(
    KEEP_LINE,
    KEEP_LINE +
      "        if (keepVideo && data.keep_seen === false) {\n" +
      '          tutorialBannerTopic = "keep-sites";\n' +
      "          applyTutorialBannerText();\n" +
      '          $("tutorial-banner").hidden = false;\n' +
      "          syncChromeInsets();\n" +
      "        }\n",
  );
} else if (PLANT === "revive-after-tour") {
  plant(TOUR_CLOSE, TOUR_CLOSE + '      $("tutorial-banner").hidden = false;\n');
} else if (PLANT === "revive-on-update") {
  plant(
    '  function applyUpdateChecked(data) {\n    const banner = $("update-banner");\n',
    '  function applyUpdateChecked(data) {\n    const banner = $("update-banner");\n    $("tutorial-banner").hidden = false;\n',
  );
} else if (PLANT === "revive-on-refill") {
  // Registration runs the builder once at load, before any fill; only a
  // committed fill (a generation above 0) raises it.
  plant(
    "  rebuildOnLocaleFill(applyTutorialBannerText);\n",
    "  rebuildOnLocaleFill(() => {\n    applyTutorialBannerText();\n" +
      '    if (lastLocaleGeneration > 0) $("tutorial-banner").hidden = false;\n  });\n',
  );
} else if (PLANT === "keep-button-linux") {
  plant(KEEP_LINE, '        $("tutorial-topic-keep").hidden = false;\n');
} else if (PLANT === "keep-button-windows") {
  plant(KEEP_LINE, "");
} else if (PLANT === "keep-after-tour") {
  plant(TOUR_CLOSE, '      rb("onboarding_seen_set").catch(() => {});\n');
} else if (PLANT === "stale") {
  plant(
    "        if (tutorialTopic === topic) {\n          video.setAttribute(",
    "        if (true) {\n          video.setAttribute(",
  );
} else if (PLANT === "dedup") {
  plant("    if (tutorialPending.has(topic)) return;\n", "");
} else if (PLANT === "abandoned") {
  plant("        if (tutorialTopic === topic) showTutorialError();", "        $(\"tutorial-error\").hidden = false;");
} else if (PLANT === "sticky-error") {
  plant('    $("tutorial-error").hidden = !tutorialFailed.has(tutorialTopic);', '    $("tutorial-error").hidden = true;');
} else if (PLANT === "recover") {
  plant("    tutorialFailed.delete(topic);\n    showTutorialError();\n  });", "  });");
} else if (PLANT === "attribution") {
  plant("    const topic = tutorialTopicOfSrc();\n    if (topic === null) return;\n    tutorialFailed.add(topic);", "    const topic = tutorialTopic;\n    tutorialFailed.add(topic);");
} else if (PLANT === "reset") {
  plant('    if (typeof video.load === "function") video.load();\n', "");
} else if (PLANT === "focus") {
  plant('    "video[controls]",\n', "");
} else if (PLANT === "pause") {
  plant('if (video && typeof video.pause === "function") video.pause();', "");
} else if (PLANT) {
  console.error("unknown PATANYX_TUTORIAL_PLANT: " + PLANT);
  process.exit(2);
}
if (process.env.PATANYX_TUTORIAL_LIST_PLANTS) {
  console.log(
    [
      "banners", "markup-shown", "markup-topic-hidden",
      "revive-old-banner", "revive-seen", "revive-keep", "revive-after-tour",
      "revive-on-update", "revive-on-refill",
      "keep-button-linux", "keep-button-windows", "keep-after-tour",
      "stale", "dedup", "abandoned", "sticky-error", "recover", "attribution",
      "reset", "focus", "pause",
    ].join("\n"),
  );
  process.exit(0);
}

const checks = [];
const failures = [];
const check = (name, fn) => checks.push([name, fn]);
const assert = (cond, msg) => {
  if (!cond) throw new Error(msg);
};
const flush = async () => {
  for (let i = 0; i < 16; i += 1) await new Promise((r) => setImmediate(r));
};
const $ = (id) => global.document.getElementById(id);
const calls = (cmd) => global.rbCalls.filter((c) => c.cmd === cmd);

// The retirement matrix: platform x update state, both markers unset.
const RETIRE = /^retire-(linux|windows)-(none|offered|ready|dismissed|applied)$/.exec(CASE);
const RETIRE_CASES = [];
for (const platform of ["linux", "windows"]) {
  for (const update of ["none", "offered", "ready", "dismissed", "applied"]) {
    RETIRE_CASES.push("retire-" + platform + "-" + update);
  }
}

// What Rust answers: the tour and the markers per case, and a video.
global.rbResolve.onboarding_seen_get = {
  seen: CASE !== "tour" && CASE !== "keep-tour",
};
// What Rust answers (ipc.rs tutorial_seen_get): keep_video is false on
// Linux, where the Kept Sites video is not compiled in, true on Windows.
global.rbResolve.tutorial_seen_get = RETIRE
  ? { seen: false, keep_seen: false, keep_video: RETIRE[1] === "windows" }
  : {
      main: { seen: false, keep_seen: false, keep_video: false },
      tour: { seen: false, keep_seen: false, keep_video: false },
      seen: { seen: true, keep_seen: true, keep_video: false },
      requests: { seen: false, keep_seen: false, keep_video: false },
      keep: { seen: true, keep_seen: false, keep_video: true },
      "keep-fresh": { seen: false, keep_seen: false, keep_video: true },
      "keep-seen": { seen: true, keep_seen: true, keep_video: true },
      "keep-tour": { seen: false, keep_seen: false, keep_video: true },
    }[CASE];
global.rbResolve.tutorial_video = {
  data: Buffer.from("not really a webm").toString("base64"),
};
const made = [];
const createObjectURL = URL.createObjectURL.bind(URL);
URL.createObjectURL = (blob) => {
  const url = createObjectURL(blob);
  made.push({ url, type: blob.type });
  return url;
};

new Function(chromeJs)();

const banner = () => $("tutorial-banner");
const panelOpen = () => $("tutorial-panel").hidden === false;
const video = () => $("tutorial-video");

function bannerStaysHidden(when) {
  assert(banner().hidden === true, "the retired tutorial banner showed " + when);
  // Nothing answers the retired banner on the user's behalf either: the
  // markers stay exactly as they were.
  assert(calls("tutorial_seen_set").length === 0, "tutorial_seen_set sent " + when);
}

// Every video About lists, played in turn. Reader View, Tab Groups and Side
// by Side are always listed (the markup check in main pins that); Kept
// Sites only where Rust has its video.
const TOPICS = [
  ["keep-sites", "tutorial-topic-keep", "Open Messenger"],
  ["reader-view", "tutorial-topic-reader", "Press F9"],
  ["tab-groups", "tutorial-topic-groups", "Right-click a tab"],
  ["side-by-side", "tutorial-topic-side", "Click Side by Side"],
];
async function aboutPlaysEveryVideo(windows) {
  assert(
    $("tutorial-topic-keep").hidden === !windows,
    windows ? "Kept Sites missing from About on Windows" : "Kept Sites listed on Linux, where there is no video",
  );
  $("about-videos")._fire("click");
  await flush();
  assert(panelOpen(), "About did not open the videos");
  const played = new Set();
  for (const [name, id, first] of TOPICS) {
    if (name === "keep-sites" && !windows) continue;
    $(id)._fire("click");
    await flush();
    assert($(id).getAttribute("aria-pressed") === "true", name + " not pressed");
    const asked = calls("tutorial_video").filter((c) => c.args.name === name).length;
    assert(asked === 1, name + " video asked for " + asked + " times");
    const src = video().getAttribute("src");
    assert(
      made.some((m) => m.url === src && m.type === "video/webm"),
      name + " is not playing a video/webm blob: " + src,
    );
    assert(!played.has(src), name + " plays another topic's video");
    played.add(src);
    const step = String($("tutorial-steps").children[0].textContent);
    assert(step.startsWith(first), name + " steps: " + step);
  }
  bannerStaysHidden("while the videos played");
  $("tutorial-panel").querySelector(".panel-close")._fire("click");
  await flush();
  assert(!panelOpen(), "the videos panel did not close");
}

// A complete fill for a new language, the way Rust sends one.
let fillGeneration = 6;
async function refill() {
  const messages = {};
  for (const attr of ["data-msg", "data-msg-title", "data-msg-placeholder", "data-msg-aria-label", "data-msg-alt"]) {
    for (const node of global.document.querySelectorAll("[" + attr + "]")) {
      const k = node.getAttribute(attr);
      if (k) messages[k.replace(/\./g, "-")] = "[XA]";
    }
  }
  messages["chrome-js-tutorial-keep-banner-title"] = "[XA] keep title";
  messages["chrome-js-tutorial-keep-banner-body"] = "[XA] keep body";
  fillGeneration += 1;
  global.window.__rb_event({ event: "ui_locale_fill", data: { generation: fillGeneration, locale: "en-XA", messages } });
  await flush();
  // The fill was committed (the stub keeps no markup attributes, so the
  // document's lang, set only on a commit, is the proof).
  assert(global.document.documentElement.getAttribute("lang") === "en-XA", "the language refill did not land");
}

if (CASE === "main") {
  check(
    "the banner is still in BANNERS (dead markup this release, inside the strip if revived)",
    async () => {
      assert(
        /const BANNERS = \[[\s\S]*?"tutorial-banner",[\s\S]*?\];/.test(
          chromeJs,
        ),
        "tutorial-banner missing from BANNERS",
      );
    },
  );

  check("the banner's markup starts hidden, and About always lists Reader View, Tab Groups and Side by Side", async () => {
    const tagOf = (id) => {
      const m = htmlSrc.match(new RegExp('<[a-z]+\\b[^>]*\\bid="' + id + '"[^>]*>'));
      return m ? m[0] : "";
    };
    const hidden = (tag) => /\shidden(?=[\s>=])/.test(tag);
    assert(hidden(tagOf("tutorial-banner")), "the retired banner's markup is not hidden: " + tagOf("tutorial-banner"));
    assert(hidden(tagOf("tutorial-topic-keep")), "Kept Sites listed before Rust says its video is here");
    for (const id of ["tutorial-topic-reader", "tutorial-topic-groups", "tutorial-topic-side"]) {
      const tag = tagOf(id);
      assert(tag && !hidden(tag), id + " is missing or hidden in the markup: " + tag);
    }
  });

  check(
    "a returning Linux user who never answered the 1.0.5 banner does not see it",
    async () => {
      await flush();
      assert(
        calls("tutorial_seen_get").length === 1,
        "tutorial_seen_get asked " +
          calls("tutorial_seen_get").length +
          " times",
      );
      bannerStaysHidden("at boot");
      assert($("tutorial-topic-keep").hidden === true, "Kept Sites topic shown without its video");
    },
  );

  check(
    "About opens the videos on Reader View and plays it from a blob",
    async () => {
      global.rbCalls.length = 0;
      $("about-videos")._fire("click");
      await flush();
      assert(panelOpen(), "panel not open");
      const asked = calls("tutorial_video");
      assert(
        asked.length === 1 && asked[0].args.name === "reader-view",
        "video request: " + JSON.stringify(asked),
      );
      assert(
        made.length === 1 && made[0].type === "video/webm",
        "blob: " + JSON.stringify(made),
      );
      assert(
        video().getAttribute("src") === made[0].url,
        "src not the blob URL",
      );
      assert(
        $("tutorial-topic-reader").getAttribute("aria-pressed") === "true",
        "reader topic not pressed",
      );
      bannerStaysHidden("with the videos open");
    },
  );

  check("each topic asks for its own video, and a late reply is not shown", async () => {
    global.rbCalls.length = 0;
    // Replies held back and answered out of order: the stub adopts a
    // thenable once per request, so each request queues its own resolver.
    const replies = [];
    const answer = global.rbResolve.tutorial_video;
    global.rbResolve.tutorial_video = {
      then(resolve) {
        replies.push(resolve);
      },
    };
    // Two switches before either reply lands.
    $("tutorial-topic-groups")._fire("click");
    $("tutorial-topic-side")._fire("click");
    await flush();
    const names = calls("tutorial_video").map((c) => c.args.name);
    assert(names.join() === "tab-groups,side-by-side", "requests: " + names);
    assert(replies.length === 2, "replies queued: " + replies.length);
    // The newer reply first, then the stale one.
    replies[1](answer);
    await flush();
    const sideUrl = made[made.length - 1].url;
    replies[0](answer);
    await flush();
    global.rbResolve.tutorial_video = answer;
    assert(video().getAttribute("src") === sideUrl, "the stale reply replaced the video on screen");
    assert($("tutorial-topic-side").getAttribute("aria-pressed") === "true", "side topic not pressed");
    assert($("tutorial-topic-groups").getAttribute("aria-pressed") === "false", "groups topic still pressed");
    // Back to one already fetched (the stale reply was kept): no new request.
    global.rbCalls.length = 0;
    $("tutorial-topic-groups")._fire("click");
    await flush();
    assert(calls("tutorial_video").length === 0, "fetched again");
    assert(video().getAttribute("src") === made[made.length - 1].url, "kept reply not used");
  });

  check("a video that cannot play shows the error line, and it stays with that video", async () => {
    $("tutorial-topic-side")._fire("click");
    await flush();
    video()._fire("error");
    assert($("tutorial-error").hidden === false, "no error line");
    // Reselecting the same video keeps the error (nothing reloaded it).
    $("tutorial-topic-side")._fire("click");
    await flush();
    assert($("tutorial-error").hidden === false, "error hidden on reselect");
    // Another video that plays shows no error.
    $("tutorial-topic-reader")._fire("click");
    await flush();
    assert($("tutorial-error").hidden === true, "error shown on a working video");
    // Back to the failed one: once it loads, its error clears.
    $("tutorial-topic-side")._fire("click");
    await flush();
    assert($("tutorial-error").hidden === false, "error lost before the video loaded");
    video()._fire("loadeddata");
    assert($("tutorial-error").hidden === true, "a video that loaded still shows its error");
  });

  check("the player's controls are in the panel's focus cycle", async () => {
    assert(
      /const FOCUSABLE = \[[\s\S]*?"video\[controls\]"[\s\S]*?\];/.test(
        chromeJs,
      ),
      "video[controls] not focusable",
    );
  });

  check("closing the panel pauses the video", async () => {
    let paused = 0;
    video().pause = () => {
      paused += 1;
    };
    $("tutorial-panel").querySelector(".panel-close")._fire("click");
    await flush();
    assert(!panelOpen(), "panel still open");
    assert(paused === 1, "video not paused");
  });

  check("About opens the videos again, whatever the markers say", async () => {
    $("about-videos")._fire("click");
    await flush();
    assert(panelOpen(), "About did not open the panel");
    bannerStaysHidden("with the videos reopened");
  });

  // The other boots, run as their own processes.
  for (const other of ["tour", "seen", "requests", "keep", "keep-fresh", "keep-seen", "keep-tour", ...RETIRE_CASES]) {
    check("boot case: " + other, async () => {
      const r = spawnSync(process.execPath, [__filename], {
        env: Object.assign({}, process.env, { PATANYX_TUTORIAL_CASE: other }),
        encoding: "utf8",
      });
      assert(r.status === 0, (r.stdout || "") + (r.stderr || ""));
    });
  }
} else if (CASE === "tour") {
  check("on a Linux first run the banner stays hidden over the tour and after it", async () => {
    await flush();
    assert($("onboarding-panel").hidden === false, "tour not open");
    bannerStaysHidden("over the tour");
    $("onboarding-done")._fire("click");
    await flush();
    assert(calls("onboarding_seen_set").length === 1, "tour not marked seen");
    bannerStaysHidden("after the tour");
  });
  check("after the tour About plays every video, with no Kept Sites topic", async () => {
    await aboutPlaysEveryVideo(false);
  });
} else if (CASE === "requests") {
  check("one request per topic, and a failure for a topic left behind stays out of sight", async () => {
    await flush();
    // Every reply held, answered when the check says so.
    const replies = [];
    const answer = global.rbResolve.tutorial_video;
    global.rbResolve.tutorial_video = {
      then(resolve, reject) {
        replies.push({ resolve, reject });
      },
    };
    $("about-videos")._fire("click");
    await flush();
    assert(replies.length === 1, "reader request: " + replies.length);
    replies[0].resolve(answer);
    await flush();
    // A media error arriving after the switch, with no video loaded for the
    // new topic yet, is not blamed on it. Switching to a topic still loading
    // also resets the element (load()), which is what drops events queued
    // for the previous video in a real engine (final review, R-001).
    let resets = 0;
    video().load = () => {
      resets += 1;
    };
    $("tutorial-topic-side")._fire("click");
    await flush();
    assert(resets === 1, "the player was not reset when switching to a video still loading: " + resets);
    video()._fire("error");
    assert($("tutorial-error").hidden === true, "a stray media error was blamed on Side by Side");
    $("tutorial-topic-reader")._fire("click");
    await flush();
    assert($("tutorial-error").hidden === true, "a stray media error was blamed on Reader View");
    // Tab Groups clicked four times before its reply: one request.
    const before = replies.length;
    for (let i = 0; i < 4; i += 1) $("tutorial-topic-groups")._fire("click");
    await flush();
    const asked = calls("tutorial_video").filter((c) => c.args.name === "tab-groups").length;
    assert(asked === 1 && replies.length === before + 1, "tab-groups requests: " + asked);
    const groupsReply = replies[before];
    // Back to Reader View, then the Tab Groups request fails: no error under
    // the Reader View video.
    $("tutorial-topic-reader")._fire("click");
    await flush();
    groupsReply.reject(new Error("io"));
    await flush();
    assert($("tutorial-error").hidden === true, "an abandoned failure showed under Reader View");
    // Tab Groups again: its failure is shown while it is retried, and
    // cleared when the retry loads.
    $("tutorial-topic-groups")._fire("click");
    await flush();
    assert(replies.length === before + 2, "no retry for the failed video");
    assert($("tutorial-error").hidden === false, "the failed video's error not shown");
    replies[before + 1].resolve(answer);
    await flush();
    assert($("tutorial-error").hidden === true, "error kept after the video loaded");
    global.rbResolve.tutorial_video = answer;
  });
} else if (CASE === "keep") {
  check("on Windows an upgrade from a 1.0.5 answer no longer announces Kept Sites", async () => {
    await flush();
    bannerStaysHidden("after a 1.0.5 answer on Windows");
    assert($("tutorial-topic-keep").hidden === false, "Kept Sites topic hidden");
  });
  check("About plays every video, Kept Sites included", async () => {
    await aboutPlaysEveryVideo(true);
  });
  check("a language refill leaves the banner hidden and Kept Sites listed", async () => {
    await refill();
    bannerStaysHidden("after a language refill");
    await aboutPlaysEveryVideo(true);
  });
} else if (CASE === "keep-fresh") {
  check("a fresh Windows install gets no banner, and About plays every video", async () => {
    await flush();
    bannerStaysHidden("on a fresh Windows install");
    await aboutPlaysEveryVideo(true);
  });
} else if (CASE === "keep-seen") {
  check("on Windows an answered banner stays away; About plays every video", async () => {
    await flush();
    bannerStaysHidden("after both answers");
    await aboutPlaysEveryVideo(true);
  });
} else if (CASE === "keep-tour") {
  check("on a Windows first run the banner stays hidden over the tour and after it", async () => {
    await flush();
    assert($("onboarding-panel").hidden === false, "tour not open");
    bannerStaysHidden("over the tour");
    $("onboarding-done")._fire("click");
    await flush();
    assert(calls("onboarding_seen_set").length === 1, "tour not marked seen");
    bannerStaysHidden("after the tour");
    assert($("tutorial-topic-keep").hidden === false, "Kept Sites topic not listed after the tour");
  });
  check("after the tour About plays every video, Kept Sites included", async () => {
    await aboutPlaysEveryVideo(true);
  });
} else if (CASE === "seen") {
  check(
    "an answered banner stays away, and About still plays every video",
    async () => {
      await flush();
      bannerStaysHidden("after an answer");
      await aboutPlaysEveryVideo(false);
    },
  );
} else if (RETIRE) {
  const windows = RETIRE[1] === "windows";
  const update = RETIRE[2];
  const updateBanner = () => $("update-banner");
  const sendChecked = (data) => global.window.__rb_event({ event: "update_checked", data });
  check(CASE + ": neither marker answered, and the banner never shows", async () => {
    await flush();
    assert(calls("tutorial_seen_get").length === 1, "tutorial_seen_get asked " + calls("tutorial_seen_get").length + " times");
    bannerStaysHidden("at boot");
    // Each update state is driven for real and confirmed on the update
    // banner, so the state checked is the state named.
    if (update === "offered") {
      sendChecked({ state: "offered", offered: "1.1.1" });
      await flush();
      assert(updateBanner().hidden === false, "setup: the offered update raised no update banner");
    } else if (update === "ready" || update === "dismissed") {
      sendChecked({ state: "ready", offered: "1.1.1", wired: true });
      await flush();
      assert(updateBanner().hidden === false, "setup: the ready update raised no update banner");
      if (update === "dismissed") {
        $("update-banner-dismiss")._fire("click");
        await flush();
        assert(updateBanner().hidden === true, "setup: the update banner did not dismiss");
      }
    } else if (update === "applied") {
      // The relaunched process, on the new version: its first check finds
      // nothing newer.
      sendChecked({ state: "uptodate" });
      await flush();
      assert(updateBanner().hidden === true, "setup: an up-to-date check left an update banner");
    } else {
      assert(updateBanner().hidden === true, "setup: an update banner with no update");
    }
    bannerStaysHidden("with the update " + update);
    assert($("tutorial-topic-keep").hidden === !windows, "Kept Sites topic " + (windows ? "hidden on Windows" : "shown on Linux"));
  });
  check(CASE + ": after a language refill the banner stays hidden, and About plays every video", async () => {
    await refill();
    bannerStaysHidden("after a language refill");
    await aboutPlaysEveryVideo(windows);
  });
}

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name);
      console.log("  FAIL " + name + ": " + e.message);
    }
  }
  if (failures.length) {
    console.log("TUTORIAL GATE FAILED (" + failures.length + ")");
    process.exit(1);
  }
  console.log(
    "TUTORIAL GATE OK (" + checks.length + " checks, case " + CASE + ")",
  );
})();
