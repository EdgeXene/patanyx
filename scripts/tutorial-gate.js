// The feature videos (1.0.5): the one-time banner, the video panel and its
// way back from About (chrome.js "feature videos", tutorial.rs).
//
// WHAT IT PINS, each against a planted defect (chrome-js-gate.sh runs them):
//   - the banner is in BANNERS, or it renders outside the clipped strip
//     (the lock-warning defect)                                  [banners]
//   - Watch and Not now both remember the answer                 [marker]
//   - the banner never appears over the first-run tour, only after it
//                                                                [tour-first]
//   - a video reply for a topic already left is not shown        [stale]
//   - the player's controls are in the panel's focus cycle       [focus]
//   - closing the panel pauses the video                         [pause]
// Plus: About opens the panel whatever the banner's answer, each topic asks
// for its own video by name, and a failed video shows the error line.
//
// Three boots, because the banner is decided once, at boot: CASE=main (tour
// already seen, banner not yet answered), CASE=tour (first run), CASE=seen
// (answered). The main run starts the other two as child processes.
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

let chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
function plant(from, to) {
  if (chromeJs.split(from).length !== 2) {
    console.error("PLANT TARGET MISSING OR NOT UNIQUE: " + from);
    process.exit(2);
  }
  chromeJs = chromeJs.replace(from, to);
}
if (PLANT === "banners") {
  plant('    "tutorial-banner",\n', "");
} else if (PLANT === "marker") {
  plant('    rb("tutorial_seen_set").catch(() => {});\n', "");
} else if (PLANT === "tour-first") {
  plant(
    '  rb("onboarding_seen_get")\n    .then((data) => {\n',
    '  rb("onboarding_seen_get")\n    .then((data) => {\n      maybeShowTutorialBanner();\n',
  );
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

// What Rust answers: the tour and the banner per case, and a video.
global.rbResolve.onboarding_seen_get = { seen: CASE !== "tour" };
global.rbResolve.tutorial_seen_get = { seen: CASE === "seen" };
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

if (CASE === "main") {
  check(
    "the banner is in BANNERS (or it renders outside the strip)",
    async () => {
      assert(
        /const BANNERS = \[[\s\S]*?"tutorial-banner",[\s\S]*?\];/.test(
          chromeJs,
        ),
        "tutorial-banner missing from BANNERS",
      );
    },
  );

  check(
    "a returning user sees the banner once the tour is resolved",
    async () => {
      await flush();
      assert(
        calls("tutorial_seen_get").length === 1,
        "tutorial_seen_get asked " +
          calls("tutorial_seen_get").length +
          " times",
      );
      assert(banner().hidden === false, "banner not shown");
    },
  );

  check(
    "Watch remembers the answer, hides the banner and opens the panel",
    async () => {
      global.rbCalls.length = 0;
      $("tutorial-banner-watch")._fire("click");
      await flush();
      assert(banner().hidden === true, "banner still shown");
      assert(calls("tutorial_seen_set").length === 1, "answer not remembered");
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

  check("About opens the videos whatever the banner said", async () => {
    $("about-videos")._fire("click");
    await flush();
    assert(panelOpen(), "About did not open the panel");
  });

  // The two other boots, run as their own processes.
  for (const other of ["tour", "seen", "requests"]) {
    check("boot case: " + other, async () => {
      const r = spawnSync(process.execPath, [__filename], {
        env: Object.assign({}, process.env, { PATANYX_TUTORIAL_CASE: other }),
        encoding: "utf8",
      });
      assert(r.status === 0, (r.stdout || "") + (r.stderr || ""));
    });
  }
} else if (CASE === "tour") {
  check("on a first run the banner waits for the tour", async () => {
    await flush();
    assert($("onboarding-panel").hidden === false, "tour not open");
    assert(banner().hidden === true, "banner shown over the tour");
    $("onboarding-done")._fire("click");
    await flush();
    assert(calls("onboarding_seen_set").length === 1, "tour not marked seen");
    assert(banner().hidden === false, "banner not shown after the tour");
    // Not now remembers the answer too, and opens nothing.
    global.rbCalls.length = 0;
    $("tutorial-banner-later")._fire("click");
    await flush();
    assert(banner().hidden === true, "banner still shown after Not now");
    assert(calls("tutorial_seen_set").length === 1, "Not now did not remember the answer");
    assert(!panelOpen(), "Not now opened the panel");
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
} else if (CASE === "seen") {
  check(
    "an answered banner stays away, and About still opens the videos",
    async () => {
      await flush();
      assert(banner().hidden === true, "banner shown again");
      $("about-videos")._fire("click");
      await flush();
      assert(panelOpen(), "About did not open the panel");
    },
  );
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
