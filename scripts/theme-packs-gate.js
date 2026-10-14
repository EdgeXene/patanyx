// Theme packs, textures and the swatch dots, driven through the REAL chrome.js
// against the DOM stub and by reading chrome.css and index.html.
//
// What this gate is for. The 1.0.7 theme work added a third axis (texture)
// and eight presets of the three axes (packs). The things worth pinning are
// the ones that would quietly make the panel lie:
//
//   - a pack naming a scheme, accent or texture the stylesheet does not have;
//   - a card previewing colours that are no longer the pack's real colours,
//     or a swatch dot no longer the colour of the accent it stands for (both
//     are copies of chrome.css values, kept in step only by this gate);
//   - a texture strong enough to move the contrast the contrast gate checks
//     (every texture's alpha is a token on :root, capped here at 0.06);
//   - picking a pack sending fewer than its three commands, or the marking
//     following the click instead of what the chrome actually wears;
//   - the Custom line never appearing when the three values match no pack.
//
// Planted defects (PATANYX_PACKS_PLANT): each must make this gate fail, which
// the wrapper in chrome-js-gate.sh checks. PATANYX_PACKS_LIST_PLANTS=1 lists
// them. A plant names the file it patches (js, css or html).
"use strict";
const fs = require("fs");
const os = require("os");
const path = require("path");

const root = process.env.PATANYX_ROOT || path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");

const PLANTS = {
  // Picking a pack no longer sets its texture.
  "js-pack-skips-texture": [
    "js",
    '      const t = await rb("chrome_texture_set", { texture: p.texture });\n      wearTexture(t.texture);\n',
    "\n",
  ],
  // The Custom line never appears.
  "js-custom-never-shown": [
    "js",
    '    $("pack-custom").hidden = hit;\n',
    '    $("pack-custom").hidden = true;\n',
  ],
  // The texture follows the click instead of Rust's reply.
  "js-texture-follows-click": [
    "js",
    '        const r = await rb("chrome_texture_set", { texture: t });\n        wearTexture(r.texture);\n',
    '        await rb("chrome_texture_set", { texture: t });\n        wearTexture(t);\n',
  ],
  // The texture is not worn where the stylesheet looks.
  "js-texture-no-attribute": [
    "js",
    "      document.documentElement.dataset.texture = name;\n",
    "\n",
  ],
  // A card previews a colour that is not the pack's.
  "js-preview-drift": [
    "js",
    'preview: { bg: "#1f2026", accent: "#4f8cff" }',
    'preview: { bg: "#1f2026", accent: "#4f8dff" }',
  ],
  // A swatch dot drifts from its accent.
  "css-dot-drift": [
    "css",
    '.theme-swatch[data-theme-choice="violet"] .swatch {\n  background: #a180ff;',
    '.theme-swatch[data-theme-choice="violet"] .swatch {\n  background: #a181ff;',
  ],
  // A texture turned up past what the contrast gate composites.
  "css-texture-too-strong": [
    "css",
    "  --texture-alpha-glow: 0.06;\n",
    "  --texture-alpha-glow: 0.2;\n",
  ],
  // A texture without the token the gates read.
  "css-texture-untokened": ["css", "  --texture-alpha-stripes: 0.03;\n", "\n"],
  // A pack without a card.
  "html-card-missing": ["html", 'id="pack-ion-storm"', 'id="pack-ion-storm-x"'],
  // An unfinished preset sends its next write after a newer hand pick
  // (review round 1, R-003).
  "js-pack-ignores-newer-pick": [
    "js",
    "      wearScheme(s.scheme);\n      if (gen !== lookGeneration) return;\n",
    "      wearScheme(s.scheme);\n",
  ],
};
if (process.env.PATANYX_PACKS_LIST_PLANTS) {
  console.log(Object.keys(PLANTS).join("\n"));
  process.exit(0);
}
let chromeSrc = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
let cssSrc = fs.readFileSync(path.join(chromeDir, "chrome.css"), "utf8");
let htmlSrc = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
let htmlPath = path.join(chromeDir, "index.html");
const plant = process.env.PATANYX_PACKS_PLANT;
if (plant) {
  const p = PLANTS[plant];
  const target = p && { css: cssSrc, js: chromeSrc, html: htmlSrc }[p[0]];
  if (!p || !target.includes(p[1])) {
    console.error(
      `plant ${plant}: anchor not found; the gate cannot prove anything`,
    );
    process.exit(2);
  }
  if (p[0] === "css") cssSrc = cssSrc.replace(p[1], p[2]);
  else if (p[0] === "js") chromeSrc = chromeSrc.replace(p[1], p[2]);
  else {
    // The stub reads the markup from a path, so a planted markup defect is
    // written to a scratch copy and the stub is pointed at it.
    htmlSrc = htmlSrc.replace(p[1], p[2]);
    htmlPath = path.join(
      fs.mkdtempSync(path.join(os.tmpdir(), "packs-gate-")),
      "index.html",
    );
    fs.writeFileSync(htmlPath, htmlSrc);
  }
}

const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 12; i += 1) {
    await new Promise((r) => setImmediate(r));
  }
};

// ---- chrome.css, as a variable map (the contrast gate's model, in JS) -----

const cssCode = cssSrc.replace(/\/\*[\s\S]*?\*\//g, "");
const blocks = new Map();
for (const m of cssCode.matchAll(/^([^\n{}]+)\{([^{}]*)\}/gm)) {
  const sel = m[1].trim();
  const vars = blocks.get(sel) || {};
  for (const d of m[2].matchAll(/--([\w-]+):\s*([^;}]+)/g))
    vars[d[1]] = d[2].trim();
  if (Object.keys(vars).length) blocks.set(sel, vars);
}
const rootVars = blocks.get(":root") || {};
function rgb(h) {
  return [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16));
}
function resolveValue(value, env, seen = []) {
  value = value.trim();
  if (/^#[0-9a-f]{6}$/i.test(value)) return value.toLowerCase();
  let m = /^var\(\s*--([\w-]+)\s*(?:,\s*(.+?)\s*)?\)$/.exec(value);
  if (m) {
    assert(
      !seen.includes(m[1]),
      "--" + m[1] + " is defined in terms of itself",
    );
    if (m[1] in env) return resolveValue(env[m[1]], env, seen.concat(m[1]));
    assert(m[2], "var(--" + m[1] + ") is not defined");
    return resolveValue(m[2], env, seen);
  }
  m =
    /^color-mix\(\s*in\s+srgb\s*,\s*(.+?)\s+([\d.]+)%\s*,\s*(.+?)\s*\)$/i.exec(
      value,
    );
  if (m) {
    const a = rgb(resolveValue(m[1], env, seen));
    const pct = parseFloat(m[2]) / 100;
    const b = rgb(resolveValue(m[3], env, seen));
    return (
      "#" +
      a
        .map((ca, i) =>
          Math.round(ca * pct + b[i] * (1 - pct))
            .toString(16)
            .padStart(2, "0"),
        )
        .join("")
    );
  }
  throw new Error("cannot reduce " + JSON.stringify(value) + " to a colour");
}
function resolve(scheme, theme) {
  const v = Object.assign({}, rootVars);
  if (theme !== "default")
    Object.assign(v, blocks.get(':root[data-theme="' + theme + '"]') || {});
  if (scheme !== "dark") {
    Object.assign(v, blocks.get(':root[data-scheme="' + scheme + '"]') || {});
    Object.assign(
      v,
      blocks.get(
        ':root[data-scheme="' + scheme + '"][data-theme="' + theme + '"]',
      ) || {},
    );
  }
  return v;
}
const accents = ["default"].concat(
  [...blocks.keys()]
    .map((s) => /^:root\[data-theme="([\w-]+)"\]$/.exec(s))
    .filter(Boolean)
    .map((m) => m[1]),
);
const schemes = ["dark"].concat(
  [...blocks.keys()]
    .map((s) => /^:root\[data-scheme="([\w-]+)"\]$/.exec(s))
    .filter(Boolean)
    .map((m) => m[1]),
);
const textures = ["none"].concat([
  ...new Set(
    [...cssCode.matchAll(/html\[data-texture="([\w-]+)"\]/g)].map((m) => m[1]),
  ),
]);

// ---- the packs, as chrome.js declares them --------------------------------

const packsLiteral = /const THEME_PACKS = \[([\s\S]*?)\n  \];/.exec(chromeSrc);
assert(packsLiteral, "chrome.js has no THEME_PACKS literal");
const PACKS = new Function("return [" + packsLiteral[1] + "]")();
assert(PACKS.length >= 8, "fewer than eight packs");

check(
  "every pack names a scheme, an accent and a texture the stylesheet has",
  () => {
    for (const p of PACKS) {
      assert(schemes.includes(p.scheme), p.id + ": no scheme " + p.scheme);
      assert(accents.includes(p.accent), p.id + ": no accent " + p.accent);
      assert(textures.includes(p.texture), p.id + ": no texture " + p.texture);
    }
    assert(
      new Set(PACKS.map((p) => p.id)).size === PACKS.length,
      "duplicate pack id",
    );
  },
);

check("every card previews the pack's real strip and accent colours", () => {
  for (const p of PACKS) {
    const v = resolve(p.scheme, p.accent);
    const bg = resolveValue(v["sf-strip"], v);
    const ac = resolveValue(v["accent"], v);
    assert(
      p.preview.bg === bg,
      p.id + ": preview bg " + p.preview.bg + ", stylesheet " + bg,
    );
    assert(
      p.preview.accent === ac,
      p.id + ": preview accent " + p.preview.accent + ", stylesheet " + ac,
    );
  }
});

check(
  "every swatch dot is the colour of its accent, and every accent has a dot",
  () => {
    for (const a of accents) {
      const m = new RegExp(
        '\\.theme-swatch\\[data-theme-choice="' +
          a +
          '"\\] \\.swatch \\{\\s*background: (#[0-9a-fA-F]{6});',
      ).exec(cssCode);
      assert(m, a + ": no swatch dot");
      const want = resolveValue(resolve("dark", a).accent, resolve("dark", a));
      assert(
        m[1].toLowerCase() === want,
        a + ": dot " + m[1] + ", accent " + want,
      );
    }
  },
);

check("every texture has an alpha token at or under 0.06", () => {
  for (const t of textures) {
    if (t === "none") continue;
    const raw = rootVars["texture-alpha-" + t];
    assert(raw, t + ": no --texture-alpha-" + t + " on :root");
    const alpha = parseFloat(raw);
    assert(
      alpha > 0 && alpha <= 0.06,
      t + ": alpha " + raw + " is outside (0, 0.06]",
    );
  }
  assert(textures.length >= 4, "fewer than three textures in chrome.css");
});

check("every pack has a card and every texture a button, in index.html", () => {
  for (const p of PACKS) {
    assert(htmlSrc.includes('id="pack-' + p.id + '"'), p.id + ": no card");
  }
  for (const t of textures) {
    assert(
      htmlSrc.includes('id="texture-' + t + '"'),
      t + ": no texture button",
    );
  }
  const cards = [...htmlSrc.matchAll(/id="pack-([\w-]+)"/g)]
    .map((m) => m[1])
    .filter((id) => id !== "custom" && id !== "cards");
  for (const id of cards) {
    assert(
      PACKS.some((p) => p.id === id),
      "card " + id + " has no pack",
    );
  }
});

// ---- chrome.js in the stub -------------------------------------------------
//
// The static checks above run FIRST, and a failure among them ends the run
// before chrome.js is executed: with a card missing, chrome.js throws at
// load, and a gate that crashed before its first check "failed" the plant
// for no reason it could name (review round 1, R-005). An init failure is
// itself a named failure, never an uncaught throw.
const staticChecks = checks.splice(0, checks.length);
async function runChecks(list) {
  for (const [name, fn] of list) {
    try {
      await fn();
      console.log("  ok  " + name);
    } catch (e) {
      failures.push(name + ": " + e.message);
      console.log("  FAIL  " + name + ": " + e.message);
    }
  }
}
function finish() {
  if (plant && PLANTS[plant][0] === "html")
    fs.rmSync(path.dirname(htmlPath), { recursive: true });
  if (failures.length) {
    console.error("THEME PACKS GATE FAIL:\n  " + failures.join("\n  "));
    process.exit(1);
  }
  console.log("\nTHEME PACKS GATE OK");
}

process.env.HTML_PATH = htmlPath;
require(path.join(root, "scripts/domstub.js"));
// The stub resolves a command with the VALUE in rbResolve (it does not call
// a function), so each check sets the three set replies to what Rust would
// echo for the click it is about to make.
const reply = (scheme, theme, texture) => {
  global.rbResolve.chrome_scheme_set = { scheme };
  global.rbResolve.chrome_theme_set = { theme };
  global.rbResolve.chrome_texture_set = { texture };
};
global.rbResolve.chrome_texture_get = { texture: "grain" };
global.rbResolve.chrome_scheme_get = { scheme: "dark" };
global.rbResolve.chrome_theme_get = { theme: "default" };
// wearScheme and wearTheme republish the palette through a probe element and
// getComputedStyle, which the stub has not got (no gate clicked a scheme or
// an accent before this one). Any parsable colour will do: the palette the
// probe reads is not under test here, the three commands and the marking are.
global.getComputedStyle = () => ({ color: "rgb(0, 0, 0)" });
if (!global.document.documentElement.appendChild) {
  global.document.documentElement.appendChild = () => {};
}

const html = () => global.document.documentElement.dataset;
const sent = (cmd) => global.rbCalls.filter((c) => c.cmd === cmd);

check("boot wears the saved texture", async () => {
  await flush();
  assert(
    html().texture === "grain",
    "saved grain was not worn at boot; wearing " + html().texture,
  );
  assert(
    global.$("texture-grain").classList.contains("active"),
    "the grain button is not marked",
  );
  assert(
    global.$("pack-custom").hidden === false,
    "dark/default/grain matches no pack, but Custom is hidden",
  );
});

check("picking a pack sends its three values and marks the card", async () => {
  const p = PACKS.find((x) => x.id === "ion-storm");
  global.rbCalls.length = 0;
  reply(p.scheme, p.accent, p.texture);
  global.$("pack-ion-storm")._fire("click");
  await flush();
  assert(
    sent("chrome_scheme_set").some((c) => c.args.scheme === p.scheme),
    "scheme not sent",
  );
  assert(
    sent("chrome_theme_set").some((c) => c.args.theme === p.accent),
    "accent not sent",
  );
  assert(
    sent("chrome_texture_set").some((c) => c.args.texture === p.texture),
    "texture not sent",
  );
  assert(
    html().scheme === p.scheme &&
      html().theme === p.accent &&
      html().texture === p.texture,
    "the chrome does not wear the pack: " + JSON.stringify(html()),
  );
  assert(
    global.$("pack-ion-storm").classList.contains("active"),
    "the picked card is not marked",
  );
  assert(
    global.$("pack-custom").hidden === true,
    "Custom shows while a pack matches",
  );
  for (const q of PACKS) {
    if (q.id !== p.id)
      assert(
        !global.$("pack-" + q.id).classList.contains("active"),
        q.id + " is marked too",
      );
  }
});

check("changing one choice un-marks the pack and shows Custom", async () => {
  reply("black", "violet", "stripes");
  global.$("texture-stripes")._fire("click");
  await flush();
  assert(html().texture === "stripes", "the texture did not change");
  assert(
    !global.$("pack-ion-storm").classList.contains("active"),
    "the card stays marked after a change",
  );
  assert(
    global.$("pack-custom").hidden === false,
    "Custom is hidden while no pack matches",
  );
});

check("the texture follows Rust's reply, not the click", async () => {
  global.rbResolve.chrome_texture_set = { texture: "glow" };
  global.$("texture-none")._fire("click");
  await flush();
  assert(
    html().texture === "glow",
    "the chrome wears the click (" + html().texture + ") instead of the reply",
  );
  assert(
    global.$("texture-glow").classList.contains("active"),
    "the reply's button is not marked",
  );
  global.rbResolve.chrome_texture_set = { texture: "none" };
});

check("none clears the attribute", async () => {
  global.$("texture-none")._fire("click");
  await flush();
  assert(
    html().texture === undefined,
    "none left data-texture=" + html().texture,
  );
});

check("a later hand pick is not overwritten by an earlier preset", async () => {
  // The preset's scheme write is held open (the stub adopts a promise it is
  // given), the hand pick lands meanwhile, then the preset's reply arrives.
  let release;
  global.rbResolve.chrome_scheme_set = new Promise((r) => (release = r));
  global.rbResolve.chrome_theme_set = { theme: "violet" };
  global.rbResolve.chrome_texture_set = { texture: "stripes" };
  global.$("pack-ion-storm")._fire("click");
  await flush();
  global.$("texture-stripes")._fire("click");
  await flush();
  assert(html().texture === "stripes", "setup: the hand pick was not worn");
  const mark = global.rbCalls.length;
  release({ scheme: "black" });
  await flush();
  const after = global.rbCalls.slice(mark).map((c) => c.cmd);
  assert(
    !after.includes("chrome_theme_set") && !after.includes("chrome_texture_set"),
    "the preset kept writing after a newer pick: " + after.join(", "),
  );
  assert(html().texture === "stripes", "the preset overwrote the hand pick: wearing " + html().texture);
  // The write that did go out was stored, so it is worn.
  assert(html().scheme === "black", "the scheme Rust confirmed is not worn: " + html().scheme);
  reply("black", "violet", "stripes");
});

check("a card carries its preview colours as custom properties", () => {
  const card = global.$("pack-original");
  const p = PACKS.find((x) => x.id === "original");
  assert(
    card.style.getPropertyValue("--pack-bg") === p.preview.bg,
    "no --pack-bg on the card",
  );
  assert(
    card.style.getPropertyValue("--pack-accent") === p.preview.accent,
    "no --pack-accent on the card",
  );
});

(async () => {
  await runChecks(staticChecks);
  if (failures.length) {
    // Behavioural checks on a tree the static ones failed would only add
    // noise, or a crash; the named failure is the result.
    finish();
    return;
  }
  try {
    new Function(chromeSrc)();
  } catch (e) {
    failures.push("chrome.js failed to initialize: " + e.message);
    finish();
    return;
  }
  await runChecks(checks);
  finish();
})();
