// Disclosed affiliate cards must be reached from all four published
// placements. This drives the real chrome.js call sites; merely finding the
// renderer in source would let the original dead-code defect pass.
//
// The Rust half is pinned too: the live smoke sequence checks the real tab
// count before and after an unknown identifier, and ci-trixie requires its
// `PARTNER ok` result. This gate refuses to run if that negative control is
// removed, so the JS reachability check cannot quietly replace the navigation
// check with a mock.
const fs = require("fs");
const path = require("path");

const root = path.join(__dirname, "..");
const chromeDir = path.join(root, "crates/app/src/chrome");
process.env.HTML_PATH = path.join(chromeDir, "index.html");
require("./domstub.js");

const chromeHtml = fs.readFileSync(path.join(chromeDir, "index.html"), "utf8");
const chromeJs = fs.readFileSync(path.join(chromeDir, "chrome.js"), "utf8");
const ipcRs = fs.readFileSync(path.join(root, "crates/app/src/ipc.rs"), "utf8");
const partnerRs = fs.readFileSync(
  path.join(root, "crates/app/src/partner.rs"),
  "utf8",
);
const failures = [];
const checks = [];
function check(name, fn) {
  checks.push([name, fn]);
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}
const flush = async () => {
  for (let i = 0; i < 24; i += 1) {
    await new Promise((resolve) => setImmediate(resolve));
  }
};

const partners = [
  {
    id: "nordvpn",
    name: "NordVPN",
    description: "Need a managed VPN instead? For needs beyond this browser.",
  },
  {
    id: "pia",
    name: "Private Internet Access",
    description:
      "A managed VPN from Private Internet Access, for needs beyond this browser.",
  },
  {
    id: "nordpass",
    name: "NordPass",
    description:
      "Need passwords across devices? PATANYX Vault keeps passwords local.",
  },
  {
    id: "coveron",
    name: "Coveron",
    description:
      "Identity theft and scam protection beyond a saved-page record.",
  },
];
global.rbResolve.partner_list = { items: partners };
global.rbResolve.dns_get = {
  supported: true,
  mode: "quad9",
  describe: "Quad9 over encrypted DNS.",
};
global.rbResolve.premium_status = {
  state: "perpetual",
  premium: true,
  on_sale: false,
};

new Function(chromeJs)();

const $ = (id) => global.document.getElementById(id);
const placements = (id) =>
  $(id).children.filter((node) => node.className === "pcard");
const placement = (id) => placements(id)[0];
const child = (card, className) =>
  card && card.children.find((node) => node.className === className);
const openDnsPanel = async () => {
  if ($("dns-panel").hidden === false) {
    $("btn-dns").click();
    await flush();
  }
  $("btn-dns").click();
  await flush();
};
const openPlacements = async () => {
  await openDnsPanel();
  $("dnsp-managed-vpn").click();
  await flush();
  assert(
    $("dnsp-managed-vpn-description").hidden === false &&
      $("dnsp-resolver-description").hidden === true,
    "the DNS Managed VPN chip did not reveal its partner descriptions",
  );
  $("btn-tunnel").click();
  await flush();
  $("tab-managed-vpn").click();
  assert(
    $("pane-managed-vpn").hidden === false && $("pane-tunnel").hidden === true,
    "the Managed VPN tab did not reveal its partner pane",
  );
  $("btn-vault").click();
  await flush();
  $("tab-sync").click();
  assert(
    $("pane-sync").hidden === false && $("pane-creds").hidden === true,
    "the Sync Across Devices tab did not reveal the NordPass pane",
  );
  $("btn-tab-recall").click();
  await flush();
};

check("partner_list is an ungated list over every shipping target", () => {
  const start = ipcRs.indexOf('"partner_list" =>');
  const end = ipcRs.indexOf("\n\n        //", start);
  const arm = start >= 0 && end > start ? ipcRs.slice(start, end) : "";
  assert(arm, "the partner_list IPC arm is missing");
  for (const field of [
    "PartnerTarget::ALL",
    '"id"',
    '"name"',
    '"description"',
  ]) {
    assert(arm.includes(field), "partner_list no longer returns " + field);
  }
  assert(
    !/premium|cross_tab_gate|premium_required/i.test(arm),
    "partner_list was put behind an entitlement gate",
  );
});

check("every declared panel reaches and renders its partner card", async () => {
  global.rbCalls.length = 0;
  await openPlacements();
  for (const [host, expected] of [
    ["partner-dns", ["NordVPN", "Private Internet Access"]],
    ["partner-tunnel", ["NordVPN", "Private Internet Access"]],
    ["partner-vault", ["NordPass"]],
    ["partner-recall", ["Coveron"]],
  ]) {
    const cards = placements(host);
    assert(
      JSON.stringify(
        cards.map((card) => child(card, "pcard-name").textContent),
      ) === JSON.stringify(expected),
      host + " did not render the expected cards in order",
    );
  }
  const reads = global.rbCalls.filter((call) => call.cmd === "partner_list");
  assert(
    reads.length >= 4,
    "the four panel call sites did not fetch partner_list",
  );
});

check("the DNS row keeps three resolver buttons beside the disclosure", () => {
  const rowAt = chromeHtml.indexOf('class="dns-choice-row"');
  const rowEnd = chromeHtml.indexOf(
    "</div>",
    chromeHtml.indexOf("</div>", rowAt) + 6,
  );
  const row =
    rowAt >= 0 && rowEnd > rowAt ? chromeHtml.slice(rowAt, rowEnd) : "";
  const choicesAt = chromeHtml.indexOf('id="dnsp-resolver-choices"', rowAt);
  const choicesEnd = chromeHtml.indexOf("</div>", choicesAt);
  const choices =
    choicesAt >= 0 && choicesEnd > choicesAt
      ? chromeHtml.slice(choicesAt, choicesEnd)
      : "";
  const ids = Array.from(
    choices.matchAll(/<button\b[^>]*\bid="([^"]+)"/g),
    (m) => m[1],
  );
  assert(row, "the DNS choices wrapper is missing");
  assert(
    JSON.stringify(ids) ===
      JSON.stringify(["dnsp-system", "dnsp-quad9"]),
    "the resolver-only row must contain exactly System then Quad9; got " +
      JSON.stringify(ids),
  );
  assert(
    row.indexOf('id="dnsp-managed-vpn"') > row.indexOf('id="dnsp-quad9"'),
    "Managed VPN is not immediately to the right of the resolver group",
  );
  assert(
    !choices.includes("partner-dns") && !choices.includes("dnsp-managed-vpn"),
    "an affiliate disclosure crept into the resolver-only button host",
  );
});

check(
  "DNS disclosure changes no resolver state and a resolver restores its copy",
  async () => {
    global.rbResolve.dns_get = {
      supported: true,
      mode: "quad9",
      describe: "Quad9 over encrypted DNS.",
    };
    await openDnsPanel();
    const resolverState = ["dnsp-system", "dnsp-quad9"].map(
      (id) => $(id).classList.contains("active"),
    );
    const description = $("dnsp-describe").textContent;
    global.rbCalls.length = 0;

    $("dnsp-managed-vpn").click();
    await flush();

    const dnsWrites = global.rbCalls.filter((call) => call.cmd === "dns_set");
    const dnsReads = global.rbCalls.filter((call) => call.cmd === "dns_get");
    assert(dnsWrites.length === 0, "Managed VPN sent dns_set");
    assert(
      dnsReads.length === 0,
      "Managed VPN re-read or replaced resolver state",
    );
    assert(
      JSON.stringify(
        ["dnsp-system", "dnsp-quad9"].map((id) =>
          $(id).classList.contains("active"),
        ),
      ) === JSON.stringify(resolverState) &&
        $("dnsp-describe").textContent === description,
      "opening Managed VPN changed the selected resolver or its description",
    );
    assert(
      $("dnsp-quad9").classList.contains("active") &&
        !$("dnsp-managed-vpn").classList.contains("active"),
      "Managed VPN rendered as the chosen resolver or hid the actual Quad9 choice",
    );
    assert(
      $("dnsp-managed-vpn").getAttribute("aria-expanded") === "true" &&
        $("dnsp-managed-vpn-description").hidden === false &&
        $("dnsp-resolver-description").hidden === true,
      "Managed VPN lost its disclosure state or did not replace resolver copy",
    );
    assert(
      $("managed-vpn-dns-framing").textContent ===
        "Managed VPNs add connection-wide privacy through separate paid providers. They work independently of PATANYX, so choosing one here won't change your browser or resolver settings.",
      "the DNS boundary line is missing or changed",
    );
    const cards = placements("partner-dns");
    assert(
      cards.length === 2 &&
        child(cards[0], "pcard-name").textContent === "NordVPN" &&
        child(cards[1], "pcard-name").textContent === "Private Internet Access",
      "partner-dns did not render NordVPN then PIA through the Managed VPN call site",
    );
    for (const card of cards) {
      assert(
        child(card, "pcard-label").textContent === "Affiliate partner" &&
          /earn a commission/i.test(
            child(card, "pcard-disclosure").textContent,
          ),
        "a DNS card lost its structural label or commission line",
      );
    }

    $("dnsp-quad9").click();
    await flush();
    assert(
      $("dnsp-managed-vpn").getAttribute("aria-expanded") === "false" &&
        !$("dnsp-managed-vpn").classList.contains("active") &&
        $("dnsp-managed-vpn-description").hidden === true &&
        $("dnsp-resolver-description").hidden === false &&
        $("dnsp-quad9").classList.contains("active"),
      "clicking a resolver did not restore normal copy and its real selected state",
    );
  },
);

check("relocated cards carry honest textContent framing", () => {
  // The import line is three child nodes: lead text, an emphasized clause,
  // trailing text. The harness stub does not flatten textContent across
  // children, so the copy is checked piece by piece (which also matches how
  // the real DOM renders the emphasis).
  const wgLead =
    "Already have a WireGuard configuration? Import it into Private Tunnel, " +
    "PATANYX's free browser-only option. Only this browser's traffic is " +
    "routed through the server you choose. ";
  const wgEmph = "Private Tunnel is not anonymity:";
  const wgTail =
    " the VPN server can still see the traffic you send through it.";
  assert(
    $("managed-vpn-framing").textContent ===
      "Private Tunnel routes this browser through a WireGuard server you " +
        "supply. These are paid managed VPNs run by their own providers.",
    "the Managed VPN framing is missing or changed",
  );
  for (const id of ["managed-vpn-wireguard", "managed-vpn-dns-wireguard"]) {
    const el = $(id);
    const kids = el.children || [];
    const emph = el.querySelector(".emph");
    assert(
      kids.length === 3 &&
        kids[0].textContent === wgLead &&
        kids[2].textContent === wgTail,
      "the approved WireGuard-import framing is missing or changed on " + id,
    );
    assert(
      emph && emph.textContent === wgEmph,
      "the anonymity disclosure must be emphasized, not plain text, on " + id,
    );
  }
    // The PIA generator note is GONE, 2026-08-27, because the
    // PIA partner card already says "A managed VPN with an official
    // WireGuard config for Private Tunnel" (partner.rs::description), and
    // the footer repeated it at length in BOTH the tunnel and resolver
    // panels. This assertion is removed rather than left pointing at
    // elements that no longer exist.
    //
    // The FTC disclosure duty is untouched by this: it attaches to the
    // partner card, which still carries its "Affiliate partner" label and
    // the commission sentence beside the link. Those are asserted below.
  assert(
    $("vault-sync-framing").textContent ===
      "PATANYX Vault keeps your passwords on this device. To use them on your " +
        "phone or another computer too, NordPass syncs across devices.",
    "the Sync Across Devices framing is missing or changed",
  );
});

check("both human-visible disclosure strings survive on every card", () => {
  for (const host of [
    "partner-dns",
    "partner-tunnel",
    "partner-vault",
    "partner-recall",
  ]) {
    for (const card of placements(host)) {
      const label = child(card, "pcard-label");
      const disclosure = child(card, "pcard-disclosure");
      assert(
        label && label.textContent === "Affiliate partner",
        host + " lost its label",
      );
      assert(
        disclosure && /earn a commission/i.test(disclosure.textContent),
        host + " lost its human disclosure line",
      );
      assert(
        !card.hasAttribute("hidden") &&
          !label.hasAttribute("hidden") &&
          !disclosure.hasAttribute("hidden"),
        host + " put disclosure text in hidden content",
      );
    }
  }
});

check(
  "the Partnerships header control opens the consolidated manager view",
  async () => {
    const asideAt = chromeHtml.indexOf('id="set-aside"');
    const partnershipAt = chromeHtml.indexOf('id="btn-partnerships"');
    const rowEnd = chromeHtml.indexOf("</div>", partnershipAt);
    assert(asideAt >= 0, "#set-aside is missing");
    assert(
      partnershipAt > asideAt && partnershipAt < rowEnd,
      "#btn-partnerships is not to the right of #set-aside in its button row",
    );
    const tag = chromeHtml.slice(
      chromeHtml.lastIndexOf("<button", partnershipAt),
      chromeHtml.indexOf(">", partnershipAt),
    );
    assert(
      /\bclass="[^"]*\bsmall\b/.test(tag),
      "#btn-partnerships does not use the neighbouring small-button class",
    );

    global.rbResolve.partner_list = { items: partners };
    global.rbCalls.length = 0;
    $("btn-partnerships").click();
    await flush();
    assert(
      $("bmm-view-partnerships").hidden === false,
      "the Partnerships view did not open",
    );
    assert(
      $("bmm-view-bookmarks").hidden === true,
      "the bookmarks view stayed visible under Partnerships",
    );
    assert(
      $("bmm-bookmark-tools").hidden === true,
      "bookmark-only controls stayed visible in Partnerships",
    );
    assert(
      $("partner-library-framing").textContent ===
        "Services PATANYX partners with. Each is labeled where it appears, " +
          "and PATANYX may earn a commission.",
      "the consolidated view's textContent framing is missing or changed",
    );
    const cards = $("partner-library").children.filter(
      (node) => node.className === "pcard",
    );
    assert(
      cards.length === partners.length,
      "the consolidated view did not render one direct child card per partner_list item",
    );
    for (let i = 0; i < cards.length; i += 1) {
      assert(
        child(cards[i], "pcard-name").textContent === partners[i].name,
        "the consolidated view changed partner_list order or omitted an item",
      );
      assert(
        child(cards[i], "pcard-label").textContent === "Affiliate partner",
        partners[i].id + " lost its structural Affiliate partner label",
      );
      assert(
        /earn a commission/i.test(
          child(cards[i], "pcard-disclosure").textContent,
        ),
        partners[i].id + " lost its commission line",
      );
    }
    assert(
      global.rbCalls.some((call) => call.cmd === "partner_list"),
      "opening Partnerships did not fetch partner_list",
    );

    $("btn-partnerships").click();
    assert(
      $("bmm-view-bookmarks").hidden === false,
      "pressing Partnerships again did not restore the manager",
    );
    $("btn-partnerships").click();
    const allBookmarks = $("bmm-folders").children.find(
      (button) =>
        button.children[0] &&
        button.children[0].textContent === "All bookmarks",
    );
    assert(allBookmarks, "the manager sidebar did not render All bookmarks");
    allBookmarks.click();
    assert(
      $("bmm-view-bookmarks").hidden === false,
      "a sidebar view did not leave Partnerships",
    );
  },
);

check(
  "the consolidated view explains empty and failed partner_list replies",
  async () => {
    global.rbResolve.partner_list = { items: [] };
    $("btn-partnerships").click();
    await flush();
    assert(
      $("partner-library").children.length === 0,
      "an empty reply left stale partner cards",
    );
    assert(
      $("partner-library-empty").hidden === false &&
        /No partner services/.test($("partner-library-empty").textContent),
      "an empty partner_list reply did not say the view is empty",
    );
    $("btn-partnerships").click();

    global.rbReject = "partner_list_failed";
    $("btn-partnerships").click();
    await flush();
    assert(
      $("partner-library-empty").hidden === false &&
        /could not be loaded/.test($("partner-library-empty").textContent),
      "a failed partner_list request did not say the view failed to load",
    );
    global.rbReject = null;
    $("btn-partnerships").click();
    global.rbResolve.partner_list = { items: partners };
  },
);

check("each CTA sends only an identifier, never a URL", async () => {
  global.rbCalls.length = 0;
  for (const host of [
    "partner-dns",
    "partner-tunnel",
    "partner-vault",
    "partner-recall",
  ]) {
    for (const card of placements(host)) {
      child(card, "small pcard-cta").click();
    }
  }
  await flush();
  const opens = global.rbCalls.filter((call) => call.cmd === "partner_open");
  assert(
    opens.length === 6,
    "expected six partner_open calls, got " + opens.length,
  );
  for (const call of opens) {
    assert(
      call.args && typeof call.args.partner === "string",
      "partner_open did not carry an identifier: " + JSON.stringify(call.args),
    );
    assert(
      Object.keys(call.args).length === 1 && !("url" in call.args),
      "partner_open carried more than its identifier: " +
        JSON.stringify(call.args),
    );
    assert(
      !/:\/\//.test(JSON.stringify(call.args)),
      "a URL crossed the chrome IPC boundary: " + JSON.stringify(call.args),
    );
  }
  assert(
    opens.filter((call) => call.args.partner === "pia").length === 2,
    "both PIA CTAs must send only the pia identifier",
  );
});

check("the PIA target exists only in compiled Rust", () => {
  assert(
    partnerRs.includes("PartnerTarget::Pia") &&
      partnerRs.includes('Self::Pia => "https://'),
    "partner.rs does not define PIA's compiled destination",
  );
  assert(
    !chromeHtml.includes("aff_" + "c?") && !chromeJs.includes("aff_" + "c?"),
    "an affiliate destination leaked into DOM or application JavaScript",
  );
});

check("an unknown identifier opens nothing in the real-dispatch smoke", () => {
  const start = ipcRs.indexOf("pub fn smoke_partner_sequence");
  const end = ipcRs.indexOf("\n}\n", start);
  const smoke = start >= 0 && end > start ? ipcRs.slice(start, end + 3) : "";
  assert(smoke, "ipc::smoke_partner_sequence is missing");
  assert(
    smoke.includes('json!({ "partner": "not-a-partner" })'),
    "the live smoke no longer sends an unknown partner identifier",
  );
  assert(
    smoke.includes("smoke_tab_count(state)?") &&
      smoke.includes("partner_open opened a tab for"),
    "the live smoke no longer proves an unknown identifier opens no tab",
  );
  assert(
    ipcRs.includes("grep -q '^PARTNER ok$'") ||
      fs
        .readFileSync(path.join(root, "scripts/ci-trixie.sh"), "utf8")
        .includes("grep -q '^PARTNER ok$'"),
    "ci-trixie no longer requires the live partner smoke result",
  );
  assert(
    !smoke.includes('"pia"'),
    "PIA was added to the real-navigation smoke; verify it only through stubs",
  );
});

check("an inapplicable partner produces no empty card", async () => {
  global.rbResolve.partner_list = {
    items: partners.filter((partner) => partner.id !== "coveron"),
  };
  $("btn-tab-recall").click();
  await flush();
  assert(
    !placement("partner-recall"),
    "an omitted partner left an empty or stale Recall card",
  );
});

(async () => {
  for (const [name, fn] of checks) {
    try {
      await fn();
      console.log("  ok: " + name);
    } catch (error) {
      failures.push(name + ": " + error.message);
      console.log("  FAIL: " + name + ": " + error.message);
    }
  }
  if (failures.length) {
    console.error("partner-gate: " + failures.length + " check(s) failed");
    process.exit(1);
  }
  console.log("partner-gate OK (" + checks.length + " checks)");
})();
