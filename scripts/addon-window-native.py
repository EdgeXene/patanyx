#!/usr/bin/env python3
"""Native Linux allocation timing with a generated dummy bundle.
Run from a real desktop, or: xvfb-run -a python3 scripts/addon-window-native.py
Requires a window manager and xdotool in the display. This is not a hardware qualification.
--plant-delay changes the actual host path, builds, expects p95 to fail, and
restores the source. A missing sample or failed launch never counts as detection.
"""
import argparse
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
HOST = ROOT / "crates/app/src/addon_host.rs"
TARGET = "let r = clamp_rect(wanted, area.2, area.3, collapsed);"
JS = r'''
"use strict";
let serial = 0;
const pending = new Map();
function call(command, args) {
  return new Promise((resolve, reject) => {
    const id = ++serial; pending.set(id, {resolve, reject});
    window.ipc.postMessage(JSON.stringify({v:1,id,generation:window.__addonHost.generation,command,args,presence:false}));
  });
}
window.__addonReceive = message => {
  if (message.event === "addon_flush") {
    call("addon_flush_done", {flush_id:message.data.flush_id,status:"saved"}); return;
  }
  const p = pending.get(message.id);
  if (p) { pending.delete(message.id); message.ok ? p.resolve(message.result) : p.reject(message.error); }
};
let sequence = 0;
let keyIndex = 0;
const expectedKeys = "abcdefg";
document.querySelector("textarea").addEventListener("keydown", event => {
  if (!event.ctrlKey && !event.altKey && event.key.length === 1) {
    const marker = event.key === expectedKeys[keyIndex] ? 1001 + keyIndex++ : 9000;
    call("window_move", {x:45+keyIndex,y:40,sequence:marker});
  }
});
// Every pointer move is forwarded immediately. No debounce or coalescing here.
document.addEventListener("pointermove", event => {
  if (event.buttons === 1) call("window_move", {x:event.clientX,y:event.clientY,sequence:++sequence});
});
(async () => {
  await call("addon_ready", {host_api:1});
  await new Promise(r => setTimeout(r, 2500));
  for (let i=0; i<120; i++) {
    await call("window_move", {x:20+i%100,y:40,sequence:++sequence});
    await new Promise(r => setTimeout(r, 50));
  }
})();
'''

def p95(values):
    return sorted(values)[math.ceil(len(values) * .95) - 1] / 1000

def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plant-delay", action="store_true")
    args = parser.parse_args()
    if not os.environ.get("DISPLAY"):
        raise RuntimeError("A working display and window manager are required")
    original = HOST.read_text()
    if original.count(TARGET) != 1:
        raise RuntimeError("Missing or ambiguous geometry timing target")
    try:
        if args.plant_delay:
            HOST.write_text(original.replace(TARGET, "std::thread::sleep(std::time::Duration::from_millis(50)); " + TARGET))
        subprocess.run(["cargo", "build", "--offline", "-p", "patanyx"], cwd=ROOT, check=True)
        with tempfile.TemporaryDirectory(prefix="addon-window-") as tmp:
            tmp = Path(tmp)
            bundle = tmp / "bundle"; bundle.mkdir()
            (bundle / "index.html").write_text('<!doctype html><html><head><link rel="stylesheet" href="style.css"></head><body><textarea autofocus></textarea><script src="main.js"></script></body></html>')
            (bundle / "main.js").write_text(JS)
            (bundle / "style.css").write_text('html,body,textarea {margin:0;width:100%;height:100%;box-sizing:border-box} textarea {background:#1b5e20;color:#fff}')
            env = dict(os.environ, PATANYX_DATA_DIR=str(tmp / "profile"), XDG_DATA_HOME=str(tmp / "data"), XDG_CACHE_HOME=str(tmp / "cache"), XDG_CONFIG_HOME=str(tmp / "config"),
                PATANYX_ADDON_DEV_BUNDLE=str(bundle), PATANYX_DEV_VAULT_PASSPHRASE="disposable-test-passphrase",
                PATANYX_ADDON_WINDOW_TIMING="1")
            binary = Path(env.get("CARGO_TARGET_DIR", str(ROOT / "target"))) / "debug/patanyx"
            with (tmp / "run.log").open("w+") as log:
                proc = subprocess.Popen([str(binary)], cwd=ROOT, env=env, stdout=log, stderr=log)
                try:
                    end = time.monotonic() + 45
                    while time.monotonic() < end:
                        time.sleep(.5)
                        log.flush(); log.seek(0); output = log.read()
                        if len(re.findall(r"addon-motion host_us=(\d+)", output)) >= 120: break
                        if proc.poll() is not None: raise RuntimeError("Browser exited before measurement\n" + output[-3000:])
                    # After the timing sequence, a real click gives the editor
                    # its first keystroke. Every following native shortcut must
                    # keep that caret; the palette must intercept its own input.
                    window_id = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--pid", str(proc.pid)], text=True).splitlines()[0]
                    subprocess.run(["xdotool", "windowactivate", "--sync", window_id], check=True)
                    # Click the add-on itself, wherever the page area put it
                    # (banners above the page move it): its editor is the only
                    # #1b5e20 area on screen.
                    shot = tmp / "focus.png"
                    subprocess.run(["import", "-window", "root", str(shot)], check=True)
                    from PIL import Image
                    img = Image.open(shot).convert("RGB"); px = img.load()
                    hits = [(x, y) for y in range(0, img.size[1], 4) for x in range(0, img.size[0], 4)
                            if abs(px[x, y][0] - 27) < 8 and abs(px[x, y][1] - 94) < 8 and abs(px[x, y][2] - 32) < 8]
                    if not hits:
                        raise RuntimeError("The add-on's editor is not on screen")
                    cx = (min(h[0] for h in hits) + max(h[0] for h in hits)) // 2
                    cy = (min(h[1] for h in hits) + max(h[1] for h in hits)) // 2
                    subprocess.run(["xdotool", "mousemove", str(cx), str(cy), "click", "1"], check=True)
                    def key(chord):
                        subprocess.run(["xdotool", "key", "--clearmodifiers", chord], check=True)
                        time.sleep(.2)
                    def expect(chord, marker):
                        key(chord)
                        for _ in range(30):
                            log.flush(); log.seek(0); text = log.read()
                            if "sequence=9000" in text: raise RuntimeError("Keyboard reached the add-on during the wrong step")
                            if f"sequence={marker}" in text: return
                            time.sleep(.1)
                        raise RuntimeError(f"Missing native keyboard proof {marker} after {chord}")
                    expect("a", 1001)
                    key("ctrl+t"); expect("b", 1002)
                    key("ctrl+shift+Tab"); expect("c", 1003)
                    key("ctrl+w"); expect("d", 1004)
                    key("ctrl+k"); key("x"); key("Escape"); expect("e", 1005)
                    key("ctrl+shift+j"); key("ctrl+shift+j"); expect("f", 1006)
                    key("Escape"); key("ctrl+shift+j"); expect("g", 1007)
                    print("Native focus: first key, tab create/switch/close, modal precedence, toggle and Escape passed")
                finally:
                    if proc.poll() is None: proc.terminate()
                    try: proc.wait(timeout=10)
                    except subprocess.TimeoutExpired: proc.kill(); proc.wait()
                log.seek(0); output = log.read()
            applied = [int(v) for v in re.findall(r"addon-motion applied_us=(\d+)", output)]
            host = [int(v) for v in re.findall(r"addon-motion host_us=(\d+)", output)]
            if len(applied) < 100 or len(host) < 100:
                raise RuntimeError(f"Incomplete native measurements: {len(applied)} applied, {len(host)} host\n" + output[-3000:])
            print(f"Native event-to-applied p95 {p95(applied):.3f} ms ({len(applied)} samples); host handling p95 {p95(host):.3f} ms")
            if args.plant_delay:
                if p95(applied) < 50: raise RuntimeError("Planted 50 ms delay was not detected")
                print("CAUGHT motion-50ms on native allocation")
            elif p95(applied) >= 33:
                raise RuntimeError("Native p95 exceeds two 60 Hz frames (33 ms)")
    finally:
        if args.plant_delay: HOST.write_text(original)

if __name__ == "__main__": run()
