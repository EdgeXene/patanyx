#!/usr/bin/env node
// Print uses of `innerHTML` after removing comments, preserving newlines so
// every finding still names its real source line. Strings are deliberately
// retained: a string spelling the API is still executable source and deserves
// a human look; only comments are outside this gate's subject.

const fs = require("fs");
const path = require("path");

const root = process.argv[2];
if (!root || !fs.statSync(root).isDirectory()) {
  console.error("usage: innerhtml-code-gate.js CHROME_DIR");
  process.exit(2);
}

function sourceFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const item = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...sourceFiles(item));
    else if (entry.isFile()) out.push(item);
  }
  return out.sort();
}

function blankComments(source) {
  let out = "";
  let mode = "code";
  let quote = "";
  let escaped = false;

  for (let i = 0; i < source.length; i += 1) {
    const ch = source[i];
    const next = source[i + 1] || "";

    if (mode === "line") {
      if (ch === "\n") {
        out += ch;
        mode = "code";
      } else {
        out += " ";
      }
      continue;
    }
    if (mode === "block") {
      if (ch === "*" && next === "/") {
        out += "  ";
        i += 1;
        mode = "code";
      } else {
        out += ch === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (mode === "html-block") {
      if (source.startsWith("-->", i)) {
        out += "   ";
        i += 2;
        mode = "code";
      } else {
        out += ch === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (mode === "quote") {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === "\\") escaped = true;
      else if (ch === quote) mode = "code";
      continue;
    }

    if (source.startsWith("<!--", i)) {
      out += "    ";
      i += 3;
      mode = "html-block";
    } else if (ch === "/" && next === "/") {
      out += "  ";
      i += 1;
      mode = "line";
    } else if (ch === "/" && next === "*") {
      out += "  ";
      i += 1;
      mode = "block";
    } else {
      out += ch;
      if (ch === "'" || ch === '"' || ch === "`") {
        mode = "quote";
        quote = ch;
        escaped = false;
      }
    }
  }
  return out;
}

let findings = 0;
for (const file of sourceFiles(root)) {
  const original = fs.readFileSync(file, "utf8");
  const code = blankComments(original);
  const originalLines = original.split(/\r?\n/);
  code.split(/\r?\n/).forEach((line, index) => {
    if (line.includes("innerHTML")) {
      findings += 1;
      console.log(`${file}:${index + 1}:${originalLines[index]}`);
    }
  });
}

if (findings) {
  console.error("GATE FAIL: innerHTML in chrome code - it holds IPC and the vault");
  process.exit(1);
}
console.log("  none (comments ignored)");
