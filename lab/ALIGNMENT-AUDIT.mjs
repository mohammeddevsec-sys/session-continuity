import fs from "node:fs";
import path from "node:path";

import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.resolve(__dirname, "..");
const MD   = path.join(ROOT, "lab", "PAPER.md");
const TEX  = path.join(ROOT, "lab", "PAPER.tex");

const mdSrc  = fs.readFileSync(MD,  "utf8");
const texSrc = fs.readFileSync(TEX, "utf8");

function stripNumericPrefix(title){
  const t = title.trim();
  const sp = t.indexOf(" ");
  if (sp <= 0) return t;
  const head = t.substring(0, sp);
  let allNumOrDot = head.length > 0;
  for (let i = 0; i < head.length; i++){
    const c = head.charCodeAt(i);
    if ((c < 48 || c > 57) && c !== 46) { allNumOrDot = false; break; }
  }
  if (allNumOrDot) return t.substring(sp + 1).trim();
  return t;
}

function coreTitle(title){
  const t = title.trim();
  for (let i = 0; i < t.length; i++){
    const c = t.charCodeAt(i);
    if (c === 0x2014 || c === 0x2013){
      return t.substring(0, i).trim();
    }
  }
  const idx = t.indexOf(" - ");
  if (idx > 0) return t.substring(0, idx).trim();
  return t;
}

function mdSections(src){
  const out = [];
  for (const line of src.split("\n")){
    let level = 0, rest = "";
    if (line.startsWith("### ")) { level = 3; rest = line.substring(4); }
    else if (line.startsWith("## ")) { level = 2; rest = line.substring(3); }
    else continue;
    out.push({level, title: coreTitle(stripNumericPrefix(rest))});
  }
  return out;
}

function texSections(src){
  const out = [];
  for (const raw of src.split("\n")){
    const line = raw.trim();
    let level = 0, inner = "";
    if (line.startsWith("\\subsection{")) { level = 3; inner = line.substring(12); }
    else if (line.startsWith("\\section{")) { level = 2; inner = line.substring(9); }
    else continue;
    const close = inner.indexOf("}");
    if (close < 0) continue;
    out.push({level, title: coreTitle(inner.substring(0, close).trim())});
  }
  return out;
}

function normalize(s){
  let buf = "";
  for (let i = 0; i < s.length; i++){
    const c = s[i];
    const code = s.charCodeAt(i);
    if (code >= 65 && code <= 90) buf += c.toLowerCase();
    else if (code >= 97 && code <= 122) buf += c;
    else if (code >= 48 && code <= 57) buf += c;
    else if (code === 32 || code === 45 || code === 95) buf += " ";
  }
  let out = "";
  let last = "";
  for (let i = 0; i < buf.length; i++){
    if (buf[i] === " "){ if (last !== " "){ out += " "; last = " "; } }
    else { out += buf[i]; last = buf[i]; }
  }
  return out.trim();
}

const mdBody  = mdSections(mdSrc).filter(s => !(s.level === 2 && (normalize(s.title) === "abstract" || normalize(s.title) === "references")));
const texBody = texSections(texSrc);

let mismatches = 0;
const issues = [];
const max = Math.max(mdBody.length, texBody.length);
for (let i = 0; i < max; i++){
  const a = mdBody[i]  ? normalize(mdBody[i].title)  : "";
  const b = texBody[i] ? normalize(texBody[i].title) : "";
  const aL = mdBody[i]  ? mdBody[i].level : 0;
  const bL = texBody[i] ? texBody[i].level : 0;
  if (a !== b || aL !== bL){
    mismatches++;
    if (issues.length < 10) issues.push("L" + aL + "/L" + bL + "  MD=[" + a + "]  TEX=[" + b + "]");
  }
}

const tokens = [
  {d:"251",   md:"251",   tex:"251"},
  {d:"20",    md:"20",    tex:"20"},
  {d:"38",    md:"38",    tex:"38"},
  {d:"12",    md:"12",    tex:"12"},
  {d:"34",    md:"thirty-four",    tex:"thirty-four"},
  {d:"9",     md:"9",     tex:"9"},
  {d:"28",    md:"28",    tex:"28"},
  {d:"1000",  md:"1,000", tex:"1{,}000"},
  {d:"71",    md:"71",    tex:"71"},
  {d:"130",   md:"130",   tex:"130"},
  {d:"48FF8147", md:"48FF8147", tex:"48FF8147"},
  {d:"941DE3DA", md:"941DE3DA", tex:"941DE3DA"},
  {d:"883FEBE7", md:"883FEBE7", tex:"883FEBE7"}
];

const missing = [];
for (const t of tokens){
  const inMd  = mdSrc.includes(t.md);
  const inTex = texSrc.includes(t.tex);
  if (!inMd || !inTex){
    mismatches++;
    missing.push(t.d + "(MD=" + (inMd?"Y":"N") + ",TEX=" + (inTex?"Y":"N") + ")");
  }
}

console.log("MD_BODY_SECTIONS=" + mdBody.length);
console.log("TEX_BODY_SECTIONS=" + texBody.length);
console.log("NUMERIC_TOKENS=" + tokens.length);
console.log("MISSING_TOKENS=" + (missing.length === 0 ? "NONE" : missing.join(",")));
console.log("SECTION_MISMATCHES=" + issues.length);
for (const i of issues) console.log("  " + i);
console.log("TOTAL_ISSUES=" + mismatches);
console.log("ALIGNMENT_AUDIT=" + (mismatches === 0 ? "PASS" : "FAIL"));
