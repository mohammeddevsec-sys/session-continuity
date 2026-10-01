import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "url";
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const FILE = path.join(__dirname, "PAPER.tex");
const src = fs.readFileSync(FILE, "utf8");
const lines = src.split(/\r?\n/);
const errors = [];

// 1. Brace balance (ignore \{ and \})
let depth = 0;
const stack = [];
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  for (let j = 0; j < line.length; j++) {
    const prev = j > 0 ? line[j-1] : "";
    if (prev === "\\") continue;
    const c = line[j];
    if (c === "{") { depth++; stack.push({line: i+1, col: j+1}); }
    else if (c === "}") {
      depth--;
      stack.pop();
      if (depth < 0) { errors.push("UNBALANCED_CLOSE_BRACE at line " + (i+1)); depth = 0; }
    }
  }
}
if (depth !== 0) {
  errors.push("UNCLOSED_BRACES: " + depth);
  for (const b of stack.slice(0,5)) errors.push("  unclosed { at line " + b.line + " col " + b.col);
}

// 2. Environment balance
const envStack = [];
const envRe = /\\(begin|end)\{([^}]+)\}/g;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  let m;
  envRe.lastIndex = 0;
  while ((m = envRe.exec(line)) !== null) {
    const kind = m[1], env = m[2];
    if (kind === "begin") envStack.push({env, line: i+1});
    else {
      if (envStack.length === 0) errors.push("END_WITHOUT_BEGIN: \\end{" + env + "} at line " + (i+1));
      else {
        const top = envStack.pop();
        if (top.env !== env) errors.push("ENV_MISMATCH at line " + (i+1) + ": \\end{" + env + "} expected \\end{" + top.env + "} (opened at line " + top.line + ")");
      }
    }
  }
}
if (envStack.length > 0) {
  for (const e of envStack) errors.push("UNCLOSED_ENV: \\begin{" + e.env + "} at line " + e.line);
}

// 3. Math mode $ balance (single $ toggle; skip \$, and skip inside lstlisting)
let inMath = false, mathStart = 0;
let inLst = false;
for (let i = 0; i < lines.length; i++) {
  const line = lines[i];
  if (/\\begin\{lstlisting\}/.test(line)) inLst = true;
  if (/\\end\{lstlisting\}/.test(line)) { inLst = false; continue; }
  if (inLst) continue;
  for (let j = 0; j < line.length; j++) {
    const prev = j > 0 ? line[j-1] : "";
    if (prev === "\\") continue;
    if (line[j] === "$") {
      if (inMath) inMath = false;
      else { inMath = true; mathStart = i+1; }
    }
  }
}
if (inMath) errors.push("UNCLOSED_MATH_MODE starting at line " + mathStart);

// 4. Required environments
for (const e of ["document","abstract","thebibliography"]) {
  const hasB = new RegExp("\\\\begin\\{" + e + "\\}").test(src);
  const hasE = new RegExp("\\\\end\\{" + e + "\\}").test(src);
  if (!hasB) errors.push("MISSING_ENV_BEGIN: " + e);
  if (!hasE) errors.push("MISSING_ENV_END: " + e);
}

// 5. Required preamble packages
for (const pkg of ["inputenc","fontenc","geometry","hyperref","booktabs","amsmath","longtable","array","listings"]) {
  const re = new RegExp("\\\\usepackage(\\[[^\\]]*\\])?\\{" + pkg + "\\}");
  if (!re.test(src)) errors.push("MISSING_PACKAGE: " + pkg);
}

// 6. Counts
const bibItems = (src.match(/\\bibitem/g) || []).length;
const sections = (src.match(/^\\section\{/gm) || []).length;
const subsections = (src.match(/^\\subsection\{/gm) || []).length;

console.log("LATEX_FILE=" + FILE);
console.log("LINES=" + lines.length);
console.log("SIZE=" + src.length);
console.log("SECTIONS=" + sections);
console.log("SUBSECTIONS=" + subsections);
console.log("BIBITEMS=" + bibItems);
console.log("BRACE_BALANCE=" + (depth === 0 ? "OK" : "FAIL"));
console.log("ENV_BALANCE=" + (envStack.length === 0 ? "OK" : "FAIL"));
console.log("MATH_BALANCE=" + (inMath ? "FAIL" : "OK"));
console.log("ERROR_COUNT=" + errors.length);
if (errors.length === 0) console.log("LATEX_AUDIT=PASS");
else {
  console.log("LATEX_AUDIT=FAIL");
  for (const e of errors) console.log("ERROR: " + e);
}