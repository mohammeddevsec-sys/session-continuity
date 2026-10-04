const fs = require("fs");
const path = "src/core/transactional-final-proof-pipeline.js";
const raw = fs.readFileSync(path, "utf8");
const eol = raw.includes("\r\n") ? "\r\n" : "\n";
const lines = raw.split(/\r?\n/);

// Find commit line
const commitLineIdx = lines.findIndex(l => l.includes("const committed=commitSessionAcceptance"));
if (commitLineIdx === -1) {
  console.error("COMMIT_LINE_NOT_FOUND");
  process.exit(1);
}
console.log("commit line at index " + commitLineIdx);

// CORRECT CHECK: only look for USAGE, not import
const usageAlreadyPresent = lines.some((l, i) =>
  i !== 12 && l.includes("claimContinuationSlot(")
);
if (usageAlreadyPresent) {
  console.log("ALREADY_PATCHED_USAGE");
  process.exit(0);
}

// Verify structure of failure branch
if (!lines[commitLineIdx + 1].includes("if(committed.decision")) { console.error("STRUCT_MISMATCH_1"); process.exit(1); }
if (!lines[commitLineIdx + 2].includes("fs.rmSync")) { console.error("STRUCT_MISMATCH_2"); process.exit(1); }
if (!lines[commitLineIdx + 3].includes("return failure")) { console.error("STRUCT_MISMATCH_3"); process.exit(1); }
if (!lines[commitLineIdx + 4].trim().startsWith("}")) { console.error("STRUCT_MISMATCH_4"); process.exit(1); }

// Insert fork claim BEFORE the commit line
const insertBefore = [
  "    const forkAnchorFp = fingerprint(anchor);",
  "    const forkClaim = claimContinuationSlot({",
  "      anchorFingerprint: forkAnchorFp,",
  "      parentSequence: lastSequence,",
  "      metadata: { sessionId: anchor.sessionId, presentedSequence: sequence, timestamp }",
  "    });",
  "    if (!forkClaim.claimed) {",
  "      fs.rmSync(stagingRoot,{recursive:true,force:true});",
  "      return failure(\"REAUTH_REQUIRED\",\"FORK_DETECTED\",[\"fork\"]);",
  "    }",
  ""
];

// Insert release on failure inside commit branch (at commitLineIdx+2 position originally, +offset after insert)
const releaseLine = "      releaseContinuationSlot({ anchorFingerprint: forkAnchorFp, parentSequence: lastSequence });";

const newLines = [];
for (let i = 0; i < lines.length; i++) {
  if (i === commitLineIdx) {
    for (const l of insertBefore) newLines.push(l);
    newLines.push(lines[i]);
  } else if (i === commitLineIdx + 2) {
    newLines.push(releaseLine);
    newLines.push(lines[i]);
  } else {
    newLines.push(lines[i]);
  }
}

fs.writeFileSync(path, newLines.join(eol), "utf8");
console.log("PATCH_APPLIED");
