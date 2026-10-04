import crypto from "node:crypto";

/**
 * RFC 6962-style Merkle tree (Certificate Transparency compatible).
 * Leaves and internal nodes use different prefixes to prevent
 * second-preimage attacks.
 */

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;

export function hashLeaf(data) {
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, "utf8");
  const h = crypto.createHash("sha256");
  h.update(Buffer.from([LEAF_PREFIX]));
  h.update(buf);
  return h.digest();
}

export function hashNode(left, right) {
  const h = crypto.createHash("sha256");
  h.update(Buffer.from([NODE_PREFIX]));
  h.update(left);
  h.update(right);
  return h.digest();
}

export function buildTree(leaves) {
  if (leaves.length === 0) return { root: null, levels: [[]] };
  let level = leaves.map(hashLeaf);
  const levels = [level];
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(hashNode(level[i], level[i + 1]));
      } else {
        // Odd leaf: promote as-is (RFC 6962 rule)
        next.push(level[i]);
      }
    }
    level = next;
    levels.push(level);
  }
  return { root: level[0], levels };
}

export function inclusionProof(leaves, index) {
  if (index < 0 || index >= leaves.length) {
    throw new Error(`index ${index} out of range [0, ${leaves.length})`);
  }
  const hashed = leaves.map(hashLeaf);
  const proof = [];
  let idx = index;
  let level = hashed;

  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(hashNode(level[i], level[i + 1]));
      } else {
        next.push(level[i]);
      }
    }
    const isRight = idx % 2 === 1;
    const siblingIdx = isRight ? idx - 1 : idx + 1;
    if (siblingIdx < level.length) {
      proof.push({ hash: level[siblingIdx], side: isRight ? "left" : "right" });
    }
    idx = Math.floor(idx / 2);
    level = next;
  }
  return proof;
}

export function verifyInclusion(leafData, proof, root) {
  let h = hashLeaf(leafData);
  for (const step of proof) {
    if (step.side === "left") {
      h = hashNode(step.hash, h);
    } else {
      h = hashNode(h, step.hash);
    }
  }
  return h.equals(root);
}
