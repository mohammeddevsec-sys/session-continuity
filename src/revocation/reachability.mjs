/**
 * Compute which nodes are reachable from the root
 * given a set of active edges.
 *
 * Uses BFS. Result: Map<nodeId, {reachable: bool, path: [edgeId...]}>
 */
export function computeReachability(rootId, activeEdges) {
  // Build adjacency list
  const adj = new Map();
  for (const e of activeEdges) {
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from).push({ to: e.to, edgeId: e.edgeId });
  }

  const result = new Map();
  result.set(rootId, { reachable: true, path: [] });

  const queue = [rootId];
  while (queue.length > 0) {
    const node = queue.shift();
    const neighbors = adj.get(node) || [];
    for (const { to, edgeId } of neighbors) {
      if (!result.has(to) || !result.get(to).reachable) {
        const parentPath = result.get(node).path;
        result.set(to, {
          reachable: true,
          path: [...parentPath, edgeId]
        });
        queue.push(to);
      }
    }
  }

  // Mark unreachable explicitly
  const allNodes = new Set();
  allNodes.add(rootId);
  for (const e of activeEdges) {
    allNodes.add(e.from);
    allNodes.add(e.to);
  }
  for (const n of allNodes) {
    if (!result.has(n)) {
      result.set(n, { reachable: false, path: null });
    }
  }

  return result;
}

/**
 * Return only the nodes that lost reachability when
 * going from "before" to "after".
 */
export function diffReachability(before, after) {
  const affected = [];
  const unaffected = [];
  for (const [node, info] of after) {
    if (info.reachable) {
      unaffected.push(node);
    } else if (before.has(node) && before.get(node).reachable) {
      affected.push(node);
    }
  }
  return { affected: affected.sort(), unaffected: unaffected.sort() };
}
