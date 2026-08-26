import type { ProxyNode } from "./types";

interface NodeSelectionRecord {
  nodeId: string;
  identity: string;
}

interface NodeSelectionStore {
  bySubscription: Record<string, NodeSelectionRecord>;
}

const STORAGE_KEY = "satelite.nodeSelection.v1";

function readStore(): NodeSelectionStore {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { bySubscription: {} };
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { bySubscription: {} };
    }
    const store = parsed as NodeSelectionStore;
    if (!store.bySubscription || typeof store.bySubscription !== "object") {
      return { bySubscription: {} };
    }
    return store;
  } catch {
    return { bySubscription: {} };
  }
}

function writeStore(store: NodeSelectionStore) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
  } catch {
    /* keep the in-memory copy for this session */
  }
}

export function nodeSelectionIdentity(node: {
  subscription_id?: string | null;
  protocol: string;
  server: string;
  port: number;
}): string {
  return `${node.subscription_id ?? "global"}|${node.protocol.toLowerCase()}|${
    node.server
  }:${node.port}`;
}

/** Remember the manually picked node per subscription. */
export function rememberNodeSelection(node: {
  id: string;
  subscription_id?: string | null;
  protocol: string;
  server: string;
  port: number;
}) {
  const subId = node.subscription_id;
  if (!subId) return;
  const store = readStore();
  store.bySubscription[subId] = {
    nodeId: node.id,
    identity: nodeSelectionIdentity(node),
  };
  writeStore(store);
}

/**
 * Resolve the last saved selection for a subscription. Falls back to matching
 * the saved endpoint identity when a refresh rotated the content-hash id.
 */
export function resolvePreferredNode(
  nodes: ProxyNode[],
  subscriptionId?: string | null,
): ProxyNode | undefined {
  if (!subscriptionId) return undefined;
  const store = readStore();
  const record = store.bySubscription[subscriptionId];
  if (!record) return undefined;
  const byId = nodes.find((n) => n.id === record.nodeId);
  if (byId) return byId;
  return nodes.find((n) => nodeSelectionIdentity(n) === record.identity);
}
