import { useCallback, useState } from "react";

export type NodeTagId = "pure" | "home" | "backup" | "avoid";

export const NODE_TAG_IDS: readonly NodeTagId[] = [
  "pure",
  "home",
  "backup",
  "avoid",
];

export type NodeTagMap = Record<string, NodeTagId>;

const STORAGE_KEY = "satelite.nodeTags.v1";

/**
 * Tags follow the subscription + endpoint (proto/server/port), so they survive
 * subscription refreshes even when the content-hash node id rotates.
 */
export function nodeTagKey(node: {
  subscription_id?: string | null;
  protocol: string;
  server: string;
  port: number;
}): string {
  return `${node.subscription_id ?? "global"}|${node.protocol.toLowerCase()}|${
    node.server
  }:${node.port}`;
}

function readNodeTags(): NodeTagMap {
  const valid = new Set<NodeTagId>(NODE_TAG_IDS);
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return {};
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      return {};
    }
    const out: NodeTagMap = {};
    for (const [key, value] of Object.entries(parsed)) {
      if (typeof value === "string" && valid.has(value as NodeTagId)) {
        out[key] = value as NodeTagId;
      }
    }
    return out;
  } catch {
    return {};
  }
}

function writeNodeTags(tags: NodeTagMap) {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(tags));
  } catch {
    /* keep the in-memory copy for this session */
  }
}

export function useNodeTags() {
  const [tags, setTags] = useState<NodeTagMap>(readNodeTags);

  const setNodeTag = useCallback((key: string, tag: NodeTagId | null) => {
    setTags((prev) => {
      const next = { ...prev };
      if (tag) next[key] = tag;
      else delete next[key];
      writeNodeTags(next);
      return next;
    });
  }, []);

  return { nodeTags: tags, setNodeTag };
}
