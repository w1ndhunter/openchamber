// The environment source a new space is being made with, as the dialog holds it, and the request
// the host takes from it.

import type { SpaceEnvironmentOptIns, SpaceEnvironmentSourceRequest } from '@/lib/spaces/spaces-api';

export type EnvironmentDraft = {
  kind: 'none' | 'folder' | 'git';
  location: string;
  ref: string;
  memory: 'off' | 'read' | 'write';
  delivery: 'snapshot' | 'mount';
  optIns: SpaceEnvironmentOptIns;
};

export const noOptIns = (): SpaceEnvironmentOptIns => ({ agents: [], mcp: [], plugins: [], commands: [], skills: [], formatter: false, skillSources: [] });

export const emptyEnvironmentDraft = (): EnvironmentDraft => ({ kind: 'none', location: '', ref: '', memory: 'off', delivery: 'snapshot', optIns: noOptIns() });

/** The request the host takes, or null for none. A mount is a folder's only. */
export const environmentRequestOf = (draft: EnvironmentDraft): SpaceEnvironmentSourceRequest | null => (draft.kind === 'none' ? null : {
  kind: draft.kind,
  location: draft.location.trim(),
  ref: draft.kind === 'git' ? draft.ref.trim() : '',
  memory: draft.memory,
  delivery: draft.kind === 'folder' ? draft.delivery : 'snapshot',
  optIns: draft.optIns,
});

export const isEnvironmentDraftComplete = (draft: EnvironmentDraft) => draft.kind === 'none' || draft.location.trim() !== '';
