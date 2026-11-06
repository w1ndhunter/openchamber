// Writes inside isolated spaces that are waiting for the user, as the host announced them. The
// gatekeeper holds the request open, so a prompt has to appear without the user opening anything;
// the list lives until each one is answered or its time runs out. Runtime-scoped like the rest.

import { create } from 'zustand';

import type { SpaceApprovalRequest } from '@/sync/event-pipeline';
import { spaceIdOfDirectory } from './space-route';

type SpaceApprovalsState = {
  requests: readonly SpaceApprovalRequest[];
  /** A wait the host announced; the same one twice, after a host restart, stays one. */
  note: (request: SpaceApprovalRequest) => void;
  /** One that was answered, or whose time ran out. */
  settle: (spaceId: string, requestId: number) => void;
  forgetSpace: (spaceId: string) => void;
  resetForRuntimeSwitch: () => void;
};

export const useSpaceApprovalsStore = create<SpaceApprovalsState>((set) => ({
  requests: [],
  note: (request) => set((state) => (
    state.requests.some((known) => known.spaceId === request.spaceId && known.requestId === request.requestId)
      ? state
      : { requests: [...state.requests, request] }
  )),
  settle: (spaceId, requestId) => set((state) => ({
    requests: state.requests.filter((request) => request.spaceId !== spaceId || request.requestId !== requestId),
  })),
  forgetSpace: (spaceId) => set((state) => ({ requests: state.requests.filter((request) => request.spaceId !== spaceId) })),
  resetForRuntimeSwitch: () => set({ requests: [] }),
}));

/**
 * The waits a chat offers: those of the space its directory belongs to. A chat outside every
 * space, and a wait of another space, show nothing here.
 */
export const approvalsOfDirectory = (
  requests: readonly SpaceApprovalRequest[],
  directory: string | null | undefined,
): readonly SpaceApprovalRequest[] => {
  const spaceId = spaceIdOfDirectory(directory ?? null);
  return spaceId === null ? [] : requests.filter((request) => request.spaceId === spaceId);
};

/** Whether a request's held time has passed, so its prompt can close itself. */
export const approvalExpired = (request: SpaceApprovalRequest, at: number = Date.now()): boolean => {
  const expires = Date.parse(request.expiresAt);
  return Number.isFinite(expires) && expires <= at;
};
