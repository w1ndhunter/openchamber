// Writes inside isolated spaces that are waiting for the user, as the host announced them. The
// gatekeeper holds the request open, so a prompt has to appear without the user opening anything;
// the list lives until each one is answered or its time runs out. Runtime-scoped like the rest.

import { create } from 'zustand';

import type { SpaceApprovalRequest } from '@/sync/event-pipeline';
import { spaceIdOfDirectory } from './space-route';

type SpaceApprovalsState = {
  requests: readonly SpaceApprovalRequest[];
  /**
   * A wait the host announced. The same id again after a host restart is the same wait; the same
   * id with another destination is a gatekeeper that restarted, whose ids begin at one again, so
   * it replaces what the list held rather than being mistaken for it.
   */
  note: (request: SpaceApprovalRequest) => void;
  /** One that was answered, or whose time ran out. */
  settle: (spaceId: string, requestId: number) => void;
  /**
   * Every wait a standing answer covers: the gatekeeper settles all writes of that destination and
   * method at once and announces no end for them.
   */
  settleCovered: (spaceId: string, host: string, method: string, path?: string) => void;
  /** Drops the waits the gatekeeper has already refused, which it announces no end for. */
  pruneExpired: (at?: number) => void;
  forgetSpace: (spaceId: string) => void;
  resetForRuntimeSwitch: () => void;
};

const sameWait = (known: SpaceApprovalRequest, request: SpaceApprovalRequest) =>
  known.spaceId === request.spaceId && known.requestId === request.requestId;

/** Whether a request's held time has passed, so its prompt can close itself. */
export const approvalExpired = (request: SpaceApprovalRequest, at: number = Date.now()): boolean => {
  const expires = Date.parse(request.expiresAt);
  return Number.isFinite(expires) && expires <= at;
};

export const useSpaceApprovalsStore = create<SpaceApprovalsState>((set) => ({
  requests: [],
  note: (request) => set((state) => ({
    requests: state.requests.some((known) => sameWait(known, request))
      ? state.requests.map((known) => (sameWait(known, request) ? request : known))
      : [...state.requests, request],
  })),
  settle: (spaceId, requestId) => set((state) => ({
    requests: state.requests.filter((request) => request.spaceId !== spaceId || request.requestId !== requestId),
  })),
  settleCovered: (spaceId, host, method, path) => set((state) => ({
    requests: state.requests.filter((request) => request.spaceId !== spaceId
      || request.host !== host
      || request.method !== method
      || (path !== undefined && request.path !== path)),
  })),
  pruneExpired: (at = Date.now()) => set((state) => {
    const requests = state.requests.filter((request) => !approvalExpired(request, at));
    return requests.length === state.requests.length ? state : { requests };
  }),
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
