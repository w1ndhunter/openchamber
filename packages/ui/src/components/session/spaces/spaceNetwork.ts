// The network of a running space as its dialogs use it: the gatekeeper's journal, and allowing a
// domain from it. The access dialog and the setup output window both list refused domains with Allow.

import React from 'react';

import { useI18n } from '@/lib/i18n';
import { approveSpaceWrites, denySpaceWrites, openSpaceDomain, readSpaceJournal, revokeSpaceWrites, type SpaceFailure, type SpaceJournal, type SpaceWriteMethod } from '@/lib/spaces/spaces-api';
import { refreshSpacesJourney } from '@/lib/spaces/spaces-store';
import { failureOfError, spaceFailureText } from './spaceFailureText';

type JournalState = { kind: 'loading' } | { kind: 'ready'; journal: SpaceJournal } | { kind: 'failed'; failure: SpaceFailure };

/** The gatekeeper's journal, read while `enabled` and again on `refresh`; never polled. */
export const useSpaceJournal = (spaceId: string, enabled: boolean) => {
  const [state, setState] = React.useState<JournalState>({ kind: 'loading' });
  const [generation, setGeneration] = React.useState(0);
  React.useEffect(() => {
    if (!enabled) return;
    const controller = new AbortController();
    setState({ kind: 'loading' });
    readSpaceJournal(spaceId, controller.signal).then(
      (journal) => setState({ kind: 'ready', journal }),
      (error: Error) => { if (!controller.signal.aborted) setState({ kind: 'failed', failure: failureOfError(error) }); },
    );
    return () => controller.abort();
  }, [enabled, generation, spaceId]);
  return { state, refresh: () => setGeneration((value) => value + 1) };
};

/** Allows a domain in a running space, one at a time, and keeps the failure by the domain it was for. */
export const useOpenSpaceDomain = (spaceId: string) => {
  const { t } = useI18n();
  const [opening, setOpening] = React.useState<string | null>(null);
  const [error, setError] = React.useState<{ domain: string; text: string } | null>(null);
  const open = async (domain: string): Promise<boolean> => {
    setOpening(domain);
    setError(null);
    try {
      await openSpaceDomain(spaceId, domain);
      await refreshSpacesJourney().catch(() => undefined);
      return true;
    } catch (failure) {
      if (!(failure instanceof Error)) throw failure;
      setError({ domain, text: spaceFailureText(t, failureOfError(failure)) });
      return false;
    } finally {
      setOpening(null);
    }
  };
  return { open, opening, error };
};

/**
 * Approves one method for one destination in a running space, one at a time, and keeps the failure
 * by the attempt it was for. The method comes from the journal, which the agent wrote; the host's
 * name and method rules are what make it a decision.
 */
export const useApproveSpaceWrites = (spaceId: string) => {
  const { t } = useI18n();
  const [approving, setApproving] = React.useState<string | null>(null);
  const [error, setError] = React.useState<{ key: string; text: string } | null>(null);
  const approve = async (host: string, method: SpaceWriteMethod): Promise<boolean> => {
    const key = `${host}:${method}`;
    setApproving(key);
    setError(null);
    try {
      await approveSpaceWrites(spaceId, host, [method]);
      await refreshSpacesJourney().catch(() => undefined);
      return true;
    } catch (failure) {
      if (!(failure instanceof Error)) throw failure;
      setError({ key, text: spaceFailureText(t, failureOfError(failure)) });
      return false;
    } finally {
      setApproving(null);
    }
  };
  return { approve, approving, error };
};

/**
 * Takes back one approved method, one at a time, and keeps the failure by the method it was for.
 * The gatekeeper stops forwarding it live, and the next write asks again.
 */
export const useRevokeSpaceWrites = (spaceId: string) => {
  const { t } = useI18n();
  const [revoking, setRevoking] = React.useState<string | null>(null);
  const [error, setError] = React.useState<{ key: string; text: string } | null>(null);
  const revoke = async (host: string, method: SpaceWriteMethod): Promise<boolean> => {
    const key = `${host}:${method}`;
    setRevoking(key);
    setError(null);
    try {
      await revokeSpaceWrites(spaceId, host, [method]);
      await refreshSpacesJourney().catch(() => undefined);
      return true;
    } catch (failure) {
      if (!(failure instanceof Error)) throw failure;
      setError({ key, text: spaceFailureText(t, failureOfError(failure)) });
      return false;
    } finally {
      setRevoking(null);
    }
  };
  return { revoke, revoking, error };
};

/**
 * Takes back one denied method: the remaining methods for the destination are said again, so a
 * method the user still refuses stays refused. The record keeps denials across starts, and this
 * is the way back to the prompt.
 */
export const useClearSpaceDenial = (spaceId: string) => {
  const { t } = useI18n();
  const [clearing, setClearing] = React.useState<string | null>(null);
  const [error, setError] = React.useState<{ key: string; text: string } | null>(null);
  const clear = async (host: string, method: SpaceWriteMethod, remaining: readonly SpaceWriteMethod[]): Promise<boolean> => {
    const key = `${host}:${method}`;
    setClearing(key);
    setError(null);
    try {
      await denySpaceWrites(spaceId, host, [...remaining]);
      await refreshSpacesJourney().catch(() => undefined);
      return true;
    } catch (failure) {
      if (!(failure instanceof Error)) throw failure;
      setError({ key, text: spaceFailureText(t, failureOfError(failure)) });
      return false;
    } finally {
      setClearing(null);
    }
  };
  return { clear, clearing, error };
};
