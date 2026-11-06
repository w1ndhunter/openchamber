/**
 * Writes held inside an isolated space, docked above the composer of that space's chat: the same
 * frame and place as the agent's permission requests, so the answer is where the user already
 * looks. The gatekeeper holds the request open, so a write from anywhere inside the space shows
 * here while a chat of that space is open; the space row carries a count when it is not.
 *
 * A write belongs to the space, not to a session: the space is the scope, and every chat of it
 * offers the same waits. The prompt closes itself when the gatekeeper's limit passes.
 */

import React from 'react';

import { Icon } from '@/components/icon/Icon';
import { Button } from '@/components/ui/button';
import { ScrollableOverlay } from '@/components/ui/ScrollableOverlay';
import { useI18n } from '@/lib/i18n';
import { approvalsOfDirectory, approvalExpired, useSpaceApprovalsStore } from '@/lib/spaces/space-approvals';
import { spaceIdOfDirectory } from '@/lib/spaces/space-route';
import { decideSpaceApproval } from '@/lib/spaces/spaces-api';
import { useSpacesStore } from '@/lib/spaces/spaces-store';
import { failureOfError, spaceFailureText } from '@/components/session/spaces/spaceFailureText';
import { ComposerFloatingPanel } from './composer/ui/ComposerFloatingPanel';

type SpaceApprovalDockProps = {
  directory?: string | null;
  hidden: boolean;
};

const SpaceApprovalDockView: React.FC<SpaceApprovalDockProps> = ({ directory, hidden }) => {
  const { t } = useI18n();
  const requests = useSpaceApprovalsStore((state) => state.requests);
  const journey = useSpacesStore((state) => state.journey);
  const [answering, setAnswering] = React.useState<string | null>(null);
  const [error, setError] = React.useState<{ key: string; text: string } | null>(null);

  const spaceId = spaceIdOfDirectory(directory ?? null);
  const waiting = React.useMemo(() => approvalsOfDirectory(requests, directory), [requests, directory]);

  // The gatekeeper refuses a wait whose time passed; a prompt for it must not stay on screen.
  React.useEffect(() => {
    if (waiting.length === 0) return undefined;
    const timer = window.setInterval(() => {
      const state = useSpaceApprovalsStore.getState();
      for (const request of state.requests) {
        if (approvalExpired(request)) state.settle(request.spaceId, request.requestId);
      }
    }, 1_000);
    return () => window.clearInterval(timer);
  }, [waiting.length]);

  if (hidden || spaceId === null || waiting.length === 0) return null;

  const answer = async (requestId: number, allowed: boolean) => {
    const key = `${spaceId}:${requestId}`;
    setAnswering(key);
    setError(null);
    try {
      await decideSpaceApproval(spaceId, requestId, allowed);
      useSpaceApprovalsStore.getState().settle(spaceId, requestId);
    } catch (failure) {
      if (!(failure instanceof Error)) throw failure;
      setError({ key, text: spaceFailureText(t, failureOfError(failure)) });
    } finally {
      setAnswering(null);
    }
  };

  const spaceName = journey?.get(spaceId)?.name ?? spaceId;
  const title = t('spaces.approval.title');

  return (
    <ComposerFloatingPanel
      role="dialog"
      ariaLabel={title}
      header={<>
        <Icon name="shield" className="size-3.5 shrink-0 text-[var(--status-warning)]" />
        <span className="typography-ui-label min-w-0 truncate text-foreground">{title}</span>
        <span className="typography-micro shrink-0 tabular-nums text-muted-foreground">
          {t('spaces.approval.count', { count: String(waiting.length) })}
        </span>
      </>}
    >
      <ScrollableOverlay outerClassName="max-h-[40vh]" className="overscroll-contain px-1.5" disableHorizontal>
        <ul className="space-y-3">
          {waiting.map((request) => {
            const key = `${spaceId}:${request.requestId}`;
            return (
              <li key={key} className="space-y-2">
                <p className="typography-meta text-muted-foreground">
                  {t('spaces.approval.body', { method: request.method, space: spaceName })}
                </p>
                {/* The destination and path exactly as the space wrote them: what the answer covers. */}
                <p dir="ltr" className="typography-meta font-mono break-all text-foreground">{request.url ?? request.host}</p>
                {error?.key === key ? <p className="typography-micro text-status-error">{error.text}</p> : null}
                <div className="flex gap-2">
                  <Button size="sm" disabled={answering !== null} onClick={() => void answer(request.requestId, true)}>
                    {t('spaces.approval.allow')}
                  </Button>
                  <Button size="sm" variant="outline" disabled={answering !== null} onClick={() => void answer(request.requestId, false)}>
                    {t('spaces.approval.deny')}
                  </Button>
                </div>
              </li>
            );
          })}
        </ul>
      </ScrollableOverlay>
    </ComposerFloatingPanel>
  );
};

export const SpaceApprovalDock = React.memo(SpaceApprovalDockView);
