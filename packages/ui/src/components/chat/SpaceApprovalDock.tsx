/**
 * Writes held inside an isolated space, docked above the composer of that space's chat: the same
 * frame and place as the agent's permission requests, so the answer is where the user already
 * looks. The gatekeeper holds the request open, so a write from anywhere inside the space shows
 * here while a chat of that space is open; the space row carries a count when it is not.
 *
 * A write belongs to the space, not to a session: the space is the scope, and every chat of it
 * offers the same waits. The prompt closes itself when the gatekeeper's limit passes.
 *
 * Four answers in the permission prompt's order: the two refusals at the start, the two approvals
 * at the end with "Allow once" last and filled. "Deny once" refuses this write and, so the agent's
 * retry is not another prompt, that destination and method for the rest of the chat's turn; the
 * next turn asks again. "Always" stands for the destination and method on the scope the space
 * chose, one path or the whole host, and is offered only where the host can keep such an answer.
 * The tooltips name that scope from the app's copy of the space; the answer itself takes it from
 * the host's record and says it back, so a scope changed elsewhere never decides from a stale copy.
 */

import React from 'react';

import { Icon } from '@/components/icon/Icon';
import { Button } from '@/components/ui/button';
import { ScrollableOverlay } from '@/components/ui/ScrollableOverlay';
import { useI18n } from '@/lib/i18n';
import { isRememberableWrite } from '@/lib/spaces/space-access';
import { approvalsOfDirectory, useSpaceApprovalsStore } from '@/lib/spaces/space-approvals';
import { spaceIdOfDirectory } from '@/lib/spaces/space-route';
import { decideSpaceApproval } from '@/lib/spaces/spaces-api';
import { refreshSpacesJourney, useSpacesStore } from '@/lib/spaces/spaces-store';
import { failureOfError, spaceFailureText } from '@/components/session/spaces/spaceFailureText';
import type { SpaceApprovalRequest } from '@/sync/event-pipeline';
import { ComposerFloatingPanel } from './composer/ui/ComposerFloatingPanel';

type SpaceApprovalDockProps = {
  directory?: string | null;
  hidden: boolean;
};

type Answer = 'deny_once' | 'deny_always' | 'allow_always' | 'allow_once';

// Stands in for the method while the sentence is translated, so the method can be set in bold
// wherever the language puts it.
const METHOD_MARK = '\u0001';

const SpaceApprovalDockView: React.FC<SpaceApprovalDockProps> = ({ directory, hidden }) => {
  const { t } = useI18n();
  const requests = useSpaceApprovalsStore((state) => state.requests);
  const journey = useSpacesStore((state) => state.journey);
  const [answering, setAnswering] = React.useState<string | null>(null);
  const [error, setError] = React.useState<{ key: string; text: string } | null>(null);

  const spaceId = spaceIdOfDirectory(directory ?? null);
  const waiting = React.useMemo(() => approvalsOfDirectory(requests, directory), [requests, directory]);

  if (hidden || spaceId === null || waiting.length === 0) return null;

  const answer = async (request: SpaceApprovalRequest, choice: Answer) => {
    const key = `${spaceId}:${request.requestId}`;
    setAnswering(key);
    setError(null);
    try {
      const store = useSpaceApprovalsStore.getState();
      const allowed = choice === 'allow_once' || choice === 'allow_always';
      const remember = choice === 'allow_always' || choice === 'deny_always';
      const shown = { host: request.host, method: request.method, path: request.path };
      const { settled, scope } = await decideSpaceApproval(spaceId, request.requestId, allowed, remember, choice === 'allow_always' ? shown : undefined);
      // Every answer but "Allow once" stands for the scope the host's record holds, which the
      // answer says back, so the other waits it covers go at once. A wait that was already gone
      // covers nothing, and a path answer with no path to name stays on its own.
      const path = scope === 'path' ? request.path : undefined;
      const coversOthers = settled && scope !== undefined && (scope === 'host' || path !== undefined);
      if (coversOthers) store.settleCovered(spaceId, request.host, request.method, path);
      else store.settle(spaceId, request.requestId);
      // A standing answer shows under Access and network.
      if (choice === 'allow_always' || choice === 'deny_always') await refreshSpacesJourney().catch(() => undefined);
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
            const [before, after = ''] = t('spaces.approval.body', { method: METHOD_MARK, space: spaceName }).split(METHOD_MARK);
            const scope = journey?.get(spaceId)?.network?.writesScope ?? 'path';
            const path = scope === 'path' ? request.path : undefined;
            // An old gatekeeper has no rule path; do not offer a path-scoped "always" against its
            // full URL, which may be shortened. Host scope remains available.
            const scoped = scope === 'host' || path !== undefined;
            const always = isRememberableWrite(request.host, request.method) && scoped;
            const destination = `${request.host}${path ?? ''}`;
            const scopeText = (kind: 'allowAlwaysScope' | 'denyAlwaysScope' | 'denyOnceScope' | 'denyOnceHostScope') => t(`spaces.approval.${kind}`, { method: request.method, host: destination });
            const busy = answering !== null;
            return (
              <li key={key} className="space-y-2">
                <p className="typography-meta text-muted-foreground">
                  {before}<strong className="font-semibold text-foreground">{request.method}</strong>{after}
                </p>
                {/* The destination and path exactly as the space wrote them: what the answer covers. */}
                <p dir="ltr" className="typography-meta font-mono break-all text-foreground">{request.url ?? request.host}</p>
                {error?.key === key ? <p className="typography-micro text-status-error">{error.text}</p> : null}
                <div className="flex flex-wrap items-center gap-1.5">
                  <div className="flex flex-wrap gap-1.5">
                    <Button variant="ghost" size="xs" disabled={busy} onClick={() => void answer(request, 'deny_once')} className="text-[var(--status-error)]" title={scoped ? scopeText(scope === 'host' ? 'denyOnceHostScope' : 'denyOnceScope') : undefined}>
                      <Icon name="close" className="size-3.5" />
                      {t('spaces.approval.denyOnce')}
                    </Button>
                    {always ? (
                      <Button variant="ghost" size="xs" disabled={busy} onClick={() => void answer(request, 'deny_always')} className="text-[var(--status-error)]" title={scopeText('denyAlwaysScope')}>
                        <Icon name="forbid" className="size-3.5" />
                        {t('spaces.approval.denyAlways')}
                      </Button>
                    ) : null}
                  </div>
                  <div className="ms-auto flex flex-wrap gap-1.5">
                    {always ? (
                      <Button variant="outline" size="xs" disabled={busy} onClick={() => void answer(request, 'allow_always')} title={scopeText('allowAlwaysScope')}>
                        <Icon name="time" className="size-3.5" />
                        {t('spaces.approval.allowAlways')}
                      </Button>
                    ) : null}
                    <Button size="xs" disabled={busy} onClick={() => void answer(request, 'allow_once')}>
                      {answering === key ? <Icon name="loader-4" className="size-3.5 animate-spin" /> : <Icon name="check" className="size-3.5" />}
                      {t('spaces.approval.allow')}
                    </Button>
                  </div>
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
