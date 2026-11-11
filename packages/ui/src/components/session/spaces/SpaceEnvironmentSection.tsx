/**
 * A space's environment source in the access dialog: what it is, the revision the space has, what
 * it brought, its shared memory and one state the user can act on. Refresh, check, the memory mode,
 * sync, the reviewed version 1 import and detach. A detach keeps every copied file in the space.
 */

import React from 'react';

import { Icon } from '@/components/icon/Icon';
import { SettingsRadioGroup, SettingsRadioOption } from '@/components/sections/shared/SettingsSection';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useI18n, type I18nKey } from '@/lib/i18n';
import { environmentStateOf, environmentStateTone, unsyncedMemoryOf, type SpaceEnvironmentState } from '@/lib/spaces/space-environment';
import {
  checkSpaceEnvironment,
  configureSpaceEnvironment,
  detachSpaceEnvironment,
  importSpaceEnvironmentMemory,
  readSpaceEnvironmentMemory,
  refreshSpaceEnvironment,
  syncSpaceEnvironmentMemory,
  grantSpaceAccess,
  mcpGrantOf,
  mcpGrantRequestOf,
  type SpaceEntry,
  type SpaceEnvironmentStatus,
  type SpaceLiveMemory,
} from '@/lib/spaces/spaces-api';
import { emptyMcpKey, type McpKeyDraft } from '@/lib/spaces/environment-draft';
import { refreshSpacesJourney } from '@/lib/spaces/spaces-store';
import { cn } from '@/lib/utils';
import { failureOfError, spaceFailureText } from './spaceFailureText';

const STATE_LABELS = {
  ready: 'spaces.access.environment.state.ready',
  needs_setup: 'spaces.access.environment.state.needsSetup',
  needs_auth: 'spaces.access.environment.state.needsAuth',
  pending: 'spaces.access.environment.state.pending',
  offline: 'spaces.access.environment.state.offline',
  conflicted: 'spaces.access.environment.state.conflicted',
  blocked: 'spaces.access.environment.state.blocked',
  off: 'spaces.access.environment.state.off',
  applies_on_restart: 'spaces.access.environment.state.appliesOnRestart',
} as const satisfies Record<SpaceEnvironmentState, I18nKey>;

const TONE_CLASS = {
  success: 'text-status-success',
  warning: 'text-status-warning',
  error: 'text-status-error',
  muted: 'text-muted-foreground',
} as const;

type Action = 'refresh' | 'check' | 'sync' | 'detach' | 'import' | 'memory';

/** The space's memory read now, again after each action that changes it. */
// `unread` while the space's memory is unknown: not asked yet, or the read failed.
const useLiveMemory = (entry: SpaceEntry): [SpaceLiveMemory | null, boolean, () => void] => {
  const [live, setLive] = React.useState<SpaceLiveMemory | null>(null);
  const [unread, setUnread] = React.useState(false);
  const [turn, setTurn] = React.useState(0);
  const wanted = Boolean(entry.environment && entry.environment.memory !== 'off' && entry.state === 'running');
  React.useEffect(() => {
    setLive(null);
    setUnread(wanted);
    if (!wanted) return undefined;
    const controller = new AbortController();
    readSpaceEnvironmentMemory(entry.id, controller.signal).then(
      (answer) => { setLive(answer); setUnread(false); },
      () => { if (!controller.signal.aborted) setUnread(true); },
    );
    return () => controller.abort();
  }, [entry.id, wanted, turn]);
  return [live, unread, () => setTurn((value) => value + 1)];
};

/**
 * The MCP servers the environment brought, each with whether it has a key. A remote server's key
 * goes to the gatekeeper and the server talks to the window; a local one reads host variables, and
 * the agent inside can read them too. Giving a key replaces the server's grant, which is how a
 * rotated token survives.
 */
const McpKeys: React.FC<{ entry: SpaceEntry; servers: SpaceEnvironmentStatus['mcpServers'] }> = ({ entry, servers }) => {
  const { t } = useI18n();
  const [open, setOpen] = React.useState<string | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [draft, setDraft] = React.useState<McpKeyDraft>(emptyMcpKey());
  const keys = React.useMemo(() => mcpGrantOf(entry.grants), [entry.grants]);
  if (servers.length === 0) return null;
  const give = async (server: { name: string; url?: string }) => {
    if (!server.url) return;
    setBusy(true);
    setError(null);
    try {
      await grantSpaceAccess(entry.id, mcpGrantRequestOf({ name: server.name, url: server.url }, draft));
      await refreshSpacesJourney().catch(() => undefined);
      setOpen(null);
      setDraft(emptyMcpKey());
    } catch (failure) {
      if (!(failure instanceof Error)) throw failure;
      setError(spaceFailureText(t, failureOfError(failure)));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="space-y-1">
      <div className="typography-ui-label text-foreground">{t('spaces.access.environment.mcp')}</div>
      {servers.map((server) => {
        const grant = keys.get(server.name);
        return (
          <div key={server.name} className="space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <span dir="ltr" className="font-mono typography-meta text-foreground">{server.name}</span>
              <span className="typography-micro text-muted-foreground">
                {server.type === 'local'
                  ? t('spaces.access.environment.mcpLocal')
                  : grant
                    ? t(grant.source.kind === 'env' ? 'spaces.access.environment.mcpKeyFromEnv' : 'spaces.access.environment.mcpKeyGiven', { name: grant.source.kind === 'env' ? grant.source.name : server.name })
                    : t('spaces.access.environment.mcpKeyNone')}
              </span>
              {server.type === 'remote' ? (
                <Button variant="outline" size="xs" disabled={busy} onClick={() => { setOpen(open === server.name ? null : server.name); setError(null); }}>
                  {t(grant ? 'spaces.access.environment.mcpKeyReplace' : 'spaces.access.environment.mcpKeyGive')}
                </Button>
              ) : null}
            </div>
            {open === server.name ? (
              <div className="space-y-1 rounded border border-border p-2">
                <Input value={draft.header} onChange={(event) => setDraft({ ...draft, header: event.target.value })} placeholder="authorization" aria-label={t('spaces.access.environment.mcpHeader')} />
                <SettingsRadioGroup aria-label={t('spaces.access.environment.mcpSource')}>
                  <SettingsRadioOption ariaLabel={t('spaces.access.environment.mcpSourceEnv')} selected={draft.source === 'env'} onSelect={() => setDraft({ ...draft, source: 'env' })} label={t('spaces.access.environment.mcpSourceEnv')} />
                  <SettingsRadioOption ariaLabel={t('spaces.access.environment.mcpSourceTyped')} selected={draft.source === 'typed'} onSelect={() => setDraft({ ...draft, source: 'typed' })} label={t('spaces.access.environment.mcpSourceTyped')} />
                </SettingsRadioGroup>
                {draft.source === 'env' ? (
                  <Input value={draft.envName} onChange={(event) => setDraft({ ...draft, envName: event.target.value })} placeholder="DOCS_TOKEN" aria-label={t('spaces.access.environment.mcpEnvName')} />
                ) : (
                  <Input type="password" value={draft.value} onChange={(event) => setDraft({ ...draft, value: event.target.value })} aria-label={t('spaces.access.environment.mcpValue')} />
                )}
                <Button size="xs" disabled={busy} onClick={() => void give(server)}>{t('spaces.access.environment.mcpSave')}</Button>
              </div>
            ) : null}
          </div>
        );
      })}
      {error ? <p className="typography-micro text-status-error">{error}</p> : null}
    </div>
  );
};

export const SpaceEnvironmentSection: React.FC<{ entry: SpaceEntry }> = ({ entry }) => {
  const { t } = useI18n();
  const [busy, setBusy] = React.useState<Action | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [confirmDetach, setConfirmDetach] = React.useState(false);
  const [importCount, setImportCount] = React.useState<number | null>(null);
  const [live, memoryUnread, reloadLive] = useLiveMemory(entry);
  const source = entry.environment ?? null;
  const status = entry.environmentStatus ?? null;
  const state = environmentStateOf(source, status, live);
  if (state === null) return <p className="typography-meta text-muted-foreground">{t('spaces.access.environment.none')}</p>;

  const running = entry.state === 'running';
  const run = async (action: Action, work: () => Promise<string | null>) => {
    setBusy(action);
    setError(null);
    setNotice(null);
    try {
      setNotice(await work());
      await refreshSpacesJourney().catch(() => undefined);
      reloadLive();
    } catch (failure) {
      if (!(failure instanceof Error)) throw failure;
      setError(spaceFailureText(t, failureOfError(failure)));
    } finally {
      setBusy(null);
    }
  };
  const spinner = (action: Action) => (busy === action ? <Icon name="loader-4" className="h-3 w-3 animate-spin" /> : null);
  const syncNotice = (result: Awaited<ReturnType<typeof syncSpaceEnvironmentMemory>>) => {
    if (result.state === 'conflicted') return t('spaces.access.environment.memoryConflicts', { count: result.conflicts.length });
    if (result.state === 'offline') return t('spaces.access.environment.memoryOffline');
    if (result.state === 'needs_auth') return t('spaces.access.environment.memoryNeedsAuth');
    return t('spaces.access.environment.memorySynced');
  };
  const location = source ?? status;
  // What a detach would leave behind: a count, or null when the memory could not be read.
  const unsynced = source?.memory === 'off' ? 0 : memoryUnread ? null : unsyncedMemoryOf(live);
  const assets = status?.assets;

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <span className="typography-meta text-muted-foreground">
          {location?.kind === 'git' ? t('spaces.create.environment.git') : t('spaces.create.environment.folder')}
        </span>
        <span className={cn('typography-micro font-medium', TONE_CLASS[environmentStateTone(state)])}>{t(STATE_LABELS[state])}</span>
      </div>
      {location ? <div dir="ltr" className="break-all font-mono typography-meta text-foreground">{location.location}{location.ref ? ` @ ${location.ref}` : ''}</div> : null}
      {status?.revision ? (
        <div className="typography-micro text-muted-foreground">
          {t('spaces.access.environment.revision', {
            revision: (status.commit ?? status.revision).slice(0, 12),
            delivery: status.delivery === 'mount' ? t('spaces.access.environment.deliveryMount') : t('spaces.access.environment.deliverySnapshot'),
          })}
        </div>
      ) : null}
      {assets ? (
        <div className="typography-micro text-muted-foreground">
          {t('spaces.access.environment.assets', { agents: assets.agents.length, commands: assets.commands.length, skills: assets.skills.length, instructions: assets.instructions.length })}
        </div>
      ) : null}
      {status && status.omitted.length > 0 ? <div className="typography-micro text-muted-foreground">{t('spaces.access.environment.omitted', { count: status.omitted.length })}</div> : null}
      {running && status ? <McpKeys entry={entry} servers={status.mcpServers} /> : null}
      {status?.pendingChange ? <p className="typography-meta text-status-warning">{t('spaces.access.environment.appliesOnRestart')}</p> : null}
      {status?.state === 'off' && status.mountRemains ? <p className="typography-meta text-muted-foreground">{t('spaces.access.environment.mountRemains')}</p> : null}
      {status?.lastFailure ? <p className="typography-meta text-status-error">{t('spaces.access.environment.lastFailure', { message: status.lastFailure.message })}</p> : null}

      {source ? (
        <>
          <div className="typography-ui-label text-foreground">{t('spaces.create.environment.memory')}</div>
          <SettingsRadioGroup aria-label={t('spaces.create.environment.memory')}>
            {(['off', 'read', 'write'] as const).map((mode) => {
              const label = mode === 'off' ? t('spaces.create.environment.memoryOff') : mode === 'read' ? t('spaces.create.environment.memoryRead') : t('spaces.create.environment.memoryWrite');
              return (
                <SettingsRadioOption
                  key={mode}
                  ariaLabel={label}
                  label={label}
                  selected={source.memory === mode}
                  disabled={busy !== null}
                  onSelect={() => { if (source.memory !== mode) void run('memory', async () => { await configureSpaceEnvironment(entry.id, { memory: mode }); return null; }); }}
                />
              );
            })}
          </SettingsRadioGroup>
          {live?.available && live.pending > 0 ? <p className="typography-meta text-muted-foreground">{t('spaces.access.environment.memoryPending', { count: live.pending })}</p> : null}
          {live?.available && live.conflicts > 0 ? <p className="typography-meta text-status-error">{t('spaces.access.environment.memoryConflicts', { count: live.conflicts })}</p> : null}
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="xs" className="gap-1" disabled={!running || busy !== null} onClick={() => void run('refresh', async () => { await refreshSpaceEnvironment(entry.id); return t('spaces.access.environment.refreshed'); })}>
              {spinner('refresh')}{t('spaces.access.environment.refresh')}
            </Button>
            <Button variant="outline" size="xs" className="gap-1" disabled={busy !== null} onClick={() => void run('check', async () => {
              const result = await checkSpaceEnvironment(entry.id);
              if (result.failure) throw new Error(result.failure.message);
              return result.changed ? t('spaces.access.environment.changed') : t('spaces.access.environment.upToDate');
            })}>
              {spinner('check')}{t('spaces.access.environment.check')}
            </Button>
            {source.memory !== 'off' ? (
              <Button variant="outline" size="xs" className="gap-1" disabled={!running || busy !== null} onClick={() => void run('sync', async () => syncNotice(await syncSpaceEnvironmentMemory(entry.id)))}>
                {spinner('sync')}{t('spaces.access.environment.syncMemory')}
              </Button>
            ) : null}
            {state === 'needs_setup' && status?.lastFailure?.code === 'environment_memory_needs_import' ? (
              <Button variant="outline" size="xs" className="gap-1" disabled={busy !== null} onClick={() => void run('import', async () => {
                const preview = await importSpaceEnvironmentMemory(entry.id, { confirm: false });
                setImportCount((preview.entries ?? []).filter((item) => !item.flagged).length);
                return null;
              })}>
                {spinner('import')}{t('spaces.access.environment.import')}
              </Button>
            ) : null}
            <Button variant="outline" size="xs" disabled={!running || busy !== null} onClick={() => setConfirmDetach(true)}>
              {t('spaces.access.environment.detach')}
            </Button>
          </div>
          {importCount !== null ? (
            <div className="space-y-1">
              <p className="typography-meta text-muted-foreground">{t('spaces.access.environment.importCount', { count: importCount })}</p>
              <Button variant="outline" size="xs" disabled={busy !== null} onClick={() => void run('import', async () => {
                const done = await importSpaceEnvironmentMemory(entry.id, { confirm: true });
                setImportCount(null);
                return t('spaces.access.environment.imported', { count: done.imported });
              })}>
                {t('spaces.access.environment.importConfirm')}
              </Button>
            </div>
          ) : null}
          {confirmDetach ? (
            <div className="space-y-1">
              <p className="typography-meta text-foreground">{t('spaces.access.environment.detachConfirm')}</p>
              {unsynced === null ? <p className="typography-meta text-status-warning">{t('spaces.delete.memoryUnknown')}</p> : null}
              {unsynced !== null && unsynced > 0 ? <p className="typography-meta text-status-warning">{t('spaces.access.environment.detachPending', { count: unsynced })}</p> : null}
              <div className="flex gap-2">
                <Button variant="outline" size="xs" onClick={() => setConfirmDetach(false)}>{t('spaces.delete.cancel')}</Button>
                <Button variant="destructive" size="xs" className="gap-1" disabled={busy !== null} onClick={() => void run('detach', async () => {
                  // The warning above is the user's decision: what is pending or unknown is left behind only now.
                  await detachSpaceEnvironment(entry.id, { discardPending: unsynced !== 0 });
                  setConfirmDetach(false);
                  return t('spaces.access.environment.detached');
                })}>
                  {spinner('detach')}{t('spaces.access.environment.detach')}
                </Button>
              </div>
            </div>
          ) : null}
        </>
      ) : null}
      {notice ? <p className="typography-meta text-muted-foreground">{notice}</p> : null}
      {error ? <p className="typography-meta text-status-error">{error}</p> : null}
    </div>
  );
};
