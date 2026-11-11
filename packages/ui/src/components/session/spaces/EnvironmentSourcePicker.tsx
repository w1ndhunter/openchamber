/**
 * The environment source of a new space: none, a folder or a Git repository, with its shared
 * memory mode. "Check source" asks the host what the source would bring; the delivery and the
 * items that run code stay behind Customize, each ticked one by one.
 */

import React from 'react';

import { Icon } from '@/components/icon/Icon';
import { Button } from '@/components/ui/button';
import { Checkbox } from '@/components/ui/checkbox';
import { SettingsRadioGroup, SettingsRadioOption } from '@/components/sections/shared/SettingsSection';
import { Input } from '@/components/ui/input';
import { useI18n } from '@/lib/i18n';
import { canKeyServer, emptyMcpKey, environmentRequestOf, headerFieldOf, noOptIns, variableFieldOf, type EnvironmentDraft, type McpKeyDraft } from '@/lib/spaces/environment-draft';
import { checkEnvironmentSource, type SpaceEnvironmentPlan } from '@/lib/spaces/spaces-api';
import { failureOfError, spaceFailureText } from './spaceFailureText';

const LIST_KINDS = ['agents', 'mcp', 'plugins', 'commands', 'skills', 'skillSources'] as const;
type ListKind = (typeof LIST_KINDS)[number];
const OFFER_LABELS = {
  agents: 'spaces.create.environment.optIn.agent',
  mcp: 'spaces.create.environment.optIn.mcp',
  plugins: 'spaces.create.environment.optIn.plugin',
  commands: 'spaces.create.environment.optIn.command',
  skills: 'spaces.create.environment.optIn.skill',
  skillSources: 'spaces.create.environment.optIn.skillSource',
} as const satisfies Record<ListKind, string>;

type CheckState = { kind: 'idle' } | { kind: 'checking' } | { kind: 'ready'; plan: SpaceEnvironmentPlan } | { kind: 'failed'; message: string };

export const EnvironmentSourcePicker: React.FC<{
  value: EnvironmentDraft;
  onChange: (next: EnvironmentDraft) => void;
  /** A folder can be mounted only into a space on this computer. */
  mountAvailable: boolean;
}> = ({ value, onChange, mountAvailable }) => {
  const { t } = useI18n();
  const [check, setCheck] = React.useState<CheckState>({ kind: 'idle' });
  const [customize, setCustomize] = React.useState(false);
  const change = (patch: Partial<EnvironmentDraft>) => {
    // Another source is another plan: what was checked or ticked no longer applies.
    if ('kind' in patch || 'location' in patch || 'ref' in patch) {
      setCheck({ kind: 'idle' });
      onChange({ ...value, ...patch, optIns: noOptIns() });
      return;
    }
    onChange({ ...value, ...patch });
  };
  React.useEffect(() => {
    if (!mountAvailable && value.delivery === 'mount') onChange({ ...value, delivery: 'snapshot' });
  }, [mountAvailable, onChange, value]);

  const runCheck = async () => {
    const request = environmentRequestOf({ ...value, optIns: noOptIns() });
    if (!request) return;
    setCheck({ kind: 'checking' });
    try {
      const plan = await checkEnvironmentSource(request);
      setCheck({ kind: 'ready', plan });
      // The dialog holds the servers too, so a key can name the url it belongs to.
      onChange({ ...value, mcpServers: plan.mcpServers });
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      setCheck({ kind: 'failed', message: spaceFailureText(t, failureOfError(error)) });
    }
  };

  const toggle = (kind: ListKind, name: string, on: boolean) => {
    const current = value.optIns[kind];
    change({ optIns: { ...value.optIns, [kind]: on ? [...current, name] : current.filter((item) => item !== name) } });
  };

  const plan = check.kind === 'ready' ? check.plan : null;
  const offers = plan?.offers ?? null;
  const offerCount = offers ? LIST_KINDS.reduce((sum, kind) => sum + offers[kind].length, 0) + (offers.formatter ? 1 : 0) : 0;
  const memory = (
    <SettingsRadioGroup aria-label={t('spaces.create.environment.memory')}>
      <SettingsRadioOption ariaLabel={t('spaces.create.environment.memoryOff')} selected={value.memory === 'off'} onSelect={() => change({ memory: 'off' })} label={t('spaces.create.environment.memoryOff')} />
      <SettingsRadioOption ariaLabel={t('spaces.create.environment.memoryRead')} selected={value.memory === 'read'} onSelect={() => change({ memory: 'read' })} label={t('spaces.create.environment.memoryRead')} />
      <SettingsRadioOption ariaLabel={t('spaces.create.environment.memoryWrite')} selected={value.memory === 'write'} onSelect={() => change({ memory: 'write' })} label={t('spaces.create.environment.memoryWrite')} />
    </SettingsRadioGroup>
  );

  return (
    <div className="space-y-2">
      <SettingsRadioGroup aria-label={t('spaces.create.environment.label')}>
        <SettingsRadioOption ariaLabel={t('spaces.create.environment.none')} selected={value.kind === 'none'} onSelect={() => change({ kind: 'none' })} label={t('spaces.create.environment.none')} />
        <SettingsRadioOption ariaLabel={t('spaces.create.environment.folder')} selected={value.kind === 'folder'} onSelect={() => change({ kind: 'folder' })} label={t('spaces.create.environment.folder')} />
        <SettingsRadioOption ariaLabel={t('spaces.create.environment.git')} selected={value.kind === 'git'} onSelect={() => change({ kind: 'git' })} label={t('spaces.create.environment.git')} />
      </SettingsRadioGroup>
      {value.kind !== 'none' ? (
        <div className="space-y-2 ps-6">
          <Input
            value={value.location}
            onChange={(event) => change({ location: event.target.value })}
            aria-label={t('spaces.create.environment.location')}
            placeholder={t('spaces.create.environment.location')}
            spellCheck={false}
            dir="ltr"
          />
          {value.kind === 'git' ? (
            <Input
              value={value.ref}
              onChange={(event) => change({ ref: event.target.value })}
              aria-label={t('spaces.create.environment.ref')}
              placeholder={t('spaces.create.environment.ref')}
              spellCheck={false}
              dir="ltr"
            />
          ) : null}
          <div className="typography-ui-label text-foreground">{t('spaces.create.environment.memory')}</div>
          {memory}
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="outline" size="xs" className="gap-1" disabled={value.location.trim() === '' || check.kind === 'checking'} onClick={() => void runCheck()}>
              {check.kind === 'checking' ? <Icon name="loader-4" className="h-3 w-3 animate-spin" /> : null}
              {t('spaces.create.environment.check')}
            </Button>
            <Button variant="ghost" size="xs" onClick={() => setCustomize((open) => !open)}>
              {customize ? t('spaces.create.environment.hideCustomize') : t('spaces.create.environment.customize')}
            </Button>
          </div>
          {check.kind === 'failed' ? <p className="typography-meta text-status-error">{check.message}</p> : null}
          {plan ? (
            <div className="space-y-1 typography-meta text-muted-foreground">
              <p>{t('spaces.create.environment.summary', { agents: plan.assets.agents.length, commands: plan.assets.commands.length, skills: plan.assets.skills.length, instructions: plan.assets.instructions.length })}</p>
              {!plan.memory.declared ? <p>{t('spaces.create.environment.memoryUndeclared')}</p> : null}
              {plan.memory.format === 'v1' ? <p className="text-status-warning">{t('spaces.create.environment.memoryLegacy')}</p> : null}
              {plan.memory.format === 'v2' ? <p>{t('spaces.create.environment.memoryEntries', { count: plan.memory.entries })}</p> : null}
              {plan.memory.flagged > 0 ? <p className="text-status-warning">{t('spaces.create.environment.flagged', { count: plan.memory.flagged })}</p> : null}
            </div>
          ) : null}
          {customize ? (
            <div className="space-y-2 rounded-md bg-muted/40 p-2">
              {value.kind === 'folder' ? (
                <>
                  <SettingsRadioGroup aria-label={t('spaces.create.environment.deliverySnapshot')}>
                    <SettingsRadioOption ariaLabel={t('spaces.create.environment.deliverySnapshot')} selected={value.delivery === 'snapshot'} onSelect={() => change({ delivery: 'snapshot' })} label={t('spaces.create.environment.deliverySnapshot')} />
                    <SettingsRadioOption ariaLabel={t('spaces.create.environment.deliveryMount')} selected={value.delivery === 'mount'} onSelect={() => change({ delivery: 'mount' })} label={t('spaces.create.environment.deliveryMount')} disabled={!mountAvailable} />
                  </SettingsRadioGroup>
                  <p className="typography-micro text-muted-foreground">{t('spaces.create.environment.deliveryMountHint')}</p>
                </>
              ) : null}
              {offers && offers.mcp.length > 0 ? (
                <div className="space-y-2">
                  {(plan?.mcpServers ?? []).filter((server) => value.optIns.mcp.includes(server.name) && canKeyServer(server.name)).map((server) => {
                    const key = value.mcpKeys[server.name] ?? emptyMcpKey();
                    const localVariables: string[] = plan?.mcpEnv[server.name] ?? [];
                    if (server.type === 'local') {
                      return localVariables.length === 0 ? null : (
                        <p key={server.name} className="typography-micro text-status-warning">
                          {t('spaces.create.environment.mcpHandedOver', { name: server.name, variables: localVariables.join(', ') })}
                        </p>
                      );
                    }
                    const change = (patch: Partial<McpKeyDraft>) => onChange({ ...value, mcpKeys: { ...value.mcpKeys, [server.name]: { ...key, ...patch } } });
                    return (
                      <div key={server.name} className="space-y-1 rounded border border-border p-2">
                        <p className="typography-meta text-foreground">{t('spaces.create.environment.mcpKey', { name: server.name })}</p>
                        <p className="typography-micro text-muted-foreground">{t('spaces.create.environment.mcpKeyHint')}</p>
                        <div className="flex flex-wrap gap-2">
                          <Input value={key.header} onChange={(event) => change({ header: headerFieldOf(event.target.value) })} placeholder="authorization" aria-label={t('spaces.create.environment.mcpHeader')} />
                          <SettingsRadioGroup aria-label={t('spaces.create.environment.mcpSource')}>
                            <SettingsRadioOption ariaLabel={t('spaces.create.environment.mcpSourceEnv')} selected={key.source === 'env'} onSelect={() => change({ source: 'env' })} label={t('spaces.create.environment.mcpSourceEnv')} />
                            <SettingsRadioOption ariaLabel={t('spaces.create.environment.mcpSourceTyped')} selected={key.source === 'typed'} onSelect={() => change({ source: 'typed' })} label={t('spaces.create.environment.mcpSourceTyped')} />
                          </SettingsRadioGroup>
                        </div>
                        {key.source === 'env' ? (
                          <Input value={key.envName} onChange={(event) => change({ envName: variableFieldOf(event.target.value) })} placeholder="DOCS_TOKEN" aria-label={t('spaces.create.environment.mcpEnvName')} />
                        ) : (
                          <Input type="password" value={key.value} onChange={(event) => change({ value: event.target.value })} aria-label={t('spaces.create.environment.mcpValue')} />
                        )}
                      </div>
                    );
                  })}
                </div>
              ) : null}
              <p className="typography-micro text-muted-foreground">{t('spaces.create.environment.optIns')}</p>
              {offers && offerCount === 0 ? <p className="typography-meta text-muted-foreground">{t('spaces.create.environment.noOffers')}</p> : null}
              {offers ? (
                <div className="space-y-1">
                  {LIST_KINDS.flatMap((kind) => offers[kind].map((name) => (
                    <label key={`${kind}:${name}`} className="flex items-center gap-2">
                      <Checkbox checked={value.optIns[kind].includes(name)} onChange={(on) => toggle(kind, name, on)} ariaLabel={t(OFFER_LABELS[kind], { name })} />
                      <span dir="auto" className="typography-meta text-foreground">{t(OFFER_LABELS[kind], { name })}</span>
                    </label>
                  )))}
                  {offers.formatter ? (
                    <label className="flex items-center gap-2">
                      <Checkbox checked={value.optIns.formatter} onChange={(on) => change({ optIns: { ...value.optIns, formatter: on } })} ariaLabel={t('spaces.create.environment.optIn.formatter')} />
                      <span className="typography-meta text-foreground">{t('spaces.create.environment.optIn.formatter')}</span>
                    </label>
                  ) : null}
                </div>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
};
