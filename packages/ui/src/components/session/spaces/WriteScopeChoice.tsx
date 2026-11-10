/** Which destination an "always" answer remembers. The dialog and a new space share one choice. */

import React from 'react';

import { SettingsRadioGroup, SettingsRadioOption } from '@/components/sections/shared/SettingsSection';
import { useI18n } from '@/lib/i18n';
import type { SpaceWriteScope } from '@/lib/spaces/spaces-api';

const WriteScopeChoice: React.FC<{
  value: SpaceWriteScope;
  onChange: (scope: SpaceWriteScope) => void;
  disabled?: boolean;
}> = ({ value, onChange, disabled = false }) => {
  const { t } = useI18n();
  return (
    <div className="space-y-1">
      <div className="typography-ui-label text-foreground">{t('spaces.access.writes.scope')}</div>
      <SettingsRadioGroup aria-label={t('spaces.access.writes.scope')}>
        <SettingsRadioOption
          ariaLabel={t('spaces.access.writes.scopePath')}
          label={t('spaces.access.writes.scopePath')}
          description={t('spaces.access.writes.scopePathDescription')}
          selected={value === 'path'}
          disabled={disabled}
          onSelect={() => onChange('path')}
        />
        <SettingsRadioOption
          ariaLabel={t('spaces.access.writes.scopeHost')}
          label={t('spaces.access.writes.scopeHost')}
          description={t('spaces.access.writes.scopeHostDescription')}
          selected={value === 'host'}
          disabled={disabled}
          onSelect={() => onChange('host')}
        />
      </SettingsRadioGroup>
    </div>
  );
};

export default WriteScopeChoice;
