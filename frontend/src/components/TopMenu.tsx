import { useEffect, useState } from 'react';
import { NavLink } from 'react-router-dom';

import { fetchServerStatus } from '../api/client';
import type { ServerStatus } from '../api/client';
import { BookIcon, BrandIcon, ComponentIcon, LogIcon, SettingsIcon, ShieldIcon } from './icons';

const NAV_ITEMS = [
  { to: '/vulnerabilities', label: 'Vulnerabilities', Icon: ShieldIcon },
  { to: '/component-inspector', label: 'Component Inspector', Icon: ComponentIcon },
  { to: '/monitoring', label: 'Monitoring', Icon: LogIcon },
  { to: '/glossary', label: 'Glossary', Icon: BookIcon },
  { to: '/settings', label: 'Settings', Icon: SettingsIcon },
] as const;

export function TopMenu() {
  const [status, setStatus] = useState<ServerStatus | null>(null);
  const [reachable, setReachable] = useState<boolean | null>(null);

  useEffect(() => {
    let cancelled = false;

    fetchServerStatus()
      .then((result) => {
        if (cancelled) return;
        setStatus(result);
        setReachable(true);
      })
      .catch(() => {
        if (!cancelled) setReachable(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <header className="topmenu">
      <div className="topmenu__brand">
        <BrandIcon className="topmenu__brand-icon" />
        <span className="topmenu__brand-label">SBOMscope</span>
      </div>

      <nav className="topmenu__nav" aria-label="Main">
        {NAV_ITEMS.map(({ to, label, Icon }) => (
          <NavLink key={to} to={to} className="navitem" aria-label={label} title={label}>
            <Icon className="navitem__icon" />
            <span className="navitem__label">{label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="topmenu__spacer" />

      <p className="status-line">
        <span
          className="status-dot"
          data-state={reachable === null ? 'unknown' : reachable ? 'up' : 'down'}
        />
        {reachable === null && 'Connecting…'}
        {reachable === false && 'Backend unreachable'}
        {reachable === true && status && `v${status.version}`}
      </p>
    </header>
  );
}
