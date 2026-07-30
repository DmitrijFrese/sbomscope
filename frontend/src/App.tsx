import { Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { SbomSidebar } from './components/SbomSidebar';
import { TopMenu } from './components/TopMenu';
import { ComponentInspectorPage } from './pages/ComponentInspectorPage';
import { GlossaryPage } from './pages/GlossaryPage';
import { LogPage } from './pages/LogPage';
import { SettingsPage } from './pages/SettingsPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { usePersistentToggle } from './state/persisted';

/** Routes that operate on a selected SBOM, and therefore show the sidebar. */
const SBOM_SCOPED_ROUTES = ['/vulnerabilities', '/component-inspector'];

export function App() {
  const { pathname } = useLocation();
  // Collapsing is about reclaiming width for the table, so it has to outlive a reload —
  // a width preference that resets constantly is worse than not offering one.
  const [sidebarCollapsed, toggleSidebar] = usePersistentToggle('sidebar.collapsed', false);

  const showSidebar = SBOM_SCOPED_ROUTES.some((route) => pathname.startsWith(route));
  const sidebarState = !showSidebar ? 'hidden' : sidebarCollapsed ? 'collapsed' : 'visible';

  return (
    <div className="app-shell">
      <TopMenu />

      <div className="app-body" data-sidebar={sidebarState}>
        {showSidebar && (
          <SbomSidebar collapsed={sidebarCollapsed} onToggleCollapsed={toggleSidebar} />
        )}

        <main className="app-main">
          <Routes>
            <Route path="/" element={<Navigate to="/vulnerabilities" replace />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="/component-inspector" element={<ComponentInspectorPage />} />
            {/* The old name, kept so a bookmarked tab lands where it meant to rather
                than bouncing to the vulnerability view via the catch-all. */}
            <Route path="/workspace" element={<Navigate to="/component-inspector" replace />} />
            <Route path="/log" element={<LogPage />} />
            <Route path="/glossary" element={<GlossaryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/vulnerabilities" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
