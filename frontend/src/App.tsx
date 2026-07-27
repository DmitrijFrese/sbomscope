import { Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { SbomSidebar } from './components/SbomSidebar';
import { TopMenu } from './components/TopMenu';
import { GlossaryPage } from './pages/GlossaryPage';
import { SettingsPage } from './pages/SettingsPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { WorkspacePage } from './pages/WorkspacePage';
import { usePersistentToggle } from './state/persisted';

/** Routes that operate on a selected SBOM, and therefore show the sidebar. */
const SBOM_SCOPED_ROUTES = ['/vulnerabilities', '/workspace'];

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
            <Route path="/workspace" element={<WorkspacePage />} />
            <Route path="/glossary" element={<GlossaryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/vulnerabilities" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
