import type { CSSProperties } from 'react';
import { Navigate, Route, Routes, useLocation } from 'react-router-dom';

import { SbomSidebar } from './components/SbomSidebar';
import { SidebarResizer } from './components/SidebarResizer';
import { TopMenu } from './components/TopMenu';
import { ComponentInspectorPage } from './pages/ComponentInspectorPage';
import { DiffPage } from './pages/DiffPage';
import { GlossaryPage } from './pages/GlossaryPage';
import { MonitoringPage } from './pages/MonitoringPage';
import { SettingsPage } from './pages/SettingsPage';
import { VulnerabilitiesPage } from './pages/VulnerabilitiesPage';
import { usePersistentState, usePersistentToggle } from './state/persisted';

/**
 * Routes that operate on documents from the sidebar, and therefore show it.
 *
 * <p>`/diff` is here for a different reason than the other two. They read the *selected*
 * document; the diff reads a pair chosen from the row menus and ignores the selection
 * entirely. It still needs the tree on screen, because choosing the two sides is the first
 * thing anyone does on that page and a panel you have to navigate away from to use is not
 * the "link two objects from the left panel" the feature was asked for.
 */
const SBOM_SCOPED_ROUTES = ['/vulnerabilities', '/component-inspector', '/diff'];

/**
 * The range the sidebar boundary can be dragged through.
 *
 * <p>`SIDEBAR_MIN` mirrors `--sidebar-width` in tokens.css deliberately. The token still
 * resolves every other state of the shell — the rail, the routes with no sidebar at all —
 * and the narrowest draggable width is exactly the layout that existed before dragging did,
 * so nothing measured against it moves unless the user asks.
 */
const SIDEBAR_MIN = 280;
const SIDEBAR_MAX = SIDEBAR_MIN * 2;

export function App() {
  const { pathname } = useLocation();
  // Collapsing is about reclaiming width for the table, so it has to outlive a reload —
  // a width preference that resets constantly is worse than not offering one.
  const [sidebarCollapsed, toggleSidebar] = usePersistentToggle('sidebar.collapsed', false);
  // Same argument as collapsing, and the same storage. Revived rather than trusted: a width
  // stored by a build with a different range must still land inside this one's.
  const [sidebarWidth, setSidebarWidth] = usePersistentState<number>(
    'sidebar.width',
    SIDEBAR_MIN,
    (stored) =>
      typeof stored === 'number' && Number.isFinite(stored)
        ? Math.min(SIDEBAR_MAX, Math.max(SIDEBAR_MIN, Math.round(stored)))
        : SIDEBAR_MIN,
  );

  const showSidebar = SBOM_SCOPED_ROUTES.some((route) => pathname.startsWith(route));
  const sidebarState = !showSidebar ? 'hidden' : sidebarCollapsed ? 'collapsed' : 'visible';

  return (
    <div className="app-shell">
      <TopMenu />

      {/* The width rides on the shell rather than on the sidebar because the grid column
          is declared here; the collapsed and hidden rules override the template outright,
          so a stored width cannot leak into either state. */}
      <div
        className="app-body"
        data-sidebar={sidebarState}
        style={{ '--sidebar-width': `${sidebarWidth}px` } as CSSProperties}
      >
        {showSidebar && (
          <SbomSidebar collapsed={sidebarCollapsed} onToggleCollapsed={toggleSidebar} />
        )}

        {sidebarState === 'visible' && (
          <SidebarResizer
            width={sidebarWidth}
            min={SIDEBAR_MIN}
            max={SIDEBAR_MAX}
            onWidth={setSidebarWidth}
          />
        )}

        <main className="app-main">
          <Routes>
            <Route path="/" element={<Navigate to="/vulnerabilities" replace />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
            <Route path="/component-inspector" element={<ComponentInspectorPage />} />
            <Route path="/diff" element={<DiffPage />} />
            {/* The old name, kept so a bookmarked tab lands where it meant to rather
                than bouncing to the vulnerability view via the catch-all. */}
            <Route path="/workspace" element={<Navigate to="/component-inspector" replace />} />
            <Route path="/monitoring" element={<MonitoringPage />} />
            {/* The old name, kept for the same reason /workspace is: a bookmarked tab should
                land where it meant to rather than bouncing via the catch-all. */}
            <Route path="/log" element={<Navigate to="/monitoring" replace />} />
            <Route path="/glossary" element={<GlossaryPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="*" element={<Navigate to="/vulnerabilities" replace />} />
          </Routes>
        </main>
      </div>
    </div>
  );
}
