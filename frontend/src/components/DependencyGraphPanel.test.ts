import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { createElement } from 'react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  fetchComponentGraph,
  fetchComponentRoutePage,
} from '../api/client';
import type { ComponentGraph, GraphNode, ModuleRoutes } from '../api/client';
import {
  DependencyGraphPanel,
  routeDeclaration,
  totalRouteCount,
} from './DependencyGraphPanel';

vi.mock('../api/client', () => ({
  fetchComponentGraph: vi.fn(),
  fetchComponentRoutePage: vi.fn(),
}));

const fetchGraph = vi.mocked(fetchComponentGraph);
const fetchRoutePage = vi.mocked(fetchComponentRoutePage);

function node(bomRef: string, scope: GraphNode['scope']): GraphNode {
  return {
    bomRef,
    coordinates: `example:${bomRef}`,
    version: '1.0.0',
    purl: `pkg:maven/example/${bomRef}@1.0.0`,
    root: false,
    scope,
    vulnerable: false,
  };
}

function route(module: GraphNode, target: GraphNode, number: number): GraphNode[] {
  return [module, node(`declaration-${number}`, 'TRANSITIVE'), target];
}

beforeEach(() => {
  fetchGraph.mockReset();
  fetchRoutePage.mockReset();
});

describe('routeDeclaration', () => {
  it('identifies the module for a direct dependency route', () => {
    const module = node('module', 'APPLICATION');
    expect(routeDeclaration([module, node('target', 'DIRECT')])).toBe(module);
  });

  it('identifies the immediate intermediate component rather than the module', () => {
    const adapter = node('adapter', 'TRANSITIVE');
    expect(routeDeclaration([
      node('module', 'APPLICATION'),
      node('framework', 'DIRECT'),
      adapter,
      node('target', 'TRANSITIVE'),
    ])).toBe(adapter);
  });
});

describe('totalRouteCount', () => {
  it('uses exact route totals rather than the number of displayed cards', () => {
    const module = (bomRef: string, totalRoutes: number, displayedRoutes: number): ModuleRoutes => ({
      module: node(bomRef, 'APPLICATION'),
      routes: Array.from({ length: displayedRoutes }, () => [node('target', 'TRANSITIVE')]),
      totalRoutes,
      truncated: totalRoutes > displayedRoutes,
      directRoutes: 0,
      declarations: [],
    });

    expect(totalRouteCount([
      module('module-a', 125, 100),
      module('module-b', 37, 37),
    ])).toBe(162);
  });
});

describe('DependencyGraphPanel route paging', () => {
  it('shows the exact total and continues numbering through the next 100 routes', async () => {
    const module = node('module-a', 'APPLICATION');
    const target = node('target', 'TRANSITIVE');
    const initialRoutes = Array.from({ length: 100 }, (_, index) => route(module, target, index + 1));
    const nextRoutes = Array.from({ length: 100 }, (_, index) => route(module, target, index + 101));
    const graph: ComponentGraph = {
      reachedFrom: [{
        module,
        routes: initialRoutes,
        totalRoutes: 237,
        truncated: false,
        directRoutes: 0,
        declarations: [],
      }],
      ownModuleCount: 2,
      targetIsOwnCode: false,
      tree: null,
    };
    fetchGraph.mockResolvedValue(graph);
    fetchRoutePage.mockResolvedValue({
      moduleBomRef: module.bomRef,
      offset: 100,
      routes: nextRoutes,
      totalRoutes: 237,
    });

    const { container } = render(createElement(
      MemoryRouter,
      null,
      createElement(DependencyGraphPanel, { sbomId: 'sbom-1', purl: target.purl! }),
    ));

    await waitFor(() => {
      expect(container.querySelector('.panel__hint')?.textContent)
        .toContain('Pulled in by 1 of your 2 modules. Total paths: 237.');
    });
    expect(screen.getByText('Route 100')).toBeTruthy();
    expect(screen.queryByText('Route 101')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Show next 100' }));

    expect(await screen.findByText('Route 101')).toBeTruthy();
    expect(screen.getByText('Route 200')).toBeTruthy();
    expect(fetchRoutePage).toHaveBeenCalledWith('sbom-1', target.purl, module.bomRef, 100);
    expect(container.querySelector('.panel__hint')?.textContent)
      .toContain('Total paths: 237.');
  });
});
