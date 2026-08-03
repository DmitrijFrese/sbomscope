import { describe, expect, it } from 'vitest';

import { pathKind } from './WorkspaceUsagePanel';

describe('pathKind', () => {
  it('distinguishes a direct component-boundary call from one through framework code', () => {
    expect(pathKind(['app.Controller#read()', 'jackson.ObjectMapper#readTree()']))
      .toBe('Direct call');
    expect(pathKind([
      'app.Controller#read()',
      'spring.JsonAdapter#convert()',
      'jackson.ObjectMapper#readTree()',
    ])).toBe('Transitive call (1 intermediate method)');
  });
});
