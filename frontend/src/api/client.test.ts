import { describe, expect, it } from 'vitest';

import { exportUrl } from './client';
import type { FindingQuery } from './client';

describe('finding query URLs', () => {
  it('carries both library selections into exports', () => {
    const query: FindingQuery = {
      sort: 'SEVERITY',
      ascending: false,
      filter: '',
      regex: false,
      negate: false,
      severities: ['CRITICAL'],
      scopes: ['DIRECT'],
      duplicatesOnly: true,
      worstPerVersion: true,
      pageSize: 20,
      page: 2,
    };

    const url = new URL(exportUrl('document-id', query, 'all'), 'http://localhost');

    expect(url.searchParams.get('duplicatesOnly')).toBe('true');
    expect(url.searchParams.get('worstPerVersion')).toBe('true');
    expect(url.searchParams.getAll('scope_filter')).toEqual(['DIRECT']);
  });
});
