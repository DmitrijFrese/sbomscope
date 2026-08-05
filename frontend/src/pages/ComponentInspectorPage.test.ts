import { describe, expect, it } from 'vitest';

import type { FindingRow } from '../api/client';
import { headlineSeverityCounts } from './ComponentInspectorPage';

function finding(osvId: string | null, severityScore: number | null): FindingRow {
  return { osvId, severityScore } as FindingRow;
}

describe('headlineSeverityCounts', () => {
  it('counts critical, high and medium findings using the shared CVSS bands', () => {
    expect(
      headlineSeverityCounts([
        finding('CRITICAL-1', 10),
        finding('CRITICAL-2', 9),
        finding('HIGH-1', 8.9),
        finding('MEDIUM-1', 4),
        finding('LOW-1', 3.9),
        finding('UNSCORED-1', null),
        finding(null, null),
      ]),
    ).toEqual({ critical: 2, high: 1, medium: 1, low: 1 });
  });
});
