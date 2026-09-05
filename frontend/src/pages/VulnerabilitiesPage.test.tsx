import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';

import { SeverityChip } from './VulnerabilitiesPage';

describe('SeverityChip', () => {
  it('shows one filtered count and exposes the whole-SBOM total through its fill and name', () => {
    const onToggle = vi.fn();
    render(
      <SeverityChip
        band="CRITICAL"
        filtered={5}
        total={10}
        selected
        onToggle={onToggle}
      />,
    );

    const chip = screen.getByRole('button', { name: 'Critical — 5 of 10 shown' });
    expect(chip.getAttribute('title')).toBe('Critical — 5 of 10 shown');
    // Both numbers are on the chip, in words. A proportional fill was tried twice and read as
    // nothing at all: the real ratios are 2 of 146, which is a mark a few pixels wide inside a
    // pill's clipped corner. The picture was right in the computed style and absent on screen.
    expect(chip.textContent).toBe('Critical5of 10');

    fireEvent.click(chip);
    expect(onToggle).toHaveBeenCalledOnce();
  });

  it('states one number only when the filter is hiding nothing from that band', () => {
    // The denominator earns its width only while it differs from the count beside it. An
    // unfiltered row of six chips reading "41 of 41" would be six numbers saying one thing.
    render(
      <SeverityChip band="CLEAN" filtered={10} total={10} selected={false} onToggle={vi.fn()} />,
    );

    const chip = screen.getByRole('button', { name: 'Clean — 10' });
    expect(chip.getAttribute('title')).toBe('Clean — 10');
    expect(chip.textContent).toBe('Clean10');
    expect(chip.textContent).not.toContain('of');
  });
});
