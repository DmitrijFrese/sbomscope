import type { SeverityBand } from '../api/client';

/**
 * The four scored CVSS bands worth triaging on at a glance. Unscored and Clean stay on the
 * findings page: they are qualitatively different states rather than another rung on the
 * CVSS scale, and a sidebar card or a project rollup is a glance, not a report.
 *
 * <p>Shared between the SBOM card and the project rollup (B19) so a reader comparing "this
 * document" against "everything in this project" is comparing the same four numbers.
 */
export const CARD_BANDS: SeverityBand[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
