import { Link } from 'react-router-dom';

import type { ScanReadiness } from '../api/client';

/**
 * Says why scanning is unavailable, next to the button that is therefore disabled.
 *
 * <p>Rendered as visible text rather than a tooltip on the button: a `title` attribute is
 * invisible on a touch device, invisible to a keyboard user, and invisible to anyone who
 * does not think to hover over a control that looks broken. The obstacle is also always
 * something the user has to go and fix somewhere else, so it carries the link there.
 */
export function ScanReadinessHint({ readiness }: { readiness: ScanReadiness }) {
  if (readiness.ready) {
    return null;
  }

  return (
    <span className="scan-hint">
      {messageFor(readiness)} <Link to="/settings">Settings</Link>
    </span>
  );
}

function messageFor(readiness: ScanReadiness): string {
  switch (readiness.reason) {
    case 'SCANNING_DISABLED':
      return 'Scanning is switched off — turn on Use OSV-Scanner in';
    case 'NO_EXECUTABLE':
      return 'No scanner binary configured. Set its path in';
    case 'EXECUTABLE_MISSING':
      // The path is named because "it moved" and "it was never there" need different
      // fixes, and only the user knows which happened.
      return `The scanner is no longer at ${readiness.detail ?? 'its configured path'}. Update it in`;
    case 'NO_DATABASE':
      return `No offline database for ${readiness.detail ?? 'this SBOM'}. Download it in`;
    default:
      return 'Scanning is unavailable. Check';
  }
}
