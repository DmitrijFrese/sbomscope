interface PaginationProps {
  page: number;
  pageCount: number;
  onPage: (page: number) => void;
}

/** Rendered as a gap in the sequence rather than a page number. */
const GAP = 'gap';

/** Slots the control occupies once it is wide enough to need gaps: 1 … 5 … 1. */
const SLOTS = 9;

/** The run of numbers shown when only one gap is present, at either end. */
const RUN_AT_EDGE = SLOTS - 3;

/**
 * Page numbers around the current page, with the first and last always reachable.
 *
 * <p>A large SBOM can run to hundreds of pages, so the full list is never rendered.
 *
 * <p>The run is pushed inward near the ends so the control keeps a constant width: at the
 * edges one gap disappears, and without compensating the row would shrink by two slots and
 * shift every button under the cursor exactly when someone is clicking through pages.
 */
function pageItems(page: number, pageCount: number): (number | typeof GAP)[] {
  // Small enough to list in full; a gap would save nothing and cost clarity.
  if (pageCount <= SLOTS - 2) {
    return Array.from({ length: pageCount }, (_, index) => index);
  }

  const items: (number | typeof GAP)[] = [0];

  let start = Math.max(1, page - 2);
  let end = Math.min(pageCount - 2, page + 2);
  if (page <= 3) {
    end = Math.min(pageCount - 2, RUN_AT_EDGE);
  }
  if (page >= pageCount - 4) {
    start = Math.max(1, pageCount - 1 - RUN_AT_EDGE);
  }

  if (start > 1) items.push(GAP);
  for (let index = start; index <= end; index++) items.push(index);
  if (end < pageCount - 2) items.push(GAP);

  items.push(pageCount - 1);
  return items;
}

export function Pagination({ page, pageCount, onPage }: PaginationProps) {
  if (pageCount <= 1) {
    return null;
  }

  return (
    <nav className="pager" aria-label="Pages">
      <button
        type="button"
        className="button button--small"
        onClick={() => onPage(page - 1)}
        disabled={page === 0}
      >
        Previous
      </button>

      <ul className="pager__pages">
        {pageItems(page, pageCount).map((item, index) =>
          item === GAP ? (
            <li key={`gap-${index}`} className="pager__gap" aria-hidden="true">
              …
            </li>
          ) : (
            <li key={item}>
              <button
                type="button"
                className="pager__page"
                aria-current={item === page ? 'page' : undefined}
                aria-label={`Page ${item + 1}`}
                onClick={() => onPage(item)}
              >
                {item + 1}
              </button>
            </li>
          ),
        )}
      </ul>

      <button
        type="button"
        className="button button--small"
        onClick={() => onPage(page + 1)}
        disabled={page + 1 >= pageCount}
      >
        Next
      </button>
    </nav>
  );
}
