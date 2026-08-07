/*
 * Inline SVG icons rather than an icon package: a handful of glyphs does not
 * justify a dependency in a tool whose own dependency tree is part of its pitch.
 */
import type { SVGProps } from 'react';

type IconProps = SVGProps<SVGSVGElement>;

function Icon({ children, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...props}
    >
      {children}
    </svg>
  );
}

export function ShieldIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3l7 3v6c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3z" />
    </Icon>
  );
}

/** The product mark: inspect one package, not a generic search or a second nav cube. */
export function BrandIcon(props: IconProps) {
  return (
    <Icon {...props} strokeWidth="1.7">
      <circle cx="10" cy="10" r="6.5" />
      <path d="M14.8 14.8L21 21" />
      <path d="M10 6.2l3.1 1.7v3.6L10 13.2l-3.1-1.7V7.9L10 6.2z" />
      <path d="M6.9 7.9L10 9.7l3.1-1.8M10 9.7v3.5" />
    </Icon>
  );
}

/**
 * A package: the Component Inspector's subject is one library, not a directory of files.
 * Three strokes on purpose — the nav renders these at 18px, where an overlaid magnifier or
 * anything finer turns to mush.
 */
export function ComponentIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 2.5l8 4.5v9l-8 4.5-8-4.5v-9l8-4.5z" />
      <path d="M4 7l8 4.5L20 7" />
      <path d="M12 11.5v9" />
    </Icon>
  );
}

export function FilesIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z" />
      <path d="M14 3v5h5" />
    </Icon>
  );
}

/** A project or folder in the sidebar tree (B19). */
export function FolderIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M3 6a1 1 0 0 1 1-1h5l2 2h9a1 1 0 0 1 1 1v10a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V6z" />
    </Icon>
  );
}

/** Small disclosure triangle, rotated by CSS rather than swapped for a second glyph. */
export function DisclosureIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M9 6l6 6-6 6" />
    </Icon>
  );
}

/**
 * An arrow going into a container: move this somewhere else.
 *
 * <p>Distinct from {@link FolderIcon} deliberately — using the folder glyph for "move" put
 * the same mark on the thing and on the action done to it, which reads as "folder" twice.
 */
export function MoveIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M3 12h10" />
      <path d="M10 9l3 3-3 3" />
      <path d="M17 5h4v14h-4" />
    </Icon>
  );
}

/** A pencil: renaming a folder in place. */
export function PencilIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 20h4L20 8l-4-4L4 16v4z" />
      <path d="M14 6l4 4" />
    </Icon>
  );
}

/** A chain link: attaching, changing or clearing a document's workspace (B20). */
export function LinkIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M9 15l6-6" />
      <path d="M13 6l1.5-1.5a3.2 3.2 0 0 1 4.5 4.5L17.5 10.5" />
      <path d="M11 18l-1.5 1.5a3.2 3.2 0 0 1-4.5-4.5L6.5 13.5" />
    </Icon>
  );
}

/** Arrow into a tray: the stored document, handed back as it arrived. */
export function DownloadIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M12 3v11" />
      <path d="M8 10.5l4 4 4-4" />
      <path d="M4.5 17v2.5a1 1 0 0 0 1 1h13a1 1 0 0 0 1-1V17" />
    </Icon>
  );
}

export function SettingsIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.7 1.7 0 0 0 .3 1.9l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-2.9 1.2v.1a2 2 0 1 1-4 0v-.1A1.7 1.7 0 0 0 7 19.4a1.7 1.7 0 0 0-1.9.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0-1.2-2.9H1a2 2 0 1 1 0-4h.1A1.7 1.7 0 0 0 2.6 7a1.7 1.7 0 0 0-.3-1.9l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 2.9-1.2V1a2 2 0 1 1 4 0v.1A1.7 1.7 0 0 0 17 2.6a1.7 1.7 0 0 0 1.9-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0 1.2 2.9h.1a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z" />
    </Icon>
  );
}

export function MoreIcon(props: IconProps) {
  return (
    <Icon {...props} fill="currentColor" stroke="none">
      <circle cx="5" cy="12" r="1.7" />
      <circle cx="12" cy="12" r="1.7" />
      <circle cx="19" cy="12" r="1.7" />
    </Icon>
  );
}

/** A log: notable-event lines of varying length, not a generic list. */
export function LogIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 6h16" />
      <path d="M4 12h11" />
      <path d="M4 18h7" />
    </Icon>
  );
}

export function BookIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M4 5a2 2 0 0 1 2-2h13v16H6a2 2 0 0 0-2 2z" />
      <path d="M4 19a2 2 0 0 1 2-2h13" />
    </Icon>
  );
}

export function ChevronLeftIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M15 5l-7 7 7 7" />
    </Icon>
  );
}

export function ChevronRightIcon(props: IconProps) {
  return (
    <Icon {...props}>
      <path d="M9 5l7 7-7 7" />
    </Icon>
  );
}
