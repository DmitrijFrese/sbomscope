/**
 * How long a folder name may be, and how that is told to the reader.
 *
 * <p>256 because `folder.name` is `VARCHAR(256)` and `FolderService.validName` refuses
 * anything longer. The cap existed on the server and nowhere on screen: a long name could
 * only be discovered to be too long after it had been typed and submitted, which is the one
 * failure mode the sibling-name check was already written to avoid.
 *
 * <p>Shared because the name field exists twice — the tree's rename/new-subfolder field and
 * the sidebar's top-level project form, which is a hand-rolled copy of it. Two copies of a
 * limit is how one of them ends up disagreeing with the database.
 */

export const MAX_FOLDER_NAME = 256;

/** Only the last stretch is worth counting; a number under every rename would be noise. */
const COUNTER_SHOWS_FROM = MAX_FOLDER_NAME - 32;

/** The counter, or nothing at all while the name is nowhere near the limit. */
export function NameLengthNote({ value }: { value: string }) {
  if (value.length < COUNTER_SHOWS_FROM) return null;
  return (
    <p className="folder-name-form__note" role="status">
      {value.length === MAX_FOLDER_NAME
        ? `${MAX_FOLDER_NAME} characters — the longest a folder name may be.`
        : `${value.length} of ${MAX_FOLDER_NAME} characters.`}
    </p>
  );
}
