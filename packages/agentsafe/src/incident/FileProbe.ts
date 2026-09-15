import { statSync, watch, type FSWatcher } from "node:fs";

/**
 * Whether a path is a regular file this process can see.
 *
 * This is the one thing the halt switch asks of the host, kept in its own
 * module because it is a question about the filesystem rather than about the
 * stop: anything the process cannot stat is not a halt file — no such path,
 * an unreadable parent directory, a symlink loop — and the look must answer
 * rather than throw, because it also runs inside the poll's own callback.
 */
export function regularFileExists(path: string): boolean {
  try {
    return statSync(path).isFile();
  } catch {
    return false;
  }
}

/**
 * Follows a directory for changes, without holding the process open.
 *
 * The halt file's own directory is what is watched rather than the file: a
 * secret or ConfigMap mount replaces the file by swapping a symlink, and a
 * watch on the old inode would never fire again. `persistent: false` keeps
 * the watch from being a reason for the process to stay alive, which matters
 * because the stop is followed for the whole life of the executor.
 */
export function watchDirectory(path: string, onChange: () => void): FSWatcher {
  return watch(path, { persistent: false }, onChange);
}
