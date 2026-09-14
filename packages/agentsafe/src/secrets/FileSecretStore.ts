import { closeSync, fstatSync, openSync, readFileSync, watch, type FSWatcher } from "node:fs";
import { dirname } from "node:path";
import type { SecurityEvents } from "../incident/SecurityEvents.js";
import { SecretHandle } from "./SecretHandle.js";
import {
  SecretError,
  type ReloadReason,
  type ReloadReport,
  type SecretName,
  type SecretStore,
} from "./SecretStore.js";

/** The largest secret file the store reads, in bytes. */
export const MAX_SECRET_BYTES = 64 * 1024;

export interface FileSecretStoreOptions {
  /** Secret name to the mounted file that holds it. */
  readonly files: Readonly<Partial<Record<SecretName, string>>>;
  readonly events: SecurityEvents;
  /** Refuse a file another user could read; on by default, off only for development. */
  readonly enforcePermissions?: boolean;
  readonly euid?: number;
  readonly egid?: number;
  /** Watch the mount directories for change; on by default. */
  readonly watch?: boolean;
  /** The poll that backs the watch, for filesystems that do not report. */
  readonly pollMs?: number;
  /** How long an old handle stays usable after its replacement is current. */
  readonly graceMs?: number;
  readonly debounceMs?: number;
}

interface Source {
  readonly path: string;
  handle: SecretHandle;
}

/**
 * Secrets read from mounted files, the shape a Kubernetes Secret volume or a
 * CSI secrets driver gives them, and the only shape production accepts. A
 * file is checked on the open descriptor before it is read: a regular file,
 * bounded in size, readable by this process alone or by root and this
 * process's group. Rotation is detected by watching the mount directory
 * (a Secret volume swaps a symlink) and by a slow poll behind it; a changed
 * file becomes current atomically, listeners hear the new handle, and the
 * old handle is zeroed after a grace so an in-flight use finishes. A file
 * that fails its checks on reload is refused and the previous handle stays.
 */
export class FileSecretStore implements SecretStore {
  private readonly sources: Map<SecretName, Source>;
  private readonly listeners = new Map<SecretName, Set<(next: SecretHandle) => void>>();
  private readonly watchers: FSWatcher[] = [];
  private poll: ReturnType<typeof setInterval> | null = null;
  private debounce: ReturnType<typeof setTimeout> | null = null;
  private readonly options: Required<Omit<FileSecretStoreOptions, "files" | "events">>;

  private constructor(
    sources: Map<SecretName, Source>,
    private readonly events: SecurityEvents,
    options: FileSecretStoreOptions,
  ) {
    this.sources = sources;
    this.options = {
      enforcePermissions: options.enforcePermissions ?? true,
      euid: options.euid ?? process.geteuid?.() ?? -1,
      egid: options.egid ?? process.getegid?.() ?? -1,
      watch: options.watch ?? true,
      pollMs: options.pollMs ?? 30_000,
      graceMs: options.graceMs ?? 5_000,
      debounceMs: options.debounceMs ?? 250,
    };
    if (this.options.watch) this.startWatching();
  }

  /** Reads every file once; a failure is a `SecretError` naming the variable. */
  public static open(options: FileSecretStoreOptions): FileSecretStore {
    const enforce = options.enforcePermissions ?? true;
    const euid = options.euid ?? process.geteuid?.() ?? -1;
    const egid = options.egid ?? process.getegid?.() ?? -1;
    const sources = new Map<SecretName, Source>();
    for (const [name, path] of Object.entries(options.files) as [SecretName, string][]) {
      sources.set(name, { path, handle: FileSecretStore.read(name, path, enforce, euid, egid) });
    }
    return new FileSecretStore(sources, options.events, options);
  }

  public has(name: SecretName): boolean {
    return this.sources.has(name);
  }

  public get(name: SecretName): SecretHandle {
    const source = this.sources.get(name);
    if (source === undefined) throw new SecretError("SECRET_UNKNOWN", name);
    return source.handle;
  }

  public onRotate(name: SecretName, listener: (next: SecretHandle) => void): () => void {
    const set = this.listeners.get(name) ?? new Set();
    set.add(listener);
    this.listeners.set(name, set);
    return () => {
      set.delete(listener);
    };
  }

  public async reload(reason: ReloadReason): Promise<ReloadReport> {
    const rotated: SecretName[] = [];
    const refused: { name: SecretName; code: string }[] = [];
    for (const [name, source] of this.sources) {
      let next: SecretHandle;
      try {
        next = FileSecretStore.read(
          name,
          source.path,
          this.options.enforcePermissions,
          this.options.euid,
          this.options.egid,
        );
      } catch (error) {
        const code = error instanceof SecretError ? error.code : "CONFIG_SECRET_FILE_UNREADABLE";
        refused.push({ name, code });
        this.events.emit({ event: "SECRET_RELOAD_REFUSED", name, code });
        continue;
      }
      if (next.equals(source.handle)) {
        next.dispose();
        continue;
      }
      const previous = source.handle;
      source.handle = next;
      rotated.push(name);
      for (const listener of this.listeners.get(name) ?? []) listener(next);
      const grace = setTimeout(() => previous.dispose(), this.options.graceMs);
      grace.unref();
      this.events.emit({ event: "SECRET_ROTATED", name });
    }
    return { reason, rotated, refused };
  }

  public close(): void {
    for (const watcher of this.watchers) watcher.close();
    this.watchers.length = 0;
    if (this.poll !== null) clearInterval(this.poll);
    if (this.debounce !== null) clearTimeout(this.debounce);
    this.poll = null;
    this.debounce = null;
    for (const source of this.sources.values()) source.handle.dispose();
  }

  private startWatching(): void {
    const directories = new Set([...this.sources.values()].map((source) => dirname(source.path)));
    for (const directory of directories) {
      try {
        const watcher = watch(directory, { persistent: false }, () => this.scheduleReload("WATCH"));
        watcher.on("error", () => undefined);
        this.watchers.push(watcher);
      } catch {
        // A filesystem that cannot be watched is covered by the poll.
      }
    }
    this.poll = setInterval(() => void this.reload("POLL"), this.options.pollMs);
    this.poll.unref();
  }

  private scheduleReload(reason: ReloadReason): void {
    if (this.debounce !== null) clearTimeout(this.debounce);
    this.debounce = setTimeout(() => {
      this.debounce = null;
      void this.reload(reason);
    }, this.options.debounceMs);
    this.debounce.unref();
  }

  /**
   * The checks run on the open descriptor, so what is checked is what is
   * read. Kubernetes mounts a Secret volume owned by root with the pod's
   * fsGroup, which is the second acceptable shape.
   */
  private static read(
    name: SecretName,
    path: string,
    enforcePermissions: boolean,
    euid: number,
    egid: number,
  ): SecretHandle {
    let descriptor: number;
    try {
      descriptor = openSync(path, "r");
    } catch {
      throw new SecretError("CONFIG_SECRET_FILE_UNREADABLE", name);
    }
    try {
      const stat = fstatSync(descriptor);
      if (!stat.isFile()) throw new SecretError("CONFIG_SECRET_FILE_MODE", name);
      if (stat.size > MAX_SECRET_BYTES) throw new SecretError("CONFIG_SECRET_TOO_LARGE", name);
      if (enforcePermissions) {
        const code = FileSecretStore.permissionRefusal(stat.mode, stat.uid, stat.gid, euid, egid);
        if (code !== null) throw new SecretError(code, name);
      }
      const raw = readFileSync(descriptor);
      const text = raw.toString("utf8").trim();
      raw.fill(0);
      if (text.length === 0) throw new SecretError("CONFIG_SECRET_EMPTY", name);
      return SecretHandle.fromString(name, text);
    } finally {
      closeSync(descriptor);
    }
  }

  /** `null` when acceptable; otherwise the refusal code. */
  public static permissionRefusal(
    mode: number,
    uid: number,
    gid: number,
    euid: number,
    egid: number,
  ): "CONFIG_SECRET_FILE_MODE" | "CONFIG_SECRET_FILE_OWNER" | null {
    const bits = mode & 0o777;
    if (uid === euid) return (bits & 0o077) === 0 ? null : "CONFIG_SECRET_FILE_MODE";
    if (uid === 0 && gid === egid) return (bits & 0o027) === 0 ? null : "CONFIG_SECRET_FILE_MODE";
    return "CONFIG_SECRET_FILE_OWNER";
  }
}
