/**
 * Which distribution this process was installed from, as one closed token,
 * so a hosted call can say `surface=homebrew` beside the version it already
 * carries and the funnel can be read per surface: installs from the release
 * downloads, first governed actions from the authority's own record. The
 * token is the whole of what is derived: the paths looked at to derive it
 * are never reported, and nothing is derived from the network, the user or
 * the machine. A distribution that runs the process itself names the
 * surface in `AGENTSAFE_SURFACE` (the image, the chart, the systemd unit);
 * the others are recognised by where the executable sits. An unknown value
 * in the variable, or a location that is none of these, is no surface at
 * all rather than a guess.
 */
export const INSTALL_SURFACES = [
  "homebrew",
  "linux",
  "installer",
  "docker",
  "kubernetes",
  "npm",
  "source",
] as const;

export type InstallSurface = (typeof INSTALL_SURFACES)[number];

export const SURFACE_ENVIRONMENT = "AGENTSAFE_SURFACE";

/** What the derivation reads: the environment, the executable, and the entry script when there is one. */
export interface SurfaceFacts {
  readonly env: Readonly<Record<string, string | undefined>>;
  readonly execPath: string;
  readonly script: string | undefined;
}

function isSurface(value: string | undefined): value is InstallSurface {
  return (INSTALL_SURFACES as readonly string[]).includes(value ?? "");
}

export function installSurface(facts: SurfaceFacts): InstallSurface | null {
  const named = facts.env[SURFACE_ENVIRONMENT]?.trim().toLowerCase();
  if (named !== undefined && named !== "") return isSurface(named) ? named : null;
  const locations = [facts.execPath, facts.script ?? ""].map((path) => path.replace(/\\/g, "/"));
  const at = (fragment: string): boolean => locations.some((path) => path.includes(fragment));
  // Homebrew keeps the release archive under the Cellar and links the bin.
  if (at("/Cellar/agentsafe/")) return "homebrew";
  // The installer puts the archive under <prefix>/lib/agentsafe/<version>/.
  if (at("/lib/agentsafe/")) return "installer";
  // The .deb and .rpm place the one executable at /usr/bin/agentsafe.
  if (locations.some((path) => path.endsWith("/usr/bin/agentsafe"))) return "linux";
  // A package install runs the bin out of node_modules; a checkout out of packages/.
  if (at("/node_modules/")) return "npm";
  if (at("/packages/agentsafe/")) return "source";
  return null;
}

/** The surface of the running process, from its own environment and location. */
export function processSurface(
  env: Readonly<Record<string, string | undefined>> = process.env,
): InstallSurface | null {
  return installSurface({ env, execPath: process.execPath, script: process.argv[1] });
}
