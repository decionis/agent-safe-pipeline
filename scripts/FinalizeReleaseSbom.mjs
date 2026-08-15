import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";

const [sbomPath, artifactPath, expectedName, expectedVersion] = process.argv.slice(2);
if (!sbomPath || !artifactPath || !expectedName || !expectedVersion) {
  throw new Error("Usage: FinalizeReleaseSbom.mjs <sbom-path> <artifact-path> <name> <version>");
}

const artifactDigest = createHash("sha256")
  .update(await readFile(artifactPath))
  .digest("hex");
const urlNamespace = Buffer.from("6ba7b8119dad11d180b400c04fd430c8", "hex");
const uuidName = `https://github.com/decionis/agent-safe-pipeline/sbom/sha256:${artifactDigest}`;
const uuidBytes = createHash("sha1").update(urlNamespace).update(uuidName).digest().subarray(0, 16);
uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x50;
uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80;
const hex = uuidBytes.toString("hex");
const uuid = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;

const sbom = JSON.parse(await readFile(sbomPath, "utf8"));
if (sbom.bomFormat !== "CycloneDX" || typeof sbom.specVersion !== "string") {
  throw new Error("Release SBOM must be CycloneDX JSON before finalization");
}
const rootComponent = sbom.metadata?.component;
if (
  rootComponent?.version !== expectedVersion ||
  typeof rootComponent.purl !== "string" ||
  !decodeURIComponent(rootComponent.purl).includes(`${expectedName}@${expectedVersion}`)
) {
  throw new Error("Release SBOM root does not match the packed package");
}
const scopeSeparator = expectedName.startsWith("@") ? expectedName.indexOf("/") : -1;
if (scopeSeparator > 0) {
  rootComponent.group = expectedName.slice(0, scopeSeparator);
  rootComponent.name = expectedName.slice(scopeSeparator + 1);
} else {
  delete rootComponent.group;
  rootComponent.name = expectedName;
}
delete sbom.metadata.timestamp;
sbom.serialNumber = `urn:uuid:${uuid}`;
await writeFile(sbomPath, `${JSON.stringify(sbom, null, 2)}\n`);
process.stdout.write(`Finalized reproducible SBOM ${sbom.serialNumber}.\n`);
