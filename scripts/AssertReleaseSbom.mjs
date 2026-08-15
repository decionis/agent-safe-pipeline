import { readFile } from "node:fs/promises";

const [path, expectedName, expectedVersion, minimumComponentsText] = process.argv.slice(2);
const minimumComponents = Number.parseInt(minimumComponentsText, 10);
if (!path || !expectedName || !expectedVersion || !Number.isInteger(minimumComponents)) {
  throw new Error("Usage: AssertReleaseSbom.mjs <path> <name> <version> <minimum-components>");
}

const sbom = JSON.parse(await readFile(path, "utf8"));
const countComponents = (components) =>
  Array.isArray(components)
    ? components.reduce((count, component) => count + 1 + countComponents(component.components), 0)
    : 0;
const componentCount = countComponents(sbom.components);
const componentName = sbom.metadata?.component?.group
  ? `${sbom.metadata.component.group}/${sbom.metadata.component.name}`
  : sbom.metadata?.component?.name;
if (sbom.bomFormat !== "CycloneDX") throw new Error("Release SBOM must be CycloneDX");
if (
  !/^urn:uuid:[0-9a-f]{8}-[0-9a-f]{4}-5[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    sbom.serialNumber ?? "",
  )
) {
  throw new Error("Release SBOM must contain a deterministic RFC 4122 UUID serial number");
}
if (componentName !== expectedName) {
  throw new Error(`Release SBOM names ${componentName ?? "no component"}`);
}
if (sbom.metadata?.component?.version !== expectedVersion) {
  throw new Error(`Release SBOM version is ${sbom.metadata?.component?.version ?? "missing"}`);
}
if (componentCount < minimumComponents) {
  throw new Error(
    `Release SBOM contains ${componentCount} components; expected at least ${minimumComponents}`,
  );
}
process.stdout.write(`Release SBOM contains ${componentCount} dependency components.\n`);
