import { fileURLToPath } from "node:url";
import { resolve } from "node:path";
import { loadReleaseMetadata } from "./ReleaseMetadata.mjs";

export async function checkReleaseMetadata(options) {
  return loadReleaseMetadata(options);
}

if (process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const metadata = await checkReleaseMetadata();
  console.log(
    `Release metadata valid: ${metadata.packageName}@${metadata.version}; ${metadata.conceptDoi}; ${metadata.creators.length} creator(s).`,
  );
}
