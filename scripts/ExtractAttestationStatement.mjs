import { createHash } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { basename } from "node:path";

const [bundlePath, statementPath, subjectPath] = process.argv.slice(2);
if (!bundlePath || !statementPath || !subjectPath) {
  throw new Error(
    "Usage: ExtractAttestationStatement.mjs <bundle> <statement-output> <subject-artifact>",
  );
}

const bundle = JSON.parse(await readFile(bundlePath, "utf8"));
if (typeof bundle.dsseEnvelope?.payload !== "string") {
  throw new Error("Sigstore bundle does not contain a DSSE payload");
}
const statement = JSON.parse(Buffer.from(bundle.dsseEnvelope.payload, "base64").toString("utf8"));
if (statement._type !== "https://in-toto.io/Statement/v1") {
  throw new Error(`Unexpected in-toto statement type: ${statement._type}`);
}
const digest = createHash("sha256")
  .update(await readFile(subjectPath))
  .digest("hex");
const subject = statement.subject?.find(
  ({ name, digest: subjectDigest }) =>
    basename(name) === basename(subjectPath) && subjectDigest?.sha256 === digest,
);
if (!subject) throw new Error("Attestation subject does not match the release artifact digest");
await writeFile(statementPath, `${JSON.stringify(statement, null, 2)}\n`);
process.stdout.write(`Extracted verified in-toto statement for ${basename(subjectPath)}.\n`);
