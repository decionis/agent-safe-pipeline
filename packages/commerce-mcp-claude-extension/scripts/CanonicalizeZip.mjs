import assert from "node:assert/strict";
import { readFile, writeFile } from "node:fs/promises";

const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;
const LOCAL_FILE_SIGNATURE = 0x04034b50;
const MAXIMUM_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAXIMUM_ENTRIES = 64;
const REPRODUCIBLE_DOS_DATE = ((2000 - 1980) << 9) | (1 << 5) | 1;

function checkedEnd(start, length, limit, label) {
  assert.ok(Number.isSafeInteger(start) && Number.isSafeInteger(length), `${label} is invalid.`);
  const end = start + length;
  assert.ok(start >= 0 && length >= 0 && end <= limit, `${label} exceeds the archive.`);
  return end;
}

function validateEntryName(nameBytes, names, foldedNames) {
  assert.ok(nameBytes.length > 0, "ZIP entries must have names.");
  const name = nameBytes.toString("utf8");
  assert.deepEqual(Buffer.from(name, "utf8"), nameBytes, "ZIP entry names must be valid UTF-8.");
  assert.ok(!name.includes("\\") && !name.includes("\0"), `${name} has an unsafe ZIP name.`);
  assert.ok(!name.startsWith("/") && !/^[A-Za-z]:/u.test(name), `${name} must be relative.`);
  const segments = name.split("/");
  assert.ok(
    segments.every((segment) => segment !== "" && segment !== "." && segment !== ".."),
    `${name} contains an unsafe path segment.`,
  );
  assert.ok(!names.has(name), `Duplicate ZIP entry: ${name}`);
  const foldedName = name.toLocaleLowerCase("en-US");
  assert.ok(!foldedNames.has(foldedName), `Case-colliding ZIP entry: ${name}`);
  names.add(name);
  foldedNames.add(foldedName);
  return name;
}

function parseEntries(archive, centralOffset, centralSize, entryCount) {
  const entries = [];
  const names = new Set();
  const foldedNames = new Set();
  let cursor = centralOffset;

  for (let index = 0; index < entryCount; index += 1) {
    checkedEnd(cursor, 46, archive.length, "Central-directory header");
    assert.equal(
      archive.readUInt32LE(cursor),
      CENTRAL_DIRECTORY_SIGNATURE,
      "ZIP central-directory entry is malformed.",
    );
    const flags = archive.readUInt16LE(cursor + 8);
    const method = archive.readUInt16LE(cursor + 10);
    const compressedSize = archive.readUInt32LE(cursor + 20);
    const uncompressedSize = archive.readUInt32LE(cursor + 24);
    const nameLength = archive.readUInt16LE(cursor + 28);
    const extraLength = archive.readUInt16LE(cursor + 30);
    const commentLength = archive.readUInt16LE(cursor + 32);
    const diskNumber = archive.readUInt16LE(cursor + 34);
    const localOffset = archive.readUInt32LE(cursor + 42);
    const centralEnd = checkedEnd(
      cursor,
      46 + nameLength + extraLength + commentLength,
      archive.length,
      "Central-directory entry",
    );

    assert.equal(flags & 0x0001, 0, "Encrypted ZIP entries are forbidden.");
    assert.equal(flags & 0x0008, 0, "ZIP data descriptors are forbidden.");
    assert.ok(method === 0 || method === 8, "Only stored or deflated ZIP entries are supported.");
    assert.notEqual(compressedSize, 0xffffffff, "ZIP64 entries are forbidden.");
    assert.notEqual(uncompressedSize, 0xffffffff, "ZIP64 entries are forbidden.");
    assert.notEqual(localOffset, 0xffffffff, "ZIP64 entries are forbidden.");
    assert.equal(extraLength, 0, "ZIP extra fields are forbidden.");
    assert.equal(commentLength, 0, "ZIP entry comments are forbidden.");
    assert.equal(diskNumber, 0, "Multi-disk ZIP entries are forbidden.");

    const nameBytes = archive.subarray(cursor + 46, cursor + 46 + nameLength);
    const name = validateEntryName(nameBytes, names, foldedNames);

    checkedEnd(localOffset, 30, centralOffset, `${name} local header`);
    assert.equal(
      archive.readUInt32LE(localOffset),
      LOCAL_FILE_SIGNATURE,
      `${name} local header is malformed.`,
    );
    assert.equal(archive.readUInt16LE(localOffset + 6), flags, `${name} flags drifted.`);
    assert.equal(archive.readUInt16LE(localOffset + 8), method, `${name} method drifted.`);
    assert.equal(
      archive.readUInt32LE(localOffset + 14),
      archive.readUInt32LE(cursor + 16),
      `${name} CRC drifted.`,
    );
    assert.equal(
      archive.readUInt32LE(localOffset + 18),
      compressedSize,
      `${name} compressed size drifted.`,
    );
    assert.equal(
      archive.readUInt32LE(localOffset + 22),
      uncompressedSize,
      `${name} uncompressed size drifted.`,
    );
    const localNameLength = archive.readUInt16LE(localOffset + 26);
    const localExtraLength = archive.readUInt16LE(localOffset + 28);
    assert.equal(localNameLength, nameLength, `${name} local name length drifted.`);
    assert.equal(localExtraLength, 0, `${name} local extra fields are forbidden.`);
    const localEnd = checkedEnd(
      localOffset,
      30 + localNameLength + localExtraLength + compressedSize,
      centralOffset,
      `${name} local record`,
    );
    assert.deepEqual(
      archive.subarray(localOffset + 30, localOffset + 30 + localNameLength),
      nameBytes,
      `${name} local and central names differ.`,
    );

    entries.push({
      name,
      nameBytes: Buffer.from(nameBytes),
      localOffset,
      localRecord: Buffer.from(archive.subarray(localOffset, localEnd)),
      centralRecord: Buffer.from(archive.subarray(cursor, centralEnd)),
    });
    cursor = centralEnd;
  }

  assert.equal(cursor, centralOffset + centralSize, "ZIP central-directory size drifted.");
  let expectedLocalOffset = 0;
  for (const entry of [...entries].sort((left, right) => left.localOffset - right.localOffset)) {
    assert.equal(entry.localOffset, expectedLocalOffset, "ZIP local records must be contiguous.");
    expectedLocalOffset += entry.localRecord.length;
  }
  assert.equal(
    expectedLocalOffset,
    centralOffset,
    "Unexpected data precedes the central directory.",
  );
  return entries;
}

export function canonicalizeZipArchive(archive) {
  assert.ok(Buffer.isBuffer(archive), "ZIP input must be a Buffer.");
  assert.ok(archive.length >= 22, "ZIP archive is truncated.");
  assert.ok(archive.length <= MAXIMUM_ARCHIVE_BYTES, "ZIP archive exceeds the size limit.");
  const endOffset = archive.length - 22;
  assert.equal(
    archive.readUInt32LE(endOffset),
    END_OF_CENTRAL_DIRECTORY_SIGNATURE,
    "ZIP comments and trailing data are forbidden.",
  );
  assert.equal(archive.readUInt16LE(endOffset + 4), 0, "Multi-disk ZIP archives are forbidden.");
  assert.equal(archive.readUInt16LE(endOffset + 6), 0, "Multi-disk ZIP archives are forbidden.");
  const entriesOnDisk = archive.readUInt16LE(endOffset + 8);
  const entryCount = archive.readUInt16LE(endOffset + 10);
  const centralSize = archive.readUInt32LE(endOffset + 12);
  const centralOffset = archive.readUInt32LE(endOffset + 16);
  assert.equal(archive.readUInt16LE(endOffset + 20), 0, "ZIP comments are forbidden.");
  assert.equal(entriesOnDisk, entryCount, "Multi-disk ZIP archives are forbidden.");
  assert.ok(entryCount > 0 && entryCount <= MAXIMUM_ENTRIES, "ZIP entry count is invalid.");
  assert.notEqual(centralSize, 0xffffffff, "ZIP64 archives are forbidden.");
  assert.notEqual(centralOffset, 0xffffffff, "ZIP64 archives are forbidden.");
  assert.equal(centralOffset + centralSize, endOffset, "ZIP central directory is misplaced.");

  const entries = parseEntries(archive, centralOffset, centralSize, entryCount).sort(
    (left, right) => Buffer.compare(left.nameBytes, right.nameBytes),
  );
  const localRecords = [];
  const centralRecords = [];
  let nextLocalOffset = 0;
  for (const entry of entries) {
    entry.localRecord.writeUInt16LE(0, 10);
    entry.localRecord.writeUInt16LE(REPRODUCIBLE_DOS_DATE, 12);
    localRecords.push(entry.localRecord);

    entry.centralRecord.writeUInt16LE(20, 4);
    entry.centralRecord.writeUInt16LE(0, 12);
    entry.centralRecord.writeUInt16LE(REPRODUCIBLE_DOS_DATE, 14);
    entry.centralRecord.writeUInt16LE(0, 34);
    entry.centralRecord.writeUInt16LE(0, 36);
    entry.centralRecord.writeUInt32LE(0, 38);
    entry.centralRecord.writeUInt32LE(nextLocalOffset, 42);
    centralRecords.push(entry.centralRecord);
    nextLocalOffset += entry.localRecord.length;
  }

  const canonicalCentralSize = centralRecords.reduce((sum, record) => sum + record.length, 0);
  const endRecord = Buffer.from(archive.subarray(endOffset));
  endRecord.writeUInt16LE(0, 4);
  endRecord.writeUInt16LE(0, 6);
  endRecord.writeUInt16LE(entryCount, 8);
  endRecord.writeUInt16LE(entryCount, 10);
  endRecord.writeUInt32LE(canonicalCentralSize, 12);
  endRecord.writeUInt32LE(nextLocalOffset, 16);
  endRecord.writeUInt16LE(0, 20);

  const canonical = Buffer.concat([...localRecords, ...centralRecords, endRecord]);
  assert.equal(canonical.length, archive.length, "ZIP canonicalization changed archive length.");
  return canonical;
}

export async function canonicalizeZipFile(archivePath) {
  const canonical = canonicalizeZipArchive(await readFile(archivePath));
  await writeFile(archivePath, canonical);
  return canonical;
}
