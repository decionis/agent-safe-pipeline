import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";

import { canonicalizeZipArchive } from "../scripts/CanonicalizeZip.mjs";

const LOCAL_FILE_SIGNATURE = 0x04034b50;
const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;

function emptyStoredZip(names, { madeBy = 0x0314, time = 0x1234, date = 0x5678 } = {}) {
  const localRecords = [];
  const centralRecords = [];
  let localOffset = 0;

  for (const name of names) {
    const nameBytes = Buffer.from(name, "utf8");
    const local = Buffer.alloc(30 + nameBytes.length);
    local.writeUInt32LE(LOCAL_FILE_SIGNATURE, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(local, 30);

    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(CENTRAL_DIRECTORY_SIGNATURE, 0);
    central.writeUInt16LE(madeBy, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt16LE(nameBytes.length, 28);
    central.writeUInt16LE(1, 36);
    central.writeUInt32LE(0x81a40000, 38);
    central.writeUInt32LE(localOffset, 42);
    nameBytes.copy(central, 46);

    localRecords.push(local);
    centralRecords.push(central);
    localOffset += local.length;
  }

  const centralSize = centralRecords.reduce((sum, record) => sum + record.length, 0);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(END_OF_CENTRAL_DIRECTORY_SIGNATURE, 0);
  end.writeUInt16LE(names.length, 8);
  end.writeUInt16LE(names.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localRecords, ...centralRecords, end]);
}

test("canonicalizes ZIP order and host metadata without changing payload records", () => {
  const macStyle = emptyStoredZip(["LICENSE", "dist/Index.js"], {
    madeBy: 0x0314,
    time: 0x1234,
    date: 0x5678,
  });
  const windowsStyle = emptyStoredZip(["dist/Index.js", "LICENSE"], {
    madeBy: 0x0014,
    time: 0x2345,
    date: 0x6789,
  });

  const canonical = canonicalizeZipArchive(macStyle);
  assert.deepEqual(canonicalizeZipArchive(windowsStyle), canonical);
  assert.deepEqual(canonicalizeZipArchive(canonical), canonical);
});

test("rejects traversal and case-colliding ZIP names", () => {
  assert.throws(() => canonicalizeZipArchive(emptyStoredZip(["../secret"])), /unsafe path/);
  assert.throws(
    () => canonicalizeZipArchive(emptyStoredZip(["README.md", "readme.md"])),
    /Case-colliding/,
  );
});
