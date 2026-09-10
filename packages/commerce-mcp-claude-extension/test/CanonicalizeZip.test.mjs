import assert from "node:assert/strict";
import { Buffer } from "node:buffer";
import test from "node:test";
import { deflateRawSync } from "node:zlib";

import { canonicalizeZipArchive } from "../scripts/CanonicalizeZip.mjs";

const LOCAL_FILE_SIGNATURE = 0x04034b50;
const CENTRAL_DIRECTORY_SIGNATURE = 0x02014b50;
const END_OF_CENTRAL_DIRECTORY_SIGNATURE = 0x06054b50;

const CRC32_TABLE = Uint32Array.from({ length: 256 }, (_, value) => {
  let crc = value;
  for (let bit = 0; bit < 8; bit += 1) {
    crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
  }
  return crc >>> 0;
});

function crc32(payload) {
  let crc = 0xffffffff;
  for (const byte of payload) {
    crc = CRC32_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function zipArchive(entries, { madeBy = 0x0314, time = 0x1234, date = 0x5678 } = {}) {
  const localRecords = [];
  const centralRecords = [];
  let localOffset = 0;

  for (const value of entries) {
    const entry = typeof value === "string" ? { name: value } : value;
    const { name } = entry;
    const nameBytes = Buffer.from(name, "utf8");
    const flags = entry.flags ?? 0;
    const method = entry.method ?? 0;
    const payload = Buffer.from(entry.payload ?? Buffer.alloc(0));
    const compressedPayload = Buffer.from(
      entry.compressedPayload ?? (method === 8 ? deflateRawSync(payload) : payload),
    );
    const checksum = entry.crc ?? crc32(payload);
    const compressedSize = entry.compressedSize ?? compressedPayload.length;
    const uncompressedSize = entry.uncompressedSize ?? payload.length;
    const local = Buffer.alloc(30 + nameBytes.length + compressedPayload.length);
    local.writeUInt32LE(LOCAL_FILE_SIGNATURE, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt16LE(time, 10);
    local.writeUInt16LE(date, 12);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(compressedSize, 18);
    local.writeUInt32LE(uncompressedSize, 22);
    local.writeUInt16LE(nameBytes.length, 26);
    nameBytes.copy(local, 30);
    compressedPayload.copy(local, 30 + nameBytes.length);

    const central = Buffer.alloc(46 + nameBytes.length);
    central.writeUInt32LE(CENTRAL_DIRECTORY_SIGNATURE, 0);
    central.writeUInt16LE(madeBy, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt16LE(time, 12);
    central.writeUInt16LE(date, 14);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(compressedSize, 20);
    central.writeUInt32LE(uncompressedSize, 24);
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
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralSize, 12);
  end.writeUInt32LE(localOffset, 16);
  return Buffer.concat([...localRecords, ...centralRecords, end]);
}

test("canonicalizes ZIP order and host metadata without changing payload records", () => {
  const macStyle = zipArchive(["LICENSE", "dist/Index.js"], {
    madeBy: 0x0314,
    time: 0x1234,
    date: 0x5678,
  });
  const windowsStyle = zipArchive(["dist/Index.js", "LICENSE"], {
    madeBy: 0x0014,
    time: 0x2345,
    date: 0x6789,
  });

  const canonical = canonicalizeZipArchive(macStyle);
  assert.deepEqual(canonicalizeZipArchive(windowsStyle), canonical);
  assert.deepEqual(canonicalizeZipArchive(canonical), canonical);
});

test("accepts UTF-8 names and validates a non-empty deflated payload", () => {
  const archive = zipArchive([
    {
      name: "résumé.txt",
      flags: 0x0800,
      method: 8,
      payload: "CommerceGate deflate payload",
    },
  ]);
  const canonical = canonicalizeZipArchive(archive);
  assert.deepEqual(canonicalizeZipArchive(canonical), canonical);
});

test("rejects unsupported general-purpose flags", () => {
  assert.throws(
    () => canonicalizeZipArchive(zipArchive([{ name: "file.txt", flags: 0x0002 }])),
    /Unsupported ZIP general-purpose flags/,
  );
});

test("rejects traversal and Windows-normalized colliding ZIP names", () => {
  assert.throws(() => canonicalizeZipArchive(zipArchive(["../secret"])), /unsafe path/);
  assert.throws(
    () => canonicalizeZipArchive(zipArchive(["README.md", "readme.md"])),
    /Windows-colliding/,
  );
  assert.throws(
    () => canonicalizeZipArchive(zipArchive(["Café.txt", "Cafe\u0301.txt"])),
    /Windows-colliding/,
  );
});

test("rejects Windows device names, alternate data streams, and trailing aliases", () => {
  for (const name of ["CON", "nested/prn.txt", "COM¹.log"]) {
    assert.throws(() => canonicalizeZipArchive(zipArchive([name])), /reserved Windows device name/);
  }
  assert.throws(() => canonicalizeZipArchive(zipArchive(["README.md:payload"])), /Windows-unsafe/);
  for (const name of ["README.md.", "README.md "]) {
    assert.throws(() => canonicalizeZipArchive(zipArchive([name])), /trailing dot or space/);
  }
});

test("validates stored sizes and CRC-32 against the payload", () => {
  assert.throws(
    () =>
      canonicalizeZipArchive(
        zipArchive([{ name: "stored.txt", payload: "abc", uncompressedSize: 2 }]),
      ),
    /stored sizes differ/,
  );
  assert.throws(
    () => canonicalizeZipArchive(zipArchive([{ name: "stored.txt", payload: "abc", crc: 0 }])),
    /CRC does not match payload/,
  );
});

test("validates deflate size, CRC-32, and full stream consumption", () => {
  const payload = Buffer.from("deflated CommerceGate payload");
  assert.throws(
    () =>
      canonicalizeZipArchive(
        zipArchive([{ name: "deflated.txt", method: 8, payload, uncompressedSize: 4 }]),
      ),
    /invalid deflate stream|declared size/,
  );
  assert.throws(
    () =>
      canonicalizeZipArchive(zipArchive([{ name: "deflated.txt", method: 8, payload, crc: 0 }])),
    /CRC does not match payload/,
  );

  const compressedPayload = Buffer.concat([deflateRawSync(payload), Buffer.from([0, 1, 2])]);
  assert.throws(
    () =>
      canonicalizeZipArchive(
        zipArchive([{ name: "deflated.txt", method: 8, payload, compressedPayload }]),
      ),
    /trailing compressed data/,
  );
});

test("enforces aggregate compressed and uncompressed payload budgets", () => {
  assert.throws(
    () =>
      canonicalizeZipArchive(
        zipArchive([{ name: "compressed.bin", compressedSize: 32 * 1024 * 1024 + 1 }]),
      ),
    /Total compressed payload size exceeds the safety budget/,
  );
  assert.throws(
    () =>
      canonicalizeZipArchive(
        zipArchive([
          {
            name: "expanded.bin",
            method: 8,
            payload: Buffer.alloc(0),
            uncompressedSize: 64 * 1024 * 1024 + 1,
          },
        ]),
      ),
    /Total uncompressed payload size exceeds the safety budget/,
  );
});
