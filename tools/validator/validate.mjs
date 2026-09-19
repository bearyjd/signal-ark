#!/usr/bin/env node
// Runs libsignal's official backup validator against a plaintext v2 frame
// stream: a varint-length-delimited BackupInfo followed by varint-length-
// delimited Frames (exactly what signal_ark.encrypt.serialize_frames emits).
//
// Usage: node validate.mjs [<plaintext-file>] [--purpose remote-backup|device-transfer]
// Without a file argument the stream is read from stdin (what signal_ark.validate
// does, so decrypted data never touches disk).
// Prints exactly one JSON line to stdout. Exit 0 = ok, 1 = validation failed,
// 2 = usage / IO error.

import { readFileSync } from 'node:fs';
import {
  OnlineBackupValidator,
  Purpose,
} from '@signalapp/libsignal-client/dist/MessageBackup.js';

const PURPOSES = {
  'remote-backup': Purpose.RemoteBackup,
  'device-transfer': Purpose.DeviceTransfer,
};

const EXIT_OK = 0;
const EXIT_INVALID = 1;
const EXIT_USAGE = 2;

/**
 * @param {Uint8Array} buf
 * @param {number} offset
 * @returns {{ value: number, next: number } | null} null at EOF
 */
function readVarint(buf, offset) {
  let result = 0;
  let shift = 0;
  let pos = offset;
  while (true) {
    if (pos >= buf.length) {
      if (pos === offset) return null;
      throw new Error(`Truncated varint at byte ${offset}`);
    }
    const b = buf[pos];
    pos += 1;
    result += (b & 0x7f) * 2 ** shift;
    if ((b & 0x80) === 0) return { value: result, next: pos };
    shift += 7;
    if (shift > 63) throw new Error(`Varint too long at byte ${offset}`);
  }
}

/**
 * @param {Uint8Array} buf
 * @returns {Uint8Array[]} length-delimited messages, first is BackupInfo
 */
function splitMessages(buf) {
  const messages = [];
  let offset = 0;
  while (true) {
    const header = readVarint(buf, offset);
    if (header === null) return messages;
    const end = header.next + header.value;
    if (end > buf.length) {
      throw new Error(`Truncated message: expected ${header.value} bytes at ${header.next}`);
    }
    messages.push(buf.subarray(header.next, end));
    offset = end;
  }
}

const STDIN_FD = 0;

/**
 * @param {string[]} argv
 * @returns {{ file: string | null, purpose: number }} file null means stdin
 */
function parseArgs(argv) {
  let file = null;
  let purposeName = 'remote-backup';
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--purpose') {
      purposeName = argv[i + 1];
      i += 1;
    } else if (file === null) {
      file = argv[i];
    } else {
      throw new Error(`Unexpected argument: ${argv[i]}`);
    }
  }
  const purpose = PURPOSES[purposeName];
  if (purpose === undefined) throw new Error(`Unknown purpose: ${purposeName}`);
  return { file, purpose };
}

/**
 * @param {string | null} file
 * @returns {Uint8Array}
 */
function readStream(file) {
  return new Uint8Array(readFileSync(file === null ? STDIN_FD : file));
}

/**
 * @param {Uint8Array[]} messages
 * @param {number} purpose
 * @returns {{ ok: boolean, frames: number, error?: string }}
 */
function runValidator(messages, purpose) {
  if (messages.length === 0) return { ok: false, frames: 0, error: 'Empty stream: no BackupInfo' };
  const [backupInfo, ...frames] = messages;
  let processed = 0;
  let stage = 'BackupInfo';
  try {
    const validator = new OnlineBackupValidator(backupInfo, purpose);
    for (const frame of frames) {
      stage = `frame ${processed}`;
      validator.addFrame(frame);
      processed += 1;
    }
    stage = 'finalize';
    validator.finalize();
    return { ok: true, frames: processed };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, frames: processed, error: `${stage}: ${message}` };
  }
}

/**
 * @param {string[]} argv
 * @returns {{ result: { ok: boolean, frames: number, error?: string }, exitCode: number }}
 */
function run(argv) {
  try {
    const { file, purpose } = parseArgs(argv);
    const result = runValidator(splitMessages(readStream(file)), purpose);
    return { result, exitCode: result.ok ? EXIT_OK : EXIT_INVALID };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`${message}\n`);
    return { result: { ok: false, frames: 0, error: message }, exitCode: EXIT_USAGE };
  }
}

function main() {
  const { result, exitCode } = run(process.argv.slice(2));
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exitCode = exitCode;
}

main();
