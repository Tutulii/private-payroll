import { bytesToHex, hexToBytes } from "@noble/hashes/utils.js";

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8(value: string): Uint8Array {
  return textEncoder.encode(value);
}

export function decodeUtf8(value: Uint8Array): string {
  return textDecoder.decode(value);
}

export function concatBytes(...values: readonly Uint8Array[]): Uint8Array {
  const size = values.reduce((total, value) => total + value.length, 0);
  const result = new Uint8Array(size);
  let offset = 0;
  for (const value of values) {
    result.set(value, offset);
    offset += value.length;
  }
  return result;
}

export function encodeU32(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error("Value does not fit in an unsigned 32-bit integer.");
  }
  const bytes = new Uint8Array(4);
  new DataView(bytes.buffer).setUint32(0, value, false);
  return bytes;
}

export function encodeUint(value: bigint, length = 32): Uint8Array {
  if (value < 0n || value >= 1n << BigInt(length * 8)) {
    throw new Error(`Value does not fit in ${length} bytes.`);
  }
  const result = new Uint8Array(length);
  let remaining = value;
  for (let index = length - 1; index >= 0; index -= 1) {
    result[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return result;
}

export function decodeUint(value: Uint8Array): bigint {
  return value.reduce((result, byte) => (result << 8n) | BigInt(byte), 0n);
}

export function encodeField(value: Uint8Array): Uint8Array {
  return concatBytes(encodeU32(value.length), value);
}

export function normalizedHexBytes(value: string, length?: number): Uint8Array {
  const raw = value.startsWith("0x") ? value.slice(2) : value;
  const normalized = raw.length % 2 === 0 ? raw : `0${raw}`;
  if (!/^[0-9a-fA-F]*$/.test(normalized)) throw new Error("Invalid hexadecimal value.");
  const bytes = hexToBytes(normalized);
  if (length === undefined) return bytes;
  if (bytes.length > length) throw new Error(`Hexadecimal value exceeds ${length} bytes.`);
  const padded = new Uint8Array(length);
  padded.set(bytes, length - bytes.length);
  return padded;
}

export function toHex(value: Uint8Array): `0x${string}` {
  return `0x${bytesToHex(value)}`;
}

export function toBase64(value: Uint8Array): string {
  let binary = "";
  for (let index = 0; index < value.length; index += 0x8000) {
    binary += String.fromCharCode(...value.subarray(index, index + 0x8000));
  }
  return btoa(binary);
}

export function fromBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

export function stableJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(",")}]`;

  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(",")}}`;
}
