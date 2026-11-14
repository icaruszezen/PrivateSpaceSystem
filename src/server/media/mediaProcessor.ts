import {
  parseImageDimensionsFromBytes,
  parseMp4MetadataFromBytes,
} from '../../shared/mediaProbe.js';

/**
 * Pure binary header dimension parser wrapper (delegates to shared client/server parser).
 * Under Zero-Knowledge E2EE v2, media probing happens exclusively on the client before encryption.
 */
export function parseImageDimensionsFromBuffer(
  buf: Buffer | Uint8Array,
): { width: number; height: number } | null {
  return parseImageDimensionsFromBytes(buf);
}

export function parseMp4MetadataFromBuffer(buf: Buffer | Uint8Array): {
  durationMs: number | null;
  width: number;
  height: number;
} {
  const parsed = parseMp4MetadataFromBytes(buf);
  return {
    durationMs: parsed.durationMs,
    width: parsed.width,
    height: parsed.height,
  };
}
