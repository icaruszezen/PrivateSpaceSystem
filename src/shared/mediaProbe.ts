/**
 * Client-side pure binary media header parsers (PNG, GIF, JPEG, WebP, MP4/MOV ISO BMFF)
 * and optional browser DOM thumbnail generator — enabling Zero-Knowledge E2EE media
 * ingestion without sending plaintext images or videos to the server.
 */

import type { MediaKind } from './types.js';

export interface ClientMediaProbeResult {
  width: number;
  height: number;
  durationMs: number | null;
  videoCodec: string | null;
  audioCodec: string | null;
  bitrate: number | null;
  thumbnailBytes: Uint8Array | null;
  thumbnailMimeType: string | null;
}

function readUInt16BE(buf: Uint8Array, offset: number): number {
  return ((buf[offset] << 8) | buf[offset + 1]) >>> 0;
}

function readUInt16LE(buf: Uint8Array, offset: number): number {
  return (buf[offset] | (buf[offset + 1] << 8)) >>> 0;
}

function readUInt32BE(buf: Uint8Array, offset: number): number {
  return (
    ((buf[offset] * 0x1000000) +
      ((buf[offset + 1] << 16) | (buf[offset + 2] << 8) | buf[offset + 3])) >>>
    0
  );
}

function readUInt24LE(buf: Uint8Array, offset: number): number {
  return (buf[offset] | (buf[offset + 1] << 8) | (buf[offset + 2] << 16)) >>> 0;
}

function readUInt64BE(buf: Uint8Array, offset: number): number {
  const hi = readUInt32BE(buf, offset);
  const lo = readUInt32BE(buf, offset + 4);
  return hi * 0x100000000 + lo;
}

function asciiSlice(buf: Uint8Array, start: number, end: number): string {
  let s = '';
  for (let i = start; i < end && i < buf.byteLength; i++) {
    s += String.fromCharCode(buf[i]);
  }
  return s;
}

/**
 * Pure TypeScript fast binary header dimension parser for PNG, GIF, JPEG, and WebP.
 */
export function parseImageDimensionsFromBytes(
  buf: Uint8Array,
): { width: number; height: number } | null {
  if (buf.byteLength < 24) return null;

  // PNG: 89 50 4E 47 0D 0A 1A 0A + IHDR
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
    return {
      width: readUInt32BE(buf, 16),
      height: readUInt32BE(buf, 20),
    };
  }

  // GIF: GIF87a or GIF89a
  if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46) {
    return {
      width: readUInt16LE(buf, 6),
      height: readUInt16LE(buf, 8),
    };
  }

  // WebP: RIFF....WEBP
  if (asciiSlice(buf, 0, 4) === 'RIFF' && asciiSlice(buf, 8, 12) === 'WEBP') {
    const chunkType = asciiSlice(buf, 12, 16);
    if (chunkType === 'VP8 ' && buf.byteLength >= 30) {
      return {
        width: readUInt16LE(buf, 26) & 0x3fff,
        height: readUInt16LE(buf, 28) & 0x3fff,
      };
    }
    if (chunkType === 'VP8L' && buf.byteLength >= 25) {
      const b0 = buf[21];
      const b1 = buf[22];
      const b2 = buf[23];
      const b3 = buf[24];
      return {
        width: 1 + (((b1 & 0x3f) << 8) | b0),
        height: 1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6)),
      };
    }
    if (chunkType === 'VP8X' && buf.byteLength >= 30) {
      return {
        width: 1 + readUInt24LE(buf, 24),
        height: 1 + readUInt24LE(buf, 27),
      };
    }
  }

  // JPEG: FF D8 ...
  if (buf[0] === 0xff && buf[1] === 0xd8) {
    let offset = 2;
    while (offset + 9 < buf.byteLength) {
      if (buf[offset] !== 0xff) {
        offset++;
        continue;
      }
      const marker = buf[offset + 1];
      if (marker === 0xff) {
        offset++;
        continue;
      }
      if (marker === 0xd8 || marker === 0xd9) {
        offset += 2;
        continue;
      }
      const segLen = readUInt16BE(buf, offset + 2);
      if (segLen < 2) break;
      const isSof =
        (marker >= 0xc0 && marker <= 0xc3) ||
        (marker >= 0xc5 && marker <= 0xc7) ||
        (marker >= 0xc9 && marker <= 0xcb) ||
        (marker >= 0xcd && marker <= 0xcf);
      if (isSof && offset + 8 < buf.byteLength) {
        return {
          height: readUInt16BE(buf, offset + 5),
          width: readUInt16BE(buf, offset + 7),
        };
      }
      offset += 2 + segLen;
    }
  }

  return null;
}

/**
 * Pure TypeScript MP4/MOV ISO BMFF box parser (mvhd duration + tkhd dimensions + codec fourcc).
 */
export function parseMp4MetadataFromBytes(buf: Uint8Array): {
  durationMs: number | null;
  width: number;
  height: number;
  videoCodec: string | null;
  audioCodec: string | null;
} {
  let durationMs: number | null = null;
  let width = 0;
  let height = 0;
  let videoCodec: string | null = null;
  let audioCodec: string | null = null;

  const containerBoxes = new Set(['moov', 'trak', 'mdia', 'minf', 'stbl']);

  function walkBoxes(start: number, end: number): void {
    let pos = start;
    while (pos + 8 <= end) {
      let size = readUInt32BE(buf, pos);
      const type = asciiSlice(buf, pos + 4, pos + 8);
      let headerLen = 8;

      if (size === 1) {
        if (pos + 16 > end) break;
        size = readUInt64BE(buf, pos + 8);
        headerLen = 16;
      } else if (size === 0) {
        size = end - pos;
      }

      if (size < headerLen || pos + size > end) break;

      const payloadStart = pos + headerLen;
      const boxEnd = pos + size;

      if (containerBoxes.has(type)) {
        walkBoxes(payloadStart, boxEnd);
      } else if (type === 'mvhd' && payloadStart + 20 <= boxEnd) {
        const version = buf[payloadStart];
        if (version === 1 && payloadStart + 32 <= boxEnd) {
          const timescale = readUInt32BE(buf, payloadStart + 20);
          const duration = readUInt64BE(buf, payloadStart + 24);
          if (timescale > 0) durationMs = Math.round((duration / timescale) * 1000);
        } else if (version === 0 && payloadStart + 20 <= boxEnd) {
          const timescale = readUInt32BE(buf, payloadStart + 12);
          const duration = readUInt32BE(buf, payloadStart + 16);
          if (timescale > 0) durationMs = Math.round((duration / timescale) * 1000);
        }
      } else if (type === 'tkhd' && payloadStart + 84 <= boxEnd) {
        const version = buf[payloadStart];
        const widthOffset = version === 1 ? payloadStart + 88 : payloadStart + 76;
        if (widthOffset + 8 <= boxEnd) {
          const w = Math.round(readUInt32BE(buf, widthOffset) / 65536);
          const h = Math.round(readUInt32BE(buf, widthOffset + 4) / 65536);
          if (w > width && h > height) {
            width = w;
            height = h;
          }
        }
      } else if (type === 'stsd' && payloadStart + 16 <= boxEnd) {
        const sampleType = asciiSlice(buf, payloadStart + 12, payloadStart + 16).trim();
        if (['avc1', 'hvc1', 'hev1', 'vp09', 'av01', 'mp4v'].includes(sampleType)) {
          videoCodec = sampleType === 'avc1' ? 'h264' : sampleType;
        } else if (['mp4a', 'Opus', 'ac-3', 'ec-3', 'alac'].includes(sampleType)) {
          audioCodec = sampleType === 'mp4a' ? 'aac' : sampleType.toLowerCase();
        }
      }

      pos = boxEnd;
    }
  }

  walkBoxes(0, buf.byteLength);
  return { durationMs, width, height, videoCodec, audioCodec };
}

// ==================== Optional Browser DOM Thumbnail Extraction ====================

interface MinimalDomCanvas {
  width: number;
  height: number;
  getContext(type: '2d'): {
    drawImage(source: unknown, dx: number, dy: number, dw: number, dh: number): void;
  } | null;
  toBlob(callback: (blob: { arrayBuffer(): Promise<ArrayBuffer> } | null) => void, mime: string, quality: number): void;
}

interface MinimalDomImage {
  naturalWidth: number;
  naturalHeight: number;
  onload: (() => void) | null;
  onerror: (() => void) | null;
  src: string;
}

interface MinimalDomVideo {
  videoWidth: number;
  videoHeight: number;
  duration: number;
  muted: boolean;
  playsInline: boolean;
  preload: string;
  currentTime: number;
  onloadedmetadata: (() => void) | null;
  onseeked: (() => void) | null;
  onerror: (() => void) | null;
  src: string;
}

interface MinimalBrowserEnv {
  document?: {
    createElement(tag: string): unknown;
  };
  Image?: new () => MinimalDomImage;
  Blob?: new (parts: ArrayBuffer[], options?: { type?: string }) => unknown;
  URL?: {
    createObjectURL(blob: unknown): string;
    revokeObjectURL(url: string): void;
  };
}

const BROWSER_ENV = globalThis as unknown as MinimalBrowserEnv;

function copyToArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

async function canvasToJpegBytes(
  source: unknown,
  srcWidth: number,
  srcHeight: number,
  maxDim: number,
): Promise<Uint8Array | null> {
  if (!BROWSER_ENV.document || srcWidth <= 0 || srcHeight <= 0) return null;
  const scale = Math.min(1, maxDim / Math.max(srcWidth, srcHeight));
  const targetW = Math.max(1, Math.round(srcWidth * scale));
  const targetH = Math.max(1, Math.round(srcHeight * scale));

  const canvas = BROWSER_ENV.document.createElement('canvas') as MinimalDomCanvas;
  canvas.width = targetW;
  canvas.height = targetH;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;
  ctx.drawImage(source, 0, 0, targetW, targetH);

  return new Promise<Uint8Array | null>((resolve) => {
    canvas.toBlob(
      async (blob) => {
        if (!blob) {
          resolve(null);
          return;
        }
        try {
          const ab = await blob.arrayBuffer();
          resolve(new Uint8Array(ab));
        } catch {
          resolve(null);
        }
      },
      'image/jpeg',
      0.84,
    );
  });
}

export async function probeMediaOnClient(
  bytes: Uint8Array,
  kind: MediaKind,
  mimeType: string,
): Promise<ClientMediaProbeResult> {
  if (kind === 'image') {
    const headerDims = parseImageDimensionsFromBytes(bytes.subarray(0, Math.min(bytes.byteLength, 65536)));
    let width = headerDims?.width ?? 0;
    let height = headerDims?.height ?? 0;
    let thumbnailBytes: Uint8Array | null = null;
    let thumbnailMimeType: string | null = null;

    if (BROWSER_ENV.document && BROWSER_ENV.Image && BROWSER_ENV.Blob && BROWSER_ENV.URL) {
      const blob = new BROWSER_ENV.Blob([copyToArrayBuffer(bytes)], {
        type: mimeType || 'image/jpeg',
      });
      const objectUrl = BROWSER_ENV.URL.createObjectURL(blob);
      try {
        const loaded = await new Promise<MinimalDomImage | null>((resolve) => {
          const img = new BROWSER_ENV.Image!();
          const timer = setTimeout(() => resolve(null), 5000);
          img.onload = () => {
            clearTimeout(timer);
            resolve(img);
          };
          img.onerror = () => {
            clearTimeout(timer);
            resolve(null);
          };
          img.src = objectUrl;
        });
        if (loaded) {
          if (!width && loaded.naturalWidth) width = loaded.naturalWidth;
          if (!height && loaded.naturalHeight) height = loaded.naturalHeight;
          const jpeg = await canvasToJpegBytes(loaded, width, height, 560);
          if (jpeg && jpeg.byteLength > 0) {
            thumbnailBytes = jpeg;
            thumbnailMimeType = 'image/jpeg';
          }
        }
      } finally {
        BROWSER_ENV.URL.revokeObjectURL(objectUrl);
      }
    }

    if (!thumbnailBytes && bytes.byteLength <= 4 * 1024 * 1024) {
      thumbnailBytes = bytes;
      thumbnailMimeType = mimeType || 'image/jpeg';
    }

    return {
      width,
      height,
      durationMs: null,
      videoCodec: null,
      audioCodec: null,
      bitrate: null,
      thumbnailBytes,
      thumbnailMimeType,
    };
  }

  // Video client probe
  const sample = bytes.subarray(0, Math.min(bytes.byteLength, 8 * 1024 * 1024));
  const mp4 = parseMp4MetadataFromBytes(sample);
  let width = mp4.width;
  let height = mp4.height;
  let durationMs = mp4.durationMs;
  const videoCodec = mp4.videoCodec;
  const audioCodec = mp4.audioCodec;
  let thumbnailBytes: Uint8Array | null = null;
  let thumbnailMimeType: string | null = null;

  if (BROWSER_ENV.document && BROWSER_ENV.Blob && BROWSER_ENV.URL) {
    const blob = new BROWSER_ENV.Blob([copyToArrayBuffer(bytes)], {
      type: mimeType || 'video/mp4',
    });
    const objectUrl = BROWSER_ENV.URL.createObjectURL(blob);
    try {
      const videoEl = BROWSER_ENV.document.createElement('video') as MinimalDomVideo;
      videoEl.muted = true;
      videoEl.playsInline = true;
      videoEl.preload = 'metadata';

      const captured = await new Promise<Uint8Array | null>((resolve) => {
        const timer = setTimeout(() => resolve(null), 6000);
        videoEl.onerror = () => {
          clearTimeout(timer);
          resolve(null);
        };
        videoEl.onloadedmetadata = () => {
          if (!width && videoEl.videoWidth) width = videoEl.videoWidth;
          if (!height && videoEl.videoHeight) height = videoEl.videoHeight;
          if (durationMs === null && Number.isFinite(videoEl.duration) && videoEl.duration > 0) {
            durationMs = Math.round(videoEl.duration * 1000);
          }
          const seekTo =
            Number.isFinite(videoEl.duration) && videoEl.duration > 0.4
              ? Math.min(1.0, videoEl.duration * 0.25)
              : 0.01;
          videoEl.currentTime = seekTo;
        };
        videoEl.onseeked = async () => {
          clearTimeout(timer);
          const poster = await canvasToJpegBytes(
            videoEl,
            videoEl.videoWidth || width,
            videoEl.videoHeight || height,
            720,
          );
          resolve(poster);
        };
        videoEl.src = objectUrl;
      });

      if (captured && captured.byteLength > 0) {
        thumbnailBytes = captured;
        thumbnailMimeType = 'image/jpeg';
      }
      videoEl.src = '';
    } finally {
      BROWSER_ENV.URL.revokeObjectURL(objectUrl);
    }
  }

  const bitrate =
    durationMs && durationMs > 0 ? Math.round((bytes.byteLength * 8 * 1000) / durationMs) : null;

  return {
    width,
    height,
    durationMs,
    videoCodec,
    audioCodec,
    bitrate,
    thumbnailBytes,
    thumbnailMimeType,
  };
}
