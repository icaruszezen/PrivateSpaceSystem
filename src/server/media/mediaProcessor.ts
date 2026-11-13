import { execFile } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { MediaKind } from '../../shared/types.js';

const execFileAsync = promisify(execFile);

export interface ProcessedMediaProbe {
  width: number;
  height: number;
  durationMs: number | null;
  videoCodec: string | null;
  audioCodec: string | null;
  bitrate: number | null;
  thumbnailBuffer: Buffer | null;
  thumbnailMimeType: string | null;
}

/**
 * Pure TypeScript fast binary header dimension parser for PNG, GIF, JPEG, and WebP.
 */
export function parseImageDimensionsFromBuffer(
  buf: Buffer,
): { width: number; height: number } | null {
  if (buf.length < 24) return null;

  // PNG: 89 50 4E 47 0D 0A 1A 0A + IHDR
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e && buf[3] === 0x47) {
    return {
      width: buf.readUInt32BE(16),
      height: buf.readUInt32BE(20),
    };
  }

  // GIF: GIF87a or GIF89a
  if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46) {
    return {
      width: buf.readUInt16LE(6),
      height: buf.readUInt16LE(8),
    };
  }

  // WebP: RIFF....WEBP
  if (
    buf.subarray(0, 4).toString('ascii') === 'RIFF' &&
    buf.subarray(8, 12).toString('ascii') === 'WEBP'
  ) {
    const chunkType = buf.subarray(12, 16).toString('ascii');
    if (chunkType === 'VP8 ' && buf.length >= 30) {
      return {
        width: buf.readUInt16LE(26) & 0x3fff,
        height: buf.readUInt16LE(28) & 0x3fff,
      };
    }
    if (chunkType === 'VP8L' && buf.length >= 25) {
      const b0 = buf[21];
      const b1 = buf[22];
      const b2 = buf[23];
      const b3 = buf[24];
      return {
        width: 1 + (((b1 & 0x3f) << 8) | b0),
        height: 1 + (((b3 & 0x0f) << 10) | (b2 << 2) | ((b1 & 0xc0) >> 6)),
      };
    }
    if (chunkType === 'VP8X' && buf.length >= 30) {
      return {
        width: 1 + buf.readUIntLE(24, 3),
        height: 1 + buf.readUIntLE(27, 3),
      };
    }
  }

  // JPEG: FF D8 ...
  if (buf[0] === 0xff && buf[1] === 0xd8) {
    let offset = 2;
    while (offset + 9 < buf.length) {
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
      const segLen = buf.readUInt16BE(offset + 2);
      if (segLen < 2) break;
      const isSof =
        (marker >= 0xc0 && marker <= 0xc3) ||
        (marker >= 0xc5 && marker <= 0xc7) ||
        (marker >= 0xc9 && marker <= 0xcb) ||
        (marker >= 0xcd && marker <= 0xcf);
      if (isSof && offset + 8 < buf.length) {
        return {
          height: buf.readUInt16BE(offset + 5),
          width: buf.readUInt16BE(offset + 7),
        };
      }
      offset += 2 + segLen;
    }
  }

  return null;
}

/**
 * Pure TypeScript MP4/MOV ISO BMFF box parser fallback (mvhd duration + tkhd dimensions).
 */
export function parseMp4MetadataFromBuffer(buf: Buffer): {
  durationMs: number | null;
  width: number;
  height: number;
} {
  let durationMs: number | null = null;
  let width = 0;
  let height = 0;

  const containerBoxes = new Set(['moov', 'trak', 'mdia', 'minf', 'stbl']);

  function walkBoxes(start: number, end: number): void {
    let pos = start;
    while (pos + 8 <= end) {
      let size = buf.readUInt32BE(pos);
      const type = buf.subarray(pos + 4, pos + 8).toString('ascii');
      let headerLen = 8;

      if (size === 1) {
        if (pos + 16 > end) break;
        size = Number(buf.readBigUInt64BE(pos + 8));
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
          const timescale = buf.readUInt32BE(payloadStart + 20);
          const duration = Number(buf.readBigUInt64BE(payloadStart + 24));
          if (timescale > 0) durationMs = Math.round((duration / timescale) * 1000);
        } else if (version === 0 && payloadStart + 20 <= boxEnd) {
          const timescale = buf.readUInt32BE(payloadStart + 12);
          const duration = buf.readUInt32BE(payloadStart + 16);
          if (timescale > 0) durationMs = Math.round((duration / timescale) * 1000);
        }
      } else if (type === 'tkhd' && payloadStart + 84 <= boxEnd) {
        const version = buf[payloadStart];
        const widthOffset = version === 1 ? payloadStart + 88 : payloadStart + 76;
        if (widthOffset + 8 <= boxEnd) {
          const w = Math.round(buf.readUInt32BE(widthOffset) / 65536);
          const h = Math.round(buf.readUInt32BE(widthOffset + 4) / 65536);
          if (w > width && h > height) {
            width = w;
            height = h;
          }
        }
      }

      pos = boxEnd;
    }
  }

  walkBoxes(0, buf.length);
  return { durationMs, width, height };
}

interface FfprobeStream {
  codec_type?: string;
  codec_name?: string;
  width?: number;
  height?: number;
  duration?: string;
}

interface FfprobeOutput {
  streams?: FfprobeStream[];
  format?: {
    duration?: string;
    bit_rate?: string;
  };
}

async function runFfprobe(filePath: string): Promise<FfprobeOutput | null> {
  try {
    const { stdout } = await execFileAsync(
      'ffprobe',
      ['-v', 'quiet', '-print_format', 'json', '-show_format', '-show_streams', filePath],
      { timeout: 15_000 },
    );
    return JSON.parse(stdout) as FfprobeOutput;
  } catch {
    return null;
  }
}

async function generateFfmpegThumbnail(
  inputPath: string,
  maxDim: number,
  seekSeconds?: number,
): Promise<Buffer | null> {
  const tempThumb = path.join(os.tmpdir(), `pss-thumb-${crypto.randomUUID()}.jpg`);
  try {
    const args: string[] = ['-y'];
    if (seekSeconds !== undefined && seekSeconds > 0) {
      args.push('-ss', seekSeconds.toFixed(2));
    }
    args.push(
      '-i',
      inputPath,
      '-frames:v',
      '1',
      '-vf',
      `scale='min(${maxDim},iw)':'min(${maxDim},ih)':force_original_aspect_ratio=decrease`,
      '-q:v',
      '4',
      tempThumb,
    );
    await execFileAsync('ffmpeg', args, { timeout: 20_000 });
    if (fs.existsSync(tempThumb)) {
      const buf = await fs.promises.readFile(tempThumb);
      if (buf.length > 0) return buf;
    }
    return null;
  } catch {
    return null;
  } finally {
    try {
      await fs.promises.unlink(tempThumb);
    } catch {
      // ignore
    }
  }
}

export async function processUploadedMediaFile(
  filePath: string,
  kind: MediaKind,
  mimeType: string,
): Promise<ProcessedMediaProbe> {
  if (kind === 'image') {
    const headFd = await fs.promises.open(filePath, 'r');
    const headBuf = Buffer.alloc(65536);
    let headLen = 0;
    try {
      const { bytesRead } = await headFd.read(headBuf, 0, headBuf.length, 0);
      headLen = bytesRead;
    } finally {
      await headFd.close();
    }

    let dims = parseImageDimensionsFromBuffer(headBuf.subarray(0, headLen));
    if (!dims) {
      const probe = await runFfprobe(filePath);
      const vStream = probe?.streams?.find((s) => s.width && s.height);
      if (vStream?.width && vStream?.height) {
        dims = { width: vStream.width, height: vStream.height };
      }
    }

    let thumbBuf = await generateFfmpegThumbnail(filePath, 560);
    let thumbMime: string | null = thumbBuf ? 'image/jpeg' : null;

    if (!thumbBuf) {
      const stat = await fs.promises.stat(filePath);
      if (stat.size <= 4 * 1024 * 1024) {
        thumbBuf = await fs.promises.readFile(filePath);
        thumbMime = mimeType || 'image/jpeg';
      }
    }

    return {
      width: dims?.width ?? 0,
      height: dims?.height ?? 0,
      durationMs: null,
      videoCodec: null,
      audioCodec: null,
      bitrate: null,
      thumbnailBuffer: thumbBuf,
      thumbnailMimeType: thumbMime,
    };
  }

  // Video processing pipeline
  let width = 0;
  let height = 0;
  let durationMs: number | null = null;
  let videoCodec: string | null = null;
  let audioCodec: string | null;
  audioCodec = null;
  let bitrate: number | null = null;

  const probe = await runFfprobe(filePath);
  if (probe) {
    const vStream = probe.streams?.find((s) => s.codec_type === 'video');
    const aStream = probe.streams?.find((s) => s.codec_type === 'audio');
    if (vStream) {
      width = vStream.width ?? 0;
      height = vStream.height ?? 0;
      videoCodec = vStream.codec_name ?? null;
      if (vStream.duration) {
        const d = Number(vStream.duration);
        if (Number.isFinite(d) && d > 0) durationMs = Math.round(d * 1000);
      }
    }
    if (aStream?.codec_name) {
      audioCodec = aStream.codec_name;
    }
    if (!durationMs && probe.format?.duration) {
      const d = Number(probe.format.duration);
      if (Number.isFinite(d) && d > 0) durationMs = Math.round(d * 1000);
    }
    if (probe.format?.bit_rate) {
      const b = Number(probe.format.bit_rate);
      if (Number.isFinite(b) && b > 0) bitrate = b;
    }
  }

  if (width === 0 || durationMs === null) {
    const stat = await fs.promises.stat(filePath);
    const sampleSize = Math.min(stat.size, 4 * 1024 * 1024);
    const fd = await fs.promises.open(filePath, 'r');
    try {
      const buf = Buffer.alloc(sampleSize);
      const { bytesRead } = await fd.read(buf, 0, sampleSize, 0);
      const parsed = parseMp4MetadataFromBuffer(buf.subarray(0, bytesRead));
      if (!width && parsed.width) width = parsed.width;
      if (!height && parsed.height) height = parsed.height;
      if (durationMs === null && parsed.durationMs !== null) durationMs = parsed.durationMs;
    } finally {
      await fd.close();
    }
  }

  const seekSec = durationMs && durationMs > 2000 ? Math.min(1.0, (durationMs / 1000) * 0.25) : 0;
  let posterBuf = await generateFfmpegThumbnail(filePath, 720, seekSec);
  if (!posterBuf && seekSec > 0) {
    posterBuf = await generateFfmpegThumbnail(filePath, 720, 0);
  }

  return {
    width,
    height,
    durationMs,
    videoCodec,
    audioCodec,
    bitrate,
    thumbnailBuffer: posterBuf,
    thumbnailMimeType: posterBuf ? 'image/jpeg' : null,
  };
}
