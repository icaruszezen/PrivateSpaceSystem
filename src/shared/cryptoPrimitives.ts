/**
 * Zero-dependency, cross-runtime cryptographic primitives for PrivateSpace E2EE v2.
 *
 * - Primary engine: WebCrypto `SubtleCrypto` (Browser HTTPS/localhost, Capacitor Android/iOS, Node.js 24).
 * - Fallback engine: Pure TypeScript FIPS 180-4 SHA-256, RFC 2104 HMAC, RFC 5869 HKDF,
 *   RFC 8018 PBKDF2-HMAC-SHA256, and NIST SP 800-38D AES-256-GCM — enabling full client-side
 *   Zero-Knowledge E2EE even over plain-HTTP home LAN (`http://192.168.x.x:8080`) where browsers
 *   withhold `window.crypto.subtle` while still providing `window.crypto.getRandomValues`.
 */

interface MinimalSubtleCrypto {
  digest(algorithm: string, data: ArrayBuffer): Promise<ArrayBuffer>;
  importKey(
    format: 'raw',
    keyData: ArrayBuffer,
    algorithm: string | { name: string; hash?: string },
    extractable: boolean,
    keyUsages: string[],
  ): Promise<unknown>;
  sign(algorithm: string, key: unknown, data: ArrayBuffer): Promise<ArrayBuffer>;
  deriveBits(
    algorithm: Record<string, unknown>,
    baseKey: unknown,
    length: number,
  ): Promise<ArrayBuffer>;
  encrypt(
    algorithm: { name: 'AES-GCM'; iv: ArrayBuffer; additionalData?: ArrayBuffer; tagLength?: number },
    key: unknown,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer>;
  decrypt(
    algorithm: { name: 'AES-GCM'; iv: ArrayBuffer; additionalData?: ArrayBuffer; tagLength?: number },
    key: unknown,
    data: ArrayBuffer,
  ): Promise<ArrayBuffer>;
}

interface MinimalCryptoGlobal {
  getRandomValues<T extends Uint8Array>(array: T): T;
  randomUUID?: () => string;
  subtle?: MinimalSubtleCrypto;
}

interface MinimalGlobalEnv {
  crypto?: MinimalCryptoGlobal;
  btoa?: (data: string) => string;
  atob?: (data: string) => string;
  Buffer?: {
    from(input: Uint8Array | string, encoding?: string): Uint8Array & { toString(enc: string): string };
  };
}

const ENV = globalThis as unknown as MinimalGlobalEnv;

function toStrictArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength);
  copy.set(bytes);
  return copy.buffer;
}

export function hasSubtleCrypto(): boolean {
  return Boolean(ENV.crypto && ENV.crypto.subtle);
}

// ==================== Encoding & Memory Hygiene ====================

const TEXT_ENCODER = new TextEncoder();
const TEXT_DECODER = new TextDecoder();

export function utf8ToBytes(text: string): Uint8Array {
  return TEXT_ENCODER.encode(text);
}

export function bytesToUtf8(bytes: Uint8Array): string {
  return TEXT_DECODER.decode(bytes);
}

const B64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';

export function bytesToBase64(bytes: Uint8Array): string {
  if (ENV.Buffer) {
    return ENV.Buffer.from(bytes).toString('base64');
  }
  if (ENV.btoa) {
    let binary = '';
    const chunkSize = 0x8000;
    for (let i = 0; i < bytes.length; i += chunkSize) {
      const sub = bytes.subarray(i, Math.min(bytes.length, i + chunkSize));
      for (let j = 0; j < sub.length; j++) {
        binary += String.fromCharCode(sub[j]);
      }
    }
    return ENV.btoa(binary);
  }
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i];
    const b1 = i + 1 < bytes.length ? bytes[i + 1] : 0;
    const b2 = i + 2 < bytes.length ? bytes[i + 2] : 0;
    const triple = (b0 << 16) | (b1 << 8) | b2;
    out += B64_ALPHABET[(triple >>> 18) & 0x3f];
    out += B64_ALPHABET[(triple >>> 12) & 0x3f];
    out += i + 1 < bytes.length ? B64_ALPHABET[(triple >>> 6) & 0x3f] : '=';
    out += i + 2 < bytes.length ? B64_ALPHABET[triple & 0x3f] : '=';
  }
  return out;
}

export function base64ToBytes(b64: string): Uint8Array {
  const normalized = b64.trim().replace(/-/g, '+').replace(/_/g, '/');
  if (!normalized) return new Uint8Array(0);
  if (ENV.Buffer) {
    const buf = ENV.Buffer.from(normalized, 'base64');
    const out = new Uint8Array(buf.byteLength);
    out.set(buf);
    return out;
  }
  const padded =
    normalized.length % 4 === 0
      ? normalized
      : normalized + '='.repeat(4 - (normalized.length % 4));
  if (ENV.atob) {
    const bin = ENV.atob(padded);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
      out[i] = bin.charCodeAt(i);
    }
    return out;
  }
  const clean = padded.replace(/[^A-Za-z0-9+/=]/g, '');
  const padCount = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
  const outLen = Math.floor((clean.length * 3) / 4) - padCount;
  const out = new Uint8Array(outLen);
  let outIdx = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const c0 = B64_ALPHABET.indexOf(clean[i]);
    const c1 = B64_ALPHABET.indexOf(clean[i + 1]);
    const c2 = clean[i + 2] === '=' ? 0 : B64_ALPHABET.indexOf(clean[i + 2]);
    const c3 = clean[i + 3] === '=' ? 0 : B64_ALPHABET.indexOf(clean[i + 3]);
    const triple = (c0 << 18) | (c1 << 12) | (c2 << 6) | c3;
    if (outIdx < outLen) out[outIdx++] = (triple >>> 16) & 0xff;
    if (outIdx < outLen) out[outIdx++] = (triple >>> 8) & 0xff;
    if (outIdx < outLen) out[outIdx++] = triple & 0xff;
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/\s+/g, '');
  if (clean.length % 2 !== 0) {
    throw new Error('Invalid hex string length');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    const val = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(val)) {
      throw new Error('Invalid hex character');
    }
    out[i] = val;
  }
  return out;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const arr of arrays) total += arr.byteLength;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.byteLength;
  }
  return out;
}

export function zeroBytes(bytes: Uint8Array | null | undefined): void {
  if (bytes) {
    bytes.fill(0);
  }
}

export function timingSafeEqualBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function randomBytes(length: number): Uint8Array {
  if (!ENV.crypto || typeof ENV.crypto.getRandomValues !== 'function') {
    throw new Error('Cryptographically secure RNG (crypto.getRandomValues) is unavailable');
  }
  const out = new Uint8Array(length);
  const maxChunk = 65536;
  for (let offset = 0; offset < length; offset += maxChunk) {
    ENV.crypto.getRandomValues(out.subarray(offset, Math.min(length, offset + maxChunk)));
  }
  return out;
}

export function randomUuid(): string {
  if (ENV.crypto && typeof ENV.crypto.randomUUID === 'function') {
    return ENV.crypto.randomUUID();
  }
  const b = randomBytes(16);
  b[6] = (b[6] & 0x0f) | 0x40;
  b[8] = (b[8] & 0x3f) | 0x80;
  const hex = bytesToHex(b);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

// ==================== Pure-TS FIPS 180-4 SHA-256 & HMAC / HKDF / PBKDF2 ====================

const SHA256_K = new Int32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const SHA256_INIT = new Int32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);

function sha256Compress(state: Int32Array, block: Uint8Array, offset: number, W: Int32Array): void {
  for (let i = 0; i < 16; i++) {
    const j = offset + i * 4;
    W[i] =
      ((block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]) | 0;
  }
  for (let i = 16; i < 64; i++) {
    const w15 = W[i - 15];
    const s0 = (((w15 >>> 7) | (w15 << 25)) ^ ((w15 >>> 18) | (w15 << 14)) ^ (w15 >>> 3)) | 0;
    const w2 = W[i - 2];
    const s1 = (((w2 >>> 17) | (w2 << 15)) ^ ((w2 >>> 19) | (w2 << 13)) ^ (w2 >>> 10)) | 0;
    W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
  }

  let a = state[0];
  let b = state[1];
  let c = state[2];
  let d = state[3];
  let e = state[4];
  let f = state[5];
  let g = state[6];
  let h = state[7];

  for (let i = 0; i < 64; i++) {
    const S1 = (((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7))) | 0;
    const ch = ((e & f) ^ (~e & g)) | 0;
    const temp1 = (h + S1 + ch + SHA256_K[i] + W[i]) | 0;
    const S0 = (((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10))) | 0;
    const maj = ((a & b) ^ (a & c) ^ (b & c)) | 0;
    const temp2 = (S0 + maj) | 0;

    h = g;
    g = f;
    f = e;
    e = (d + temp1) | 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) | 0;
  }

  state[0] = (state[0] + a) | 0;
  state[1] = (state[1] + b) | 0;
  state[2] = (state[2] + c) | 0;
  state[3] = (state[3] + d) | 0;
  state[4] = (state[4] + e) | 0;
  state[5] = (state[5] + f) | 0;
  state[6] = (state[6] + g) | 0;
  state[7] = (state[7] + h) | 0;
}

export function sha256Pure(data: Uint8Array): Uint8Array {
  const state = new Int32Array(SHA256_INIT);
  const W = new Int32Array(64);
  const len = data.byteLength;
  const fullLen = len - (len % 64);

  for (let offset = 0; offset < fullLen; offset += 64) {
    sha256Compress(state, data, offset, W);
  }

  const rem = len - fullLen;
  const padBlocks = rem + 9 <= 64 ? 64 : 128;
  const tail = new Uint8Array(padBlocks);
  tail.set(data.subarray(fullLen), 0);
  tail[rem] = 0x80;

  const bitLenHi = Math.floor(len / 0x20000000);
  const bitLenLo = (len << 3) >>> 0;
  const dv = new DataView(tail.buffer);
  dv.setUint32(padBlocks - 8, bitLenHi, false);
  dv.setUint32(padBlocks - 4, bitLenLo, false);

  for (let offset = 0; offset < padBlocks; offset += 64) {
    sha256Compress(state, tail, offset, W);
  }

  const out = new Uint8Array(32);
  const outDv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) {
    outDv.setInt32(i * 4, state[i], false);
  }
  W.fill(0);
  return out;
}

export function hmacSha256Pure(key: Uint8Array, message: Uint8Array): Uint8Array {
  const normalizedKey = key.byteLength > 64 ? sha256Pure(key) : key;
  const ipad = new Uint8Array(64);
  const opad = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const kb = i < normalizedKey.byteLength ? normalizedKey[i] : 0;
    ipad[i] = kb ^ 0x36;
    opad[i] = kb ^ 0x5c;
  }
  const inner = sha256Pure(concatBytes(ipad, message));
  const outer = sha256Pure(concatBytes(opad, inner));
  ipad.fill(0);
  opad.fill(0);
  inner.fill(0);
  return outer;
}

export function hkdfSha256Pure(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
): Uint8Array {
  if (length <= 0 || length > 255 * 32) {
    throw new Error('Invalid HKDF output length');
  }
  const effectiveSalt = salt.byteLength > 0 ? salt : new Uint8Array(32);
  const prk = hmacSha256Pure(effectiveSalt, ikm);
  try {
    const out = new Uint8Array(length);
    let prev: Uint8Array = new Uint8Array(0);
    let written = 0;
    let counter = 1;
    while (written < length) {
      const input = new Uint8Array(prev.byteLength + info.byteLength + 1);
      input.set(prev, 0);
      input.set(info, prev.byteLength);
      input[prev.byteLength + info.byteLength] = counter;
      const next = hmacSha256Pure(prk, input);
      prev.fill(0);
      prev = next;
      const take = Math.min(32, length - written);
      out.set(prev.subarray(0, take), written);
      written += take;
      counter++;
    }
    prev.fill(0);
    return out;
  } finally {
    prk.fill(0);
  }
}

/**
 * Zero-allocation inner-loop PBKDF2-HMAC-SHA256 using SHA-256 ipad/opad midstate caching.
 */
export function pbkdf2HmacSha256Pure(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
): Uint8Array {
  if (iterations < 1 || dkLen < 1) {
    throw new Error('Invalid PBKDF2 parameters');
  }

  const normalizedKey = password.byteLength > 64 ? sha256Pure(password) : password;
  const ipadBlock = new Uint8Array(64);
  const opadBlock = new Uint8Array(64);
  for (let i = 0; i < 64; i++) {
    const kb = i < normalizedKey.byteLength ? normalizedKey[i] : 0;
    ipadBlock[i] = kb ^ 0x36;
    opadBlock[i] = kb ^ 0x5c;
  }

  const W = new Int32Array(64);
  const ipadMidstate = new Int32Array(SHA256_INIT);
  const opadMidstate = new Int32Array(SHA256_INIT);
  sha256Compress(ipadMidstate, ipadBlock, 0, W);
  sha256Compress(opadMidstate, opadBlock, 0, W);
  ipadBlock.fill(0);
  opadBlock.fill(0);

  // Pre-build padded 64-byte block template for HMAC(key, 32-byte U):
  // Total message hashed after 64-byte ipad/opad block is 32 bytes -> total bits = (64 + 32) * 8 = 768 (0x300)
  const block32Padded = new Uint8Array(64);
  block32Padded[32] = 0x80;
  block32Padded[62] = 0x03;
  block32Padded[63] = 0x00;
  const block32Dv = new DataView(block32Padded.buffer);

  const innerState = new Int32Array(8);
  const outerState = new Int32Array(8);
  const accWords = new Int32Array(8);

  const numBlocks = Math.ceil(dkLen / 32);
  const derived = new Uint8Array(dkLen);
  const saltPlusIndex = new Uint8Array(salt.byteLength + 4);
  saltPlusIndex.set(salt, 0);
  const saltDv = new DataView(saltPlusIndex.buffer);

  for (let blockIdx = 1; blockIdx <= numBlocks; blockIdx++) {
    saltDv.setUint32(salt.byteLength, blockIdx, false);
    const u1 = hmacSha256Pure(normalizedKey, saltPlusIndex);
    const u1Dv = new DataView(u1.buffer);
    for (let w = 0; w < 8; w++) {
      const word = u1Dv.getInt32(w * 4, false);
      accWords[w] = word;
      block32Dv.setInt32(w * 4, word, false);
    }
    u1.fill(0);

    for (let iter = 1; iter < iterations; iter++) {
      innerState.set(ipadMidstate);
      sha256Compress(innerState, block32Padded, 0, W);
      for (let w = 0; w < 8; w++) {
        block32Dv.setInt32(w * 4, innerState[w], false);
      }

      outerState.set(opadMidstate);
      sha256Compress(outerState, block32Padded, 0, W);
      for (let w = 0; w < 8; w++) {
        const uw = outerState[w];
        accWords[w] ^= uw;
        block32Dv.setInt32(w * 4, uw, false);
      }
    }

    const blockBytes = new Uint8Array(32);
    const blockBytesDv = new DataView(blockBytes.buffer);
    for (let w = 0; w < 8; w++) {
      blockBytesDv.setInt32(w * 4, accWords[w], false);
    }
    const offset = (blockIdx - 1) * 32;
    const take = Math.min(32, dkLen - offset);
    derived.set(blockBytes.subarray(0, take), offset);
    blockBytes.fill(0);
  }

  ipadMidstate.fill(0);
  opadMidstate.fill(0);
  innerState.fill(0);
  outerState.fill(0);
  accWords.fill(0);
  block32Padded.fill(0);
  W.fill(0);
  if (normalizedKey !== password) {
    normalizedKey.fill(0);
  }

  return derived;
}

// ==================== Pure-TS NIST SP 800-38D AES-256-GCM ====================

const AES_SBOX = new Uint8Array([
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
]);

const AES_RCON = new Uint8Array([0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40]);

function expandAes256Key(key: Uint8Array): Uint8Array {
  if (key.byteLength !== 32) {
    throw new Error('AES-256 requires a 32-byte key');
  }
  const roundKeys = new Uint8Array(240); // 15 * 16 bytes
  roundKeys.set(key, 0);

  let bytesGenerated = 32;
  let rconIdx = 1;
  const temp = new Uint8Array(4);

  while (bytesGenerated < 240) {
    for (let i = 0; i < 4; i++) {
      temp[i] = roundKeys[bytesGenerated - 4 + i];
    }

    if (bytesGenerated % 32 === 0) {
      const t = temp[0];
      temp[0] = AES_SBOX[temp[1]] ^ AES_RCON[rconIdx++];
      temp[1] = AES_SBOX[temp[2]];
      temp[2] = AES_SBOX[temp[3]];
      temp[3] = AES_SBOX[t];
    } else if (bytesGenerated % 32 === 16) {
      for (let i = 0; i < 4; i++) {
        temp[i] = AES_SBOX[temp[i]];
      }
    }

    for (let i = 0; i < 4; i++) {
      roundKeys[bytesGenerated] = roundKeys[bytesGenerated - 32] ^ temp[i];
      bytesGenerated++;
    }
  }

  temp.fill(0);
  return roundKeys;
}

function aes256EncryptBlock(roundKeys: Uint8Array, input: Uint8Array, out: Uint8Array): void {
  const s = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    s[i] = input[i] ^ roundKeys[i];
  }

  for (let round = 1; round <= 14; round++) {
    // SubBytes
    for (let i = 0; i < 16; i++) {
      s[i] = AES_SBOX[s[i]];
    }

    // ShiftRows
    const s1 = s[1];
    s[1] = s[5];
    s[5] = s[9];
    s[9] = s[13];
    s[13] = s1;

    const s2 = s[2];
    const s6 = s[6];
    s[2] = s[10];
    s[6] = s[14];
    s[10] = s2;
    s[14] = s6;

    const s15 = s[15];
    s[15] = s[11];
    s[11] = s[7];
    s[7] = s[3];
    s[3] = s15;

    // MixColumns (rounds 1..13)
    if (round < 14) {
      for (let col = 0; col < 16; col += 4) {
        const a0 = s[col];
        const a1 = s[col + 1];
        const a2 = s[col + 2];
        const a3 = s[col + 3];
        const t = a0 ^ a1 ^ a2 ^ a3;
        const x01 = a0 ^ a1;
        const x12 = a1 ^ a2;
        const x23 = a2 ^ a3;
        const x30 = a3 ^ a0;
        s[col] = a0 ^ t ^ (((x01 << 1) ^ ((x01 & 0x80) !== 0 ? 0x1b : 0)) & 0xff);
        s[col + 1] = a1 ^ t ^ (((x12 << 1) ^ ((x12 & 0x80) !== 0 ? 0x1b : 0)) & 0xff);
        s[col + 2] = a2 ^ t ^ (((x23 << 1) ^ ((x23 & 0x80) !== 0 ? 0x1b : 0)) & 0xff);
        s[col + 3] = a3 ^ t ^ (((x30 << 1) ^ ((x30 & 0x80) !== 0 ? 0x1b : 0)) & 0xff);
      }
    }

    // AddRoundKey
    const rkOffset = round * 16;
    for (let i = 0; i < 16; i++) {
      s[i] ^= roundKeys[rkOffset + i];
    }
  }

  out.set(s, 0);
  s.fill(0);
}

/**
 * GF(2^128) multiplication Y = X * H with polynomial x^128 + x^7 + x^2 + x + 1 (0xe1000000).
 */
function ghashMultiply(yWords: Uint32Array, hWords: Uint32Array): void {
  let z0 = 0;
  let z1 = 0;
  let z2 = 0;
  let z3 = 0;
  let v0 = hWords[0];
  let v1 = hWords[1];
  let v2 = hWords[2];
  let v3 = hWords[3];

  for (let wordIdx = 0; wordIdx < 4; wordIdx++) {
    const xWord = yWords[wordIdx];
    for (let bit = 31; bit >= 0; bit--) {
      if (((xWord >>> bit) & 1) !== 0) {
        z0 = (z0 ^ v0) >>> 0;
        z1 = (z1 ^ v1) >>> 0;
        z2 = (z2 ^ v2) >>> 0;
        z3 = (z3 ^ v3) >>> 0;
      }
      const lsb = v3 & 1;
      v3 = ((v3 >>> 1) | ((v2 & 1) << 31)) >>> 0;
      v2 = ((v2 >>> 1) | ((v1 & 1) << 31)) >>> 0;
      v1 = ((v1 >>> 1) | ((v0 & 1) << 31)) >>> 0;
      v0 = (v0 >>> 1) >>> 0;
      if (lsb !== 0) {
        v0 = (v0 ^ 0xe1000000) >>> 0;
      }
    }
  }

  yWords[0] = z0;
  yWords[1] = z1;
  yWords[2] = z2;
  yWords[3] = z3;
}

function ghashCompute(hBlock: Uint8Array, aad: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const hDv = new DataView(hBlock.buffer, hBlock.byteOffset, 16);
  const hWords = new Uint32Array([
    hDv.getUint32(0, false),
    hDv.getUint32(4, false),
    hDv.getUint32(8, false),
    hDv.getUint32(12, false),
  ]);
  const yWords = new Uint32Array(4);
  const blockBuf = new Uint8Array(16);
  const blockDv = new DataView(blockBuf.buffer);

  const feedData = (data: Uint8Array) => {
    const len = data.byteLength;
    for (let offset = 0; offset < len; offset += 16) {
      const rem = len - offset;
      if (rem >= 16) {
        const dv = new DataView(data.buffer, data.byteOffset + offset, 16);
        yWords[0] = (yWords[0] ^ dv.getUint32(0, false)) >>> 0;
        yWords[1] = (yWords[1] ^ dv.getUint32(4, false)) >>> 0;
        yWords[2] = (yWords[2] ^ dv.getUint32(8, false)) >>> 0;
        yWords[3] = (yWords[3] ^ dv.getUint32(12, false)) >>> 0;
      } else {
        blockBuf.fill(0);
        blockBuf.set(data.subarray(offset, len), 0);
        yWords[0] = (yWords[0] ^ blockDv.getUint32(0, false)) >>> 0;
        yWords[1] = (yWords[1] ^ blockDv.getUint32(4, false)) >>> 0;
        yWords[2] = (yWords[2] ^ blockDv.getUint32(8, false)) >>> 0;
        yWords[3] = (yWords[3] ^ blockDv.getUint32(12, false)) >>> 0;
      }
      ghashMultiply(yWords, hWords);
    }
  };

  feedData(aad);
  feedData(ciphertext);

  const aadBitsHi = Math.floor(aad.byteLength / 0x20000000) >>> 0;
  const aadBitsLo = (aad.byteLength << 3) >>> 0;
  const ctBitsHi = Math.floor(ciphertext.byteLength / 0x20000000) >>> 0;
  const ctBitsLo = (ciphertext.byteLength << 3) >>> 0;

  yWords[0] = (yWords[0] ^ aadBitsHi) >>> 0;
  yWords[1] = (yWords[1] ^ aadBitsLo) >>> 0;
  yWords[2] = (yWords[2] ^ ctBitsHi) >>> 0;
  yWords[3] = (yWords[3] ^ ctBitsLo) >>> 0;
  ghashMultiply(yWords, hWords);

  const out = new Uint8Array(16);
  const outDv = new DataView(out.buffer);
  outDv.setUint32(0, yWords[0], false);
  outDv.setUint32(4, yWords[1], false);
  outDv.setUint32(8, yWords[2], false);
  outDv.setUint32(12, yWords[3], false);
  hWords.fill(0);
  yWords.fill(0);
  return out;
}

function aes256Gctr(
  roundKeys: Uint8Array,
  nonce12: Uint8Array,
  input: Uint8Array,
): Uint8Array {
  const out = new Uint8Array(input.byteLength);
  if (input.byteLength === 0) return out;

  const counterBlock = new Uint8Array(16);
  counterBlock.set(nonce12, 0);
  const counterDv = new DataView(counterBlock.buffer);
  let counter = 2; // J0 uses counter=1; encryption starts at inc32(J0)=2
  const keystream = new Uint8Array(16);

  for (let offset = 0; offset < input.byteLength; offset += 16) {
    counterDv.setUint32(12, counter >>> 0, false);
    counter = (counter + 1) >>> 0;
    aes256EncryptBlock(roundKeys, counterBlock, keystream);
    const take = Math.min(16, input.byteLength - offset);
    for (let i = 0; i < take; i++) {
      out[offset + i] = input[offset + i] ^ keystream[i];
    }
  }

  keystream.fill(0);
  counterBlock.fill(0);
  return out;
}

export function aes256GcmEncryptPure(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): { ciphertext: Uint8Array; authTag: Uint8Array } {
  if (key.byteLength !== 32) throw new Error('AES-256-GCM requires a 32-byte key');
  if (nonce.byteLength !== 12) throw new Error('AES-256-GCM requires a 12-byte nonce');

  const roundKeys = expandAes256Key(key);
  const hBlock = new Uint8Array(16);
  const j0 = new Uint8Array(16);
  const j0Enc = new Uint8Array(16);

  try {
    aes256EncryptBlock(roundKeys, hBlock, hBlock);
    j0.set(nonce, 0);
    j0[15] = 1;
    aes256EncryptBlock(roundKeys, j0, j0Enc);

    const ciphertext = aes256Gctr(roundKeys, nonce, plaintext);
    const ghash = ghashCompute(hBlock, aad, ciphertext);
    const authTag = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      authTag[i] = j0Enc[i] ^ ghash[i];
    }
    ghash.fill(0);
    return { ciphertext, authTag };
  } finally {
    roundKeys.fill(0);
    hBlock.fill(0);
    j0.fill(0);
    j0Enc.fill(0);
  }
}

export function aes256GcmDecryptPure(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  authTag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
): Uint8Array {
  if (key.byteLength !== 32) throw new Error('AES-256-GCM requires a 32-byte key');
  if (nonce.byteLength !== 12) throw new Error('AES-256-GCM requires a 12-byte nonce');
  if (authTag.byteLength !== 16) throw new Error('AES-256-GCM requires a 16-byte authentication tag');

  const roundKeys = expandAes256Key(key);
  const hBlock = new Uint8Array(16);
  const j0 = new Uint8Array(16);
  const j0Enc = new Uint8Array(16);

  try {
    aes256EncryptBlock(roundKeys, hBlock, hBlock);
    j0.set(nonce, 0);
    j0[15] = 1;
    aes256EncryptBlock(roundKeys, j0, j0Enc);

    const ghash = ghashCompute(hBlock, aad, ciphertext);
    const expectedTag = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
      expectedTag[i] = j0Enc[i] ^ ghash[i];
    }
    ghash.fill(0);

    const valid = timingSafeEqualBytes(expectedTag, authTag);
    expectedTag.fill(0);
    if (!valid) {
      throw new Error('AES-256-GCM authentication tag verification failed');
    }

    return aes256Gctr(roundKeys, nonce, ciphertext);
  } finally {
    roundKeys.fill(0);
    hBlock.fill(0);
    j0.fill(0);
    j0Enc.fill(0);
  }
}

// ==================== Unified Async API (WebCrypto Primary + Pure-TS Fallback) ====================

export async function sha256(data: Uint8Array, forcePure = false): Promise<Uint8Array> {
  if (!forcePure && ENV.crypto?.subtle) {
    const digest = await ENV.crypto.subtle.digest('SHA-256', toStrictArrayBuffer(data));
    return new Uint8Array(digest);
  }
  return sha256Pure(data);
}

export async function hmacSha256(
  key: Uint8Array,
  message: Uint8Array,
  forcePure = false,
): Promise<Uint8Array> {
  if (!forcePure && ENV.crypto?.subtle && key.byteLength > 0) {
    const cryptoKey = await ENV.crypto.subtle.importKey(
      'raw',
      toStrictArrayBuffer(key),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign'],
    );
    const sig = await ENV.crypto.subtle.sign('HMAC', cryptoKey, toStrictArrayBuffer(message));
    return new Uint8Array(sig);
  }
  return hmacSha256Pure(key, message);
}

export async function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number,
  forcePure = false,
): Promise<Uint8Array> {
  if (!forcePure && ENV.crypto?.subtle && ikm.byteLength > 0) {
    const baseKey = await ENV.crypto.subtle.importKey(
      'raw',
      toStrictArrayBuffer(ikm),
      'HKDF',
      false,
      ['deriveBits'],
    );
    const bits = await ENV.crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: toStrictArrayBuffer(salt),
        info: toStrictArrayBuffer(info),
      },
      baseKey,
      length * 8,
    );
    return new Uint8Array(bits);
  }
  return hkdfSha256Pure(ikm, salt, info, length);
}

export async function pbkdf2HmacSha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
  dkLen: number,
  forcePure = false,
): Promise<Uint8Array> {
  if (!forcePure && ENV.crypto?.subtle && password.byteLength > 0) {
    const baseKey = await ENV.crypto.subtle.importKey(
      'raw',
      toStrictArrayBuffer(password),
      'PBKDF2',
      false,
      ['deriveBits'],
    );
    const bits = await ENV.crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        hash: 'SHA-256',
        salt: toStrictArrayBuffer(salt),
        iterations,
      },
      baseKey,
      dkLen * 8,
    );
    return new Uint8Array(bits);
  }
  return pbkdf2HmacSha256Pure(password, salt, iterations, dkLen);
}

export async function aes256GcmEncrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  forcePure = false,
): Promise<{ ciphertext: Uint8Array; authTag: Uint8Array }> {
  if (!forcePure && ENV.crypto?.subtle) {
    const cryptoKey = await ENV.crypto.subtle.importKey(
      'raw',
      toStrictArrayBuffer(key),
      { name: 'AES-GCM' },
      false,
      ['encrypt'],
    );
    const combined = new Uint8Array(
      await ENV.crypto.subtle.encrypt(
        {
          name: 'AES-GCM',
          iv: toStrictArrayBuffer(nonce),
          additionalData: toStrictArrayBuffer(aad),
          tagLength: 128,
        },
        cryptoKey,
        toStrictArrayBuffer(plaintext),
      ),
    );
    const ctLen = combined.byteLength - 16;
    return {
      ciphertext: combined.slice(0, ctLen),
      authTag: combined.slice(ctLen),
    };
  }
  return aes256GcmEncryptPure(key, nonce, plaintext, aad);
}

export async function aes256GcmDecrypt(
  key: Uint8Array,
  nonce: Uint8Array,
  ciphertext: Uint8Array,
  authTag: Uint8Array,
  aad: Uint8Array = new Uint8Array(0),
  forcePure = false,
): Promise<Uint8Array> {
  if (!forcePure && ENV.crypto?.subtle) {
    if (authTag.byteLength !== 16) {
      throw new Error('AES-256-GCM requires a 16-byte authentication tag');
    }
    const cryptoKey = await ENV.crypto.subtle.importKey(
      'raw',
      toStrictArrayBuffer(key),
      { name: 'AES-GCM' },
      false,
      ['decrypt'],
    );
    const combined = concatBytes(ciphertext, authTag);
    try {
      const plainBuf = await ENV.crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: toStrictArrayBuffer(nonce),
          additionalData: toStrictArrayBuffer(aad),
          tagLength: 128,
        },
        cryptoKey,
        toStrictArrayBuffer(combined),
      );
      return new Uint8Array(plainBuf);
    } catch {
      throw new Error('AES-256-GCM authentication tag verification failed');
    }
  }
  return aes256GcmDecryptPure(key, nonce, ciphertext, authTag, aad);
}
