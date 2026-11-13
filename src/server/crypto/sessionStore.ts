import crypto from 'node:crypto';

/**
 * Ephemeral runtime secret generated exclusively in volatile RAM at process boot.
 * Combined with the client-held session secret via HKDF-SHA256 to wrap the Vault Master Key (DEK)
 * per active session, ensuring:
 * 1. Raw DEK never sits unencrypted in heap memory between requests.
 * 2. Database theft at rest cannot decrypt session envelopes even if a token were captured.
 */
export class EphemeralSessionCrypto {
  private readonly runtimeSecret: Buffer;

  constructor() {
    this.runtimeSecret = crypto.randomBytes(32);
  }

  /**
   * Generates a structured token: `pss_<sessionId>.<secretHex>`
   */
  generateToken(): {
    fullToken: string;
    sessionId: string;
    sessionSecret: Buffer;
    tokenHash: Buffer;
  } {
    const sessionId = crypto.randomUUID();
    const sessionSecret = crypto.randomBytes(32);
    const secretHex = sessionSecret.toString('hex');
    const tokenHash = crypto.createHash('sha256').update(sessionSecret).digest();
    return {
      fullToken: `pss_${sessionId}.${secretHex}`,
      sessionId,
      sessionSecret,
      tokenHash,
    };
  }

  parseToken(rawToken: string | undefined | null): {
    sessionId: string;
    sessionSecret: Buffer;
    tokenHash: Buffer;
  } | null {
    if (!rawToken || !rawToken.startsWith('pss_')) {
      return null;
    }
    const body = rawToken.slice(4);
    const dotIdx = body.indexOf('.');
    if (dotIdx <= 0) {
      return null;
    }
    const sessionId = body.slice(0, dotIdx);
    const secretHex = body.slice(dotIdx + 1);
    if (!/^[0-9a-f]{64}$/i.test(secretHex)) {
      return null;
    }
    const sessionSecret = Buffer.from(secretHex, 'hex');
    const tokenHash = crypto.createHash('sha256').update(sessionSecret).digest();
    return { sessionId, sessionSecret, tokenHash };
  }

  private deriveSessionWrapKey(sessionId: string, sessionSecret: Buffer): Buffer {
    const ikm = Buffer.concat([this.runtimeSecret, sessionSecret]);
    try {
      const derived = crypto.hkdfSync(
        'sha256',
        ikm,
        Buffer.from(sessionId, 'utf8'),
        Buffer.from('privatespace:session-dek:v1', 'utf8'),
        32,
      );
      return Buffer.from(derived);
    } finally {
      ikm.fill(0);
    }
  }

  wrapDekForSession(
    dek: Buffer,
    sessionId: string,
    sessionSecret: Buffer,
  ): { iv: Buffer; tag: Buffer; ciphertext: Buffer } {
    const wrapKey = this.deriveSessionWrapKey(sessionId, sessionSecret);
    try {
      const iv = crypto.randomBytes(12);
      const cipher = crypto.createCipheriv('aes-256-gcm', wrapKey, iv);
      cipher.setAAD(Buffer.from(`session:${sessionId}`, 'utf8'));
      const ciphertext = Buffer.concat([cipher.update(dek), cipher.final()]);
      const tag = cipher.getAuthTag();
      return { iv, tag, ciphertext };
    } finally {
      wrapKey.fill(0);
    }
  }

  unwrapDekForSession(
    sessionId: string,
    sessionSecret: Buffer,
    envelope: { iv: Buffer; tag: Buffer; ciphertext: Buffer },
  ): Buffer | null {
    const wrapKey = this.deriveSessionWrapKey(sessionId, sessionSecret);
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', wrapKey, envelope.iv);
      decipher.setAAD(Buffer.from(`session:${sessionId}`, 'utf8'));
      decipher.setAuthTag(envelope.tag);
      return Buffer.concat([decipher.update(envelope.ciphertext), decipher.final()]);
    } catch {
      return null;
    } finally {
      wrapKey.fill(0);
    }
  }
}

interface RateBucket {
  failures: number;
  firstFailureAt: number;
  blockedUntil: number;
}

/**
 * Protects the single-administrator login endpoint against brute-force guessing.
 */
export class LoginRateLimiter {
  private readonly buckets = new Map<string, RateBucket>();
  private readonly maxFailures: number;
  private readonly windowMs: number;
  private readonly lockoutMs: number;

  constructor(maxFailures = 8, windowMs = 5 * 60 * 1000, lockoutMs = 5 * 60 * 1000) {
    this.maxFailures = maxFailures;
    this.windowMs = windowMs;
    this.lockoutMs = lockoutMs;
  }

  checkAllowed(clientKey: string): { allowed: boolean; retryAfterSeconds: number } {
    const now = Date.now();
    const bucket = this.buckets.get(clientKey);
    if (!bucket) {
      return { allowed: true, retryAfterSeconds: 0 };
    }
    if (bucket.blockedUntil > now) {
      return {
        allowed: false,
        retryAfterSeconds: Math.ceil((bucket.blockedUntil - now) / 1000),
      };
    }
    if (now - bucket.firstFailureAt > this.windowMs) {
      this.buckets.delete(clientKey);
    }
    return { allowed: true, retryAfterSeconds: 0 };
  }

  recordFailure(clientKey: string): void {
    const now = Date.now();
    const existing = this.buckets.get(clientKey);
    if (!existing || now - existing.firstFailureAt > this.windowMs) {
      this.buckets.set(clientKey, {
        failures: 1,
        firstFailureAt: now,
        blockedUntil: 0,
      });
      return;
    }
    existing.failures += 1;
    if (existing.failures >= this.maxFailures) {
      existing.blockedUntil = now + this.lockoutMs;
    }
  }

  reset(clientKey: string): void {
    this.buckets.delete(clientKey);
  }
}
