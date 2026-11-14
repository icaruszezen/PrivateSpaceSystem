import crypto from 'node:crypto';

/**
 * Blind session token manager (`pss_<sessionId>.<secretHex>`).
 *
 * Under Zero-Knowledge E2EE v2, the server stores ONLY `SHA-256(sessionSecret)` to authenticate
 * API requests. No DEK or KEK is ever wrapped in or recoverable from server sessions.
 */
export class EphemeralSessionCrypto {
  /**
   * Generates a structured bearer/cookie token: `pss_<sessionId>.<secretHex>`
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
}

interface RateBucket {
  failures: number;
  firstFailureAt: number;
  blockedUntil: number;
}

/**
 * Protects the single-administrator Zero-Knowledge login endpoint against brute-force guessing.
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
