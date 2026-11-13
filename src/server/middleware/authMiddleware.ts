import crypto from 'node:crypto';
import { getCookie } from 'hono/cookie';
import type { Context, MiddlewareHandler } from 'hono';
import type { EphemeralSessionCrypto } from '../crypto/sessionStore.js';
import type { VaultRepository } from '../db/repositories.js';
import type { SessionInfo } from '../../shared/types.js';

export const SESSION_COOKIE_NAME = 'pss_session';

export interface AuthEnv {
  Variables: {
    dek: Buffer;
    sessionId: string;
    sessionInfo: SessionInfo;
  };
}

export function extractRawToken(c: Context): string | null {
  const authHeader = c.req.header('Authorization');
  if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
    const token = authHeader.slice(7).trim();
    if (token) return token;
  }
  const cookieToken = getCookie(c, SESSION_COOKIE_NAME);
  return cookieToken || null;
}

export function detectDeviceLabel(c: Context, explicitDeviceName?: string): {
  deviceName: string;
  platform: 'web' | 'ios' | 'android' | 'api';
  ipAddress: string;
} {
  const forwarded = c.req.header('x-forwarded-for')?.split(',')[0]?.trim();
  const realIp = c.req.header('x-real-ip')?.trim();
  const ipAddress = forwarded || realIp || '127.0.0.1';

  const ua = c.req.header('user-agent') || '';
  let platform: 'web' | 'ios' | 'android' | 'api' = 'web';
  let inferredDevice = 'Web Browser';

  if (/iPhone|iPad|iPod/i.test(ua)) {
    platform = 'ios';
    inferredDevice = /iPad/i.test(ua) ? 'iPad · Safari/Web' : 'iPhone · Safari/Web';
  } else if (/Android/i.test(ua)) {
    platform = 'android';
    inferredDevice = 'Android · Mobile';
  } else if (/Macintosh|Mac OS X/i.test(ua)) {
    inferredDevice = 'macOS · Web';
  } else if (/Windows/i.test(ua)) {
    inferredDevice = 'Windows · Web';
  } else if (/Linux/i.test(ua)) {
    inferredDevice = 'Linux · Web';
  } else if (!ua || /curl|httpie|okhttp|dart|alamofire/i.test(ua)) {
    platform = 'api';
    inferredDevice = 'API / Sync Client';
  }

  return {
    deviceName: explicitDeviceName?.trim() || inferredDevice,
    platform,
    ipAddress,
  };
}

export function resolveOptionalSession(
  c: Context,
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
): { dek: Buffer; sessionInfo: SessionInfo } | null {
  const rawToken = extractRawToken(c);
  const parsed = sessionCrypto.parseToken(rawToken);
  if (!parsed) {
    return null;
  }

  const stored = repo.getSessionById(parsed.sessionId);
  if (!stored) {
    return null;
  }

  if (
    stored.tokenHash.length !== parsed.tokenHash.length ||
    !crypto.timingSafeEqual(stored.tokenHash, parsed.tokenHash)
  ) {
    parsed.sessionSecret.fill(0);
    return null;
  }

  const dek = sessionCrypto.unwrapDekForSession(parsed.sessionId, parsed.sessionSecret, {
    iv: stored.wrappedDekIv,
    tag: stored.wrappedDekTag,
    ciphertext: stored.wrappedDekCiphertext,
  });
  parsed.sessionSecret.fill(0);

  if (!dek) {
    // Ephemeral runtime secret rotated (e.g., server restarted); purge stale session envelope
    repo.deleteSession(parsed.sessionId);
    return null;
  }

  repo.touchSession(parsed.sessionId);

  return {
    dek,
    sessionInfo: {
      id: stored.id,
      deviceName: stored.deviceName,
      platform: stored.platform,
      ipAddress: stored.ipAddress,
      createdAt: stored.createdAt,
      lastActiveAt: new Date().toISOString(),
      expiresAt: stored.expiresAt,
      current: true,
    },
  };
}

export function createRequireAuthMiddleware(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
): MiddlewareHandler<AuthEnv> {
  return async (c, next) => {
    const admin = repo.getAdminConfig();
    if (!admin) {
      return c.json(
        {
          error: {
            code: 'VAULT_NOT_INITIALIZED',
            message: '私密空间尚未初始化，请先设置管理员密码',
          },
        },
        403,
      );
    }

    const resolved = resolveOptionalSession(c, repo, sessionCrypto);
    if (!resolved) {
      return c.json(
        {
          error: {
            code: 'UNAUTHORIZED',
            message: '空间已锁定或登录已过期，请重新输入管理员密码解锁',
          },
        },
        401,
      );
    }

    c.set('dek', resolved.dek);
    c.set('sessionId', resolved.sessionInfo.id);
    c.set('sessionInfo', resolved.sessionInfo);

    try {
      await next();
    } finally {
      // Wipe unwrapped DEK from RAM immediately after serving the request
      resolved.dek.fill(0);
    }
  };
}
