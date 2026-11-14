import { Hono } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';
import type {
  AuthEnvelopeResponse,
  AuthParamsResponse,
  AuthSessionResponse,
  AuthStatusResponse,
  UpdateVaultSettingsRequest,
  ZeroKnowledgeChangePasswordRequest,
  ZeroKnowledgeLoginRequest,
  ZeroKnowledgeSetupRequest,
} from '../../shared/types.js';
import type { ServerConfig } from '../config.js';
import type { EphemeralSessionCrypto, LoginRateLimiter } from '../crypto/sessionStore.js';
import {
  buildZeroKnowledgeAdminEnvelope,
  CryptoValidationError,
  ENCRYPTION_SPEC,
  verifyClientAuthKey,
} from '../crypto/vaultCrypto.js';
import {
  type AdminConfigRow,
  ConflictError,
  type VaultRepository,
} from '../db/repositories.js';
import {
  type AuthEnv,
  createRequireAuthMiddleware,
  detectDeviceLabel,
  resolveOptionalSession,
  SESSION_COOKIE_NAME,
} from '../middleware/authMiddleware.js';

export function createAuthRoutes(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
  rateLimiter: LoginRateLimiter,
  config: ServerConfig,
): Hono<AuthEnv> {
  const router = new Hono<AuthEnv>();
  const requireAuth = createRequireAuthMiddleware(repo, sessionCrypto);

  function issueBlindSessionResponse(
    c: Parameters<typeof setCookie>[0],
    admin: AdminConfigRow,
    deviceOverride?: { deviceName?: string; platform?: 'web' | 'ios' | 'android' | 'api' },
  ): AuthSessionResponse {
    const detected = detectDeviceLabel(c, deviceOverride?.deviceName);
    const platform = deviceOverride?.platform || detected.platform;
    const tokenBundle = sessionCrypto.generateToken();
    tokenBundle.sessionSecret.fill(0);

    const session = repo.createSession({
      id: tokenBundle.sessionId,
      tokenHash: tokenBundle.tokenHash,
      deviceName: detected.deviceName,
      platform,
      ipAddress: detected.ipAddress,
      ttlHours: config.sessionTtlHours,
    });

    setCookie(c, SESSION_COOKIE_NAME, tokenBundle.fullToken, {
      httpOnly: true,
      secure: config.cookieSecure,
      sameSite: 'Lax',
      path: '/',
      maxAge: config.sessionTtlHours * 3600,
    });

    return {
      token: tokenBundle.fullToken,
      expiresAt: session.expiresAt,
      vaultName: admin.vaultName,
      keyFingerprint: admin.envelope.keyFingerprint,
      kdfSalt: admin.kdfSaltBase64,
      kdfParams: admin.kdfParams,
      wrappedDek: admin.wrappedDekDto,
      session,
    };
  }

  // GET /api/v1/auth/params - Public pre-login KDF salt & iteration parameters (NEVER exposes wrappedDek)
  router.get('/params', (c) => {
    const admin = repo.getAdminConfig();
    if (!admin) {
      const resp: AuthParamsResponse = {
        initialized: false,
        vaultName: config.vaultDefaultName,
        keyFingerprint: null,
        kdfSalt: null,
        kdfParams: null,
        encryption: ENCRYPTION_SPEC,
      };
      return c.json(resp);
    }

    const resp: AuthParamsResponse = {
      initialized: true,
      vaultName: admin.vaultName,
      keyFingerprint: admin.envelope.keyFingerprint,
      kdfSalt: admin.kdfSaltBase64,
      kdfParams: admin.kdfParams,
      encryption: ENCRYPTION_SPEC,
    };
    return c.json(resp);
  });

  // GET /api/v1/auth/status
  router.get('/status', (c) => {
    const admin = repo.getAdminConfig();
    if (!admin) {
      const status: AuthStatusResponse = {
        initialized: false,
        authenticated: false,
        vaultName: config.vaultDefaultName,
        keyFingerprint: null,
        kdfSalt: null,
        kdfParams: null,
        wrappedDek: null,
        encryption: ENCRYPTION_SPEC,
        session: null,
      };
      return c.json(status);
    }

    const resolved = resolveOptionalSession(c, repo, sessionCrypto);
    const authenticated = Boolean(resolved);

    const status: AuthStatusResponse = {
      initialized: true,
      authenticated,
      vaultName: admin.vaultName,
      keyFingerprint: admin.envelope.keyFingerprint,
      kdfSalt: admin.kdfSaltBase64,
      kdfParams: admin.kdfParams,
      wrappedDek: authenticated ? admin.wrappedDekDto : null,
      encryption: ENCRYPTION_SPEC,
      session: resolved?.sessionInfo ?? null,
    };
    return c.json(status);
  });

  // GET /api/v1/auth/envelope - Authenticated fetch of wrapped Master Key envelope
  router.get('/envelope', requireAuth, (c) => {
    const admin = repo.getAdminConfig()!;
    const resp: AuthEnvelopeResponse = {
      vaultName: admin.vaultName,
      keyFingerprint: admin.envelope.keyFingerprint,
      kdfSalt: admin.kdfSaltBase64,
      kdfParams: admin.kdfParams,
      wrappedDek: admin.wrappedDekDto,
    };
    return c.json(resp);
  });

  // POST /api/v1/auth/setup - Zero-Knowledge client-generated DEK envelope bootstrap
  router.post('/setup', async (c) => {
    const existing = repo.getAdminConfig();
    if (existing) {
      return c.json(
        {
          error: {
            code: 'ALREADY_INITIALIZED',
            message: '系统已存在唯一管理员账户，禁止重复初始化',
          },
        },
        409,
      );
    }

    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if ('password' in rawBody) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message:
              '服务端已启用零知识端到端加密（E2EE v2），禁止向服务端发送明文主密码，请在客户端派生密钥后提交密文信封',
          },
        },
        400,
      );
    }

    const body = rawBody as Partial<ZeroKnowledgeSetupRequest>;

    try {
      const envelope = buildZeroKnowledgeAdminEnvelope({
        kdfSaltBase64: body.kdfSalt || '',
        kdfParams: body.kdfParams!,
        authKeyBase64: body.authKey || '',
        wrappedDek: body.wrappedDek!,
        keyFingerprint: body.keyFingerprint || '',
      });

      const admin = repo.initializeAdmin(body.vaultName || config.vaultDefaultName, envelope);
      const response = issueBlindSessionResponse(c, admin, {
        deviceName: body.deviceName,
        platform: body.platform,
      });
      return c.json(response, 201);
    } catch (err) {
      if (err instanceof CryptoValidationError) {
        return c.json({ error: { code: 'INVALID_E2EE_ENVELOPE', message: err.message } }, 400);
      }
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'ALREADY_INITIALIZED', message: err.message } }, 409);
      }
      throw err;
    }
  });

  // POST /api/v1/auth/login - Zero-Knowledge split-key authentication (never sees password or KEK)
  router.post('/login', async (c) => {
    const admin = repo.getAdminConfig();
    if (!admin) {
      return c.json(
        {
          error: {
            code: 'VAULT_NOT_INITIALIZED',
            message: '私密空间尚未初始化，请先创建管理员主密码',
          },
        },
        403,
      );
    }

    const { ipAddress } = detectDeviceLabel(c);
    const rateCheck = rateLimiter.checkAllowed(ipAddress);
    if (!rateCheck.allowed) {
      c.header('Retry-After', String(rateCheck.retryAfterSeconds));
      return c.json(
        {
          error: {
            code: 'RATE_LIMITED',
            message: `认证尝试次数过多，请等待 ${rateCheck.retryAfterSeconds} 秒后再试`,
          },
        },
        429,
      );
    }

    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if ('password' in rawBody) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '服务端已启用零知识端到端加密（E2EE v2），禁止上传明文主密码',
          },
        },
        400,
      );
    }

    const body = rawBody as Partial<ZeroKnowledgeLoginRequest>;
    const authKey = typeof body.authKey === 'string' ? body.authKey.trim() : '';
    if (!authKey) {
      return c.json(
        {
          error: {
            code: 'MISSING_AUTH_KEY',
            message: '缺少客户端派生的零知识认证密钥 authKey',
          },
        },
        400,
      );
    }

    const verified = verifyClientAuthKey(
      authKey,
      admin.envelope.verifierSalt,
      admin.envelope.authVerifier,
    );
    if (!verified) {
      rateLimiter.recordFailure(ipAddress);
      return c.json(
        {
          error: {
            code: 'INVALID_CREDENTIALS',
            message: '管理员主密码不正确，零知识密钥校验未通过',
          },
        },
        401,
      );
    }

    rateLimiter.reset(ipAddress);
    const response = issueBlindSessionResponse(c, admin, {
      deviceName: body.deviceName,
      platform: body.platform,
    });
    return c.json(response);
  });

  // POST /api/v1/auth/logout
  router.post('/logout', (c) => {
    const resolved = resolveOptionalSession(c, repo, sessionCrypto);
    if (resolved) {
      repo.deleteSession(resolved.sessionInfo.id);
    }
    deleteCookie(c, SESSION_COOKIE_NAME, { path: '/' });
    return c.json({ ok: true });
  });

  // POST /api/v1/auth/change-password - Client-side KEK rotation without exposing DEK or re-encrypting items
  router.post('/change-password', requireAuth, async (c) => {
    const rawBody = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    if ('currentPassword' in rawBody || 'newPassword' in rawBody) {
      return c.json(
        {
          error: {
            code: 'E2EE_REQUIRED',
            message: '零知识模式下禁止向服务端发送明文原密码或新密码',
          },
        },
        400,
      );
    }

    const body = rawBody as Partial<ZeroKnowledgeChangePasswordRequest>;
    const currentAuthKey =
      typeof body.currentAuthKey === 'string' ? body.currentAuthKey.trim() : '';
    const revokeOtherSessions = body.revokeOtherSessions !== false;

    const admin = repo.getAdminConfig()!;
    if (
      !currentAuthKey ||
      !verifyClientAuthKey(
        currentAuthKey,
        admin.envelope.verifierSalt,
        admin.envelope.authVerifier,
      )
    ) {
      return c.json(
        {
          error: {
            code: 'INVALID_CREDENTIALS',
            message: '当前管理员主密码校验失败',
          },
        },
        401,
      );
    }

    try {
      const newEnvelope = buildZeroKnowledgeAdminEnvelope({
        kdfSaltBase64: body.newKdfSalt || '',
        kdfParams: body.newKdfParams!,
        authKeyBase64: body.newAuthKey || '',
        wrappedDek: body.newWrappedDek!,
        keyFingerprint: body.keyFingerprint || '',
      });

      if (newEnvelope.keyFingerprint !== admin.envelope.keyFingerprint) {
        return c.json(
          {
            error: {
              code: 'FINGERPRINT_MISMATCH',
              message: '新信封包裹的主密钥指纹与原 DEK 不一致，已拒绝替换以保护既有密文数据',
            },
          },
          400,
        );
      }

      repo.updateAdminEnvelope(newEnvelope);
      if (revokeOtherSessions) {
        repo.deleteAllSessionsExcept(c.get('sessionId'));
      }

      return c.json({
        ok: true,
        keyFingerprint: newEnvelope.keyFingerprint,
        passwordUpdatedAt: new Date().toISOString(),
      });
    } catch (err) {
      if (err instanceof CryptoValidationError) {
        return c.json({ error: { code: 'INVALID_E2EE_ENVELOPE', message: err.message } }, 400);
      }
      throw err;
    }
  });

  // PATCH /api/v1/auth/settings
  router.patch('/settings', requireAuth, async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as Partial<UpdateVaultSettingsRequest>;
    if (!body.vaultName || !body.vaultName.trim()) {
      return c.json(
        {
          error: {
            code: 'INVALID_INPUT',
            message: '空间名称不能为空',
          },
        },
        400,
      );
    }
    const vaultName = repo.updateVaultName(body.vaultName);
    return c.json({ vaultName });
  });

  // GET /api/v1/auth/security - Blind cryptographic storage summary
  router.get('/security', requireAuth, (c) => {
    const summary = repo.getSecuritySummary();
    return c.json(summary);
  });

  // GET /api/v1/auth/sessions - Active multi-device sessions
  router.get('/sessions', requireAuth, (c) => {
    const sessions = repo.listSessions(c.get('sessionId'));
    return c.json({ sessions });
  });

  // DELETE /api/v1/auth/sessions/:id - Revoke a specific device session
  router.delete('/sessions/:id', requireAuth, (c) => {
    const targetId = c.req.param('id');
    const deleted = repo.deleteSession(targetId);
    if (targetId === c.get('sessionId')) {
      deleteCookie(c, SESSION_COOKIE_NAME, { path: '/' });
    }
    return c.json({ ok: deleted });
  });

  return router;
}
