import { Hono } from 'hono';
import { deleteCookie, setCookie } from 'hono/cookie';
import type {
  AuthSessionResponse,
  AuthStatusResponse,
  ChangePasswordRequest,
  LoginRequest,
  SetupRequest,
  UpdateVaultSettingsRequest,
} from '../../shared/types.js';
import type { ServerConfig } from '../config.js';
import type { EphemeralSessionCrypto, LoginRateLimiter } from '../crypto/sessionStore.js';
import {
  createMasterKeyEnvelope,
  ENCRYPTION_SPEC,
  unlockMasterKeyEnvelope,
} from '../crypto/vaultCrypto.js';
import { ConflictError, type VaultRepository } from '../db/repositories.js';
import {
  type AuthEnv,
  createRequireAuthMiddleware,
  detectDeviceLabel,
  resolveOptionalSession,
  SESSION_COOKIE_NAME,
} from '../middleware/authMiddleware.js';

const MIN_PASSWORD_LENGTH = 8;
const MAX_PASSWORD_LENGTH = 128;

export function createAuthRoutes(
  repo: VaultRepository,
  sessionCrypto: EphemeralSessionCrypto,
  rateLimiter: LoginRateLimiter,
  config: ServerConfig,
): Hono<AuthEnv> {
  const router = new Hono<AuthEnv>();
  const requireAuth = createRequireAuthMiddleware(repo, sessionCrypto);

  function issueSessionResponse(
    c: Parameters<typeof setCookie>[0],
    dek: Buffer,
    vaultName: string,
    keyFingerprint: string,
    deviceOverride?: { deviceName?: string; platform?: 'web' | 'ios' | 'android' | 'api' },
  ): AuthSessionResponse {
    const detected = detectDeviceLabel(c, deviceOverride?.deviceName);
    const platform = deviceOverride?.platform || detected.platform;
    const tokenBundle = sessionCrypto.generateToken();
    const wrappedDek = sessionCrypto.wrapDekForSession(
      dek,
      tokenBundle.sessionId,
      tokenBundle.sessionSecret,
    );
    tokenBundle.sessionSecret.fill(0);

    const session = repo.createSession({
      id: tokenBundle.sessionId,
      tokenHash: tokenBundle.tokenHash,
      deviceName: detected.deviceName,
      platform,
      ipAddress: detected.ipAddress,
      wrappedDek,
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
      vaultName,
      keyFingerprint,
      session,
    };
  }

  // GET /api/v1/auth/status
  router.get('/status', (c) => {
    const admin = repo.getAdminConfig();
    if (!admin) {
      const status: AuthStatusResponse = {
        initialized: false,
        authenticated: false,
        vaultName: config.vaultDefaultName,
        keyFingerprint: null,
        encryption: ENCRYPTION_SPEC,
        session: null,
      };
      return c.json(status);
    }

    const resolved = resolveOptionalSession(c, repo, sessionCrypto);
    if (resolved) {
      resolved.dek.fill(0);
    }

    const status: AuthStatusResponse = {
      initialized: true,
      authenticated: Boolean(resolved),
      vaultName: admin.vaultName,
      keyFingerprint: admin.envelope.keyFingerprint,
      encryption: ENCRYPTION_SPEC,
      session: resolved?.sessionInfo ?? null,
    };
    return c.json(status);
  });

  // POST /api/v1/auth/setup - Single administrator initial bootstrap
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

    const body = (await c.req.json().catch(() => ({}))) as Partial<SetupRequest>;
    const password = typeof body.password === 'string' ? body.password : '';

    if (password.length < MIN_PASSWORD_LENGTH) {
      return c.json(
        {
          error: {
            code: 'WEAK_PASSWORD',
            message: `管理员主密码长度至少需要 ${MIN_PASSWORD_LENGTH} 个字符`,
          },
        },
        400,
      );
    }
    if (password.length > MAX_PASSWORD_LENGTH) {
      return c.json(
        {
          error: {
            code: 'INVALID_PASSWORD',
            message: `密码长度不能超过 ${MAX_PASSWORD_LENGTH} 个字符`,
          },
        },
        400,
      );
    }

    const { dek, envelope } = createMasterKeyEnvelope(password);
    try {
      const admin = repo.initializeAdmin(body.vaultName || config.vaultDefaultName, envelope);
      const response = issueSessionResponse(
        c,
        dek,
        admin.vaultName,
        admin.envelope.keyFingerprint,
        {
          deviceName: body.deviceName,
          platform: body.platform,
        },
      );
      return c.json(response, 201);
    } catch (err) {
      if (err instanceof ConflictError) {
        return c.json({ error: { code: 'ALREADY_INITIALIZED', message: err.message } }, 409);
      }
      throw err;
    } finally {
      dek.fill(0);
    }
  });

  // POST /api/v1/auth/login - Single administrator unlock
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
            message: `密码尝试次数过多，请等待 ${rateCheck.retryAfterSeconds} 秒后再试`,
          },
        },
        429,
      );
    }

    const body = (await c.req.json().catch(() => ({}))) as Partial<LoginRequest>;
    const password = typeof body.password === 'string' ? body.password : '';
    if (!password) {
      return c.json(
        {
          error: {
            code: 'MISSING_PASSWORD',
            message: '请输入管理员密码',
          },
        },
        400,
      );
    }

    const dek = unlockMasterKeyEnvelope(password, admin.envelope);
    if (!dek) {
      rateLimiter.recordFailure(ipAddress);
      return c.json(
        {
          error: {
            code: 'INVALID_CREDENTIALS',
            message: '管理员密码不正确，无法解密主密钥信封',
          },
        },
        401,
      );
    }

    try {
      rateLimiter.reset(ipAddress);
      const response = issueSessionResponse(
        c,
        dek,
        admin.vaultName,
        admin.envelope.keyFingerprint,
        {
          deviceName: body.deviceName,
          platform: body.platform,
        },
      );
      return c.json(response);
    } finally {
      dek.fill(0);
    }
  });

  // POST /api/v1/auth/logout (also serves as "Lock Vault" for current device)
  router.post('/logout', (c) => {
    const resolved = resolveOptionalSession(c, repo, sessionCrypto);
    if (resolved) {
      resolved.dek.fill(0);
      repo.deleteSession(resolved.sessionInfo.id);
    }
    deleteCookie(c, SESSION_COOKIE_NAME, { path: '/' });
    return c.json({ ok: true });
  });

  // POST /api/v1/auth/change-password - Envelope KEK rotation without re-encrypting vault items
  router.post('/change-password', requireAuth, async (c) => {
    const body = (await c.req.json().catch(() => ({}))) as Partial<ChangePasswordRequest>;
    const currentPassword = typeof body.currentPassword === 'string' ? body.currentPassword : '';
    const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';
    const revokeOtherSessions = body.revokeOtherSessions !== false;

    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      return c.json(
        {
          error: {
            code: 'WEAK_PASSWORD',
            message: `新管理员主密码长度至少需要 ${MIN_PASSWORD_LENGTH} 个字符`,
          },
        },
        400,
      );
    }
    if (newPassword.length > MAX_PASSWORD_LENGTH) {
      return c.json(
        {
          error: {
            code: 'INVALID_PASSWORD',
            message: `密码长度不能超过 ${MAX_PASSWORD_LENGTH} 个字符`,
          },
        },
        400,
      );
    }

    const admin = repo.getAdminConfig()!;
    const verifiedDek = unlockMasterKeyEnvelope(currentPassword, admin.envelope);
    if (!verifiedDek) {
      return c.json(
        {
          error: {
            code: 'INVALID_CREDENTIALS',
            message: '当前管理员密码验证失败',
          },
        },
        401,
      );
    }

    try {
      const { dek: sameDek, envelope: newEnvelope } = createMasterKeyEnvelope(
        newPassword,
        verifiedDek,
      );
      sameDek.fill(0);
      repo.updateAdminEnvelope(newEnvelope);

      if (revokeOtherSessions) {
        repo.deleteAllSessionsExcept(c.get('sessionId'));
      }

      return c.json({
        ok: true,
        keyFingerprint: newEnvelope.keyFingerprint,
        passwordUpdatedAt: new Date().toISOString(),
      });
    } finally {
      verifiedDek.fill(0);
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

  // GET /api/v1/auth/security - Cryptographic storage summary
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
