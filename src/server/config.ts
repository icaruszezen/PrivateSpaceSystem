import path from 'node:path';

export interface ServerConfig {
  port: number;
  host: string;
  dataDir: string;
  dbPath: string;
  nodeEnv: 'development' | 'production' | 'test';
  sessionTtlHours: number;
  adminBootstrapPassword?: string;
  vaultDefaultName: string;
  cookieSecure: boolean;
  corsOrigins: string[];
}

export function loadConfig(overrides: Partial<ServerConfig> = {}): ServerConfig {
  const nodeEnv = (process.env.NODE_ENV as ServerConfig['nodeEnv']) || 'development';
  const port = Number.parseInt(process.env.PORT || '8080', 10);
  const host = process.env.HOST || '0.0.0.0';
  const dataDir = overrides.dataDir || process.env.DATA_DIR || path.resolve(process.cwd(), 'data');
  const dbPath = overrides.dbPath || path.join(dataDir, 'vault.db');
  const sessionTtlHours = Math.max(
    1,
    Number.parseInt(process.env.SESSION_TTL_HOURS || '72', 10) || 72,
  );
  const adminBootstrapPassword = process.env.ADMIN_PASSWORD?.trim() || undefined;
  const vaultDefaultName = process.env.VAULT_NAME?.trim() || 'PrivateSpace';
  const cookieSecure = process.env.COOKIE_SECURE === 'true';
  const corsOrigins = process.env.CORS_ORIGINS
    ? process.env.CORS_ORIGINS.split(',').map((s) => s.trim()).filter(Boolean)
    : [];

  return {
    port,
    host,
    dataDir,
    dbPath,
    nodeEnv,
    sessionTtlHours,
    adminBootstrapPassword,
    vaultDefaultName,
    cookieSecure,
    corsOrigins,
    ...overrides,
  };
}
