import path from 'node:path';
import {
  DEFAULT_ANDROID_APP_ID,
  DEFAULT_GITHUB_API_BASE,
  DEFAULT_GITHUB_REPO,
  DEFAULT_IOS_BUNDLE_ID,
  normalizeGithubRepo,
} from '../shared/appUpdate.js';
import type { UpdateChannel } from '../shared/types.js';

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
  appleAppId: string;
  githubRepo: string;
  githubApiBaseUrl: string;
  githubToken?: string;
  updateChannel: UpdateChannel;
  updateCacheTtlSeconds: number;
  androidApplicationId: string;
  androidMinSupportedVersion?: string;
  iosBundleId: string;
  iosMinSupportedVersion?: string;
  iosAppStoreId?: string;
  iosTestFlightUrl?: string;
  iosOtaManifestUrl?: string;
}

function inferIosBundleIdFromAppleAppId(appleAppId: string): string {
  const dotIdx = appleAppId.indexOf('.');
  if (dotIdx > 0 && dotIdx < appleAppId.length - 1) {
    return appleAppId.slice(dotIdx + 1);
  }
  return DEFAULT_IOS_BUNDLE_ID;
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
  const appleAppId = process.env.APPLE_APP_ID?.trim() || 'TEAMID.io.privatespace.ios';

  const githubRepo =
    normalizeGithubRepo(process.env.GITHUB_REPO) || DEFAULT_GITHUB_REPO;
  const githubApiBaseUrl = (process.env.GITHUB_API_BASE_URL?.trim() || DEFAULT_GITHUB_API_BASE).replace(
    /\/+$/,
    '',
  );
  const githubToken = process.env.GITHUB_TOKEN?.trim() || undefined;
  const rawChannel = process.env.UPDATE_CHANNEL?.trim().toLowerCase();
  const updateChannel: UpdateChannel = rawChannel === 'beta' ? 'beta' : 'stable';
  const updateCacheTtlSeconds = Math.max(
    0,
    Number.parseInt(process.env.UPDATE_CACHE_TTL_SECONDS || '300', 10) || 300,
  );
  const androidApplicationId =
    process.env.ANDROID_APPLICATION_ID?.trim() || DEFAULT_ANDROID_APP_ID;
  const androidMinSupportedVersion =
    process.env.ANDROID_MIN_SUPPORTED_VERSION?.trim() || undefined;
  const iosBundleId =
    process.env.IOS_BUNDLE_ID?.trim() || inferIosBundleIdFromAppleAppId(appleAppId);
  const iosMinSupportedVersion =
    process.env.IOS_MIN_SUPPORTED_VERSION?.trim() || undefined;
  const iosAppStoreId = process.env.IOS_APP_STORE_ID?.trim() || undefined;
  const iosTestFlightUrl = process.env.IOS_TESTFLIGHT_URL?.trim() || undefined;
  const iosOtaManifestUrl = process.env.IOS_OTA_MANIFEST_URL?.trim() || undefined;

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
    appleAppId,
    githubRepo,
    githubApiBaseUrl,
    githubToken,
    updateChannel,
    updateCacheTtlSeconds,
    androidApplicationId,
    androidMinSupportedVersion,
    iosBundleId,
    iosMinSupportedVersion,
    iosAppStoreId,
    iosTestFlightUrl,
    iosOtaManifestUrl,
    ...overrides,
  };
}
