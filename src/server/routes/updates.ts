import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { Hono } from 'hono';
import type { ServerConfig } from '../config.js';
import {
  buildAppleOtaManifestPlist,
  buildItmsServicesUrl,
  cleanSemverString,
  computeVersionCodeFromSemver,
  CURRENT_APP_VERSION,
  parseSha256SumsText,
  resolveUpdateFromGithubReleases,
  resolveUpdateFromManifest,
  type GithubReleaseApiItem,
  type GithubReleaseAssetApiItem,
} from '../../shared/appUpdate.js';
import type {
  AppUpdateCheckResponse,
  MobileUpdatePlatform,
  ReleaseManifestDto,
  ServerUpdateConfigResponse,
  UpdateChannel,
} from '../../shared/types.js';

interface CachedUpstreamReleases {
  fetchedAtMs: number;
  releases: GithubReleaseApiItem[];
  manifestByTag: Record<string, ReleaseManifestDto>;
  sha256ByTag: Record<string, Record<string, string>>;
}

function inferRequestOrigin(reqUrl: string, headers: Headers): string {
  const forwardedProto = headers.get('x-forwarded-proto')?.split(',')[0]?.trim();
  const forwardedHost = headers.get('x-forwarded-host')?.split(',')[0]?.trim();
  if (forwardedHost) {
    const proto = forwardedProto || 'https';
    return `${proto}://${forwardedHost}`;
  }
  try {
    return new URL(reqUrl).origin;
  } catch {
    return 'http://127.0.0.1:8080';
  }
}

export function createUpdateRoutes(
  config: ServerConfig,
  fetchImpl: typeof fetch = globalThis.fetch,
): Hono {
  const router = new Hono();
  let cache: CachedUpstreamReleases | null = null;
  let lastForceRefreshAtMs = 0;

  function buildGithubHeaders(accept = 'application/vnd.github+json'): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: accept,
      'User-Agent': `PrivateSpace-Server/${CURRENT_APP_VERSION}`,
      'X-GitHub-Api-Version': '2022-11-28',
    };
    if (config.githubToken) {
      headers.Authorization = `Bearer ${config.githubToken}`;
    }
    return headers;
  }

  function loadLocalOverrideManifest(): ReleaseManifestDto | null {
    const manifestPath = path.join(config.dataDir, 'releases', 'release-manifest.json');
    if (!fs.existsSync(manifestPath)) return null;
    try {
      const raw = fs.readFileSync(manifestPath, 'utf8');
      return JSON.parse(raw) as ReleaseManifestDto;
    } catch {
      return null;
    }
  }

  async function fetchAssetText(asset: GithubReleaseAssetApiItem): Promise<string | null> {
    try {
      const targetUrl = config.githubToken && asset.url ? asset.url : asset.browser_download_url;
      const accept = config.githubToken && asset.url ? 'application/octet-stream' : 'text/plain';
      const res = await fetchImpl(targetUrl, {
        headers: buildGithubHeaders(accept),
      });
      if (!res.ok) return null;
      return await res.text();
    } catch {
      return null;
    }
  }

  async function getUpstreamReleases(forceRefresh = false): Promise<CachedUpstreamReleases> {
    const now = Date.now();
    const ttlMs = config.updateCacheTtlSeconds * 1000;
    const allowForce = forceRefresh && now - lastForceRefreshAtMs >= 10_000;

    if (cache && !allowForce && ttlMs > 0 && now - cache.fetchedAtMs < ttlMs) {
      return cache;
    }
    if (allowForce) {
      lastForceRefreshAtMs = now;
    }

    const url = `${config.githubApiBaseUrl}/repos/${config.githubRepo}/releases?per_page=10`;
    const res = await fetchImpl(url, {
      headers: buildGithubHeaders('application/vnd.github+json'),
    });

    if (!res.ok) {
      if (cache) {
        return cache;
      }
      throw new Error(`GitHub Releases API 响应异常 (HTTP ${res.status})`);
    }

    const releases = (await res.json()) as GithubReleaseApiItem[];
    const manifestByTag: Record<string, ReleaseManifestDto> = {};
    const sha256ByTag: Record<string, Record<string, string>> = {};

    // Inspect up to top 2 non-draft releases for attached release-manifest.json or SHA256SUMS.txt
    const topReleases = (releases || []).filter((r) => !r.draft).slice(0, 2);
    for (const rel of topReleases) {
      const assets = rel.assets ?? [];
      const manifestAsset = assets.find((a) => a.name === 'release-manifest.json');
      if (manifestAsset) {
        const text = await fetchAssetText(manifestAsset);
        if (text) {
          try {
            manifestByTag[rel.tag_name] = JSON.parse(text) as ReleaseManifestDto;
          } catch {
            // ignore malformed JSON
          }
        }
      }

      const sumsMap: Record<string, string> = {};
      const shaSumsAsset = assets.find((a) => /^SHA256SUMS(\.txt)?$/i.test(a.name));
      if (shaSumsAsset) {
        const sumsText = await fetchAssetText(shaSumsAsset);
        if (sumsText) {
          Object.assign(sumsMap, parseSha256SumsText(sumsText));
        }
      }

      for (const sidecar of assets.filter((a) => /\.sha256$/i.test(a.name))) {
        const baseFileName = sidecar.name.replace(/\.sha256$/i, '');
        if (!sumsMap[baseFileName]) {
          const txt = await fetchAssetText(sidecar);
          if (txt) {
            Object.assign(sumsMap, parseSha256SumsText(txt, baseFileName));
          }
        }
      }

      if (Object.keys(sumsMap).length > 0) {
        sha256ByTag[rel.tag_name] = sumsMap;
      }
    }

    cache = {
      fetchedAtMs: now,
      releases,
      manifestByTag,
      sha256ByTag,
    };
    return cache;
  }

  async function resolveForPlatform(params: {
    platform: MobileUpdatePlatform;
    channel: UpdateChannel;
    currentVersion: string;
    currentBuild?: number;
    forceRefresh?: boolean;
    origin: string;
  }): Promise<{
    response: AppUpdateCheckResponse;
    upstreamAssetApiUrl?: string;
    localFilePath?: string;
  }> {
    const minSupported =
      params.platform === 'android'
        ? config.androidMinSupportedVersion || null
        : config.iosMinSupportedVersion || null;

    const dynamicOtaPlistUrl =
      config.iosOtaManifestUrl ||
      `${params.origin}/api/v1/updates/ios-manifest.plist?channel=${params.channel}`;

    // 1. Local air-gapped / LAN release override inside ${DATA_DIR}/releases/release-manifest.json
    const localManifest = loadLocalOverrideManifest();
    if (localManifest && (params.channel === 'beta' || !localManifest.prerelease)) {
      const resolved = resolveUpdateFromManifest(localManifest, {
        repository: localManifest.repository || config.githubRepo,
        platform: params.platform,
        channel: params.channel,
        currentVersion: params.currentVersion,
        currentBuild: params.currentBuild,
        source: 'server-local-override',
        minSupportedVersion: minSupported,
        iosAppStoreId: config.iosAppStoreId,
        iosTestFlightUrl: config.iosTestFlightUrl,
        iosOtaManifestUrl: dynamicOtaPlistUrl,
      });

      let localFilePath: string | undefined;
      if (resolved.asset) {
        const releasesDir = path.resolve(config.dataDir, 'releases');
        const candidatePath = path.resolve(releasesDir, path.basename(resolved.asset.fileName));
        if (candidatePath.startsWith(releasesDir) && fs.existsSync(candidatePath)) {
          localFilePath = candidatePath;
          const stat = fs.statSync(candidatePath);
          resolved.asset.fileSize = resolved.asset.fileSize ?? stat.size;
          if (!resolved.asset.sha256) {
            const buf = fs.readFileSync(candidatePath);
            resolved.asset.sha256 = crypto.createHash('sha256').update(buf).digest('hex');
          }
          if (
            !resolved.asset.downloadUrl ||
            !resolved.asset.downloadUrl.startsWith('http')
          ) {
            resolved.asset.downloadUrl = `${params.origin}/api/v1/updates/download/${params.platform}?channel=${params.channel}`;
          }
          if (params.platform === 'ios') {
            resolved.asset.otaManifestUrl = dynamicOtaPlistUrl;
            resolved.asset.itmsServicesUrl = buildItmsServicesUrl(dynamicOtaPlistUrl);
          }
        }
      }

      return { response: resolved, localFilePath };
    }

    // 2. Upstream GitHub Releases API
    const upstream = await getUpstreamReleases(Boolean(params.forceRefresh));
    const matchingReleases = upstream.releases
      .filter((r) => !r.draft)
      .filter((r) => (params.channel === 'beta' ? true : !r.prerelease));
    const topRelease = matchingReleases[0];
    const attachedManifest = topRelease ? upstream.manifestByTag[topRelease.tag_name] : undefined;
    const shaMap = topRelease ? upstream.sha256ByTag[topRelease.tag_name] : undefined;

    const resolved = resolveUpdateFromGithubReleases(upstream.releases, {
      repository: config.githubRepo,
      platform: params.platform,
      channel: params.channel,
      currentVersion: params.currentVersion,
      currentBuild: params.currentBuild,
      source: 'server-github',
      minSupportedVersion: minSupported,
      iosAppStoreId: config.iosAppStoreId,
      iosTestFlightUrl: config.iosTestFlightUrl,
      iosOtaManifestUrl: dynamicOtaPlistUrl,
      manifestOverride: attachedManifest ?? null,
      sha256Map: shaMap,
    });

    let upstreamAssetApiUrl: string | undefined;
    if (resolved.asset && topRelease?.assets) {
      const rawAsset = topRelease.assets.find((a) => a.name === resolved.asset?.fileName);
      upstreamAssetApiUrl = rawAsset?.url || rawAsset?.browser_download_url;

      // When GITHUB_TOKEN is configured (e.g. private GitHub repo), proxy binary downloads
      // through this server so mobile phones never need a GitHub Personal Access Token!
      if (config.githubToken && upstreamAssetApiUrl) {
        resolved.asset.downloadUrl = `${params.origin}/api/v1/updates/download/${params.platform}?channel=${params.channel}`;
        if (params.platform === 'ios') {
          resolved.asset.otaManifestUrl = dynamicOtaPlistUrl;
          resolved.asset.itmsServicesUrl = buildItmsServicesUrl(dynamicOtaPlistUrl);
        }
      }
    }

    return { response: resolved, upstreamAssetApiUrl };
  }

  router.get('/config', (c) => {
    const payload: ServerUpdateConfigResponse = {
      githubRepo: config.githubRepo,
      githubApiBaseUrl: config.githubApiBaseUrl,
      hasGithubTokenConfigured: Boolean(config.githubToken),
      defaultChannel: config.updateChannel,
      cacheTtlSeconds: config.updateCacheTtlSeconds,
      serverVersion: CURRENT_APP_VERSION,
      androidApplicationId: config.androidApplicationId,
      androidMinSupportedVersion: config.androidMinSupportedVersion ?? null,
      iosBundleId: config.iosBundleId,
      iosMinSupportedVersion: config.iosMinSupportedVersion ?? null,
      iosAppStoreId: config.iosAppStoreId ?? null,
      iosTestFlightUrl: config.iosTestFlightUrl ?? null,
      iosOtaManifestUrl: config.iosOtaManifestUrl ?? null,
    };
    return c.json(payload);
  });

  router.get('/check', async (c) => {
    const rawPlatform = (c.req.query('platform') || 'android').toLowerCase();
    if (rawPlatform !== 'android' && rawPlatform !== 'ios') {
      return c.json(
        {
          error: {
            code: 'INVALID_PLATFORM',
            message: 'platform 参数必须为 android 或 ios',
          },
        },
        400,
      );
    }
    const platform = rawPlatform as MobileUpdatePlatform;
    const rawChannel = (c.req.query('channel') || config.updateChannel).toLowerCase();
    const channel: UpdateChannel = rawChannel === 'beta' ? 'beta' : 'stable';
    const currentVersion = cleanSemverString(
      c.req.query('current_version') || CURRENT_APP_VERSION,
      CURRENT_APP_VERSION,
    );
    const parsedBuild = Number.parseInt(c.req.query('current_build') || '', 10);
    const currentBuild = Number.isFinite(parsedBuild)
      ? parsedBuild
      : computeVersionCodeFromSemver(currentVersion);
    const forceRefresh = c.req.query('force') === '1' || c.req.query('force') === 'true';
    const origin = inferRequestOrigin(c.req.url, c.req.raw.headers);

    try {
      const { response } = await resolveForPlatform({
        platform,
        channel,
        currentVersion,
        currentBuild,
        forceRefresh,
        origin,
      });
      return c.json(response);
    } catch (err) {
      return c.json(
        {
          error: {
            code: 'UPDATE_UPSTREAM_UNAVAILABLE',
            message: err instanceof Error ? err.message : '无法获取 GitHub Release 版本信息',
          },
        },
        502,
      );
    }
  });

  router.get('/ios-manifest.plist', async (c) => {
    const rawChannel = (c.req.query('channel') || config.updateChannel).toLowerCase();
    const channel: UpdateChannel = rawChannel === 'beta' ? 'beta' : 'stable';
    const origin = inferRequestOrigin(c.req.url, c.req.raw.headers);

    try {
      const { response } = await resolveForPlatform({
        platform: 'ios',
        channel,
        currentVersion: '0.0.0',
        currentBuild: 0,
        origin,
      });
      const ipaUrl =
        response.asset?.downloadUrl ||
        `${origin}/api/v1/updates/download/ios?channel=${channel}`;
      const plistXml = buildAppleOtaManifestPlist({
        ipaUrl,
        bundleId: config.iosBundleId,
        bundleVersion: response.latestVersion || CURRENT_APP_VERSION,
        title: `${config.vaultDefaultName} (v${response.latestVersion})`,
      });
      return new Response(plistXml, {
        status: 200,
        headers: {
          'Content-Type': 'application/xml; charset=utf-8',
          'Cache-Control': 'no-store',
        },
      });
    } catch (err) {
      return c.json(
        {
          error: {
            code: 'MANIFEST_GENERATION_FAILED',
            message: err instanceof Error ? err.message : '无法生成 iOS OTA 安装清单',
          },
        },
        502,
      );
    }
  });

  router.get('/download/:platform', async (c) => {
    const rawPlatform = c.req.param('platform').toLowerCase();
    if (rawPlatform !== 'android' && rawPlatform !== 'ios') {
      return c.json(
        { error: { code: 'INVALID_PLATFORM', message: '仅支持 android 或 ios 安装包下载' } },
        400,
      );
    }
    const platform = rawPlatform as MobileUpdatePlatform;
    const rawChannel = (c.req.query('channel') || config.updateChannel).toLowerCase();
    const channel: UpdateChannel = rawChannel === 'beta' ? 'beta' : 'stable';
    const origin = inferRequestOrigin(c.req.url, c.req.raw.headers);

    try {
      const { response, upstreamAssetApiUrl, localFilePath } = await resolveForPlatform({
        platform,
        channel,
        currentVersion: '0.0.0',
        currentBuild: 0,
        origin,
      });

      const contentType =
        platform === 'android'
          ? 'application/vnd.android.package-archive'
          : 'application/octet-stream';

      if (localFilePath && fs.existsSync(localFilePath)) {
        const body = fs.readFileSync(localFilePath);
        const fileName = response.asset?.fileName || path.basename(localFilePath);
        const headers: Record<string, string> = {
          'Content-Type': contentType,
          'Content-Length': String(body.byteLength),
          'Content-Disposition': `attachment; filename="${fileName.replace(/"/g, '')}"`,
        };
        if (response.asset?.sha256) {
          headers['X-Content-SHA256'] = response.asset.sha256;
        }
        return new Response(body, { status: 200, headers });
      }

      if (!response.asset) {
        return c.json(
          {
            error: {
              code: 'RELEASE_ASSET_NOT_FOUND',
              message: `当前 GitHub Release (${response.releaseName}) 未包含 ${platform.toUpperCase()} 安装包产物`,
            },
          },
          404,
        );
      }

      // If private repo token is set, proxy stream from GitHub API asset endpoint
      if (config.githubToken && upstreamAssetApiUrl) {
        const upstreamRes = await fetchImpl(upstreamAssetApiUrl, {
          headers: buildGithubHeaders('application/octet-stream'),
          redirect: 'follow',
        });
        if (!upstreamRes.ok) {
          return c.json(
            {
              error: {
                code: 'UPSTREAM_DOWNLOAD_FAILED',
                message: `无法从私有 GitHub Release 拉取安装包 (HTTP ${upstreamRes.status})`,
              },
            },
            502,
          );
        }
        const headers: Record<string, string> = {
          'Content-Type': contentType,
          'Content-Disposition': `attachment; filename="${response.asset.fileName.replace(/"/g, '')}"`,
        };
        const len = upstreamRes.headers.get('content-length');
        if (len) headers['Content-Length'] = len;
        if (response.asset.sha256) headers['X-Content-SHA256'] = response.asset.sha256;
        return new Response(upstreamRes.body, { status: 200, headers });
      }

      return c.redirect(response.asset.downloadUrl, 302);
    } catch (err) {
      return c.json(
        {
          error: {
            code: 'UPDATE_DOWNLOAD_ERROR',
            message: err instanceof Error ? err.message : '下载更新包失败',
          },
        },
        502,
      );
    }
  });

  return router;
}
