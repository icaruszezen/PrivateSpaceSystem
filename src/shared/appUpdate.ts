import type {
  AppUpdateCheckResponse,
  IosInstallMethod,
  MobileUpdatePlatform,
  PlatformReleaseAsset,
  ReleaseManifestDto,
  UpdateChannel,
} from './types.js';

export const DEFAULT_GITHUB_REPO = 'icaruszezen/PrivateSpaceSystem';
export const DEFAULT_GITHUB_API_BASE = 'https://api.github.com';
export const CURRENT_APP_VERSION = '0.4.0';
export const CURRENT_APP_BUILD = 400;
export const DEFAULT_ANDROID_APP_ID = 'com.privatespace.mobile';
export const DEFAULT_IOS_BUNDLE_ID = 'io.privatespace.ios';

export interface ParsedSemver {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
  rawClean: string;
}

export interface GithubReleaseAssetApiItem {
  name: string;
  size?: number;
  browser_download_url: string;
  url?: string;
  content_type?: string;
  digest?: string | null; // GitHub Releases API native "sha256:..." digest when present
}

export interface GithubReleaseApiItem {
  tag_name: string;
  name?: string | null;
  body?: string | null;
  draft?: boolean;
  prerelease?: boolean;
  published_at?: string | null;
  html_url?: string | null;
  assets?: GithubReleaseAssetApiItem[];
}

export interface ResolveReleaseOptions {
  repository: string;
  platform: MobileUpdatePlatform;
  channel: UpdateChannel;
  currentVersion: string;
  currentBuild?: number;
  source?: AppUpdateCheckResponse['source'];
  minSupportedVersion?: string | null;
  iosAppStoreId?: string | null;
  iosTestFlightUrl?: string | null;
  iosOtaManifestUrl?: string | null;
  manifestOverride?: ReleaseManifestDto | null;
  sha256Map?: Record<string, string>;
}

const GITHUB_REPO_PATTERN = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const SHA256_HEX_PATTERN = /^[a-fA-F0-9]{64}$/;

/**
 * Validates and normalizes a GitHub `owner/repo` identifier or full GitHub URL.
 */
export function normalizeGithubRepo(raw: string | null | undefined): string | null {
  if (!raw) return null;
  let cleaned = raw.trim();
  if (!cleaned) return null;

  cleaned = cleaned
    .replace(/^https?:\/\/github\.com\//i, '')
    .replace(/^\/+|\/+$/g, '')
    .replace(/\.git$/i, '')
    .replace(/^\/+|\/+$/g, '');

  const parts = cleaned.split('/');
  if (parts.length >= 2) {
    const repoPart = parts[1].replace(/\.git$/i, '');
    const candidate = `${parts[0]}/${repoPart}`;
    if (
      GITHUB_REPO_PATTERN.test(candidate) &&
      parts[0] !== '.' &&
      parts[0] !== '..' &&
      parts[1] !== '.' &&
      parts[1] !== '..'
    ) {
      return candidate;
    }
  }
  return null;
}

/**
 * Cleans a tag or version string (e.g. "v0.5.0" -> "0.5.0") and parses SemVer 2.0 components.
 */
export function parseSemver(raw: string | null | undefined): ParsedSemver | null {
  if (!raw) return null;
  const trimmed = raw.trim().replace(/^[vV]/, '');
  if (!trimmed) return null;

  const withoutBuild = trimmed.split('+')[0];
  const dashIdx = withoutBuild.indexOf('-');
  const corePart = dashIdx >= 0 ? withoutBuild.slice(0, dashIdx) : withoutBuild;
  const prePart = dashIdx >= 0 ? withoutBuild.slice(dashIdx + 1) : '';

  const nums = corePart.split('.');
  if (nums.length < 2 || nums.length > 3) return null;

  const major = Number.parseInt(nums[0], 10);
  const minor = Number.parseInt(nums[1], 10);
  const patch = nums.length >= 3 ? Number.parseInt(nums[2], 10) : 0;

  if (
    !Number.isFinite(major) ||
    !Number.isFinite(minor) ||
    !Number.isFinite(patch) ||
    major < 0 ||
    minor < 0 ||
    patch < 0 ||
    !/^\d+$/.test(nums[0]) ||
    !/^\d+$/.test(nums[1]) ||
    (nums[2] !== undefined && !/^\d+$/.test(nums[2]))
  ) {
    return null;
  }

  const prerelease = prePart
    ? prePart
        .split('.')
        .map((s) => s.trim())
        .filter(Boolean)
    : [];

  const normalizedCore = `${major}.${minor}.${patch}`;
  const rawClean = prerelease.length > 0 ? `${normalizedCore}-${prerelease.join('.')}` : normalizedCore;

  return {
    major,
    minor,
    patch,
    prerelease,
    rawClean,
  };
}

export function cleanSemverString(raw: string | null | undefined, fallback = '0.0.0'): string {
  return parseSemver(raw)?.rawClean ?? fallback;
}

/**
 * Computes a monotonic integer versionCode / CFBundleVersion from SemVer:
 * e.g. 0.4.0 -> 400, 0.5.2 -> 502, 1.2.3 -> 10203.
 */
export function computeVersionCodeFromSemver(raw: string | null | undefined): number {
  const parsed = parseSemver(raw);
  if (!parsed) return 1;
  return Math.max(1, parsed.major * 10_000 + parsed.minor * 100 + parsed.patch);
}

function comparePrereleaseIdentifiers(a: string[], b: string[]): number {
  if (a.length === 0 && b.length === 0) return 0;
  // Normal release has higher precedence than a prerelease of the same major.minor.patch
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;

  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const idA = a[i];
    const idB = b[i];
    if (idA === undefined) return -1;
    if (idB === undefined) return 1;
    if (idA === idB) continue;

    const numA = /^\d+$/.test(idA) ? Number.parseInt(idA, 10) : null;
    const numB = /^\d+$/.test(idB) ? Number.parseInt(idB, 10) : null;

    if (numA !== null && numB !== null) {
      return numA > numB ? 1 : -1;
    }
    if (numA !== null) return -1;
    if (numB !== null) return 1;
    return idA > idB ? 1 : -1;
  }
  return 0;
}

/**
 * Compares two SemVer strings: returns 1 if a > b, -1 if a < b, 0 if equal.
 */
export function compareSemver(a: string | null | undefined, b: string | null | undefined): number {
  const pa = parseSemver(a);
  const pb = parseSemver(b);
  if (!pa && !pb) return 0;
  if (!pa) return -1;
  if (!pb) return 1;

  if (pa.major !== pb.major) return pa.major > pb.major ? 1 : -1;
  if (pa.minor !== pb.minor) return pa.minor > pb.minor ? 1 : -1;
  if (pa.patch !== pb.patch) return pa.patch > pb.patch ? 1 : -1;

  return comparePrereleaseIdentifiers(pa.prerelease, pb.prerelease);
}

/**
 * Determines whether a candidate release is newer than the currently running app version.
 */
export function isNewerRelease(params: {
  currentVersion: string;
  currentBuild?: number;
  latestVersion: string;
  latestBuild?: number;
  explicitBuildNumber?: boolean;
}): boolean {
  const cmp = compareSemver(params.latestVersion, params.currentVersion);
  if (cmp > 0) return true;
  if (cmp < 0) return false;

  if (
    params.explicitBuildNumber &&
    typeof params.currentBuild === 'number' &&
    typeof params.latestBuild === 'number' &&
    params.currentBuild > 0 &&
    params.latestBuild > params.currentBuild
  ) {
    const synthesized = computeVersionCodeFromSemver(params.latestVersion);
    if (params.currentBuild < 100 && params.latestBuild === synthesized) {
      return false;
    }
    return true;
  }
  return false;
}

/**
 * Parses `SHA256SUMS.txt` or `.sha256` sidecar lines (`<64-hex>  <filename>` or `<64-hex>`).
 */
export function parseSha256SumsText(text: string, fallbackFileName?: string): Record<string, string> {
  const out: Record<string, string> = {};
  if (!text) return out;

  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;

    const twoCol = line.match(/^([a-fA-F0-9]{64})\s+\*?(.+)$/);
    if (twoCol) {
      const hash = twoCol[1].toLowerCase();
      const file = twoCol[2].trim().replace(/^\.?\//, '');
      const baseName = file.split('/').pop() || file;
      out[baseName] = hash;
      out[file] = hash;
      continue;
    }

    if (SHA256_HEX_PATTERN.test(line) && fallbackFileName) {
      out[fallbackFileName] = line.toLowerCase();
    }
  }
  return out;
}

function extractNativeAssetSha256(
  asset: GithubReleaseAssetApiItem | undefined,
  sha256Map?: Record<string, string>,
): string | null {
  if (!asset) return null;
  if (asset.digest && asset.digest.toLowerCase().startsWith('sha256:')) {
    const hex = asset.digest.slice('sha256:'.length).trim().toLowerCase();
    if (SHA256_HEX_PATTERN.test(hex)) return hex;
  }
  const fromMap = sha256Map?.[asset.name];
  if (fromMap && SHA256_HEX_PATTERN.test(fromMap)) {
    return fromMap.toLowerCase();
  }
  return null;
}

export function buildItmsServicesUrl(manifestHttpsUrl: string): string {
  return `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestHttpsUrl)}`;
}

export function buildAltStoreInstallUrl(ipaUrl: string): string {
  return `altstore://install?url=${encodeURIComponent(ipaUrl)}`;
}

export function buildAppStoreUrl(appStoreId: string): string {
  const cleanId = appStoreId.trim().replace(/^id/i, '');
  return `itms-apps://itunes.apple.com/app/id${encodeURIComponent(cleanId)}`;
}

function escapeXml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

/**
 * Generates an Apple OTA installation PropertyList (`manifest.plist`) for `itms-services://`.
 */
export function buildAppleOtaManifestPlist(params: {
  ipaUrl: string;
  bundleId?: string;
  bundleVersion: string;
  buildNumber?: number;
  title?: string;
}): string {
  const bundleId = (params.bundleId || DEFAULT_IOS_BUNDLE_ID).trim();
  const version = cleanSemverString(params.bundleVersion, CURRENT_APP_VERSION);
  const title = (params.title || 'PSS').trim();
  const subtitleXml =
    typeof params.buildNumber === 'number' && Number.isFinite(params.buildNumber)
      ? `\n        <key>subtitle</key>\n        <string>${escapeXml(`Build ${Math.trunc(params.buildNumber)}`)}</string>`
      : '';

  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict>
          <key>kind</key>
          <string>software-package</string>
          <key>url</key>
          <string>${escapeXml(params.ipaUrl)}</string>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key>
        <string>${escapeXml(bundleId)}</string>
        <key>bundle-version</key>
        <string>${escapeXml(version)}</string>
        <key>kind</key>
        <string>software</string>${subtitleXml}
        <key>title</key>
        <string>${escapeXml(title)}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>
`;
}

function enrichIosAssetUrls(
  asset: PlatformReleaseAsset,
  opts: {
    iosAppStoreId?: string | null;
    iosTestFlightUrl?: string | null;
    iosOtaManifestUrl?: string | null;
  },
): PlatformReleaseAsset {
  const otaManifestUrl = opts.iosOtaManifestUrl || asset.otaManifestUrl || null;
  const itmsServicesUrl = otaManifestUrl
    ? buildItmsServicesUrl(otaManifestUrl)
    : asset.itmsServicesUrl || null;
  const appStoreUrl = opts.iosAppStoreId
    ? buildAppStoreUrl(opts.iosAppStoreId)
    : asset.appStoreUrl || null;
  const testFlightUrl = opts.iosTestFlightUrl || asset.testFlightUrl || null;
  const altStoreUrl =
    asset.downloadUrl && /\.ipa(\?|$)/i.test(asset.downloadUrl)
      ? buildAltStoreInstallUrl(asset.downloadUrl)
      : asset.altStoreUrl || null;

  let iosInstallMethod: IosInstallMethod = asset.iosInstallMethod || 'ipa-release';
  if (!asset.iosInstallMethod) {
    if (itmsServicesUrl) iosInstallMethod = 'ota-itms';
    else if (testFlightUrl) iosInstallMethod = 'testflight';
    else if (appStoreUrl) iosInstallMethod = 'appstore';
    else if (altStoreUrl) iosInstallMethod = 'altstore';
    else iosInstallMethod = 'pwa-reload';
  }

  return {
    ...asset,
    iosInstallMethod,
    otaManifestUrl,
    itmsServicesUrl,
    appStoreUrl,
    testFlightUrl,
    altStoreUrl,
  };
}

/**
 * Evaluates a `ReleaseManifestDto` (from `release-manifest.json` or local override) into an `AppUpdateCheckResponse`.
 */
export function resolveUpdateFromManifest(
  manifest: ReleaseManifestDto,
  options: ResolveReleaseOptions,
): AppUpdateCheckResponse {
  const currentVersion = cleanSemverString(options.currentVersion, CURRENT_APP_VERSION);
  const currentBuild = options.currentBuild ?? computeVersionCodeFromSemver(currentVersion);
  const rawPlatformAsset = options.platform === 'android' ? manifest.android : manifest.ios;

  const latestVersion = cleanSemverString(
    rawPlatformAsset?.version || manifest.version || manifest.tagName,
    currentVersion,
  );
  const latestBuild =
    rawPlatformAsset?.buildNumber ??
    manifest.buildNumber ??
    computeVersionCodeFromSemver(latestVersion);

  const hasUpdate = isNewerRelease({
    currentVersion,
    currentBuild,
    latestVersion,
    latestBuild,
    explicitBuildNumber: Boolean(rawPlatformAsset?.buildNumber || manifest.buildNumber),
  });

  const effectiveMinSupported =
    options.minSupportedVersion || rawPlatformAsset?.minSupportedVersion || null;
  const belowMinSupported = effectiveMinSupported
    ? compareSemver(currentVersion, effectiveMinSupported) < 0
    : false;
  const notesText = manifest.releaseNotes ?? '';
  const mandatoryInNotes = /\[mandatory\]|\[强制更新\]/i.test(notesText);
  const mandatory =
    hasUpdate && Boolean(rawPlatformAsset?.mandatory || belowMinSupported || mandatoryInNotes);

  let asset: PlatformReleaseAsset | null = rawPlatformAsset
    ? {
        ...rawPlatformAsset,
        platform: options.platform,
        version: latestVersion,
        buildNumber: latestBuild,
        minSupportedVersion: effectiveMinSupported,
        mandatory,
      }
    : null;

  if (options.platform === 'ios' && asset) {
    asset = enrichIosAssetUrls(asset, options);
  } else if (
    options.platform === 'ios' &&
    !asset &&
    (options.iosOtaManifestUrl || options.iosTestFlightUrl || options.iosAppStoreId)
  ) {
    const primaryUrl =
      options.iosTestFlightUrl ||
      (options.iosAppStoreId ? buildAppStoreUrl(options.iosAppStoreId) : '') ||
      options.iosOtaManifestUrl ||
      manifest.htmlUrl ||
      `https://github.com/${options.repository}/releases`;
    asset = enrichIosAssetUrls(
      {
        platform: 'ios',
        version: latestVersion,
        buildNumber: latestBuild,
        minSupportedVersion: effectiveMinSupported,
        mandatory,
        fileName: `PrivateSpace-iOS-v${latestVersion}.ipa`,
        downloadUrl: primaryUrl,
      },
      options,
    );
  }

  return {
    checkedAt: new Date().toISOString(),
    source: options.source ?? 'server-github',
    repository: manifest.repository || options.repository,
    channel: options.channel,
    platform: options.platform,
    currentVersion,
    currentBuild,
    latestVersion,
    latestBuild,
    hasUpdate,
    mandatory,
    prerelease: Boolean(manifest.prerelease),
    releaseName: manifest.tagName || `v${latestVersion}`,
    releaseNotes: notesText,
    publishedAt: manifest.publishedAt || null,
    htmlUrl:
      manifest.htmlUrl ||
      `https://github.com/${manifest.repository || options.repository}/releases/tag/${
        manifest.tagName || `v${latestVersion}`
      }`,
    asset,
  };
}

/**
 * Selects the newest applicable GitHub Release for the requested channel (`stable` or `beta`)
 * and builds a structured `AppUpdateCheckResponse` for Android or iOS.
 */
export function resolveUpdateFromGithubReleases(
  releases: GithubReleaseApiItem[],
  options: ResolveReleaseOptions,
): AppUpdateCheckResponse {
  if (options.manifestOverride) {
    return resolveUpdateFromManifest(options.manifestOverride, options);
  }

  const currentVersion = cleanSemverString(options.currentVersion, CURRENT_APP_VERSION);
  const currentBuild = options.currentBuild ?? computeVersionCodeFromSemver(currentVersion);

  const candidates = (releases || [])
    .filter((r) => !r.draft)
    .filter((r) => (options.channel === 'beta' ? true : !r.prerelease))
    .filter((r) => parseSemver(r.tag_name) !== null)
    .sort((a, b) => compareSemver(b.tag_name, a.tag_name));

  const chosen = candidates[0];
  if (!chosen) {
    return {
      checkedAt: new Date().toISOString(),
      source: options.source ?? 'server-github',
      repository: options.repository,
      channel: options.channel,
      platform: options.platform,
      currentVersion,
      currentBuild,
      latestVersion: currentVersion,
      latestBuild: currentBuild,
      hasUpdate: false,
      mandatory: false,
      prerelease: false,
      releaseName: `v${currentVersion}`,
      releaseNotes: '当前仓库暂无已发布的 GitHub Release 版本。',
      publishedAt: null,
      htmlUrl: `https://github.com/${options.repository}/releases`,
      asset: null,
    };
  }

  const latestVersion = cleanSemverString(chosen.tag_name, currentVersion);
  const latestBuild = computeVersionCodeFromSemver(latestVersion);
  const hasUpdate = isNewerRelease({
    currentVersion,
    currentBuild,
    latestVersion,
    latestBuild,
    explicitBuildNumber: false,
  });

  const notesText = chosen.body?.trim() || '';
  const effectiveMinSupported = options.minSupportedVersion || null;
  const belowMinSupported = effectiveMinSupported
    ? compareSemver(currentVersion, effectiveMinSupported) < 0
    : false;
  const mandatory =
    hasUpdate && (belowMinSupported || /\[mandatory\]|\[强制更新\]/i.test(notesText));

  const assets = chosen.assets ?? [];
  let platformAsset: PlatformReleaseAsset | null = null;

  if (options.platform === 'android') {
    const apkCandidates = assets.filter((a) => /\.apk$/i.test(a.name));
    const preferredApk =
      apkCandidates.find((a) => /release|signed/i.test(a.name) && !/unsigned/i.test(a.name)) ??
      apkCandidates[0];

    if (preferredApk) {
      platformAsset = {
        platform: 'android',
        version: latestVersion,
        buildNumber: latestBuild,
        minSupportedVersion: effectiveMinSupported,
        mandatory,
        fileName: preferredApk.name,
        downloadUrl: preferredApk.browser_download_url,
        sha256: extractNativeAssetSha256(preferredApk, options.sha256Map),
        fileSize: preferredApk.size ?? null,
        signingMode: /debug/i.test(preferredApk.name) ? 'debug-signed' : 'release-signed',
      };
    }
  } else {
    const ipaCandidates = assets.filter((a) => /\.ipa$/i.test(a.name));
    const preferredIpa =
      ipaCandidates.find((a) => !/unsigned/i.test(a.name)) ?? ipaCandidates[0];
    const plistAsset = assets.find((a) => /manifest.*\.plist$/i.test(a.name));

    const effectivePlistUrl =
      options.iosOtaManifestUrl || plistAsset?.browser_download_url || null;

    if (preferredIpa) {
      platformAsset = enrichIosAssetUrls(
        {
          platform: 'ios',
          version: latestVersion,
          buildNumber: latestBuild,
          minSupportedVersion: effectiveMinSupported,
          mandatory,
          fileName: preferredIpa.name,
          downloadUrl: preferredIpa.browser_download_url,
          sha256: extractNativeAssetSha256(preferredIpa, options.sha256Map),
          fileSize: preferredIpa.size ?? null,
          signingMode: /unsigned/i.test(preferredIpa.name) ? 'unsigned-sideload' : 'adhoc-ota',
          otaManifestUrl: effectivePlistUrl,
        },
        {
          ...options,
          iosOtaManifestUrl: effectivePlistUrl,
        },
      );
    } else if (options.iosOtaManifestUrl || options.iosTestFlightUrl || options.iosAppStoreId) {
      const fallbackUrl =
        options.iosTestFlightUrl ||
        (options.iosAppStoreId ? buildAppStoreUrl(options.iosAppStoreId) : '') ||
        options.iosOtaManifestUrl ||
        chosen.html_url ||
        `https://github.com/${options.repository}/releases`;
      platformAsset = enrichIosAssetUrls(
        {
          platform: 'ios',
          version: latestVersion,
          buildNumber: latestBuild,
          minSupportedVersion: effectiveMinSupported,
          mandatory,
          fileName: `PrivateSpace-iOS-v${latestVersion}.ipa`,
          downloadUrl: fallbackUrl,
        },
        options,
      );
    }
  }

  return {
    checkedAt: new Date().toISOString(),
    source: options.source ?? 'server-github',
    repository: options.repository,
    channel: options.channel,
    platform: options.platform,
    currentVersion,
    currentBuild,
    latestVersion,
    latestBuild,
    hasUpdate,
    mandatory,
    prerelease: Boolean(chosen.prerelease),
    releaseName: chosen.name?.trim() || chosen.tag_name,
    releaseNotes: notesText,
    publishedAt: chosen.published_at ?? null,
    htmlUrl:
      chosen.html_url || `https://github.com/${options.repository}/releases/tag/${chosen.tag_name}`,
    asset: platformAsset,
  };
}
