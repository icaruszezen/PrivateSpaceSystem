import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { createApp, type AppInstance } from '../src/server/app.js';
import { loadConfig } from '../src/server/config.js';
import {
  buildAppleOtaManifestPlist,
  buildItmsServicesUrl,
  compareSemver,
  computeVersionCodeFromSemver,
  isNewerRelease,
  normalizeGithubRepo,
  parseSemver,
  parseSha256SumsText,
  resolveUpdateFromGithubReleases,
  type GithubReleaseApiItem,
} from '../src/shared/appUpdate.js';
import type { ReleaseManifestDto } from '../src/shared/types.js';
import {
  InMemoryVaultPersistence,
  loadMobileUpdatePreferences,
  PrivateSpaceMobileClient,
  saveMobileUpdatePreferences,
} from '../mobile/src/syncClient.js';

const tempDirs: string[] = [];
const activeApps: AppInstance[] = [];

afterEach(() => {
  while (activeApps.length > 0) {
    const inst = activeApps.pop();
    try {
      inst?.db.close();
    } catch {
      // ignore
    }
  }
  while (tempDirs.length > 0) {
    const d = tempDirs.pop();
    if (d) fs.rmSync(d, { recursive: true, force: true });
  }
});

function createUpdateTestServer(
  envOverrides: Record<string, string> = {},
  updateFetchImpl?: typeof fetch,
) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pss-update-test-'));
  tempDirs.push(dir);

  const prevEnv: Record<string, string | undefined> = {};
  const merged = { DATA_DIR: dir, ...envOverrides };
  for (const [k, v] of Object.entries(merged)) {
    prevEnv[k] = process.env[k];
    process.env[k] = v;
  }
  const config = loadConfig();
  for (const [k, v] of Object.entries(prevEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }

  const inst = createApp(config, { updateFetchImpl });
  activeApps.push(inst);
  return { dir, inst, config };
}

describe('Android & iOS Software Auto-Update & GitHub Release Gateway', () => {
  it('parses and compares SemVer 2.0 versions, prereleases, build numbers, and GitHub repo slugs', () => {
    expect(normalizeGithubRepo('https://github.com/icaruszezen/PrivateSpaceSystem.git/')).toBe(
      'icaruszezen/PrivateSpaceSystem',
    );
    expect(normalizeGithubRepo('my-org/private_space.app')).toBe('my-org/private_space.app');
    expect(normalizeGithubRepo('../evil')).toBeNull();
    expect(normalizeGithubRepo('single-segment')).toBeNull();

    expect(parseSemver('v0.5.0+20261114')).toEqual({
      major: 0,
      minor: 5,
      patch: 0,
      prerelease: [],
      rawClean: '0.5.0',
    });
    expect(computeVersionCodeFromSemver('v0.4.0')).toBe(400);
    expect(computeVersionCodeFromSemver('1.2.3')).toBe(10203);

    expect(compareSemver('0.5.0', '0.4.0')).toBe(1);
    expect(compareSemver('0.5.0-beta.1', '0.4.9')).toBe(1);
    expect(compareSemver('0.5.0', '0.5.0-beta.2')).toBe(1);
    expect(compareSemver('0.5.0-beta.2', '0.5.0-beta.1')).toBe(1);
    expect(compareSemver('v0.4.0', '0.4.0')).toBe(0);

    expect(
      isNewerRelease({
        currentVersion: '0.4.0',
        currentBuild: 400,
        latestVersion: '0.5.0',
        latestBuild: 500,
      }),
    ).toBe(true);
    expect(
      isNewerRelease({
        currentVersion: '0.5.0',
        currentBuild: 500,
        latestVersion: '0.5.0',
        latestBuild: 500,
      }),
    ).toBe(false);
  });

  it('parses SHA256SUMS.txt and generates valid Apple OTA itms-services manifest.plist XML', () => {
    const hashA = 'a'.repeat(64);
    const hashB = 'b'.repeat(64);
    const sums = parseSha256SumsText(
      `# Release checksums\n${hashA}  PrivateSpace-Android-v0.5.0.apk\n${hashB} *dist/PrivateSpace-iOS-v0.5.0.ipa\n`,
    );
    expect(sums['PrivateSpace-Android-v0.5.0.apk']).toBe(hashA);
    expect(sums['PrivateSpace-iOS-v0.5.0.ipa']).toBe(hashB);

    const plist = buildAppleOtaManifestPlist({
      ipaUrl: 'https://vault.example.com/api/v1/updates/download/ios?tag=v0.5.0',
      bundleId: 'io.privatespace.ios',
      bundleVersion: '0.5.0',
      buildNumber: 500,
      title: 'PrivateSpace <E2EE>',
    });
    expect(plist).toContain('<string>software-package</string>');
    expect(plist).toContain('<string>io.privatespace.ios</string>');
    expect(plist).toContain('PrivateSpace &lt;E2EE&gt;');

    const itms = buildItmsServicesUrl('https://vault.example.com/api/v1/updates/ios-manifest.plist');
    expect(itms).toBe(
      'itms-services://?action=download-manifest&url=https%3A%2F%2Fvault.example.com%2Fapi%2Fv1%2Fupdates%2Fios-manifest.plist',
    );
  });

  it('resolves stable vs beta GitHub Releases and enforces minSupportedVersion mandatory flags', () => {
    const apkSha = '1'.repeat(64);
    const ipaSha = '2'.repeat(64);
    const releases: GithubReleaseApiItem[] = [
      {
        tag_name: 'v0.6.0-beta.1',
        name: 'PrivateSpace v0.6.0 Beta 1',
        body: 'Beta features',
        prerelease: true,
        published_at: '2026-11-14T10:00:00Z',
        html_url: 'https://github.com/icaruszezen/PrivateSpaceSystem/releases/tag/v0.6.0-beta.1',
        assets: [
          {
            name: 'PrivateSpace-Android-v0.6.0-beta.1.apk',
            size: 14_200_000,
            browser_download_url:
              'https://github.com/icaruszezen/PrivateSpaceSystem/releases/download/v0.6.0-beta.1/PrivateSpace-Android-v0.6.0-beta.1.apk',
            digest: `sha256:${apkSha}`,
          },
        ],
      },
      {
        tag_name: 'v0.5.0',
        name: 'PrivateSpace v0.5.0',
        body: 'Stable release with auto-update',
        prerelease: false,
        published_at: '2026-11-14T08:00:00Z',
        html_url: 'https://github.com/icaruszezen/PrivateSpaceSystem/releases/tag/v0.5.0',
        assets: [
          {
            name: 'PrivateSpace-Android-v0.5.0.apk',
            size: 13_800_000,
            browser_download_url:
              'https://github.com/icaruszezen/PrivateSpaceSystem/releases/download/v0.5.0/PrivateSpace-Android-v0.5.0.apk',
          },
          {
            name: 'PrivateSpace-iOS-v0.5.0.ipa',
            size: 18_500_000,
            browser_download_url:
              'https://github.com/icaruszezen/PrivateSpaceSystem/releases/download/v0.5.0/PrivateSpace-iOS-v0.5.0.ipa',
          },
        ],
      },
    ];

    const stableAndroid = resolveUpdateFromGithubReleases(releases, {
      repository: 'icaruszezen/PrivateSpaceSystem',
      platform: 'android',
      channel: 'stable',
      currentVersion: '0.4.0',
      currentBuild: 400,
      minSupportedVersion: '0.4.5',
      sha256Map: { 'PrivateSpace-Android-v0.5.0.apk': apkSha },
    });
    expect(stableAndroid.hasUpdate).toBe(true);
    expect(stableAndroid.latestVersion).toBe('0.5.0');
    expect(stableAndroid.mandatory).toBe(true);
    expect(stableAndroid.asset?.sha256).toBe(apkSha);

    const betaAndroid = resolveUpdateFromGithubReleases(releases, {
      repository: 'icaruszezen/PrivateSpaceSystem',
      platform: 'android',
      channel: 'beta',
      currentVersion: '0.5.0',
      currentBuild: 500,
    });
    expect(betaAndroid.hasUpdate).toBe(true);
    expect(betaAndroid.latestVersion).toBe('0.6.0-beta.1');
    expect(betaAndroid.prerelease).toBe(true);
    expect(betaAndroid.asset?.sha256).toBe(apkSha);

    const stableIos = resolveUpdateFromGithubReleases(releases, {
      repository: 'icaruszezen/PrivateSpaceSystem',
      platform: 'ios',
      channel: 'stable',
      currentVersion: '0.4.0',
      currentBuild: 400,
      iosTestFlightUrl: 'https://testflight.apple.com/join/psstest',
      sha256Map: { 'PrivateSpace-iOS-v0.5.0.ipa': ipaSha },
    });
    expect(stableIos.hasUpdate).toBe(true);
    expect(stableIos.asset?.iosInstallMethod).toBe('testflight');
    expect(stableIos.asset?.testFlightUrl).toBe('https://testflight.apple.com/join/psstest');
    expect(stableIos.asset?.sha256).toBe(ipaSha);
  });

  it('serves /api/v1/updates/* with private GitHub token proxy, OTA plist, and SHA-256 headers', async () => {
    const fakeApkBytes = Buffer.from('PK\x03\x04FAKE_SIGNED_ANDROID_APK_BINARY_V050');
    const fakeApkSha = crypto.createHash('sha256').update(fakeApkBytes).digest('hex');
    const fakeIpaBytes = Buffer.from('PK\x03\x04FAKE_SIGNED_IOS_IPA_BINARY_V050');
    const fakeIpaSha = crypto.createHash('sha256').update(fakeIpaBytes).digest('hex');

    const observedAuthHeaders: string[] = [];

    const mockUpstreamFetch: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
      const headers = new Headers(init?.headers);
      const auth = headers.get('authorization');
      if (auth) observedAuthHeaders.push(auth);

      if (url.endsWith('/repos/acme-sec/PrivateVault/releases?per_page=10')) {
        return new Response(
          JSON.stringify([
            {
              tag_name: 'v0.5.0',
              name: 'PrivateVault v0.5.0',
              body: 'Private repo release notes',
              draft: false,
              prerelease: false,
              published_at: '2026-11-14T09:00:00Z',
              html_url: 'https://github.com/acme-sec/PrivateVault/releases/tag/v0.5.0',
              assets: [
                {
                  name: 'PrivateSpace-Android-v0.5.0.apk',
                  size: fakeApkBytes.length,
                  url: 'https://api.github.com/repos/acme-sec/PrivateVault/releases/assets/1001',
                  browser_download_url:
                    'https://github.com/acme-sec/PrivateVault/releases/download/v0.5.0/PrivateSpace-Android-v0.5.0.apk',
                  digest: `sha256:${fakeApkSha}`,
                },
                {
                  name: 'PrivateSpace-iOS-v0.5.0.ipa',
                  size: fakeIpaBytes.length,
                  url: 'https://api.github.com/repos/acme-sec/PrivateVault/releases/assets/1002',
                  browser_download_url:
                    'https://github.com/acme-sec/PrivateVault/releases/download/v0.5.0/PrivateSpace-iOS-v0.5.0.ipa',
                  digest: `sha256:${fakeIpaSha}`,
                },
              ],
            },
          ]),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }

      if (url === 'https://api.github.com/repos/acme-sec/PrivateVault/releases/assets/1001') {
        expect(headers.get('accept')).toBe('application/octet-stream');
        return new Response(fakeApkBytes, {
          status: 200,
          headers: { 'Content-Type': 'application/vnd.android.package-archive' },
        });
      }

      return new Response('Not Found', { status: 404 });
    };

    const { inst } = createUpdateTestServer(
      {
        GITHUB_REPO: 'acme-sec/PrivateVault',
        GITHUB_TOKEN: 'ghp_secret_private_repo_token_do_not_leak',
        IOS_BUNDLE_ID: 'io.acme.privatevault',
      },
      mockUpstreamFetch,
    );

    // 1. Public config endpoint never leaks the raw GITHUB_TOKEN
    const cfgRes = await inst.app.request('https://vault.acme.internal/api/v1/updates/config');
    expect(cfgRes.status).toBe(200);
    const cfgJson = await cfgRes.json();
    expect(cfgJson.githubRepo).toBe('acme-sec/PrivateVault');
    expect(cfgJson.hasGithubTokenConfigured).toBe(true);
    expect(JSON.stringify(cfgJson)).not.toContain('ghp_secret_private_repo_token_do_not_leak');

    // 2. Android update check rewrites downloadUrl to the server proxy when GITHUB_TOKEN is set
    const checkAndroidRes = await inst.app.request(
      'https://vault.acme.internal/api/v1/updates/check?platform=android&current_version=0.4.0&current_build=400',
    );
    expect(checkAndroidRes.status).toBe(200);
    const checkAndroid = await checkAndroidRes.json();
    expect(checkAndroid.hasUpdate).toBe(true);
    expect(checkAndroid.latestVersion).toBe('0.5.0');
    expect(checkAndroid.asset.sha256).toBe(fakeApkSha);
    expect(checkAndroid.asset.downloadUrl).toContain(
      'https://vault.acme.internal/api/v1/updates/download/android',
    );

    // 3. Proxy binary download injects Bearer token upstream and exposes X-Content-SHA256
    const dlRes = await inst.app.request(checkAndroid.asset.downloadUrl);
    expect(dlRes.status).toBe(200);
    expect(dlRes.headers.get('x-content-sha256')).toBe(fakeApkSha);
    const downloadedBuf = Buffer.from(await dlRes.arrayBuffer());
    expect(downloadedBuf.equals(fakeApkBytes)).toBe(true);
    expect(observedAuthHeaders).toContain('Bearer ghp_secret_private_repo_token_do_not_leak');

    // 4. iOS update check synthesizes dynamic OTA manifest URL & itms-services:// install URL
    const checkIosRes = await inst.app.request(
      'https://vault.acme.internal/api/v1/updates/check?platform=ios&current_version=0.4.0&current_build=400',
    );
    expect(checkIosRes.status).toBe(200);
    const checkIos = await checkIosRes.json();
    expect(checkIos.hasUpdate).toBe(true);
    expect(checkIos.asset.itmsServicesUrl).toContain('itms-services://?action=download-manifest');

    const plistRes = await inst.app.request(checkIos.asset.otaManifestUrl);
    expect(plistRes.status).toBe(200);
    const plistXml = await plistRes.text();
    expect(plistXml).toContain('<string>io.acme.privatevault</string>');
    expect(plistXml).toContain('/api/v1/updates/download/ios');
  });

  it('supports air-gapped local release-manifest.json override and Mobile SDK dual-mode checks', async () => {
    const { dir, inst } = createUpdateTestServer();
    const releasesDir = path.join(dir, 'releases');
    fs.mkdirSync(releasesDir, { recursive: true });

    const localApk = Buffer.from('PK\x03\x04LOCAL_LAN_APK_V052');
    const localApkSha = crypto.createHash('sha256').update(localApk).digest('hex');
    fs.writeFileSync(path.join(releasesDir, 'PrivateSpace-Android-v0.5.2.apk'), localApk);

    const localManifest: ReleaseManifestDto = {
      schemaVersion: 1,
      repository: 'icaruszezen/PrivateSpaceSystem',
      tagName: 'v0.5.2',
      version: '0.5.2',
      buildNumber: 502,
      prerelease: false,
      publishedAt: '2026-11-14T12:00:00Z',
      releaseNotes: 'LAN offline self-hosted release package',
      android: {
        platform: 'android',
        version: '0.5.2',
        buildNumber: 502,
        fileName: 'PrivateSpace-Android-v0.5.2.apk',
        downloadUrl: '/api/v1/updates/download/android',
        sha256: localApkSha,
        fileSize: localApk.length,
        signingMode: 'release-signed',
      },
      ios: {
        platform: 'ios',
        version: '0.5.2',
        buildNumber: 502,
        fileName: 'PrivateSpace-iOS-v0.5.2.ipa',
        downloadUrl: 'https://vault.lan/releases/PrivateSpace-iOS-v0.5.2.ipa',
        sha256: 'c'.repeat(64),
        fileSize: 16_000_000,
        signingMode: 'adhoc-ota',
      },
    };
    fs.writeFileSync(
      path.join(releasesDir, 'release-manifest.json'),
      JSON.stringify(localManifest, null, 2),
    );

    const inProcessFetch: typeof fetch = async (input, init) => {
      const urlStr =
        typeof input === 'string'
          ? input
          : input instanceof URL
            ? input.toString()
            : input.url;
      if (urlStr.startsWith('https://api.github.com/repos/custom-fork/PrivateSpaceSystem/releases')) {
        return new Response(
          JSON.stringify([
            {
              tag_name: 'v0.7.0',
              name: 'Custom Fork v0.7.0',
              body: 'Direct GitHub custom repo check',
              draft: false,
              prerelease: false,
              published_at: '2026-11-14T12:30:00Z',
              html_url: 'https://github.com/custom-fork/PrivateSpaceSystem/releases/tag/v0.7.0',
              assets: [
                {
                  name: 'PrivateSpace-iOS-v0.7.0.ipa',
                  size: 19_000_000,
                  browser_download_url:
                    'https://github.com/custom-fork/PrivateSpaceSystem/releases/download/v0.7.0/PrivateSpace-iOS-v0.7.0.ipa',
                },
              ],
            },
          ]),
          { status: 200, headers: { 'Content-Type': 'application/json' } },
        );
      }
      const u = new URL(urlStr);
      return inst.app.request(`http://127.0.0.1:8080${u.pathname}${u.search}`, init);
    };

    const androidClient = new PrivateSpaceMobileClient({
      baseUrl: 'http://127.0.0.1:8080',
      platform: 'android',
      persistence: new InMemoryVaultPersistence(),
      fetchImpl: inProcessFetch,
    });

    const serverModeRes = await androidClient.checkAppUpdate({
      platform: 'android',
      currentVersion: '0.4.0',
      currentBuild: 400,
      sourceMode: 'server',
    });
    expect(serverModeRes.source).toBe('server-local-override');
    expect(serverModeRes.hasUpdate).toBe(true);
    expect(serverModeRes.latestVersion).toBe('0.5.2');
    expect(serverModeRes.asset?.sha256).toBe(localApkSha);

    const localDl = await inst.app.request('http://127.0.0.1:8080/api/v1/updates/download/android');
    expect(localDl.status).toBe(200);
    expect(localDl.headers.get('x-content-sha256')).toBe(localApkSha);
    expect(Buffer.from(await localDl.arrayBuffer()).equals(localApk)).toBe(true);

    const iosClient = new PrivateSpaceMobileClient({
      baseUrl: 'http://127.0.0.1:8080',
      platform: 'ios',
      persistence: new InMemoryVaultPersistence(),
      fetchImpl: inProcessFetch,
    });

    const githubDirectRes = await iosClient.checkAppUpdate({
      platform: 'ios',
      currentVersion: '0.4.0',
      currentBuild: 400,
      sourceMode: 'github',
      customGithubRepo: 'https://github.com/custom-fork/PrivateSpaceSystem',
    });
    expect(githubDirectRes.source).toBe('github-direct');
    expect(githubDirectRes.repository).toBe('custom-fork/PrivateSpaceSystem');
    expect(githubDirectRes.hasUpdate).toBe(true);
    expect(githubDirectRes.latestVersion).toBe('0.7.0');

    // Verify preference helper defaults cleanly in non-DOM test environment
    saveMobileUpdatePreferences(
      {
        autoCheckOnLaunch: true,
        sourceMode: 'github',
        customGithubRepo: 'custom-fork/PrivateSpaceSystem',
        channel: 'beta',
        skippedVersion: null,
        lastCheckedAt: null,
      },
      'pss_test_prefs',
    );
    const prefs = loadMobileUpdatePreferences('pss_test_prefs');
    expect(prefs.autoCheckOnLaunch).toBe(true);
  });
});
