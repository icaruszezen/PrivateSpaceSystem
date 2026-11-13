import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import PrivateSpaceMobileApp from '@mobile/App';
import type { IosColorMode } from '@mobile/src/iosTheme';
import './styles/ios-shell.css';

type StudioDevice = 'iphone' | 'ipad' | 'fullscreen';

function detectInitialDeviceMode(): StudioDevice {
  try {
    const params = new URLSearchParams(window.location.search);
    const forced = params.get('device');
    if (forced === 'fullscreen' || forced === 'ipad' || forced === 'iphone') {
      return forced;
    }
    const isStandalone =
      window.matchMedia?.('(display-mode: standalone)').matches ||
      Boolean((navigator as Navigator & { standalone?: boolean }).standalone);
    const isPhoneViewport = window.innerWidth <= 560;
    if (isStandalone || isPhoneViewport) {
      return 'fullscreen';
    }
  } catch {
    // ignore
  }
  return 'iphone';
}

function formatClock(): string {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function IosStandaloneHost(): React.JSX.Element {
  const [deviceMode, setDeviceMode] = useState<StudioDevice>(detectInitialDeviceMode);
  const [themeMode, setThemeMode] = useState<IosColorMode>(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get('theme') === 'dark') return 'dark';
    return 'light';
  });
  const [clockText, setClockText] = useState<string>(formatClock);

  useEffect(() => {
    document.documentElement.setAttribute('data-ios-theme', themeMode);
  }, [themeMode]);

  useEffect(() => {
    const id = setInterval(() => setClockText(formatClock()), 15000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    const onResize = () => {
      if (window.innerWidth <= 560) {
        setDeviceMode('fullscreen');
      }
    };
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  if (deviceMode === 'fullscreen') {
    return (
      <div className="ios-native-fullscreen">
        <PrivateSpaceMobileApp
          externalThemeMode={themeMode}
          onThemeModeChange={setThemeMode}
          deviceName="iPhone 16 Pro (Safari PWA)"
        />
      </div>
    );
  }

  return (
    <div className="ios-studio-layout">
      <aside className="ios-studio-sidebar" aria-label="iOS 客户端架构说明">
        <span className="ios-studio-kicker">APPLE iOS 17+ SWIFTUI + STANDALONE PWA</span>
        <h1 className="ios-studio-title">PrivateSpace iOS 移动加密空间</h1>
        <p className="ios-studio-desc">
          在 iPhone Safari 访问 <code>/ios</code> 并「添加到主屏幕」即可开启全屏原生应用体验；或使用仓库{' '}
          <code>ios/</code> 目录下的纯原生 SwiftUI + AutoFill 工程编译安装至真机。
        </p>

        <div className="ios-studio-panel">
          <div className="ios-studio-panel-title">
            <span>视口设备形态切换</span>
            <button
              type="button"
              onClick={() => setThemeMode((t) => (t === 'light' ? 'dark' : 'light'))}
              style={{
                border: 'none',
                background: 'transparent',
                color: 'var(--ios-studio-accent)',
                fontWeight: 700,
                fontSize: '12px',
                cursor: 'pointer',
              }}
              data-testid="studio-toggle-theme"
            >
              {themeMode === 'light' ? '切换深色暗房' : '切换浅色纸感'}
            </button>
          </div>
          <div className="ios-device-Seg">
            <button
              type="button"
              className={`ios-device-btn ${deviceMode === 'iphone' ? 'is-active' : ''}`}
              onClick={() => setDeviceMode('iphone')}
            >
              iPhone 16 Pro
            </button>
            <button
              type="button"
              className={`ios-device-btn ${deviceMode === 'ipad' ? 'is-active' : ''}`}
              onClick={() => setDeviceMode('ipad')}
            >
              iPad Mini
            </button>
            <button
              type="button"
              className="ios-device-btn"
              onClick={() => setDeviceMode('fullscreen')}
            >
              沉浸全屏
            </button>
          </div>
        </div>

        <div className="ios-studio-panel">
          <div className="ios-studio-panel-title">
            <span>原生 iOS 工程能力矩阵</span>
          </div>
          <ul className="ios-arch-list">
            <li>
              <strong>PrivateSpaceKit (Swift 6)</strong>：<code>CryptoKit</code> 本机{' '}
              <code>PSCACHE1</code> <code>AES-256-GCM</code> 二次加密缓存与 Keychain 令牌隔离。
            </li>
            <li>
              <strong>系统级密码自动填充</strong>：内置{' '}
              <code>ASCredentialProviderViewController</code> 扩展与{' '}
              <code>/.well-known/apple-app-site-association</code> 域名关联。
            </li>
            <li>
              <strong>流式影院与断点续传</strong>：<code>512 KiB</code> 分片 +{' '}
              <code>SHA-256</code> 完整性校验，配合 <code>AVURLAsset</code> HTTP <code>206</code>{' '}
              随机分块解密流。
            </li>
            <li>
              <strong>面容 ID 与多任务遮罩</strong>：<code>LocalAuthentication</code> 生物识别解锁与后台切换自动高斯遮蔽。
            </li>
          </ul>
        </div>

        <div className="ios-studio-links">
          <a className="ios-studio-link" href="/">
            ← 返回桌面端私密工作台
          </a>
          <a
            className="ios-studio-link"
            href="/.well-known/apple-app-site-association"
            target="_blank"
            rel="noreferrer"
          >
            查看 Apple AASA 凭证配置 ↗
          </a>
        </div>
      </aside>

      <main className="ios-stage-center">
        <div
          className={`ios-bezel-frame ${deviceMode === 'ipad' ? 'is-ipad' : ''}`}
          data-testid="ios-device-frame"
        >
          <div className="ios-screen-inner">
            <div className="ios-statusbar" aria-hidden="true">
              <span>{clockText}</span>
              {deviceMode === 'iphone' && (
                <div className="ios-dynamic-island">
                  <span className="ios-island-lens" />
                </div>
              )}
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: '5px', fontSize: '11px' }}>
                <span>5G</span>
                <span>100%</span>
              </span>
            </div>

            <div className="ios-app-viewport">
              <PrivateSpaceMobileApp
                externalThemeMode={themeMode}
                onThemeModeChange={setThemeMode}
                deviceName={
                  deviceMode === 'ipad' ? 'iPad Mini (iPadOS 18)' : 'iPhone 16 Pro (iOS 18)'
                }
              />
            </div>

            <div className="ios-home-indicator-bar" aria-hidden="true">
              <span className="ios-home-pill" />
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

const container = document.getElementById('ios-root');
if (container) {
  createRoot(container).render(
    <React.StrictMode>
      <IosStandaloneHost />
    </React.StrictMode>,
  );
}
