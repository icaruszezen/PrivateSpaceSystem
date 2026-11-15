import React, { useMemo, useRef, useState } from 'react';
import {
  Activity,
  Calculator,
  Check,
  Copy,
  Delete,
  Moon,
  Radio,
  Sun,
} from 'lucide-react';
import { CURRENT_APP_BUILD, CURRENT_APP_VERSION } from '@shared/appUpdate';
import {
  evaluateSystemExpression,
  matchesDisguiseUnlockTrigger,
  recordRapidTap,
  type DisguisePreferences,
} from '@shared/disguise';
import { androidBridge, type NativeDeviceMetadata } from '../nativeBridge';

interface MobileDisguiseCoverProps {
  theme: 'light' | 'dark';
  prefs: DisguisePreferences;
  deviceMeta: NativeDeviceMetadata;
  defaultProbeUrl: string;
  onToggleTheme: () => void;
  onUnlockCover: () => void;
}

const MOBILE_PRESETS = [
  { label: '4 GiB', expr: '4 GiB' },
  { label: '0x1F40', expr: '0x1F40' },
  { label: '64 * 1024', expr: '64 * 1024' },
  { label: '256 MiB / 8', expr: '256 MiB / 8' },
];

export const MobilePssMark: React.FC<{ size?: number }> = ({ size = 20 }) => (
  <svg
    width={size}
    height={size}
    viewBox="0 0 24 24"
    fill="none"
    aria-hidden="true"
  >
    <rect x="4" y="3.5" width="4" height="17" rx="1.6" fill="currentColor" />
    <path
      d="M6.5 3.5H13.4C16.7 3.5 19.2 5.75 19.2 8.75C19.2 11.75 16.7 14 13.4 14H6.5V10.4H13.1C14.45 10.4 15.4 9.7 15.4 8.75C15.4 7.8 14.45 7.1 13.1 7.1H6.5V3.5Z"
      fill="currentColor"
    />
    <circle cx="17.2" cy="18.3" r="2.2" fill="#D28E36" />
  </svg>
);

export const MobileDisguiseCover: React.FC<MobileDisguiseCoverProps> = ({
  theme,
  prefs,
  deviceMeta,
  defaultProbeUrl,
  onToggleTheme,
  onUnlockCover,
}) => {
  const [tab, setTab] = useState<'calc' | 'probe'>('calc');
  const [expr, setExpr] = useState('4 GiB');
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const [probeInput, setProbeInput] = useState(
    defaultProbeUrl || (typeof window !== 'undefined' ? window.location.origin : 'https://127.0.0.1:8080'),
  );
  const [probing, setProbing] = useState(false);
  const [probeResult, setProbeResult] = useState<{
    ok: boolean;
    statusText: string;
    rttMs: number;
    checkedAt: string;
  } | null>(null);

  const tapTimestampsRef = useRef<number[]>([]);

  const evalRes = useMemo(() => evaluateSystemExpression(expr), [expr]);

  const handleCopy = async (key: string, val: string) => {
    try {
      await navigator.clipboard.writeText(val);
      androidBridge.haptic('light');
      setCopiedField(key);
      window.setTimeout(() => setCopiedField((prev) => (prev === key ? null : prev)), 1400);
    } catch {
      // ignore clipboard errors
    }
  };

  const handleEvaluateOrTrigger = () => {
    androidBridge.haptic('light');
    if (matchesDisguiseUnlockTrigger(expr, prefs)) {
      androidBridge.haptic('success');
      onUnlockCover();
      return;
    }
    if (evalRes.ok) {
      setExpr(evalRes.formattedDecimal.replace(/,/g, ''));
    }
  };

  const appendToken = (token: string) => {
    androidBridge.haptic('light');
    setExpr((prev) => (prev === '0' ? token : `${prev}${token}`));
  };

  const handleProbe = async (e?: React.FormEvent) => {
    e?.preventDefault();
    if (matchesDisguiseUnlockTrigger(probeInput, prefs)) {
      androidBridge.haptic('success');
      onUnlockCover();
      return;
    }

    const raw = probeInput.trim();
    if (!raw) return;

    setProbing(true);
    const t0 = performance.now();
    try {
      const normalized = /^https?:\/\//i.test(raw) ? raw : `http://${raw}`;
      const target = `${normalized.replace(/\/+$/, '')}/api/v1/health`;
      const resp = await fetch(target, { method: 'GET', cache: 'no-store' });
      const rttMs = Math.max(1, Math.round(performance.now() - t0));
      setProbeResult({
        ok: resp.ok,
        statusText: `HTTP ${resp.status}`,
        rttMs,
        checkedAt: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
      });
    } catch {
      const rttMs = Math.max(1, Math.round(performance.now() - t0));
      setProbeResult({
        ok: false,
        statusText: '连接超时或跨域受限',
        rttMs,
        checkedAt: new Date().toLocaleTimeString('zh-CN', { hour12: false }),
      });
    } finally {
      setProbing(false);
    }
  };

  const handleVersionBadgeTap = () => {
    if (!prefs.gestureUnlockEnabled) return;
    const res = recordRapidTap(tapTimestampsRef.current, Date.now());
    tapTimestampsRef.current = res.nextTimestamps;
    if (res.triggered) {
      androidBridge.haptic('success');
      onUnlockCover();
    }
  };

  return (
    <div className="m-app-shell m-cover-shell" data-testid="mobile-pss-disguise-cover">
      <header className="m-topbar">
        <div className="m-topbar-brand">
          <div className="m-brand-mark">
            <MobilePssMark size={19} />
          </div>
          <div className="m-topbar-titles">
            <h1 className="m-topbar-title">PSS</h1>
            <div className="m-sync-status">
              <span className="m-sync-dot is-live" />
              <span className="mono">Personal System Service</span>
            </div>
          </div>
        </div>
        <div className="m-topbar-actions">
          <button
            id="m-cover-theme-btn"
            type="button"
            className="m-icon-btn"
            onClick={onToggleTheme}
            aria-label="切换深浅色主题"
          >
            {theme === 'dark' ? <Sun size={17} /> : <Moon size={17} />}
          </button>
        </div>
      </header>

      <div className="m-cover-tabs-wrap">
        <div className="m-seg-row">
          <button
            id="m-cover-tab-calc"
            type="button"
            className={`m-seg-btn ${tab === 'calc' ? 'is-active' : ''}`}
            onClick={() => setTab('calc')}
          >
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <Calculator size={13} />
              <span>数值与字节换算</span>
            </span>
          </button>
          <button
            id="m-cover-tab-probe"
            type="button"
            className={`m-seg-btn ${tab === 'probe' ? 'is-active' : ''}`}
            onClick={() => setTab('probe')}
          >
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <Radio size={13} />
              <span>节点延迟探测</span>
            </span>
          </button>
        </div>
      </div>

      <main className="m-viewport m-cover-body">
        {tab === 'calc' ? (
          <>
            <section className="m-card m-cover-display-card">
              <div className="m-cover-expr-row">
                <input
                  id="m-cover-expr-input"
                  type="text"
                  className="m-cover-expr-input mono"
                  value={expr}
                  onChange={(e) => setExpr(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      handleEvaluateOrTrigger();
                    }
                  }}
                  placeholder="输入算式、0x十六进制或 MiB/GiB"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                />
                {expr && (
                  <button
                    type="button"
                    className="m-icon-btn"
                    style={{ width: 32, height: 32 }}
                    onClick={() => setExpr((prev) => prev.slice(0, -1))}
                    aria-label="退格"
                  >
                    <Delete size={16} />
                  </button>
                )}
              </div>

              <div className="m-cover-main-result mono" id="m-cover-main-result">
                {evalRes.ok ? evalRes.formattedDecimal : evalRes.error || '—'}
              </div>

              <div className="m-cover-radix-list">
                <div className="m-cover-radix-item">
                  <span className="m-cover-radix-tag mono">HEX</span>
                  <span className="m-cover-radix-val mono">
                    {evalRes.ok ? evalRes.hexValue : '—'}
                  </span>
                  {evalRes.ok && evalRes.hexValue !== '—' && (
                    <button
                      type="button"
                      className="m-cover-copy-mini"
                      onClick={() => void handleCopy('hex', evalRes.hexValue)}
                      aria-label="复制 HEX"
                    >
                      {copiedField === 'hex' ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                  )}
                </div>
                <div className="m-cover-radix-item">
                  <span className="m-cover-radix-tag mono">IEC</span>
                  <span className="m-cover-radix-val mono">
                    {evalRes.ok ? evalRes.byteHuman : '—'}
                  </span>
                  {evalRes.ok && evalRes.byteHuman !== '—' && (
                    <button
                      type="button"
                      className="m-cover-copy-mini"
                      onClick={() => void handleCopy('iec', evalRes.byteHuman)}
                      aria-label="复制字节换算"
                    >
                      {copiedField === 'iec' ? <Check size={12} /> : <Copy size={12} />}
                    </button>
                  )}
                </div>
              </div>

              <div className="m-cover-presets">
                {MOBILE_PRESETS.map((p) => (
                  <button
                    key={p.label}
                    type="button"
                    className="m-cover-chip mono"
                    onClick={() => setExpr(p.expr)}
                  >
                    {p.label}
                  </button>
                ))}
              </div>
            </section>

            <section className="m-cover-keypad" aria-label="系统换算键盘">
              <button type="button" className="m-cover-key is-fn" onClick={() => setExpr('')}>
                AC
              </button>
              <button type="button" className="m-cover-key is-fn mono" onClick={() => appendToken('0x')}>
                0x
              </button>
              <button type="button" className="m-cover-key is-fn mono" onClick={() => appendToken(' MiB')}>
                MiB
              </button>
              <button type="button" className="m-cover-key is-op mono" onClick={() => appendToken(' / ')}>
                ÷
              </button>

              <button type="button" className="m-cover-key mono" onClick={() => appendToken('7')}>
                7
              </button>
              <button type="button" className="m-cover-key mono" onClick={() => appendToken('8')}>
                8
              </button>
              <button type="button" className="m-cover-key mono" onClick={() => appendToken('9')}>
                9
              </button>
              <button type="button" className="m-cover-key is-op mono" onClick={() => appendToken(' * ')}>
                ×
              </button>

              <button type="button" className="m-cover-key mono" onClick={() => appendToken('4')}>
                4
              </button>
              <button type="button" className="m-cover-key mono" onClick={() => appendToken('5')}>
                5
              </button>
              <button type="button" className="m-cover-key mono" onClick={() => appendToken('6')}>
                6
              </button>
              <button type="button" className="m-cover-key is-op mono" onClick={() => appendToken(' - ')}>
                −
              </button>

              <button type="button" className="m-cover-key mono" onClick={() => appendToken('1')}>
                1
              </button>
              <button type="button" className="m-cover-key mono" onClick={() => appendToken('2')}>
                2
              </button>
              <button type="button" className="m-cover-key mono" onClick={() => appendToken('3')}>
                3
              </button>
              <button type="button" className="m-cover-key is-op mono" onClick={() => appendToken(' + ')}>
                +
              </button>

              <button type="button" className="m-cover-key is-fn mono" onClick={() => appendToken(' GiB')}>
                GiB
              </button>
              <button type="button" className="m-cover-key mono" onClick={() => appendToken('0')}>
                0
              </button>
              <button type="button" className="m-cover-key mono" onClick={() => appendToken('.')}>
                .
              </button>
              <button
                id="m-cover-eval-btn"
                type="button"
                className="m-cover-key is-eq mono"
                onClick={handleEvaluateOrTrigger}
              >
                =
              </button>
            </section>
          </>
        ) : (
          <>
            <section className="m-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
                <Radio size={15} style={{ color: 'var(--m-accent)' }} />
                <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>HTTP 端点连通性与 RTT 探测</span>
              </div>
              <form onSubmit={(e) => void handleProbe(e)} className="m-input-group">
                <input
                  id="m-cover-probe-input"
                  type="text"
                  className="m-input mono"
                  style={{ fontSize: '0.82rem' }}
                  value={probeInput}
                  onChange={(e) => setProbeInput(e.target.value)}
                  placeholder="https://example.com 或节点地址"
                  autoCapitalize="none"
                  autoCorrect="off"
                />
                <button
                  id="m-cover-probe-btn"
                  type="submit"
                  className="m-btn m-btn-primary"
                  style={{ flexShrink: 0 }}
                  disabled={probing}
                >
                  <span>{probing ? '探测中' : '探测'}</span>
                </button>
              </form>

              {probeResult && (
                <div className="m-probe-box" style={{ marginTop: 12, marginBottom: 0 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontWeight: 700 }}>
                    <span style={{ color: probeResult.ok ? 'var(--m-accent)' : 'var(--m-amber)' }}>
                      {probeResult.statusText}
                    </span>
                    <span className="mono">{probeResult.rttMs} ms</span>
                  </div>
                  <div
                    className="mono"
                    style={{ fontSize: '0.7rem', color: 'var(--m-text-tertiary)', marginTop: 4 }}
                  >
                    采样时间：{probeResult.checkedAt}
                  </div>
                </div>
              )}
            </section>

            <section className="m-card">
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
                <Activity size={15} style={{ color: 'var(--m-accent)' }} />
                <span style={{ fontWeight: 700, fontSize: '0.9rem' }}>本机运行环境诊断</span>
              </div>
              <div className="m-kv-row">
                <span className="m-kv-key">终端型号标识</span>
                <span className="m-kv-val">{deviceMeta.deviceName}</span>
              </div>
              <div className="m-kv-row">
                <span className="m-kv-key">运行容器</span>
                <span className="m-kv-val">
                  {deviceMeta.isNativeAndroid ? `Android SDK ${deviceMeta.sdkInt}` : 'Mobile Web Runtime'}
                </span>
              </div>
              <div className="m-kv-row">
                <span className="m-kv-key">网络状态</span>
                <span className="m-kv-val">
                  {typeof navigator !== 'undefined' && navigator.onLine ? 'ONLINE' : 'OFFLINE'}
                </span>
              </div>
              <div className="m-kv-row">
                <span className="m-kv-key">本地时区</span>
                <span className="m-kv-val">
                  {Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC'}
                </span>
              </div>
            </section>
          </>
        )}

        <footer className="m-cover-footer">
          <button
            id="m-cover-version-badge"
            type="button"
            className="m-cover-version-btn mono"
            onClick={handleVersionBadgeTap}
          >
            PSS Core v{deviceMeta.appVersionName || CURRENT_APP_VERSION} (
            {deviceMeta.appVersionCode || CURRENT_APP_BUILD})
          </button>
        </footer>
      </main>
    </div>
  );
};
