import React, { useEffect, useState } from 'react';
import {
  CheckCircle2,
  ClipboardPaste,
  Eye,
  EyeOff,
  Lock,
  Moon,
  RefreshCw,
  Server,
  ShieldCheck,
  Smartphone,
  Sun,
  WifiOff,
} from 'lucide-react';
import { evaluatePasswordEntropy } from '@shared/passwordGenerator';
import type { AuthStatusResponse } from '@shared/types';
import {
  normalizeServerUrl,
  parsePairingInput,
  type PrivateSpaceMobileClient,
} from '../syncClient';

interface MobileAuthScreenProps {
  client: PrivateSpaceMobileClient;
  initialServerUrl: string;
  deviceName: string;
  hasOfflineCache: boolean;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  onAuthenticated: (params: {
    serverUrl: string;
    vaultName: string;
    keyFingerprint: string;
    quickPin?: string;
  }) => Promise<void>;
  onEnterOfflineMode: () => void;
  onNotify: (msg: string) => void;
}

export const MobileAuthScreen: React.FC<MobileAuthScreenProps> = ({
  client,
  initialServerUrl,
  deviceName,
  hasOfflineCache,
  theme,
  onToggleTheme,
  onAuthenticated,
  onEnterOfflineMode,
  onNotify,
}) => {
  const [serverInput, setServerInput] = useState(initialServerUrl);
  const [probing, setProbing] = useState(false);
  const [probeStatus, setProbeStatus] = useState<AuthStatusResponse | null>(null);
  const [probeError, setProbeError] = useState<string | null>(null);

  const [vaultNameInput, setVaultNameInput] = useState('PrivateSpace');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [enableQuickPin, setEnableQuickPin] = useState(false);
  const [quickPinInput, setQuickPinInput] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const probeEndpoint = async (rawUrl: string) => {
    const clean = normalizeServerUrl(rawUrl);
    if (!clean) {
      setProbeStatus(null);
      setProbeError('请输入有效的自部署服务器地址');
      return;
    }
    setProbing(true);
    setProbeError(null);
    try {
      client.setBaseUrl(clean);
      const status = await client.getAuthStatus();
      setProbeStatus(status);
      if (status.vaultName) {
        setVaultNameInput(status.vaultName);
      }
    } catch (err) {
      setProbeStatus(null);
      setProbeError(err instanceof Error ? err.message : '无法连接节点');
    } finally {
      setProbing(false);
    }
  };

  useEffect(() => {
    if (initialServerUrl) {
      void probeEndpoint(initialServerUrl);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handlePastePairing = async () => {
    try {
      const clipText = await navigator.clipboard.readText();
      const parsed = parsePairingInput(clipText);
      if (!parsed) {
        onNotify('剪贴板中未检测到有效的配对码或服务器地址');
        return;
      }
      setServerInput(parsed.serverUrl);
      if (parsed.vaultName) setVaultNameInput(parsed.vaultName);
      onNotify('已识别配对节点，正在探测加密状态...');
      await probeEndpoint(parsed.serverUrl);
    } catch {
      onNotify('请长按输入框直接粘贴配对地址');
    }
  };

  const isSetupMode = probeStatus ? !probeStatus.initialized : false;
  const pwdEntropy = evaluatePasswordEntropy(password);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError(null);

    const parsedInput = parsePairingInput(serverInput);
    const normalizedUrl = parsedInput?.serverUrl || normalizeServerUrl(serverInput);
    if (!normalizedUrl) {
      setFormError('请先填写自部署服务器地址');
      return;
    }

    if (password.length < 8) {
      setFormError('唯一管理员主密码长度至少需要 8 位字符');
      return;
    }

    if (isSetupMode && password !== confirmPassword) {
      setFormError('两次输入的管理员主密码不一致');
      return;
    }

    if (enableQuickPin && !/^\d{6}$/.test(quickPinInput)) {
      setFormError('快捷解锁 PIN 码需为 6 位数字');
      return;
    }

    setSubmitting(true);
    try {
      client.setBaseUrl(normalizedUrl);
      const session = isSetupMode
        ? await client.setupAdmin({
            password,
            vaultName: vaultNameInput.trim() || 'PrivateSpace',
          })
        : await client.login(password);

      setPassword('');
      setConfirmPassword('');
      await onAuthenticated({
        serverUrl: normalizedUrl,
        vaultName: session.vaultName,
        keyFingerprint: session.keyFingerprint,
        quickPin: enableQuickPin ? quickPinInput : undefined,
      });
    } catch (err) {
      setFormError(err instanceof Error ? err.message : '认证失败，请检查网络或密码');
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="m-app-shell">
      <div className="m-auth-screen">
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span className="m-crypto-badge">
              <ShieldCheck size={13} />
              <span>AES-256-GCM · Android 安全空间</span>
            </span>
            <button
              id="m-auth-theme-toggle"
              type="button"
              className="m-icon-btn"
              onClick={onToggleTheme}
              aria-label="切换深浅色外观"
            >
              {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
            </button>
          </div>

          <div className="m-auth-hero">
            <h1 className="m-auth-title">
              {isSetupMode ? '初始化私密空间' : 'PrivateSpace 手机端'}
            </h1>
            <p className="m-auth-sub">
              自部署、静态零明文存储的密码 (2FA)、原图相册、流式视频与 Markdown 笔记多端同步客户端。
            </p>
          </div>

          <form onSubmit={handleSubmit} className="m-card" style={{ padding: 16 }}>
            <div className="m-field">
              <label htmlFor="m-server-url-input" className="m-label">
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                  <Server size={13} />
                  <span>自部署服务器节点地址</span>
                </span>
                <button
                  id="m-paste-pair-btn"
                  type="button"
                  onClick={() => void handlePastePairing()}
                  style={{
                    border: 'none',
                    background: 'transparent',
                    color: 'var(--m-accent)',
                    fontWeight: 700,
                    fontSize: '0.75rem',
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: 4,
                    cursor: 'pointer',
                    padding: 0,
                  }}
                >
                  <ClipboardPaste size={12} />
                  <span>粘贴配对码</span>
                </button>
              </label>
              <div className="m-input-group">
                <input
                  id="m-server-url-input"
                  type="text"
                  className="m-input mono"
                  style={{ fontSize: '0.84rem' }}
                  value={serverInput}
                  onChange={(e) => {
                    const v = e.target.value;
                    const maybePair = v.startsWith('privatespace://') ? parsePairingInput(v) : null;
                    if (maybePair) {
                      setServerInput(maybePair.serverUrl);
                      if (maybePair.vaultName) setVaultNameInput(maybePair.vaultName);
                      void probeEndpoint(maybePair.serverUrl);
                    } else {
                      setServerInput(v);
                    }
                  }}
                  placeholder="https://vault.yourdomain.com 或 192.168.1.10:8080"
                  autoCapitalize="none"
                  autoCorrect="off"
                />
                <button
                  id="m-probe-server-btn"
                  type="button"
                  className="m-btn m-btn-soft"
                  style={{ padding: '0 12px', flexShrink: 0 }}
                  onClick={() => void probeEndpoint(serverInput)}
                  disabled={probing}
                >
                  <RefreshCw size={15} />
                  <span>{probing ? '探测中' : '检测'}</span>
                </button>
              </div>
            </div>

            {probeStatus && (
              <div className="m-probe-box">
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    fontWeight: 700,
                    color: 'var(--m-accent)',
                  }}
                >
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                    <CheckCircle2 size={14} />
                    <span>
                      {probeStatus.initialized
                        ? `节点在线 · ${probeStatus.vaultName}`
                        : '节点在线 · 待首次初始化管理员'}
                    </span>
                  </span>
                  <span className="mono" style={{ fontSize: '0.7rem' }}>
                    {probeStatus.encryption.cipher}
                  </span>
                </div>
                {probeStatus.keyFingerprint && (
                  <div
                    className="mono"
                    style={{
                      fontSize: '0.7rem',
                      color: 'var(--m-text-tertiary)',
                      marginTop: 4,
                    }}
                  >
                    主密钥指纹: {probeStatus.keyFingerprint}
                  </div>
                )}
              </div>
            )}

            {probeError && (
              <div className="m-error-box">
                <div>{probeError}</div>
                {hasOfflineCache && (
                  <button
                    id="m-enter-offline-btn"
                    type="button"
                    className="m-btn m-btn-sm"
                    style={{ marginTop: 8, width: '100%' }}
                    onClick={onEnterOfflineMode}
                  >
                    <WifiOff size={14} />
                    <span>进入本机离线加密缓存模式</span>
                  </button>
                )}
              </div>
            )}

            {isSetupMode && (
              <div className="m-field">
                <label htmlFor="m-setup-vault-name" className="m-label">
                  <span>私密空间名称</span>
                </label>
                <input
                  id="m-setup-vault-name"
                  type="text"
                  className="m-input"
                  value={vaultNameInput}
                  maxLength={48}
                  onChange={(e) => setVaultNameInput(e.target.value)}
                  placeholder="例如：个人数字保险箱"
                />
              </div>
            )}

            <div className="m-field">
              <label htmlFor="m-master-password-input" className="m-label">
                <span>{isSetupMode ? '创建唯一管理员主密码 (≥8位)' : '唯一管理员主密码'}</span>
                {isSetupMode && password && (
                  <span className="mono" style={{ color: 'var(--m-accent)' }}>
                    {pwdEntropy.label} · {pwdEntropy.entropyBits}b
                  </span>
                )}
              </label>
              <div style={{ position: 'relative' }}>
                <input
                  id="m-master-password-input"
                  type={showPassword ? 'text' : 'password'}
                  className="m-input"
                  style={{ paddingRight: 42 }}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="输入主密码解封 256-bit DEK 信封"
                  autoComplete={isSetupMode ? 'new-password' : 'current-password'}
                />
                <button
                  type="button"
                  className="m-icon-btn"
                  style={{ position: 'absolute', right: 3, top: 3 }}
                  onClick={() => setShowPassword((v) => !v)}
                  aria-label="切换密码可见性"
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {isSetupMode && (
              <div className="m-field">
                <label htmlFor="m-confirm-password-input" className="m-label">
                  <span>确认管理员主密码</span>
                </label>
                <input
                  id="m-confirm-password-input"
                  type={showPassword ? 'text' : 'password'}
                  className="m-input"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="再次输入主密码防止误输"
                  autoComplete="new-password"
                />
              </div>
            )}

            <div
              style={{
                padding: '10px 12px',
                borderRadius: 10,
                background: 'var(--m-bg-muted)',
                border: '1px solid var(--m-border)',
                marginBottom: 14,
              }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                }}
              >
                <span style={{ fontSize: '0.8rem', fontWeight: 600 }}>
                  设置本机 6 位快捷 PIN 解锁
                </span>
                <button
                  id="m-auth-pin-toggle"
                  type="button"
                  className={`m-toggle ${enableQuickPin ? 'is-on' : ''}`}
                  onClick={() => setEnableQuickPin((v) => !v)}
                  aria-label="启用本机快捷 PIN 解锁"
                />
              </div>
              {enableQuickPin && (
                <div style={{ marginTop: 10 }}>
                  <input
                    id="m-auth-pin-input"
                    type="password"
                    inputMode="numeric"
                    maxLength={6}
                    className="m-input mono"
                    value={quickPinInput}
                    onChange={(e) => setQuickPinInput(e.target.value.replace(/\D/g, '').slice(0, 6))}
                    placeholder="输入 6 位数字 PIN (存入 Android Keystore)"
                  />
                </div>
              )}
            </div>

            {formError && <div className="m-error-box">{formError}</div>}

            <button
              id="m-auth-submit-btn"
              type="submit"
              className="m-btn m-btn-primary m-btn-block"
              disabled={submitting}
            >
              <Lock size={16} />
              <span>
                {submitting
                  ? '正在解封密钥并增量同步...'
                  : isSetupMode
                    ? '初始化并解锁空间'
                    : '解锁并同步私密空间'}
              </span>
            </button>
          </form>
        </div>

        <div
          style={{
            textAlign: 'center',
            fontSize: '0.74rem',
            color: 'var(--m-text-tertiary)',
            marginTop: 14,
          }}
        >
          <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            <Smartphone size={13} />
            <span>当前设备标识：{deviceName}</span>
          </div>
          <div style={{ marginTop: 3 }}>
            端到端零知识加密 (E2EE v2) · PBKDF2-SHA256 + HKDF · PSENC001 流媒体
          </div>
        </div>
      </div>
    </div>
  );
};
