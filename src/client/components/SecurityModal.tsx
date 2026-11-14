import React, { useEffect, useState } from 'react';
import { Copy, KeyRound, Laptop, ShieldCheck, Smartphone, Trash2, X } from 'lucide-react';
import type {
  CipherEnvelopeInspection,
  SessionInfo,
  VaultSecuritySummary,
} from '@shared/types';
import { api } from '../api/client';
import {
  evaluatePasswordStrength,
  formatBytes,
  formatFullDateTime,
} from '../utils/format';

export type SecurityTab = 'cipher' | 'password' | 'sessions';

interface SecurityModalProps {
  open: boolean;
  initialTab: SecurityTab;
  inspectItemId: string | null;
  vaultName: string;
  onClose: () => void;
  onVaultNameUpdated: (newName: string) => void;
  onNotify: (msg: string) => void;
}

export const SecurityModal: React.FC<SecurityModalProps> = ({
  open,
  initialTab,
  inspectItemId,
  vaultName,
  onClose,
  onVaultNameUpdated,
  onNotify,
}) => {
  const [tab, setTab] = useState<SecurityTab>(initialTab);
  const [summary, setSummary] = useState<VaultSecuritySummary | null>(null);
  const [envelope, setEnvelope] = useState<CipherEnvelopeInspection | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(false);

  // Vault name edit
  const [nameInput, setNameInput] = useState(vaultName);

  // Password change state
  const [currentPassword, setCurrentPassword] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [revokeOthers, setRevokeOthers] = useState(true);
  const [pwdSubmitting, setPwdSubmitting] = useState(false);
  const [pwdError, setPwdError] = useState<string | null>(null);

  useEffect(() => {
    if (open) {
      setTab(initialTab);
      setNameInput(vaultName);
      setPwdError(null);
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
    }
  }, [open, initialTab, vaultName]);

  useEffect(() => {
    if (!open) return;
    let cancelled = false;
    setLoading(true);

    async function load() {
      try {
        const [sec, sess] = await Promise.all([
          api.getSecuritySummary(),
          api.listSessions(),
        ]);
        if (cancelled) return;
        setSummary(sec);
        setSessions(sess.sessions);

        if (inspectItemId) {
          const envRes = await api.inspectItemCipher(inspectItemId).catch(() => null);
          if (!cancelled) {
            setEnvelope(envRes?.envelope ?? null);
          }
        } else {
          setEnvelope(null);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, [open, inspectItemId]);

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const strength = evaluatePasswordStrength(newPassword);
  const serverEndpoint =
    typeof window !== 'undefined' ? window.location.origin : 'http://127.0.0.1:8080';

  async function handleSaveVaultName(e: React.FormEvent) {
    e.preventDefault();
    if (!nameInput.trim()) return;
    const res = await api.updateVaultName(nameInput.trim());
    onVaultNameUpdated(res.vaultName);
    onNotify('空间名称已更新');
  }

  async function handleRotatePassword(e: React.FormEvent) {
    e.preventDefault();
    setPwdError(null);

    if (newPassword.length < 8) {
      setPwdError('新管理员主密码长度至少需要 8 位字符');
      return;
    }
    if (newPassword !== confirmPassword) {
      setPwdError('两次输入的新密码不一致');
      return;
    }

    setPwdSubmitting(true);
    try {
      await api.changePassword({
        currentPassword,
        newPassword,
        revokeOtherSessions: revokeOthers,
      });
      setCurrentPassword('');
      setNewPassword('');
      setConfirmPassword('');
      onNotify('管理员主密码已轮换，主密钥信封已完成重新加密');
      const sess = await api.listSessions();
      setSessions(sess.sessions);
    } catch (err) {
      setPwdError(err instanceof Error ? err.message : '修改密码失败');
    } finally {
      setPwdSubmitting(false);
    }
  }

  async function handleRevokeSession(sessionId: string) {
    await api.revokeSession(sessionId);
    setSessions((prev) => prev.filter((s) => s.id !== sessionId));
    onNotify('设备会话已吊销');
  }

  return (
    <div
      className="modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="modal-dialog"
        style={{ maxWidth: 660 }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="security-modal-title"
      >
        <header className="modal-header">
          <div className="modal-title-wrap">
            <ShieldCheck size={19} style={{ color: 'var(--accent)' }} />
            <h2 id="security-modal-title" className="modal-title">
              安全中心、加密透视与多端同步 (Web · Android · iOS)
            </h2>
          </div>
          <button
            type="button"
            className="btn-icon"
            onClick={onClose}
            aria-label="关闭弹窗"
          >
            <X size={17} />
          </button>
        </header>

        <div className="modal-tabs" role="tablist">
          <button
            id="sec-tab-cipher"
            type="button"
            role="tab"
            aria-selected={tab === 'cipher'}
            className={`modal-tab ${tab === 'cipher' ? 'is-active' : ''}`}
            onClick={() => setTab('cipher')}
          >
            <ShieldCheck size={14} />
            <span>密文存储透视</span>
          </button>
          <button
            id="sec-tab-sessions"
            type="button"
            role="tab"
            aria-selected={tab === 'sessions'}
            className={`modal-tab ${tab === 'sessions' ? 'is-active' : ''}`}
            onClick={() => setTab('sessions')}
          >
            <Laptop size={14} />
            <span>多端同步与设备 ({sessions.length})</span>
          </button>
          <button
            id="sec-tab-password"
            type="button"
            role="tab"
            aria-selected={tab === 'password'}
            className={`modal-tab ${tab === 'password' ? 'is-active' : ''}`}
            onClick={() => setTab('password')}
          >
            <KeyRound size={14} />
            <span>管理员密码与设置</span>
          </button>
        </div>

        <div className="modal-body">
          {tab === 'cipher' && (
            <>
              <div className="sec-stat-grid">
                <div className="sec-stat-card">
                  <div className="sec-stat-label">零知识架构 / 媒体分块</div>
                  <div className="sec-stat-value">E2EE v2 · AES-256-GCM · PSENC001</div>
                </div>
                <div className="sec-stat-card">
                  <div className="sec-stat-label">主密钥指纹 (HMAC)</div>
                  <div className="sec-stat-value mono">
                    {summary?.keyFingerprint ?? '—'}
                  </div>
                </div>
                <div className="sec-stat-card">
                  <div className="sec-stat-label">总密文占用 / 同步游标</div>
                  <div className="sec-stat-value mono">
                    {summary
                      ? `${formatBytes(summary.totalEncryptedBytes)} · #${summary.latestSyncSeq}`
                      : loading
                        ? '读取中...'
                        : '0 B'}
                  </div>
                </div>
              </div>

              {summary && (
                <div className="pss-breakdown-grid">
                  <div className="pss-breakdown-card">
                    <span>私密密码</span>
                    <strong>{summary.activePasswords} 条</strong>
                    <small className="mono">{formatBytes(summary.passwordsEncryptedBytes)}</small>
                  </div>
                  <div className="pss-breakdown-card">
                    <span>加密图片</span>
                    <strong>{summary.activeImages} 张</strong>
                    <small className="mono">{formatBytes(summary.imagesEncryptedBytes)}</small>
                  </div>
                  <div className="pss-breakdown-card">
                    <span>流式视频</span>
                    <strong>{summary.activeVideos} 部</strong>
                    <small className="mono">{formatBytes(summary.videosEncryptedBytes)}</small>
                  </div>
                  <div className="pss-breakdown-card">
                    <span>加密文本</span>
                    <strong>{summary.activeNotes} 篇</strong>
                    <small className="mono">{formatBytes(summary.notesEncryptedBytes)}</small>
                  </div>
                </div>
              )}

              {envelope ? (
                <div className="cipher-inspector-box">
                  <div className="cipher-inspector-head">
                    <span>
                      当前检视记录 ({envelope.itemType.toUpperCase()}) · 底层加密信封
                    </span>
                    <span className="mono" style={{ color: 'var(--accent)' }}>
                      Rev v{envelope.revision} · Sync #{envelope.syncSeq}
                    </span>
                  </div>
                  <div className="cipher-kv-list">
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">记录 UUID</span>
                      <span className="cipher-kv-val">{envelope.itemId}</span>
                    </div>
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">密钥派生链路</span>
                      <span className="cipher-kv-val">{envelope.kdfSpec}</span>
                    </div>
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">HKDF 上下文</span>
                      <span className="cipher-kv-val">{envelope.hkdfContext}</span>
                    </div>
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">AAD 防篡改绑定</span>
                      <span className="cipher-kv-val">{envelope.aadJson}</span>
                    </div>
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">记录随机盐 / Nonce</span>
                      <span className="cipher-kv-val">
                        {envelope.saltHex.slice(0, 16)}… / {envelope.nonceHex}
                      </span>
                    </div>
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">GCM 认证标签 (128b)</span>
                      <span className="cipher-kv-val">{envelope.authTagHex}</span>
                    </div>
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">零明文保护字段</span>
                      <span className="cipher-kv-val">
                        {envelope.sqliteColumnsEncrypted.join(', ')}
                      </span>
                    </div>

                    {envelope.chunkStore && (
                      <>
                        <div className="cipher-kv-row">
                          <span className="cipher-kv-key">.psenc 分块格式</span>
                          <span className="cipher-kv-val">
                            {envelope.chunkStore.formatMagic} · {envelope.chunkStore.chunkCount} ×{' '}
                            {Math.round(envelope.chunkStore.chunkPlainBytes / 1024)} KiB
                          </span>
                        </div>
                        <div className="cipher-kv-row">
                          <span className="cipher-kv-key">FEK 信封上下文</span>
                          <span className="cipher-kv-val">{envelope.chunkStore.fekWrapInfo}</span>
                        </div>
                        <div className="cipher-kv-row">
                          <span className="cipher-kv-key">SHA-256 原始指纹</span>
                          <span className="cipher-kv-val">
                            {envelope.chunkStore.sha256Hex}
                          </span>
                        </div>
                      </>
                    )}

                    <div>
                      <div
                        style={{
                          fontSize: '0.76rem',
                          color: 'var(--text-tertiary)',
                          marginBottom: 4,
                        }}
                      >
                        vault_items.ciphertext 磁盘原始密文采样 ({envelope.ciphertextTotalBytes}{' '}
                        Bytes)：
                      </div>
                      <div className="cipher-hex-dump">{envelope.ciphertextPreviewHex}</div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="auth-notice">
                  <ShieldCheck size={16} />
                  <span>
                    在密码库、加密图库、视频影院或文本编辑器中点击「AES-256-GCM」徽章，即可在此实时检视对应的 SQLite 密文信封与 .psenc 分块元数据。
                  </span>
                </div>
              )}
            </>
          )}

          {tab === 'sessions' && (
            <>
              <div className="pss-endpoint-box">
                <div>
                  <div className="pss-field-caption">
                    Android / iOS 客户端接入服务器地址 (Server Endpoint)
                  </div>
                  <div className="mono" style={{ fontSize: '0.88rem', fontWeight: 600 }}>
                    {serverEndpoint}
                  </div>
                  <div style={{ fontSize: '0.76rem', color: 'var(--text-tertiary)', marginTop: 3 }}>
                    支持在 Android 手机端粘贴配对码自动填入服务器地址，通过{' '}
                    <code className="mono">/api/v1/sync?since_seq={summary?.latestSyncSeq ?? 0}</code>{' '}
                    与 SSE 实时增量同步密码、相册、视频与文本。
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6, flexShrink: 0, flexWrap: 'wrap' }}>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ height: 32 }}
                    onClick={() => {
                      const pairUri = `privatespace://pair?server=${encodeURIComponent(
                        serverEndpoint,
                      )}&vault=${encodeURIComponent(vaultName)}`;
                      void navigator.clipboard.writeText(pairUri);
                      onNotify('安卓手机端一键配对码已复制');
                    }}
                  >
                    <Smartphone size={13} />
                    <span>复制配对码</span>
                  </button>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ height: 32 }}
                    onClick={() => {
                      void navigator.clipboard.writeText(serverEndpoint);
                      onNotify('自部署服务地址已复制');
                    }}
                  >
                    <Copy size={13} />
                    <span>复制地址</span>
                  </button>
                </div>
              </div>

              <div className="session-list">
                {sessions.map((s) => (
                  <div key={s.id} className="session-row">
                    <div className="session-meta">
                      <div className="session-device">
                        <Smartphone size={14} style={{ color: 'var(--accent)' }} />
                        <span>{s.deviceName}</span>
                        <span className="tag-chip-mini mono">{s.platform.toUpperCase()}</span>
                        {s.current && <span className="current-session-pill">当前设备</span>}
                      </div>
                      <div className="session-sub">
                        IP: {s.ipAddress} · 最近活跃: {formatFullDateTime(s.lastActiveAt)} · 过期:{' '}
                        {formatFullDateTime(s.expiresAt)}
                      </div>
                    </div>

                    {!s.current && (
                      <button
                        type="button"
                        className="btn btn-danger"
                        style={{ height: 30, padding: '0 10px', fontSize: '0.78rem' }}
                        onClick={() => void handleRevokeSession(s.id)}
                      >
                        <Trash2 size={13} />
                        <span>吊销授权</span>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}

          {tab === 'password' && (
            <>
              <form
                onSubmit={(e) => void handleSaveVaultName(e)}
                style={{
                  display: 'flex',
                  gap: 10,
                  alignItems: 'flex-end',
                  paddingBottom: 16,
                  borderBottom: '1px solid var(--border-subtle)',
                }}
              >
                <div className="field-group" style={{ flex: 1 }}>
                  <label htmlFor="settings-vault-name" className="field-label">
                    <span>私密空间显示名称</span>
                  </label>
                  <input
                    id="settings-vault-name"
                    type="text"
                    className="field-input"
                    style={{ height: 36 }}
                    value={nameInput}
                    maxLength={48}
                    onChange={(e) => setNameInput(e.target.value)}
                  />
                </div>
                <button type="submit" className="btn btn-secondary">
                  保存名称
                </button>
              </form>

              <form className="auth-form" onSubmit={(e) => void handleRotatePassword(e)}>
                <div className="auth-notice">
                  <KeyRound size={16} />
                  <span>
                    零知识信封重包裹机制：原密码与新密码均仅在浏览器本地派生 KEK 重新包裹 256 位主密钥（DEK），服务端永不获知密码或 DEK，所有既有密码、.psenc 图片与高清视频无需重加密即可无缝访问。
                  </span>
                </div>

                <div className="field-group">
                  <label htmlFor="cur-admin-pwd" className="field-label">
                    <span>当前管理员密码</span>
                  </label>
                  <input
                    id="cur-admin-pwd"
                    type="password"
                    className="field-input"
                    value={currentPassword}
                    onChange={(e) => setCurrentPassword(e.target.value)}
                    required
                  />
                </div>

                <div className="field-group">
                  <label htmlFor="new-admin-pwd" className="field-label">
                    <span>新管理员主密码（至少 8 位）</span>
                  </label>
                  <input
                    id="new-admin-pwd"
                    type="password"
                    className="field-input"
                    value={newPassword}
                    onChange={(e) => setNewPassword(e.target.value)}
                    required
                  />
                  {newPassword && (
                    <div className="strength-meter">
                      <div className="strength-bars">
                        {[1, 2, 3, 4].map((idx) => (
                          <span
                            key={idx}
                            className={`strength-bar ${
                              strength.score >= idx ? `level-${strength.score}` : ''
                            }`}
                          />
                        ))}
                      </div>
                      <div className="strength-caption">
                        <span>{strength.label}</span>
                      </div>
                    </div>
                  )}
                </div>

                <div className="field-group">
                  <label htmlFor="confirm-admin-pwd" className="field-label">
                    <span>确认新管理员主密码</span>
                  </label>
                  <input
                    id="confirm-admin-pwd"
                    type="password"
                    className="field-input"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                  />
                </div>

                <label className="auth-checkbox-row">
                  <input
                    type="checkbox"
                    checked={revokeOthers}
                    onChange={(e) => setRevokeOthers(e.target.checked)}
                  />
                  <span>同时强制下线并吊销其他已登录设备（推荐）</span>
                </label>

                {pwdError && <div className="auth-error">{pwdError}</div>}

                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={pwdSubmitting}
                  style={{ alignSelf: 'flex-start' }}
                >
                  {pwdSubmitting ? '正在重新封装主密钥...' : '轮换管理员密码'}
                </button>
              </form>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
