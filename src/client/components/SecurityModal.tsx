import React, { useEffect, useState } from 'react';
import { KeyRound, Laptop, ShieldCheck, Smartphone, Trash2, X } from 'lucide-react';
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
  inspectNoteId: string | null;
  vaultName: string;
  onClose: () => void;
  onVaultNameUpdated: (newName: string) => void;
  onNotify: (msg: string) => void;
}

export const SecurityModal: React.FC<SecurityModalProps> = ({
  open,
  initialTab,
  inspectNoteId,
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

        if (inspectNoteId) {
          const envRes = await api.inspectNoteCipher(inspectNoteId).catch(() => null);
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
  }, [open, inspectNoteId]);

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
        role="dialog"
        aria-modal="true"
        aria-labelledby="security-modal-title"
      >
        <header className="modal-header">
          <div className="modal-title-wrap">
            <ShieldCheck size={19} style={{ color: 'var(--accent)' }} />
            <h2 id="security-modal-title" className="modal-title">
              安全中心与加密存储验证
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
          <button
            id="sec-tab-sessions"
            type="button"
            role="tab"
            aria-selected={tab === 'sessions'}
            className={`modal-tab ${tab === 'sessions' ? 'is-active' : ''}`}
            onClick={() => setTab('sessions')}
          >
            <Laptop size={14} />
            <span>多端会话 ({sessions.length})</span>
          </button>
        </div>

        <div className="modal-body">
          {tab === 'cipher' && (
            <>
              <div className="sec-stat-grid">
                <div className="sec-stat-card">
                  <div className="sec-stat-label">加密套件</div>
                  <div className="sec-stat-value">AES-256-GCM</div>
                </div>
                <div className="sec-stat-card">
                  <div className="sec-stat-label">主密钥指纹 (HMAC)</div>
                  <div className="sec-stat-value mono">
                    {summary?.keyFingerprint ?? '—'}
                  </div>
                </div>
                <div className="sec-stat-card">
                  <div className="sec-stat-label">加密记录 / 密文体积</div>
                  <div className="sec-stat-value">
                    {summary
                      ? `${summary.totalNotes} 篇 · ${formatBytes(summary.totalEncryptedBytes)}`
                      : loading
                        ? '读取中...'
                        : '0 B'}
                  </div>
                </div>
              </div>

              {envelope ? (
                <div className="cipher-inspector-box">
                  <div className="cipher-inspector-head">
                    <span>当前选中记录 · SQLite 真实存储信封</span>
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
                      <span className="cipher-kv-key">记录随机盐 (128b)</span>
                      <span className="cipher-kv-val">{envelope.saltHex}</span>
                    </div>
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">GCM Nonce (96b)</span>
                      <span className="cipher-kv-val">{envelope.nonceHex}</span>
                    </div>
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">GCM 认证标签 (128b)</span>
                      <span className="cipher-kv-val">{envelope.authTagHex}</span>
                    </div>
                    <div className="cipher-kv-row">
                      <span className="cipher-kv-key">加密保护字段</span>
                      <span className="cipher-kv-val">
                        {envelope.sqliteColumnsEncrypted.join(', ')}（SQLite 零明文留存）
                      </span>
                    </div>

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
                    在编辑器中打开任意文本记录后，此处将实时读取并展示该记录在 SQLite
                    数据库中的原始 AES-256-GCM 密文摘要、随机盐、Nonce 与认证标签。
                  </span>
                </div>
              )}
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
                    本系统仅存在唯一管理员账户。采用信封加密机制，修改管理员密码仅重新包裹
                    256 位空间主密钥（DEK），所有历史加密记录自动无缝衔接。
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

          {tab === 'sessions' && (
            <>
              <div className="auth-notice">
                <Smartphone size={16} />
                <span>
                  支持网页端、Android 与 iOS 客户端通过{' '}
                  <code className="mono">/api/v1/sync?since_seq=...</code>{' '}
                  游标协议增量同步加密记录。下方列出当前处于解锁有效期的全部设备会话。
                </span>
              </div>

              <div className="session-list">
                {sessions.map((s) => (
                  <div key={s.id} className="session-row">
                    <div className="session-meta">
                      <div className="session-device">
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
                        <span>吊销</span>
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
