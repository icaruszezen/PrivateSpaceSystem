import React, { useState } from 'react';
import { Eye, EyeOff, KeyRound, Lock, Moon, ShieldCheck, Sun } from 'lucide-react';
import { api } from '../api/client';
import { evaluatePasswordStrength, WELCOME_NOTE_TEMPLATE } from '../utils/format';

interface SetupViewProps {
  defaultVaultName: string;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  onInitialized: (payload: { vaultName: string; keyFingerprint: string }) => void;
}

export const SetupView: React.FC<SetupViewProps> = ({
  defaultVaultName,
  theme,
  onToggleTheme,
  onInitialized,
}) => {
  const [vaultName, setVaultName] = useState(defaultVaultName || 'PrivateSpace');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [seedWelcomeNote, setSeedWelcomeNote] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const strength = evaluatePasswordStrength(password);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError('管理员主密码长度至少需要 8 位字符');
      return;
    }
    if (password !== confirmPassword) {
      setError('两次输入的管理员主密码不一致');
      return;
    }

    setSubmitting(true);
    try {
      const res = await api.setupAdmin({
        vaultName: vaultName.trim() || 'PrivateSpace',
        password,
      });

      if (seedWelcomeNote) {
        await api.createNote(WELCOME_NOTE_TEMPLATE).catch(() => undefined);
      }

      onInitialized({
        vaultName: res.vaultName,
        keyFingerprint: res.keyFingerprint,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : '初始化失败，请重试');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="auth-shell">
      <header className="auth-topbar">
        <div className="auth-brand-inline">
          <span className="auth-brand-mark" aria-hidden="true">
            <Lock size={15} strokeWidth={2.2} />
          </span>
          <span>PrivateSpace · 私密空间</span>
        </div>
        <button
          type="button"
          id="setup-theme-toggle"
          className="btn-icon"
          onClick={onToggleTheme}
          title={theme === 'light' ? '切换深色模式' : '切换浅色模式'}
          aria-label="切换主题模式"
        >
          {theme === 'light' ? <Moon size={17} /> : <Sun size={17} />}
        </button>
      </header>

      <main className="auth-center">
        <section className="auth-card" aria-labelledby="setup-heading">
          <div className="auth-header">
            <div className="auth-key-badge">
              <KeyRound size={12} />
              <span>ZERO-KNOWLEDGE E2EE · 唯一管理员</span>
            </div>
            <h1 id="setup-heading" className="auth-title">
              初始化零知识私密空间
            </h1>
            <p className="auth-subtitle">
              设置管理员主密码，浏览器将在本地随机生成 256 位主密钥（DEK）并端到端加密全部数据，服务器永不接触明文密码或解密密钥。
            </p>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="field-group">
              <label htmlFor="setup-vault-name" className="field-label">
                <span>空间名称</span>
              </label>
              <input
                id="setup-vault-name"
                type="text"
                className="field-input"
                value={vaultName}
                maxLength={48}
                onChange={(e) => setVaultName(e.target.value)}
                placeholder="例如：PrivateSpace · 个人空间"
              />
            </div>

            <div className="field-group">
              <label htmlFor="setup-password" className="field-label">
                <span>管理员主密码</span>
              </label>
              <div className="field-input-wrap">
                <input
                  id="setup-password"
                  type={showPassword ? 'text' : 'password'}
                  className="field-input has-trailing"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="输入至少 8 位高强度主密码"
                  autoComplete="new-password"
                  autoFocus
                  required
                />
                <button
                  type="button"
                  className="field-trailing-btn"
                  onClick={() => setShowPassword((s) => !s)}
                  aria-label={showPassword ? '隐藏密码' : '显示密码'}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              <div className="strength-meter" aria-live="polite">
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
                  <span className="mono">PBKDF2 310k · Client E2EE</span>
                </div>
              </div>
            </div>

            <div className="field-group">
              <label htmlFor="setup-confirm-password" className="field-label">
                <span>确认管理员主密码</span>
              </label>
              <input
                id="setup-confirm-password"
                type={showPassword ? 'text' : 'password'}
                className="field-input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="再次输入主密码以确认"
                autoComplete="new-password"
                required
              />
            </div>

            <label className="auth-checkbox-row" htmlFor="setup-seed-welcome">
              <input
                id="setup-seed-welcome"
                type="checkbox"
                checked={seedWelcomeNote}
                onChange={(e) => setSeedWelcomeNote(e.target.checked)}
              />
              <span>创建一篇《欢迎使用 PrivateSpace 私密空间》端到端加密示例记录</span>
            </label>

            <div className="auth-notice">
              <ShieldCheck size={16} />
              <span>
                零知识端到端加密架构：主密码永不离开当前设备，即使服务器主机或磁盘完全失陷，攻击者也无法解密任何数据。请务必牢记主密码。
              </span>
            </div>

            {error && (
              <div className="auth-error" role="alert">
                {error}
              </div>
            )}

            <button
              id="setup-submit-btn"
              type="submit"
              className="btn btn-primary auth-submit"
              disabled={submitting}
            >
              {submitting ? '正在本地生成主密钥并初始化...' : '本地创建密钥并进入空间'}
            </button>
          </form>
        </section>
      </main>

      <footer className="auth-footer">
        <span className="auth-spec-item">零知识端到端加密 (E2EE v2)</span>
        <span>·</span>
        <span className="auth-spec-item">PBKDF2-SHA256 310k 客户端派生</span>
        <span>·</span>
        <span className="auth-spec-item">服务端零明文 / 零密钥</span>
      </footer>
    </div>
  );
};
