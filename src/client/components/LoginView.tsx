import React, { useState } from 'react';
import { Eye, EyeOff, KeyRound, Lock, Moon, Shield, Sun } from 'lucide-react';
import { api } from '../api/client';

interface LoginViewProps {
  vaultName: string;
  keyFingerprint: string | null;
  theme: 'light' | 'dark';
  onToggleTheme: () => void;
  onUnlocked: (payload: { vaultName: string; keyFingerprint: string }) => void;
}

export const LoginView: React.FC<LoginViewProps> = ({
  vaultName,
  keyFingerprint,
  theme,
  onToggleTheme,
  onUnlocked,
}) => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!password) {
      setError('请输入管理员主密码');
      return;
    }

    setSubmitting(true);
    try {
      const res = await api.login({ password });
      onUnlocked({
        vaultName: res.vaultName,
        keyFingerprint: res.keyFingerprint,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : '登录失败，请检查管理员密码');
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
          <span>{vaultName || 'PrivateSpace'}</span>
        </div>
        <button
          type="button"
          id="login-theme-toggle"
          className="btn-icon"
          onClick={onToggleTheme}
          title={theme === 'light' ? '切换深色模式' : '切换浅色模式'}
          aria-label="切换主题模式"
        >
          {theme === 'light' ? <Moon size={17} /> : <Sun size={17} />}
        </button>
      </header>

      <main className="auth-center">
        <section className="auth-card" aria-labelledby="login-heading">
          <div className="auth-header">
            {keyFingerprint && (
              <div className="auth-key-badge" title="空间主密钥指纹（HMAC-SHA256 不可逆摘要）">
                <KeyRound size={12} />
                <span>E2EE KEY · {keyFingerprint}</span>
              </div>
            )}
            <h1 id="login-heading" className="auth-title">
              零知识密钥解锁
            </h1>
            <p className="auth-subtitle">
              当前空间处于端到端加密锁定状态。输入管理员主密码以在浏览器本地派生 KEK 并解封主密钥。
            </p>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="field-group">
              <label htmlFor="login-password" className="field-label">
                <span>管理员主密码</span>
                <span className="mono" style={{ fontSize: '0.73rem' }}>
                  零知识本地派生
                </span>
              </label>
              <div className="field-input-wrap">
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  className="field-input has-trailing"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="输入管理员主密码以本地解封密钥"
                  autoComplete="current-password"
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
            </div>

            <div className="auth-notice">
              <Shield size={16} />
              <span>
                端到端零知识加密（E2EE v2）：主密码永不发送至服务器；解封后的 256 位 DEK 仅驻留当前浏览器内存，服务端全程仅存储不透明密文。
              </span>
            </div>

            {error && (
              <div className="auth-error" role="alert">
                {error}
              </div>
            )}

            <button
              id="login-submit-btn"
              type="submit"
              className="btn btn-primary auth-submit"
              disabled={submitting}
            >
              {submitting ? '正在本地派生密钥并解封...' : '本地解封进入私密空间'}
            </button>
          </form>
        </section>
      </main>

      <footer className="auth-footer">
        <span className="auth-spec-item">零知识端到端加密 (E2EE v2)</span>
        <span>·</span>
        <span className="auth-spec-item">PBKDF2-SHA256 310k + AES-256-GCM</span>
        <span>·</span>
        <span className="auth-spec-item">服务端零明文 / 零主密钥</span>
      </footer>
    </div>
  );
};
