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
                <span>KEY · {keyFingerprint}</span>
              </div>
            )}
            <h1 id="login-heading" className="auth-title">
              管理员解锁登录
            </h1>
            <p className="auth-subtitle">
              当前空间处于加密锁定状态。输入唯一管理员密码以解封主密钥并访问私密记录。
            </p>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <div className="field-group">
              <label htmlFor="login-password" className="field-label">
                <span>管理员密码</span>
                <span className="mono" style={{ fontSize: '0.73rem' }}>
                  单管理员身份
                </span>
              </label>
              <div className="field-input-wrap">
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  className="field-input has-trailing"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="输入管理员密码以解锁空间"
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
                解封后的主密钥仅驻留于临时会话内存，每次请求完成后自动擦除明文缓冲。
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
              {submitting ? '正在验证并解封密钥...' : '解锁进入私密空间'}
            </button>
          </form>
        </section>
      </main>

      <footer className="auth-footer">
        <span className="auth-spec-item">AES-256-GCM 静态数据加密</span>
        <span>·</span>
        <span className="auth-spec-item">自部署私有存储</span>
        <span>·</span>
        <span className="auth-spec-item">支持网页与多端同步协议</span>
      </footer>
    </div>
  );
};
