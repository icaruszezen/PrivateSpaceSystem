import React, { useEffect, useState } from 'react';
import { Eye, EyeOff, Feather, X } from 'lucide-react';
import { api } from '../api/client';
import { sanitizeDisguiseAuthError } from '../utils/disguiseConfig';
import { evaluatePasswordStrength, WELCOME_NOTE_TEMPLATE } from '../utils/format';

interface AuthorPortalModalProps {
  open: boolean;
  siteTitle: string;
  initialVaultInitialized: boolean | null;
  defaultVaultName: string;
  onClose: () => void;
  onAuthenticated: (payload: {
    vaultName: string;
    keyFingerprint: string;
    initialized: boolean;
  }) => Promise<void> | void;
  onStatusResolved?: (payload: {
    initialized: boolean;
    vaultName: string;
    keyFingerprint: string | null;
  }) => void;
}

export const AuthorPortalModal: React.FC<AuthorPortalModalProps> = ({
  open,
  siteTitle,
  initialVaultInitialized,
  defaultVaultName,
  onClose,
  onAuthenticated,
  onStatusResolved,
}) => {
  const [checkingMode, setCheckingMode] = useState(false);
  const [isInitialized, setIsInitialized] = useState<boolean>(
    initialVaultInitialized ?? true,
  );

  // Login state
  const [password, setPassword] = useState('');
  // Setup state
  const [workspaceName, setWorkspaceName] = useState(
    defaultVaultName && defaultVaultName !== 'PrivateSpace'
      ? defaultVaultName
      : 'PrivateSpace',
  );
  const [confirmPassword, setConfirmPassword] = useState('');
  const [seedWelcomeNote, setSeedWelcomeNote] = useState(true);

  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (initialVaultInitialized !== null) {
      setIsInitialized(initialVaultInitialized);
    }
  }, [initialVaultInitialized]);

  useEffect(() => {
    if (!open) return;
    setPassword('');
    setConfirmPassword('');
    setShowPassword(false);
    setError(null);

    if (initialVaultInitialized !== null) {
      setIsInitialized(initialVaultInitialized);
      return;
    }

    let cancelled = false;
    setCheckingMode(true);
    api
      .getAuthStatus()
      .then((status) => {
        if (cancelled) return;
        setIsInitialized(status.initialized);
        if (status.vaultName) {
          setWorkspaceName(status.vaultName);
        }
        onStatusResolved?.({
          initialized: status.initialized,
          vaultName: status.vaultName,
          keyFingerprint: status.keyFingerprint,
        });
      })
      .catch(() => {
        if (!cancelled) {
          setIsInitialized(true);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setCheckingMode(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [open, initialVaultInitialized, onStatusResolved]);

  useEffect(() => {
    if (!open) return;
    function handleKeyDown(e: KeyboardEvent) {
      if (e.key === 'Escape' && !submitting) {
        e.preventDefault();
        onClose();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [open, submitting, onClose]);

  if (!open) return null;

  const strength = evaluatePasswordStrength(password);

  async function handleLoginSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!password) {
      setError('请输入站点维护口令');
      return;
    }

    setSubmitting(true);
    try {
      const res = await api.login({ password });
      await onAuthenticated({
        vaultName: res.vaultName,
        keyFingerprint: res.keyFingerprint,
        initialized: true,
      });
    } catch (err) {
      setError(sanitizeDisguiseAuthError(err));
    } finally {
      setSubmitting(false);
    }
  }

  async function handleSetupSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (password.length < 8) {
      setError('维护口令长度至少需要 8 位字符');
      return;
    }
    if (password !== confirmPassword) {
      setError('两次输入的维护口令不一致');
      return;
    }

    setSubmitting(true);
    try {
      const res = await api.setupAdmin({
        vaultName: workspaceName.trim() || 'PrivateSpace',
        password,
      });

      if (seedWelcomeNote) {
        await api.createNote(WELCOME_NOTE_TEMPLATE).catch(() => undefined);
      }

      await onAuthenticated({
        vaultName: res.vaultName,
        keyFingerprint: res.keyFingerprint,
        initialized: true,
      });
    } catch (err) {
      setError(sanitizeDisguiseAuthError(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      id="author-portal-backdrop"
      className="journal-portal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget && !submitting) {
          onClose();
        }
      }}
    >
      <section
        id="author-portal-dialog"
        className="journal-portal-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="author-portal-heading"
      >
        <header className="journal-portal-head">
          <div className="journal-portal-brand">
            <span className="journal-portal-icon" aria-hidden="true">
              <Feather size={15} strokeWidth={2} />
            </span>
            <div>
              <h2 id="author-portal-heading" className="journal-portal-title">
                {checkingMode
                  ? '站点管理后台'
                  : isInitialized
                    ? '作者后台验证'
                    : '首次站点配置'}
              </h2>
              <p className="journal-portal-meta">{siteTitle} · 稿件与归档管理</p>
            </div>
          </div>

          <button
            id="author-portal-close-btn"
            type="button"
            className="btn-icon"
            onClick={onClose}
            disabled={submitting}
            aria-label="关闭窗口"
          >
            <X size={16} />
          </button>
        </header>

        {checkingMode ? (
          <div className="journal-portal-loading">
            <div className="boot-spinner" />
            <span>正在读取站点配置状态...</span>
          </div>
        ) : isInitialized ? (
          <form className="journal-portal-form" onSubmit={(e) => void handleLoginSubmit(e)}>
            <p className="journal-portal-desc">
              请输入作者维护口令以继续访问草稿箱与站点设置。
            </p>

            <div className="field-group">
              <label htmlFor="login-password" className="field-label">
                <span>维护口令</span>
              </label>
              <div className="field-input-wrap">
                <input
                  id="login-password"
                  type={showPassword ? 'text' : 'password'}
                  className="field-input has-trailing"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="输入站点维护口令"
                  autoComplete="current-password"
                  autoFocus
                  required
                />
                <button
                  type="button"
                  className="field-trailing-btn"
                  onClick={() => setShowPassword((s) => !s)}
                  aria-label={showPassword ? '隐藏口令' : '显示口令'}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
            </div>

            {error && (
              <div className="auth-error" role="alert">
                {error}
              </div>
            )}

            <div className="journal-portal-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={onClose}
                disabled={submitting}
              >
                取消
              </button>
              <button
                id="login-submit-btn"
                type="submit"
                className="btn btn-primary"
                disabled={submitting}
              >
                {submitting ? '正在校验凭据...' : '验证并进入后台'}
              </button>
            </div>
          </form>
        ) : (
          <form className="journal-portal-form" onSubmit={(e) => void handleSetupSubmit(e)}>
            <p className="journal-portal-desc">
              当前站点尚未设置维护凭据。请配置后台工作台名称与至少 8 位的维护口令，并请妥善牢记。
            </p>

            <div className="field-group">
              <label htmlFor="setup-vault-name" className="field-label">
                <span>后台工作台名称</span>
              </label>
              <input
                id="setup-vault-name"
                type="text"
                className="field-input"
                value={workspaceName}
                maxLength={48}
                onChange={(e) => setWorkspaceName(e.target.value)}
                placeholder="例如：个人工作台"
              />
            </div>

            <div className="field-group">
              <label htmlFor="setup-password" className="field-label">
                <span>设置维护口令</span>
              </label>
              <div className="field-input-wrap">
                <input
                  id="setup-password"
                  type={showPassword ? 'text' : 'password'}
                  className="field-input has-trailing"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="输入至少 8 位高强度口令"
                  autoComplete="new-password"
                  autoFocus
                  required
                />
                <button
                  type="button"
                  className="field-trailing-btn"
                  onClick={() => setShowPassword((s) => !s)}
                  aria-label={showPassword ? '隐藏口令' : '显示口令'}
                >
                  {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>
              {password.length > 0 && (
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
                  </div>
                </div>
              )}
            </div>

            <div className="field-group">
              <label htmlFor="setup-confirm-password" className="field-label">
                <span>确认维护口令</span>
              </label>
              <input
                id="setup-confirm-password"
                type={showPassword ? 'text' : 'password'}
                className="field-input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="再次输入维护口令以确认"
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
              <span>同时生成一篇快速使用说明文稿</span>
            </label>

            {error && (
              <div className="auth-error" role="alert">
                {error}
              </div>
            )}

            <div className="journal-portal-actions">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={onClose}
                disabled={submitting}
              >
                取消
              </button>
              <button
                id="setup-submit-btn"
                type="submit"
                className="btn btn-primary"
                disabled={submitting}
              >
                {submitting ? '正在完成配置...' : '完成配置并进入后台'}
              </button>
            </div>
          </form>
        )}
      </section>
    </div>
  );
};
