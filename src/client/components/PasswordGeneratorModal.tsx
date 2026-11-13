import React, { useEffect, useMemo, useState } from 'react';
import { Check, Copy, RefreshCw, Sparkles, X } from 'lucide-react';
import {
  evaluatePasswordEntropy,
  generateMemorablePassphrase,
  generateSecurePassword,
} from '@shared/passwordGenerator';

interface PasswordGeneratorModalProps {
  open: boolean;
  onClose: () => void;
  onUsePassword?: (pwd: string) => void;
  onNotify: (msg: string) => void;
}

export const PasswordGeneratorModal: React.FC<PasswordGeneratorModalProps> = ({
  open,
  onClose,
  onUsePassword,
  onNotify,
}) => {
  const [mode, setMode] = useState<'random' | 'passphrase'>('random');
  const [length, setLength] = useState(20);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(true);
  const [excludeAmbiguous, setExcludeAmbiguous] = useState(true);

  const [wordCount, setWordCount] = useState(4);
  const [capitalize, setCapitalize] = useState(true);
  const [includeNumber, setIncludeNumber] = useState(true);
  const [seed, setSeed] = useState(0);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  const generated = useMemo(() => {
    void seed;
    if (mode === 'passphrase') {
      return generateMemorablePassphrase({
        wordCount,
        separator: '-',
        capitalize,
        includeNumber,
      });
    }
    return generateSecurePassword({
      length,
      uppercase,
      lowercase,
      digits,
      symbols,
      excludeAmbiguous,
    });
  }, [
    mode,
    length,
    uppercase,
    lowercase,
    digits,
    symbols,
    excludeAmbiguous,
    wordCount,
    capitalize,
    includeNumber,
    seed,
  ]);

  const strength = useMemo(() => evaluatePasswordEntropy(generated), [generated]);

  if (!open) return null;

  async function handleCopy() {
    await navigator.clipboard.writeText(generated);
    setCopied(true);
    onNotify('高强度随机口令已复制到剪贴板');
    setTimeout(() => setCopied(false), 1500);
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
        style={{ maxWidth: 500 }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="pwd-gen-title"
      >
        <header className="modal-header">
          <div className="modal-title-wrap">
            <Sparkles size={18} style={{ color: 'var(--accent)' }} />
            <h2 id="pwd-gen-title" className="modal-title">
              密码学安全生成器 (CSPRNG)
            </h2>
          </div>
          <button type="button" className="btn-icon" onClick={onClose} aria-label="关闭">
            <X size={17} />
          </button>
        </header>

        <div className="modal-tabs" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'random'}
            className={`modal-tab ${mode === 'random' ? 'is-active' : ''}`}
            onClick={() => setMode('random')}
          >
            随机字符密码
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={mode === 'passphrase'}
            className={`modal-tab ${mode === 'passphrase' ? 'is-active' : ''}`}
            onClick={() => setMode('passphrase')}
          >
            易记词组口令
          </button>
        </div>

        <div className="modal-body" style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          <div className="pss-gen-preview-box">
            <div className="pss-gen-output mono">{generated}</div>
            <div className="pss-gen-preview-footer">
              <span className={`pss-entropy-pill level-${strength.score}`}>
                强度: {strength.label} · {strength.entropyBits} bits
              </span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ height: 32, padding: '0 10px' }}
                  onClick={() => setSeed((s) => s + 1)}
                >
                  <RefreshCw size={13} />
                  <span>换一个</span>
                </button>
                <button
                  type="button"
                  className="btn btn-primary"
                  style={{ height: 32, padding: '0 12px' }}
                  onClick={() => void handleCopy()}
                >
                  {copied ? <Check size={13} /> : <Copy size={13} />}
                  <span>{copied ? '已复制' : '复制'}</span>
                </button>
                {onUsePassword && (
                  <button
                    type="button"
                    className="btn btn-primary"
                    style={{ height: 32, padding: '0 12px' }}
                    onClick={() => {
                      onUsePassword(generated);
                      onClose();
                    }}
                  >
                    <span>填入密码</span>
                  </button>
                )}
              </div>
            </div>
          </div>

          {mode === 'random' ? (
            <>
              <div className="field-group">
                <div className="field-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>密码长度</span>
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--accent)' }}>
                    {length} 位
                  </span>
                </div>
                <input
                  type="range"
                  min={8}
                  max={64}
                  value={length}
                  onChange={(e) => setLength(Number(e.target.value))}
                  style={{ width: '100%', accentColor: 'var(--accent)' }}
                />
              </div>

              <div className="pss-checkbox-grid">
                <label className="auth-checkbox-row">
                  <input
                    type="checkbox"
                    checked={uppercase}
                    onChange={(e) => setUppercase(e.target.checked)}
                  />
                  <span>大写字母 (A-Z)</span>
                </label>
                <label className="auth-checkbox-row">
                  <input
                    type="checkbox"
                    checked={lowercase}
                    onChange={(e) => setLowercase(e.target.checked)}
                  />
                  <span>小写字母 (a-z)</span>
                </label>
                <label className="auth-checkbox-row">
                  <input
                    type="checkbox"
                    checked={digits}
                    onChange={(e) => setDigits(e.target.checked)}
                  />
                  <span>数字 (0-9)</span>
                </label>
                <label className="auth-checkbox-row">
                  <input
                    type="checkbox"
                    checked={symbols}
                    onChange={(e) => setSymbols(e.target.checked)}
                  />
                  <span>特殊符号 (!@#$%)</span>
                </label>
                <label className="auth-checkbox-row" style={{ gridColumn: '1 / -1' }}>
                  <input
                    type="checkbox"
                    checked={excludeAmbiguous}
                    onChange={(e) => setExcludeAmbiguous(e.target.checked)}
                  />
                  <span>排除易混淆字符 (0, O, 1, l, I)</span>
                </label>
              </div>
            </>
          ) : (
            <>
              <div className="field-group">
                <div className="field-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span>词组数量</span>
                  <span className="mono" style={{ fontWeight: 600, color: 'var(--accent)' }}>
                    {wordCount} 个词
                  </span>
                </div>
                <input
                  type="range"
                  min={3}
                  max={8}
                  value={wordCount}
                  onChange={(e) => setWordCount(Number(e.target.value))}
                  style={{ width: '100%', accentColor: 'var(--accent)' }}
                />
              </div>

              <div className="pss-checkbox-grid">
                <label className="auth-checkbox-row">
                  <input
                    type="checkbox"
                    checked={capitalize}
                    onChange={(e) => setCapitalize(e.target.checked)}
                  />
                  <span>单词首字母大写</span>
                </label>
                <label className="auth-checkbox-row">
                  <input
                    type="checkbox"
                    checked={includeNumber}
                    onChange={(e) => setIncludeNumber(e.target.checked)}
                  />
                  <span>附加随机数字后缀</span>
                </label>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};
