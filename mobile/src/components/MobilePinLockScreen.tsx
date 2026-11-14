import React, { useEffect, useState } from 'react';
import { Delete, Fingerprint, KeyRound, ShieldCheck } from 'lucide-react';
import { androidBridge, quickLockManager } from '../nativeBridge';

interface MobilePinLockScreenProps {
  vaultName: string;
  biometricAvailable: boolean;
  biometricEnabled: boolean;
  onUnlockedWithToken: (token: string) => Promise<void>;
  onFallbackMasterPassword: () => void;
}

export const MobilePinLockScreen: React.FC<MobilePinLockScreenProps> = ({
  vaultName,
  biometricAvailable,
  biometricEnabled,
  onUnlockedWithToken,
  onFallbackMasterPassword,
}) => {
  const [pin, setPin] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [verifying, setVerifying] = useState(false);

  const handleBiometric = async () => {
    setError(null);
    const token = await quickLockManager.unlockWithBiometrics();
    if (token) {
      androidBridge.haptic('success');
      await onUnlockedWithToken(token);
    } else {
      setError('生物识别未通过，请输入 6 位快捷 PIN');
    }
  };

  useEffect(() => {
    if (biometricAvailable && biometricEnabled) {
      void handleBiometric();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const appendDigit = async (digit: string) => {
    if (verifying || pin.length >= 6) return;
    androidBridge.haptic('light');
    const next = `${pin}${digit}`;
    setPin(next);
    setError(null);

    if (next.length === 6) {
      setVerifying(true);
      try {
        const token = await quickLockManager.verifyPinAndRestoreToken(next);
        if (!token) {
          androidBridge.haptic('warning');
          setError('PIN 码不正确，请重试');
          setPin('');
          return;
        }
        androidBridge.haptic('success');
        await onUnlockedWithToken(token);
      } finally {
        setVerifying(false);
      }
    }
  };

  const removeDigit = () => {
    if (pin.length === 0) return;
    androidBridge.haptic('light');
    setPin((prev) => prev.slice(0, -1));
  };

  return (
    <div className="m-app-shell">
      <div className="m-auth-screen" style={{ justifyContent: 'center', textAlign: 'center' }}>
        <div>
          <span className="m-crypto-badge">
            <ShieldCheck size={13} />
            <span>Android Keystore 硬件保护已就绪</span>
          </span>
          <h1 className="m-auth-title" style={{ marginTop: 14 }}>
            解锁 {vaultName}
          </h1>
          <p className="m-auth-sub">请输入 6 位快捷 PIN 码或验证生物识别</p>

          <div className="m-pin-dots" aria-label="PIN 输入进度">
            {[0, 1, 2, 3, 4, 5].map((idx) => (
              <span key={idx} className={`m-pin-dot ${pin.length > idx ? 'is-filled' : ''}`} />
            ))}
          </div>

          {error && (
            <div className="m-error-box" style={{ maxWidth: 290, margin: '0 auto 16px' }}>
              {error}
            </div>
          )}

          <div className="m-pin-grid">
            {['1', '2', '3', '4', '5', '6', '7', '8', '9'].map((d) => (
              <button
                key={d}
                type="button"
                className="m-pin-key mono"
                onClick={() => void appendDigit(d)}
              >
                {d}
              </button>
            ))}

            {biometricAvailable && biometricEnabled ? (
              <button
                id="m-pin-biometric-btn"
                type="button"
                className="m-pin-key"
                style={{ color: 'var(--m-accent)' }}
                onClick={() => void handleBiometric()}
                aria-label="指纹或面容解锁"
              >
                <Fingerprint size={24} />
              </button>
            ) : (
              <div />
            )}

            <button
              type="button"
              className="m-pin-key mono"
              onClick={() => void appendDigit('0')}
            >
              0
            </button>

            <button
              type="button"
              className="m-pin-key"
              onClick={removeDigit}
              aria-label="退格"
            >
              <Delete size={21} />
            </button>
          </div>

          <button
            id="m-pin-fallback-master-btn"
            type="button"
            className="m-btn m-btn-sm"
            style={{ marginTop: 26 }}
            onClick={onFallbackMasterPassword}
          >
            <KeyRound size={14} />
            <span>改用管理员主密码登录</span>
          </button>
        </div>
      </div>
    </div>
  );
};
