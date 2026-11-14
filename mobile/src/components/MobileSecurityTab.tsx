import React, { useEffect, useState } from 'react';
import {
  Copy,
  Fingerprint,
  KeyRound,
  Lock,
  LogOut,
  Moon,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  Sun,
  Trash2,
  X,
} from 'lucide-react';
import type {
  CipherEnvelopeInspection,
  MediaItem,
  NoteItem,
  PasswordItem,
  SessionInfo,
  VaultSecuritySummary,
} from '@shared/types';
import {
  androidBridge,
  quickLockManager,
  type NativeDeviceMetadata,
  type StoredQuickLockMeta,
} from '../nativeBridge';
import { formatPairingUri, type PrivateSpaceMobileClient } from '../syncClient';
import { formatBytes, formatDateTime } from '../utils/mobileFormat';

interface MobileSecurityTabProps {
  client: PrivateSpaceMobileClient;
  vaultName: string;
  serverUrl: string;
  deviceMeta: NativeDeviceMetadata;
  theme: 'light' | 'dark';
  clipboardAutoClear: boolean;
  screenshotShield: boolean;
  quickLockConfig: StoredQuickLockMeta | null;
  sseConnected: boolean;
  pendingOfflineCount: number;
  inspectTargetId: string | null;
  notes: NoteItem[];
  passwords: PasswordItem[];
  media: MediaItem[];
  onToggleTheme: () => void;
  onToggleClipboardAutoClear: () => void;
  onToggleScreenshotShield: (next: boolean) => Promise<void>;
  onQuickLockChanged: () => Promise<void>;
  onVaultNameUpdated: (name: string) => void;
  onManualSync: () => Promise<void>;
  onLockVault: () => void;
  onSwitchServer: () => Promise<void>;
  onNotify: (msg: string) => void;
}

export const MobileSecurityTab: React.FC<MobileSecurityTabProps> = ({
  client,
  vaultName,
  serverUrl,
  deviceMeta,
  theme,
  clipboardAutoClear,
  screenshotShield,
  quickLockConfig,
  sseConnected,
  pendingOfflineCount,
  inspectTargetId,
  notes,
  passwords,
  media,
  onToggleTheme,
  onToggleClipboardAutoClear,
  onToggleScreenshotShield,
  onQuickLockChanged,
  onVaultNameUpdated,
  onManualSync,
  onLockVault,
  onSwitchServer,
  onNotify,
}) => {
  const [summary, setSummary] = useState<VaultSecuritySummary | null>(null);
  const [sessions, setSessions] = useState<SessionInfo[]>([]);
  const [selectedCipherId, setSelectedCipherId] = useState<string>(inspectTargetId ?? '');
  const [envelope, setEnvelope] = useState<CipherEnvelopeInspection | null>(null);
  const [loading, setLoading] = useState(false);

  // PIN Setup Modal
  const [pinModalOpen, setPinModalOpen] = useState(false);
  const [pinInput, setPinInput] = useState('');
  const [bioToggle, setBioToggle] = useState(deviceMeta.biometricAvailable);

  // Vault Name & Password Rotation Sheet
  const [adminSheetOpen, setAdminSheetOpen] = useState(false);
  const [nameInput, setNameInput] = useState(vaultName);
  const [curPwd, setCurPwd] = useState('');
  const [newPwd, setNewPwd] = useState('');
  const [confirmPwd, setConfirmPwd] = useState('');
  const [revokeOthers, setRevokeOthers] = useState(true);

  const allInspectableItems = [
    ...passwords.filter((p) => !p.isTrashed).map((p) => ({ id: p.id, label: `[密码] ${p.title}` })),
    ...media
      .filter((m) => !m.isTrashed)
      .map((m) => ({
        id: m.id,
        label: `[${m.itemType === 'video' ? '视频' : '原图'}] ${m.title}`,
      })),
    ...notes
      .filter((n) => !n.isTrashed)
      .map((n) => ({ id: n.id, label: `[笔记] ${n.title || '无标题'}` })),
  ];

  const loadSecurityData = async () => {
    setLoading(true);
    try {
      const [sec, sess] = await Promise.all([
        client.getSecuritySummary(),
        client.listSessions(),
      ]);
      setSummary(sec);
      setSessions(sess);
    } catch {
      // offline fallback
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void loadSecurityData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (inspectTargetId) {
      setSelectedCipherId(inspectTargetId);
    } else if (!selectedCipherId && allInspectableItems.length > 0) {
      setSelectedCipherId(allInspectableItems[0].id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inspectTargetId]);

  useEffect(() => {
    if (!selectedCipherId) {
      setEnvelope(null);
      return;
    }
    let cancelled = false;
    client
      .inspectItemCipher(selectedCipherId)
      .then((env) => {
        if (!cancelled) setEnvelope(env);
      })
      .catch(() => {
        if (!cancelled) setEnvelope(null);
      });
    return () => {
      cancelled = true;
    };
  }, [client, selectedCipherId]);

  const handleSaveQuickPin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!/^\d{6}$/.test(pinInput)) {
      onNotify('请输入 6 位数字 PIN 码');
      return;
    }
    const token = client.getToken();
    const dekBase64 = client.getDekBase64();
    if (!token || !dekBase64) {
      onNotify('当前离线或主密钥未解封，请重新登录后设置');
      return;
    }
    await quickLockManager.configurePin(pinInput, bioToggle, token, dekBase64);
    setPinInput('');
    setPinModalOpen(false);
    await onQuickLockChanged();
    onNotify('Android Keystore 零知识密钥快捷解锁已启用');
  };

  const handleRotatePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    if (newPwd.length < 8) {
      onNotify('新管理员密码至少需要 8 位字符');
      return;
    }
    if (newPwd !== confirmPwd) {
      onNotify('两次输入的新密码不一致');
      return;
    }
    try {
      await client.changeMasterPassword({
        currentPassword: curPwd,
        newPassword: newPwd,
        revokeOtherSessions: revokeOthers,
      });
      setCurPwd('');
      setNewPwd('');
      setConfirmPwd('');
      setAdminSheetOpen(false);
      onNotify('主密钥信封已重新封装，无需重加密底层媒体');
      await loadSecurityData();
    } catch (err) {
      onNotify(err instanceof Error ? err.message : '修改主密码失败');
    }
  };

  return (
    <>
      {/* 1. Android Native Privacy & Hardware Controls */}
      <section className="m-card">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 6,
          }}
        >
          <span style={{ fontWeight: 700, fontSize: '0.92rem' }}>Android 原生安全与隐私防护</span>
          <span className="m-crypto-badge" style={{ fontSize: '0.68rem', padding: '2px 8px' }}>
            {deviceMeta.isNativeAndroid ? `SDK ${deviceMeta.sdkInt}` : 'Mobile Guard'}
          </span>
        </div>

        <div className="m-switch-row">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>
              防截屏与多任务模糊保护 (FLAG_SECURE)
            </div>
            <div style={{ fontSize: '0.73rem', color: 'var(--m-text-tertiary)' }}>
              阻止系统截屏、录屏及最近任务视图泄露密码明文
            </div>
          </div>
          <button
            id="m-sec-flag-secure-toggle"
            type="button"
            className={`m-toggle ${screenshotShield ? 'is-on' : ''}`}
            onClick={() => void onToggleScreenshotShield(!screenshotShield)}
            aria-label="切换防截屏保护"
          />
        </div>

        <div className="m-switch-row">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>
              Android Keystore 快捷 PIN / 生物识别
            </div>
            <div style={{ fontSize: '0.73rem', color: 'var(--m-text-tertiary)' }}>
              {quickLockConfig
                ? `已开启 6 位 PIN${quickLockConfig.biometricEnabled ? ' + 生物识别' : ''}`
                : '使用本机安全硬件加密保存会话令牌'}
            </div>
          </div>
          {quickLockConfig ? (
            <button
              type="button"
              className="m-btn m-btn-danger m-btn-sm"
              onClick={async () => {
                await quickLockManager.disableQuickLock();
                await onQuickLockChanged();
                onNotify('已关闭本机快捷 PIN 解锁');
              }}
            >
              关闭
            </button>
          ) : (
            <button
              id="m-sec-setup-pin-btn"
              type="button"
              className="m-btn m-btn-soft m-btn-sm"
              onClick={() => setPinModalOpen(true)}
            >
              <Fingerprint size={14} />
              <span>启用</span>
            </button>
          )}
        </div>

        <div className="m-switch-row">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>
              敏感剪贴板 30 秒自动擦除
            </div>
            <div style={{ fontSize: '0.73rem', color: 'var(--m-text-tertiary)' }}>
              启用 Android 13+ 剪贴板隐私掩码并定时清空口令
            </div>
          </div>
          <button
            type="button"
            className={`m-toggle ${clipboardAutoClear ? 'is-on' : ''}`}
            onClick={onToggleClipboardAutoClear}
            aria-label="切换剪贴板自动擦除"
          />
        </div>

        <div className="m-switch-row">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>深色外观主题</div>
            <div style={{ fontSize: '0.73rem', color: 'var(--m-text-tertiary)' }}>
              {theme === 'dark' ? 'Deep Graphite Ink 暗夜石墨绿' : 'Warm Editorial Paper 暖感纸张'}
            </div>
          </div>
          <button
            type="button"
            className="m-btn m-btn-sm"
            onClick={onToggleTheme}
          >
            {theme === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
            <span>{theme === 'dark' ? '切换浅色' : '切换深色'}</span>
          </button>
        </div>
      </section>

      {/* 2. Cryptographic Storage & Sync Overview */}
      <section className="m-card">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 10,
          }}
        >
          <div>
            <div style={{ fontWeight: 700, fontSize: '0.92rem' }}>全栈加密存储与同步游标</div>
            <div className="mono" style={{ fontSize: '0.72rem', color: 'var(--m-text-secondary)' }}>
              {sseConnected ? 'SSE 实时推送已连接' : '增量轮询模式'} · 待传离线队列 {pendingOfflineCount} 项
            </div>
          </div>
          <button
            type="button"
            className="m-btn m-btn-soft m-btn-sm"
            onClick={() => void onManualSync()}
          >
            <RefreshCw size={13} />
            <span>同步</span>
          </button>
        </div>

        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(2, 1fr)',
            gap: 8,
            marginBottom: 10,
          }}
        >
          <div className="m-probe-box" style={{ marginBottom: 0 }}>
            <div style={{ color: 'var(--m-text-tertiary)', fontSize: '0.7rem' }}>密码保险箱</div>
            <div style={{ fontWeight: 800, fontSize: '0.95rem', marginTop: 2 }}>
              {summary?.activePasswords ?? passwords.filter((p) => !p.isTrashed).length} 条
            </div>
            <div className="mono" style={{ fontSize: '0.68rem', color: 'var(--m-text-secondary)' }}>
              {formatBytes(summary?.passwordsEncryptedBytes ?? 0)}
            </div>
          </div>
          <div className="m-probe-box" style={{ marginBottom: 0 }}>
            <div style={{ color: 'var(--m-text-tertiary)', fontSize: '0.7rem' }}>加密原图相册</div>
            <div style={{ fontWeight: 800, fontSize: '0.95rem', marginTop: 2 }}>
              {summary?.activeImages ??
                media.filter((m) => m.itemType === 'image' && !m.isTrashed).length}{' '}
              张
            </div>
            <div className="mono" style={{ fontSize: '0.68rem', color: 'var(--m-text-secondary)' }}>
              {formatBytes(summary?.imagesEncryptedBytes ?? 0)}
            </div>
          </div>
          <div className="m-probe-box" style={{ marginBottom: 0 }}>
            <div style={{ color: 'var(--m-text-tertiary)', fontSize: '0.7rem' }}>流式加密视频</div>
            <div style={{ fontWeight: 800, fontSize: '0.95rem', marginTop: 2 }}>
              {summary?.activeVideos ??
                media.filter((m) => m.itemType === 'video' && !m.isTrashed).length}{' '}
              部
            </div>
            <div className="mono" style={{ fontSize: '0.68rem', color: 'var(--m-text-secondary)' }}>
              {formatBytes(summary?.videosEncryptedBytes ?? 0)}
            </div>
          </div>
          <div className="m-probe-box" style={{ marginBottom: 0 }}>
            <div style={{ color: 'var(--m-text-tertiary)', fontSize: '0.7rem' }}>加密文本笔记</div>
            <div style={{ fontWeight: 800, fontSize: '0.95rem', marginTop: 2 }}>
              {summary?.activeNotes ?? notes.filter((n) => !n.isTrashed).length} 篇
            </div>
            <div className="mono" style={{ fontSize: '0.68rem', color: 'var(--m-text-secondary)' }}>
              {formatBytes(summary?.notesEncryptedBytes ?? 0)}
            </div>
          </div>
        </div>

        <div className="m-kv-row">
          <span className="m-kv-key">主密钥指纹 (HMAC)</span>
          <span className="m-kv-val">{summary?.keyFingerprint ?? (loading ? '读取中...' : '—')}</span>
        </div>
        <div className="m-kv-row">
          <span className="m-kv-key">总密文占用 / 最新游标</span>
          <span className="m-kv-val">
            {formatBytes(summary?.totalEncryptedBytes ?? 0)} · #{summary?.latestSyncSeq ?? 0}
          </span>
        </div>
      </section>

      {/* 3. Raw Cipher Envelope Inspector */}
      <section className="m-card">
        <div style={{ fontWeight: 700, fontSize: '0.92rem', marginBottom: 8 }}>
          底层 AES-256-GCM / PSENC001 密文信封透视
        </div>
        {allInspectableItems.length > 0 ? (
          <>
            <select
              id="m-cipher-select"
              className="m-select"
              style={{ marginBottom: 10, fontSize: '0.82rem' }}
              value={selectedCipherId}
              onChange={(e) => setSelectedCipherId(e.target.value)}
            >
              {allInspectableItems.map((it) => (
                <option key={it.id} value={it.id}>
                  {it.label}
                </option>
              ))}
            </select>

            {envelope && (
              <div>
                <div className="m-kv-row">
                  <span className="m-kv-key">算法与 KDF 链路</span>
                  <span className="m-kv-val">{envelope.algorithm} · HKDF-SHA256</span>
                </div>
                <div className="m-kv-row">
                  <span className="m-kv-key">HKDF 上下文</span>
                  <span className="m-kv-val">{envelope.hkdfContext}</span>
                </div>
                <div className="m-kv-row">
                  <span className="m-kv-key">AAD 防篡改绑定</span>
                  <span className="m-kv-val">{envelope.aadJson}</span>
                </div>
                <div className="m-kv-row">
                  <span className="m-kv-key">128b GCM 认证标签</span>
                  <span className="m-kv-val">{envelope.authTagHex}</span>
                </div>
                {envelope.chunkStore && (
                  <div className="m-kv-row">
                    <span className="m-kv-key">.psenc 分块容器</span>
                    <span className="m-kv-val">
                      {envelope.chunkStore.formatMagic} · {envelope.chunkStore.chunkCount} ×{' '}
                      {Math.round(envelope.chunkStore.chunkPlainBytes / 1024)} KiB
                    </span>
                  </div>
                )}
                <div
                  style={{
                    fontSize: '0.72rem',
                    color: 'var(--m-text-tertiary)',
                    marginTop: 8,
                  }}
                >
                  SQLite 磁盘密文采样 ({envelope.ciphertextTotalBytes} Bytes)：
                </div>
                <div className="m-hex-dump">{envelope.ciphertextPreviewHex}</div>
              </div>
            )}
          </>
        ) : (
          <div style={{ fontSize: '0.8rem', color: 'var(--m-text-secondary)' }}>
            创建任意密码、图片、视频或笔记后即可在此实时透视磁盘原始密文。
          </div>
        )}
      </section>

      {/* 4. Multi-Device Sessions & Pairing */}
      <section className="m-card">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            marginBottom: 8,
          }}
        >
          <span style={{ fontWeight: 700, fontSize: '0.92rem' }}>
            已授权设备会话 ({sessions.length})
          </span>
          <button
            type="button"
            className="m-btn m-btn-sm"
            onClick={async () => {
              const uri = formatPairingUri(serverUrl, vaultName);
              await androidBridge.copySensitive(uri, '节点配对码', false);
              onNotify('多端配对码已复制');
            }}
          >
            <Copy size={12} />
            <span>复制配对码</span>
          </button>
        </div>

        {sessions.map((s) => (
          <div
            key={s.id}
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              gap: 8,
              padding: '9px 0',
              borderBottom: '1px solid var(--m-border)',
            }}
          >
            <div style={{ minWidth: 0 }}>
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 6,
                  fontSize: '0.84rem',
                  fontWeight: 600,
                }}
              >
                <Smartphone size={14} style={{ color: 'var(--m-accent)', flexShrink: 0 }} />
                <span
                  style={{
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {s.deviceName}
                </span>
                <span className="m-mini-pill mono">{s.platform.toUpperCase()}</span>
                {s.current && (
                  <span
                    className="m-mini-pill"
                    style={{ background: 'var(--m-accent-soft)', color: 'var(--m-accent)' }}
                  >
                    本机
                  </span>
                )}
              </div>
              <div style={{ fontSize: '0.7rem', color: 'var(--m-text-tertiary)', marginTop: 2 }}>
                {s.ipAddress} · 活跃于 {formatDateTime(s.lastActiveAt)}
              </div>
            </div>

            {!s.current && (
              <button
                type="button"
                className="m-btn m-btn-danger m-btn-sm"
                onClick={async () => {
                  await client.revokeSession(s.id);
                  setSessions((prev) => prev.filter((x) => x.id !== s.id));
                  onNotify('已远程吊销该设备会话');
                }}
              >
                <Trash2 size={13} />
              </button>
            )}
          </div>
        ))}
      </section>

      {/* 5. Admin Vault Settings & Lock / Switch Server */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginBottom: 18 }}>
        <button
          type="button"
          className="m-btn m-btn-block"
          onClick={() => {
            setNameInput(vaultName);
            setAdminSheetOpen(true);
          }}
        >
          <KeyRound size={15} />
          <span>空间名称设置与管理员主密码轮换</span>
        </button>

        <div style={{ display: 'flex', gap: 8 }}>
          <button
            id="m-sec-lock-btn"
            type="button"
            className="m-btn m-btn-soft"
            style={{ flex: 1 }}
            onClick={onLockVault}
          >
            <Lock size={15} />
            <span>立即锁定空间</span>
          </button>
          <button
            type="button"
            className="m-btn m-btn-danger"
            style={{ flex: 1 }}
            onClick={() => void onSwitchServer()}
          >
            <LogOut size={15} />
            <span>退出 / 切换节点</span>
          </button>
        </div>
      </div>

      {/* Quick PIN Setup Sheet */}
      {pinModalOpen && (
        <div
          className="m-sheet-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setPinModalOpen(false);
          }}
        >
          <div className="m-sheet">
            <div className="m-sheet-handle" />
            <div className="m-sheet-header">
              <h2 className="m-sheet-title">设置本机 6 位快捷 PIN 解锁</h2>
              <button
                type="button"
                className="m-icon-btn"
                onClick={() => setPinModalOpen(false)}
              >
                <X size={18} />
              </button>
            </div>
            <form onSubmit={(e) => void handleSaveQuickPin(e)} className="m-sheet-body">
              <div className="m-field">
                <label className="m-label">6 位数字 PIN 码</label>
                <input
                  type="password"
                  inputMode="numeric"
                  maxLength={6}
                  className="m-input mono"
                  placeholder="输入 6 位数字"
                  value={pinInput}
                  onChange={(e) => setPinInput(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  required
                />
              </div>
              {deviceMeta.biometricAvailable && (
                <div className="m-switch-row" style={{ marginBottom: 12 }}>
                  <span>同时允许 Android 指纹 / 面容解锁</span>
                  <button
                    type="button"
                    className={`m-toggle ${bioToggle ? 'is-on' : ''}`}
                    onClick={() => setBioToggle((v) => !v)}
                  />
                </div>
              )}
              <button type="submit" className="m-btn m-btn-primary m-btn-block">
                <ShieldCheck size={15} />
                <span>加密写入 Android Keystore</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* Vault Name & Master Password Rotation Sheet */}
      {adminSheetOpen && (
        <div
          className="m-sheet-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setAdminSheetOpen(false);
          }}
        >
          <div className="m-sheet">
            <div className="m-sheet-handle" />
            <div className="m-sheet-header">
              <h2 className="m-sheet-title">空间名称与主密码轮换</h2>
              <button
                type="button"
                className="m-icon-btn"
                onClick={() => setAdminSheetOpen(false)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="m-sheet-body">
              <form
                onSubmit={async (e) => {
                  e.preventDefault();
                  if (!nameInput.trim()) return;
                  const res = await client.updateVaultName(nameInput.trim());
                  onVaultNameUpdated(res.vaultName);
                  onNotify('空间显示名称已更新');
                }}
                style={{
                  paddingBottom: 14,
                  marginBottom: 14,
                  borderBottom: '1px solid var(--m-border)',
                }}
              >
                <div className="m-field">
                  <label className="m-label">私密空间名称</label>
                  <div className="m-input-group">
                    <input
                      type="text"
                      className="m-input"
                      value={nameInput}
                      onChange={(e) => setNameInput(e.target.value)}
                    />
                    <button type="submit" className="m-btn m-btn-soft">
                      保存
                    </button>
                  </div>
                </div>
              </form>

              <form onSubmit={(e) => void handleRotatePassword(e)}>
                <div className="m-field">
                  <label className="m-label">当前管理员主密码</label>
                  <input
                    type="password"
                    className="m-input"
                    value={curPwd}
                    onChange={(e) => setCurPwd(e.target.value)}
                    required
                  />
                </div>
                <div className="m-field">
                  <label className="m-label">新管理员主密码 (≥8位)</label>
                  <input
                    type="password"
                    className="m-input"
                    value={newPwd}
                    onChange={(e) => setNewPwd(e.target.value)}
                    required
                  />
                </div>
                <div className="m-field">
                  <label className="m-label">确认新主密码</label>
                  <input
                    type="password"
                    className="m-input"
                    value={confirmPwd}
                    onChange={(e) => setConfirmPwd(e.target.value)}
                    required
                  />
                </div>
                <div className="m-switch-row" style={{ marginBottom: 12 }}>
                  <span style={{ fontSize: '0.82rem' }}>同时吊销其他设备登录态</span>
                  <button
                    type="button"
                    className={`m-toggle ${revokeOthers ? 'is-on' : ''}`}
                    onClick={() => setRevokeOthers((v) => !v)}
                  />
                </div>
                <button type="submit" className="m-btn m-btn-primary m-btn-block">
                  轮换 KEK 信封密码
                </button>
              </form>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
