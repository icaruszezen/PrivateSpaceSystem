import React, { useEffect, useState } from 'react';
import {
  Calculator,
  Copy,
  Download,
  EyeOff,
  Fingerprint,
  KeyRound,
  Lock,
  LogOut,
  Moon,
  RefreshCw,
  ShieldCheck,
  Smartphone,
  Sparkles,
  Sun,
  Trash2,
  X,
} from 'lucide-react';
import { normalizeGithubRepo } from '@shared/appUpdate';
import {
  DEFAULT_DISGUISE_SECRET_CODE,
  normalizeDisguiseSecretCode,
  type DisguisePreferences,
} from '@shared/disguise';
import type {
  AppUpdateCheckResponse,
  CipherEnvelopeInspection,
  MediaItem,
  MobileUpdatePreferences,
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
  disguisePrefs: DisguisePreferences;
  onDisguisePrefsChange: (next: DisguisePreferences) => void;
  onActivateCoverNow: () => void;
  updatePrefs: MobileUpdatePreferences;
  updateInfo: AppUpdateCheckResponse | null;
  checkingUpdate: boolean;
  onUpdatePrefsChange: (next: MobileUpdatePreferences) => void;
  onCheckUpdate: (force?: boolean) => Promise<void>;
  onOpenUpdateModal: () => void;
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
  disguisePrefs,
  onDisguisePrefsChange,
  onActivateCoverNow,
  updatePrefs,
  updateInfo,
  checkingUpdate,
  onUpdatePrefsChange,
  onCheckUpdate,
  onOpenUpdateModal,
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
  const [repoDraft, setRepoDraft] = useState<string>(updatePrefs.customGithubRepo);
  const [secretCodeDraft, setSecretCodeDraft] = useState<string>(disguisePrefs.secretCode);

  useEffect(() => {
    setRepoDraft(updatePrefs.customGithubRepo);
  }, [updatePrefs.customGithubRepo]);

  useEffect(() => {
    setSecretCodeDraft(disguisePrefs.secretCode);
  }, [disguisePrefs.secretCode]);

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

  const handleSaveSecretCode = (e: React.FormEvent) => {
    e.preventDefault();
    const normalized = normalizeDisguiseSecretCode(secretCodeDraft);
    if (!normalized) {
      onNotify('隐藏唤出口令需为 3 ~ 16 位可见 ASCII 字符（不含空格）');
      return;
    }
    onDisguisePrefsChange({
      ...disguisePrefs,
      secretCode: normalized,
    });
    setSecretCodeDraft(normalized);
    onNotify(`已更新 PSS 工具页唤出口令为 ${normalized}`);
  };

  return (
    <>
      {/* 0A. PSS Application Disguise & De-sensitization */}
      <section className="m-card" data-testid="android-disguise-card">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 8,
            marginBottom: 8,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <Calculator size={16} style={{ color: 'var(--m-accent)', flexShrink: 0 }} />
            <span style={{ fontWeight: 700, fontSize: '0.92rem' }}>
              应用伪装与图标脱敏 (PSS)
            </span>
          </div>
          <span className="m-crypto-badge mono" style={{ fontSize: '0.68rem', padding: '2px 8px' }}>
            {disguisePrefs.enabled ? '伪装开启' : '直连模式'}
          </span>
        </div>

        <div className="m-probe-box" style={{ marginBottom: 10 }}>
          桌面图标与系统名称统一显示为 <strong>PSS</strong> (Personal System Service)。开启伪装入口后，启动默认展示「数值换算与节点探测」工具页，在算式框输入隐藏口令并按 <code>=</code> 即可进入工作区。
        </div>

        <div className="m-switch-row">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>启动时默认进入 PSS 工具页</div>
            <div style={{ fontSize: '0.73rem', color: 'var(--m-text-tertiary)' }}>
              关闭后打开应用将直接进入低调版 PSS 节点验证页
            </div>
          </div>
          <button
            id="m-disguise-enable-toggle"
            type="button"
            className={`m-toggle ${disguisePrefs.enabled ? 'is-on' : ''}`}
            onClick={() => {
              const next = !disguisePrefs.enabled;
              onDisguisePrefsChange({ ...disguisePrefs, enabled: next });
              onNotify(next ? '已开启启动时默认展示 PSS 工具页' : '已切换为直接进入 PSS 验证页');
            }}
            aria-label="切换启动默认伪装工具页"
          />
        </div>

        <div className="m-switch-row">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>切回后台时自动恢复伪装封面</div>
            <div style={{ fontSize: '0.73rem', color: 'var(--m-text-tertiary)' }}>
              切换多任务或锁屏时立即覆盖工作区画面
            </div>
          </div>
          <button
            id="m-disguise-autocover-toggle"
            type="button"
            className={`m-toggle ${disguisePrefs.autoCoverOnBackground ? 'is-on' : ''}`}
            onClick={() =>
              onDisguisePrefsChange({
                ...disguisePrefs,
                autoCoverOnBackground: !disguisePrefs.autoCoverOnBackground,
              })
            }
            aria-label="切换后台自动恢复伪装封面"
          />
        </div>

        <div className="m-switch-row">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>底部版本号连点 5 次手势唤出</div>
            <div style={{ fontSize: '0.73rem', color: 'var(--m-text-tertiary)' }}>
              允许连续快速点击底部 PSS Core 版本号进入验证页
            </div>
          </div>
          <button
            id="m-disguise-gesture-toggle"
            type="button"
            className={`m-toggle ${disguisePrefs.gestureUnlockEnabled ? 'is-on' : ''}`}
            onClick={() =>
              onDisguisePrefsChange({
                ...disguisePrefs,
                gestureUnlockEnabled: !disguisePrefs.gestureUnlockEnabled,
              })
            }
            aria-label="切换版本号连点手势唤出"
          />
        </div>

        <form onSubmit={handleSaveSecretCode} style={{ paddingTop: 10 }}>
          <label htmlFor="m-disguise-secret-input" className="m-label">
            <span>计算器隐藏唤出口令 (输入后按 =)</span>
            <span className="mono" style={{ fontSize: '0.72rem' }}>
              默认 {DEFAULT_DISGUISE_SECRET_CODE}
            </span>
          </label>
          <div className="m-input-group">
            <input
              id="m-disguise-secret-input"
              type="text"
              className="m-input mono"
              value={secretCodeDraft}
              maxLength={16}
              onChange={(e) => setSecretCodeDraft(e.target.value)}
              placeholder="例如 2580 或 0x99"
              autoCapitalize="none"
              autoCorrect="off"
            />
            <button
              id="m-disguise-secret-save-btn"
              type="submit"
              className="m-btn m-btn-soft"
              style={{ flexShrink: 0 }}
            >
              <span>保存口令</span>
            </button>
          </div>
        </form>

        <button
          id="m-disguise-activate-now-btn"
          type="button"
          className="m-btn m-btn-soft m-btn-block"
          style={{ marginTop: 12 }}
          onClick={onActivateCoverNow}
        >
          <EyeOff size={15} />
          <span>立即切换至 PSS 伪装工具页</span>
        </button>
      </section>

      {/* 0. Software Version & GitHub Auto-Update Configuration */}
      <section className="m-card" data-testid="android-auto-update-card">
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 8,
            marginBottom: 8,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <Sparkles size={16} style={{ color: 'var(--m-accent)', flexShrink: 0 }} />
            <span style={{ fontWeight: 700, fontSize: '0.92rem' }}>
              软件版本与 GitHub 自动更新
            </span>
          </div>
          <span
            className="m-crypto-badge mono"
            style={{
              fontSize: '0.68rem',
              padding: '2px 8px',
              background: updateInfo?.hasUpdate ? 'var(--m-accent-soft)' : undefined,
              color: updateInfo?.hasUpdate ? 'var(--m-accent)' : undefined,
            }}
          >
            v{deviceMeta.appVersionName} ({deviceMeta.appVersionCode})
          </span>
        </div>

        <div
          className="m-probe-box"
          style={{
            marginBottom: 10,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: 8,
          }}
        >
          <div style={{ minWidth: 0 }}>
            <div style={{ fontWeight: 700, fontSize: '0.84rem' }}>
              {updateInfo?.hasUpdate
                ? `发现新版本 v${updateInfo.latestVersion} (${updateInfo.releaseName})`
                : `当前已是最新版本 v${deviceMeta.appVersionName}`}
            </div>
            <div
              className="mono"
              style={{
                fontSize: '0.7rem',
                color: 'var(--m-text-tertiary)',
                marginTop: 2,
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              源：{updateInfo?.repository ?? updatePrefs.customGithubRepo} ·{' '}
              {updatePrefs.channel === 'beta' ? '预览通道' : '正式通道'}
            </div>
          </div>

          <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
            {updateInfo?.hasUpdate && (
              <button
                id="m-sec-open-update-btn"
                type="button"
                className="m-btn m-btn-primary m-btn-sm"
                onClick={onOpenUpdateModal}
              >
                <Download size={13} />
                <span>立即升级</span>
              </button>
            )}
            <button
              id="m-sec-check-update-btn"
              type="button"
              className="m-btn m-btn-soft m-btn-sm"
              disabled={checkingUpdate}
              onClick={() => void onCheckUpdate(true)}
            >
              <RefreshCw size={13} />
              <span>{checkingUpdate ? '检测中' : '检查更新'}</span>
            </button>
          </div>
        </div>

        <div className="m-switch-row">
          <div>
            <div style={{ fontWeight: 600, fontSize: '0.86rem' }}>启动时自动检测新版本</div>
            <div style={{ fontSize: '0.73rem', color: 'var(--m-text-tertiary)' }}>
              后台静默比对 SemVer 版本号并校验 APK SHA-256 指纹
            </div>
          </div>
          <button
            id="m-sec-autocheck-toggle"
            type="button"
            className={`m-toggle ${updatePrefs.autoCheckOnLaunch ? 'is-on' : ''}`}
            onClick={() =>
              onUpdatePrefsChange({
                ...updatePrefs,
                autoCheckOnLaunch: !updatePrefs.autoCheckOnLaunch,
              })
            }
            aria-label="切换启动时自动检测更新"
          />
        </div>

        <div style={{ paddingTop: 8 }}>
          <div
            style={{
              fontSize: '0.75rem',
              fontWeight: 600,
              color: 'var(--m-text-secondary)',
              marginBottom: 5,
            }}
          >
            版本发布通道 (Release Channel)
          </div>
          <div className="m-seg-row" style={{ marginBottom: 10 }}>
            <button
              type="button"
              className={`m-seg-btn ${updatePrefs.channel === 'stable' ? 'is-active' : ''}`}
              onClick={() =>
                onUpdatePrefsChange({ ...updatePrefs, channel: 'stable', skippedVersion: null })
              }
            >
              正式版 (Stable)
            </button>
            <button
              type="button"
              className={`m-seg-btn ${updatePrefs.channel === 'beta' ? 'is-active' : ''}`}
              onClick={() =>
                onUpdatePrefsChange({ ...updatePrefs, channel: 'beta', skippedVersion: null })
              }
            >
              含预览版 (Beta)
            </button>
          </div>

          <div
            style={{
              fontSize: '0.75rem',
              fontWeight: 600,
              color: 'var(--m-text-secondary)',
              marginBottom: 5,
            }}
          >
            更新源模式 (GitHub 仓库连接方式)
          </div>
          <div className="m-seg-row" style={{ marginBottom: 8 }}>
            <button
              type="button"
              className={`m-seg-btn ${updatePrefs.sourceMode === 'server' ? 'is-active' : ''}`}
              onClick={() => onUpdatePrefsChange({ ...updatePrefs, sourceMode: 'server' })}
            >
              跟随服务端网关 (推荐)
            </button>
            <button
              type="button"
              className={`m-seg-btn ${updatePrefs.sourceMode === 'github' ? 'is-active' : ''}`}
              onClick={() => onUpdatePrefsChange({ ...updatePrefs, sourceMode: 'github' })}
            >
              直连 GitHub 仓库
            </button>
          </div>

          {updatePrefs.sourceMode === 'github' && (
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const normalized = normalizeGithubRepo(repoDraft);
                if (!normalized) {
                  onNotify('请输入有效的 GitHub 仓库 owner/repo，例如 icaruszezen/PrivateSpaceSystem');
                  return;
                }
                onUpdatePrefsChange({
                  ...updatePrefs,
                  customGithubRepo: normalized,
                  skippedVersion: null,
                });
                onNotify(`已绑定 GitHub 更新仓库：${normalized}`);
              }}
              style={{ marginTop: 6 }}
            >
              <div className="m-input-group">
                <input
                  type="text"
                  className="m-input mono"
                  style={{ fontSize: '0.8rem' }}
                  placeholder="owner/repo (如 icaruszezen/PrivateSpaceSystem)"
                  value={repoDraft}
                  onChange={(e) => setRepoDraft(e.target.value)}
                />
                <button type="submit" className="m-btn m-btn-soft m-btn-sm">
                  保存仓库
                </button>
              </div>
            </form>
          )}
        </div>
      </section>

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
