import React, { useEffect, useState } from 'react';
import {
  AlertTriangle,
  CheckCircle2,
  Download,
  ExternalLink,
  ShieldCheck,
  Sparkles,
  X,
} from 'lucide-react';
import type { AppUpdateCheckResponse } from '@shared/types';
import {
  androidBridge,
  type ApkDownloadProgressEvent,
  type NativeDeviceMetadata,
} from '../nativeBridge';
import { formatBytes, formatDateTime, renderSafeMarkdown } from '../utils/mobileFormat';

interface MobileUpdateModalProps {
  open: boolean;
  updateInfo: AppUpdateCheckResponse | null;
  deviceMeta: NativeDeviceMetadata;
  onClose: () => void;
  onSkipVersion: (version: string) => void;
  onNotify: (msg: string) => void;
}

export const MobileUpdateModal: React.FC<MobileUpdateModalProps> = ({
  open,
  updateInfo,
  deviceMeta,
  onClose,
  onSkipVersion,
  onNotify,
}) => {
  const [progress, setProgress] = useState<ApkDownloadProgressEvent | null>(null);
  const [installing, setInstalling] = useState(false);
  const [needsInstallPermission, setNeedsInstallPermission] = useState(false);
  const [verifiedSha, setVerifiedSha] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!open) {
      setProgress(null);
      setInstalling(false);
      setNeedsInstallPermission(false);
      setVerifiedSha(null);
      setErrorMsg(null);
      return;
    }

    let unsubscribe: (() => void) | null = null;
    void androidBridge
      .onUpdateDownloadProgress((evt) => {
        setProgress(evt);
      })
      .then((unsub) => {
        unsubscribe = unsub;
      });

    return () => {
      unsubscribe?.();
    };
  }, [open]);

  if (!open || !updateInfo) return null;

  const asset = updateInfo.asset;
  const isMandatory = updateInfo.mandatory;

  const handleDownloadAndInstall = async () => {
    if (!asset?.downloadUrl) {
      window.open(updateInfo.htmlUrl, '_blank', 'noopener,noreferrer');
      return;
    }

    setErrorMsg(null);
    setInstalling(true);
    setNeedsInstallPermission(false);

    try {
      const result = await androidBridge.downloadAndInstallApk({
        url: asset.downloadUrl,
        expectedSha256: asset.sha256,
        versionName: updateInfo.latestVersion,
        fileName: asset.fileName,
      });

      if (result.sha256) {
        setVerifiedSha(result.sha256);
      }

      if (result.status === 'permission_required') {
        setNeedsInstallPermission(true);
        onNotify('请在系统设置中开启「允许来自此来源的应用」后点击继续安装');
      } else if (result.status === 'browser_downloaded') {
        onNotify('新版本 APK 已完成 SHA-256 校验并下载');
      } else {
        onNotify('SHA-256 校验通过，已唤起 Android 系统安装程序');
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '下载或校验安装包失败');
    } finally {
      setInstalling(false);
    }
  };

  const handleContinuePendingInstall = async () => {
    setErrorMsg(null);
    try {
      const res = await androidBridge.installPendingApk();
      if (res.status === 'permission_required') {
        onNotify('尚未授予未知来源安装权限，请先开启开关');
      } else {
        setNeedsInstallPermission(false);
        onNotify('正在启动系统覆盖安装界面');
      }
    } catch (err) {
      setErrorMsg(err instanceof Error ? err.message : '启动安装程序失败');
    }
  };

  return (
    <div
      className="m-sheet-backdrop"
      onClick={(e) => {
        if (!isMandatory && e.target === e.currentTarget) {
          onClose();
        }
      }}
    >
      <div
        className="m-sheet"
        role="dialog"
        aria-modal="true"
        aria-labelledby="m-update-sheet-title"
        data-testid="android-update-modal"
      >
        <div className="m-sheet-handle" />
        <div className="m-sheet-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Sparkles size={18} style={{ color: 'var(--m-accent)' }} />
            <h2 id="m-update-sheet-title" className="m-sheet-title">
              {updateInfo.hasUpdate
                ? `发现新版本 v${updateInfo.latestVersion}`
                : `当前已是最新版本 v${updateInfo.currentVersion}`}
            </h2>
          </div>
          {!isMandatory && (
            <button
              type="button"
              className="m-icon-btn"
              onClick={onClose}
              aria-label="关闭更新弹窗"
            >
              <X size={18} />
            </button>
          )}
        </div>

        <div className="m-sheet-body" style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {/* Version Comparison Strip */}
          <div
            className="m-probe-box"
            style={{
              marginBottom: 0,
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              flexWrap: 'wrap',
              gap: 8,
            }}
          >
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--m-text-tertiary)' }}>
                软件版本升级路径 ({updateInfo.repository})
              </div>
              <div className="mono" style={{ fontWeight: 800, fontSize: '0.94rem', marginTop: 2 }}>
                v{updateInfo.currentVersion} → v{updateInfo.latestVersion}{' '}
                <span style={{ fontSize: '0.74rem', color: 'var(--m-text-secondary)' }}>
                  (Build {updateInfo.latestBuild})
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              {updateInfo.prerelease && (
                <span
                  className="m-mini-pill"
                  style={{ background: 'var(--m-amber-soft)', color: 'var(--m-amber)' }}
                >
                  预览版 BETA
                </span>
              )}
              {isMandatory ? (
                <span
                  className="m-mini-pill"
                  style={{ background: 'var(--m-danger-soft)', color: 'var(--m-danger)' }}
                >
                  强制安全更新
                </span>
              ) : (
                <span
                  className="m-mini-pill"
                  style={{ background: 'var(--m-accent-soft)', color: 'var(--m-accent)' }}
                >
                  {updateInfo.source === 'github-direct' ? 'GitHub 直连' : '服务端分发'}
                </span>
              )}
            </div>
          </div>

          {isMandatory && (
            <div
              style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: 8,
                padding: '9px 11px',
                borderRadius: 10,
                background: 'var(--m-amber-soft)',
                color: 'var(--m-amber)',
                fontSize: '0.78rem',
                fontWeight: 600,
              }}
            >
              <AlertTriangle size={16} style={{ flexShrink: 0, marginTop: 2 }} />
              <span>
                当前客户端版本低于安全基线要求，请升级至 v{updateInfo.latestVersion}{' '}
                以继续同步加密保险库。
              </span>
            </div>
          )}

          {/* Release Notes */}
          <div>
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-between',
                fontSize: '0.75rem',
                color: 'var(--m-text-tertiary)',
                marginBottom: 5,
              }}
            >
              <span>版本更新说明 ({updateInfo.releaseName})</span>
              {updateInfo.publishedAt && <span>{formatDateTime(updateInfo.publishedAt)}</span>}
            </div>
            <div
              style={{
                maxHeight: 175,
                overflowY: 'auto',
                padding: '10px 12px',
                borderRadius: 10,
                background: 'var(--m-bg-code)',
                border: '1px solid var(--m-border)',
                fontSize: '0.82rem',
                lineHeight: 1.55,
              }}
              dangerouslySetInnerHTML={{
                __html: renderSafeMarkdown(
                  updateInfo.releaseNotes || '包含端到端零知识加密性能优化与移动端稳定性改进。',
                ),
              }}
            />
          </div>

          {/* Cryptographic Package Metadata */}
          {asset && (
            <div style={{ fontSize: '0.76rem' }}>
              <div className="m-kv-row">
                <span className="m-kv-key">安装包产物</span>
                <span className="m-kv-val">{asset.fileName}</span>
              </div>
              {typeof asset.fileSize === 'number' && asset.fileSize > 0 && (
                <div className="m-kv-row">
                  <span className="m-kv-key">包体大小</span>
                  <span className="m-kv-val">{formatBytes(asset.fileSize)}</span>
                </div>
              )}
              <div className="m-kv-row">
                <span className="m-kv-key">SHA-256 完整性校验</span>
                <span className="m-kv-val">
                  {asset.sha256 ? `${asset.sha256.slice(0, 16)}…${asset.sha256.slice(-8)}` : '下载时计算'}
                </span>
              </div>
            </div>
          )}

          {/* Live Download & SHA-256 Verification Progress */}
          {progress && (
            <div
              style={{
                padding: '10px 12px',
                borderRadius: 10,
                background: 'var(--m-bg-subtle)',
                border: '1px solid var(--m-border)',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  fontSize: '0.76rem',
                  fontWeight: 600,
                  marginBottom: 6,
                }}
              >
                <span>
                  {progress.status === 'downloading' && '正在下载新版本 APK...'}
                  {progress.status === 'verifying' && '正在校验 APK SHA-256 哈希指纹...'}
                  {progress.status === 'installing' && '校验通过，已就绪安装'}
                  {progress.status === 'permission_required' && '等待授予未知来源应用安装权限'}
                  {progress.status === 'error' && '下载或完整性校验异常'}
                </span>
                <span className="mono">
                  {progress.percent >= 0 ? `${progress.percent}%` : formatBytes(progress.receivedBytes)}
                </span>
              </div>
              <div className="m-progress-track">
                <div
                  className="m-progress-fill"
                  style={{ width: `${Math.max(4, progress.percent >= 0 ? progress.percent : 50)}%` }}
                />
              </div>
              {verifiedSha && (
                <div
                  className="mono"
                  style={{
                    marginTop: 6,
                    fontSize: '0.68rem',
                    color: 'var(--m-accent)',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  <CheckCircle2 size={12} />
                  <span>SHA-256 校验一致：{verifiedSha.slice(0, 24)}…</span>
                </div>
              )}
            </div>
          )}

          {needsInstallPermission && (
            <div
              style={{
                padding: '10px 12px',
                borderRadius: 10,
                background: 'var(--m-amber-soft)',
                border: '1px solid hsla(30, 76%, 41%, 0.3)',
                display: 'flex',
                flexDirection: 'column',
                gap: 8,
              }}
            >
              <div style={{ fontSize: '0.78rem', fontWeight: 600 }}>
                Android 8.0+ 首次应用内自更新需开启「允许安装未知应用」权限（安装包已完成 SHA-256 校验缓存，无需重复下载）。
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  type="button"
                  className="m-btn m-btn-sm"
                  style={{ flex: 1 }}
                  onClick={() => void androidBridge.openUnknownSourcesSettings()}
                >
                  打开权限设置
                </button>
                <button
                  type="button"
                  className="m-btn m-btn-primary m-btn-sm"
                  style={{ flex: 1 }}
                  onClick={() => void handleContinuePendingInstall()}
                >
                  已授权，继续安装
                </button>
              </div>
            </div>
          )}

          {errorMsg && (
            <div
              style={{
                padding: '9px 11px',
                borderRadius: 10,
                background: 'var(--m-danger-soft)',
                color: 'var(--m-danger)',
                fontSize: '0.78rem',
                fontWeight: 600,
              }}
            >
              {errorMsg}
            </div>
          )}

          {/* Action Buttons */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 2 }}>
            {updateInfo.hasUpdate && (
              <button
                id="m-confirm-update-install-btn"
                type="button"
                className="m-btn m-btn-primary m-btn-block"
                disabled={installing}
                onClick={() => void handleDownloadAndInstall()}
              >
                {deviceMeta.isNativeAndroid ? <ShieldCheck size={16} /> : <Download size={16} />}
                <span>
                  {installing
                    ? '正在下载并校验 SHA-256...'
                    : deviceMeta.isNativeAndroid
                      ? `立即下载并覆盖安装 v${updateInfo.latestVersion}`
                      : `校验 SHA-256 并下载 Android APK (v${updateInfo.latestVersion})`}
                </span>
              </button>
            )}

            <div style={{ display: 'flex', gap: 8 }}>
              <a
                href={updateInfo.htmlUrl}
                target="_blank"
                rel="noreferrer"
                className="m-btn"
                style={{ flex: 1, textDecoration: 'none', justifyContent: 'center' }}
              >
                <ExternalLink size={14} />
                <span>GitHub Release 页</span>
              </a>

              {updateInfo.hasUpdate && !isMandatory && (
                <button
                  type="button"
                  className="m-btn m-btn-soft"
                  style={{ flex: 1 }}
                  onClick={() => {
                    onSkipVersion(updateInfo.latestVersion);
                    onClose();
                  }}
                >
                  忽略 v{updateInfo.latestVersion}
                </button>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
