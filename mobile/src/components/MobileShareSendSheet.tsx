import React, { useEffect, useMemo, useState } from 'react';
import {
  Archive,
  CheckCircle2,
  Code2,
  File as FileGenericIcon,
  FileText,
  Film,
  Lock,
  Package,
  Send,
  ShieldCheck,
  X,
} from 'lucide-react';
import {
  TRANSFER_CATEGORY_LABELS,
  classifyTransferFile,
  formatTransferByteSize,
  type TransferFileCategory,
} from '@shared/transferFiles';
import type { NativeSharedInboundBatch, NativeSharedInboundFile } from '../nativeBridge';

interface MobileShareSendSheetProps {
  batch: NativeSharedInboundBatch | null;
  deviceName: string;
  sending: boolean;
  fileProgressMap: Record<string, number>;
  errorMessage: string | null;
  onConfirmSend: (options: { note: string }) => Promise<void>;
  onCancel: () => Promise<void>;
}

function renderShareFileIcon(file: NativeSharedInboundFile) {
  const cat: TransferFileCategory =
    file.category || classifyTransferFile(file.name, file.mimeType);
  switch (cat) {
    case 'document':
      return <FileText size={17} />;
    case 'archive':
      return <Archive size={17} />;
    case 'package':
      return <Package size={17} />;
    case 'code':
      return <Code2 size={17} />;
    case 'media':
      return <Film size={17} />;
    default:
      return <FileGenericIcon size={17} />;
  }
}

export const MobileShareSendSheet: React.FC<MobileShareSendSheetProps> = ({
  batch,
  deviceName,
  sending,
  fileProgressMap,
  errorMessage,
  onConfirmSend,
  onCancel,
}) => {
  const [note, setNote] = useState('');

  useEffect(() => {
    if (!batch) {
      setNote('');
      return;
    }
    setNote(batch.sharedText?.trim() ?? '');
  }, [batch]);

  const totalBytes = useMemo(
    () => (batch ? batch.files.reduce((sum, f) => sum + (f.size || 0), 0) : 0),
    [batch],
  );

  if (!batch || batch.files.length === 0) {
    return null;
  }

  return (
    <div
      className="m-sheet-backdrop"
      style={{ zIndex: 88 }}
      data-testid="mobile-share-send-sheet"
    >
      <div className="m-sheet" onClick={(e) => e.stopPropagation()}>
        <div className="m-sheet-handle" />

        <div className="m-sheet-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: 9, minWidth: 0 }}>
            <div className="m-transfer-hero-icon" style={{ width: 34, height: 34, borderRadius: 10 }}>
              <Send size={16} />
            </div>
            <div style={{ minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <h3 className="m-sheet-title">发送至多端互传空间</h3>
                <span className="m-crypto-badge mono" style={{ fontSize: '0.65rem', padding: '1px 7px' }}>
                  系统分享
                </span>
              </div>
              <div style={{ fontSize: '0.74rem', color: 'var(--m-text-secondary)', marginTop: 1 }}>
                已接收 {batch.files.length} 个外部应用分享文件 · 共 {formatTransferByteSize(totalBytes)}
              </div>
            </div>
          </div>

          <button
            type="button"
            className="m-icon-btn"
            disabled={sending}
            onClick={() => void onCancel()}
            aria-label="取消发送"
          >
            <X size={18} />
          </button>
        </div>

        <div className="m-sheet-body">
          {/* Zero-Knowledge Security Guarantee Strip */}
          <div className="m-share-e2ee-banner">
            <ShieldCheck size={16} style={{ color: 'var(--m-accent)', flexShrink: 0 }} />
            <div>
              <div style={{ fontWeight: 700, fontSize: '0.8rem', color: 'var(--m-text)' }}>
                端侧分块零知识加密 · PSENC001 (AES-256-GCM)
              </div>
              <div style={{ fontSize: '0.73rem', color: 'var(--m-text-secondary)', marginTop: 1 }}>
                来自 <strong>{deviceName}</strong> · 文件名、类型与字节流均在本机加密后上传，发送完毕立即清理临时缓存。
              </div>
            </div>
          </div>

          {/* Staged Shared File List */}
          <div className="m-share-file-list" data-testid="mobile-share-staged-files">
            {batch.files.map((file) => {
              const cat = file.category || classifyTransferFile(file.name, file.mimeType);
              const progress = fileProgressMap[file.fileId];
              const isDone = progress !== undefined && progress >= 1;

              return (
                <div key={file.fileId} className="m-share-file-item">
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div className={`m-transfer-cat-box is-${cat}`} style={{ width: 38, height: 38 }}>
                      {renderShareFileIcon(file)}
                    </div>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div
                        style={{
                          fontWeight: 700,
                          fontSize: '0.87rem',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {file.name}
                      </div>
                      <div
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: 6,
                          fontSize: '0.73rem',
                          color: 'var(--m-text-secondary)',
                          marginTop: 2,
                          flexWrap: 'wrap',
                        }}
                      >
                        <span className="mono">{formatTransferByteSize(file.size)}</span>
                        <span>·</span>
                        <span>{TRANSFER_CATEGORY_LABELS[cat]}</span>
                        {file.sha256Hex && (
                          <>
                            <span>·</span>
                            <span className="mono">SHA-256 #{file.sha256Hex.slice(0, 8)}</span>
                          </>
                        )}
                      </div>
                    </div>
                    {isDone && (
                      <CheckCircle2 size={17} style={{ color: 'var(--m-accent)', flexShrink: 0 }} />
                    )}
                  </div>

                  {progress !== undefined && progress < 1 && (
                    <div className="m-progress-track" style={{ marginTop: 8 }}>
                      <div
                        className="m-progress-fill"
                        style={{ width: `${Math.max(8, Math.round(progress * 100))}%` }}
                      />
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {/* Optional Note */}
          <div className="m-field" style={{ marginTop: 12, marginBottom: 14 }}>
            <label htmlFor="m-share-note-input" className="m-label">
              <span>随附传输备注（可选，随文件元数据端侧加密）</span>
              <span className="mono" style={{ fontSize: '0.7rem' }}>
                <Lock size={11} style={{ verticalAlign: 'middle', marginRight: 3 }} />
                E2EE
              </span>
            </label>
            <input
              id="m-share-note-input"
              type="text"
              className="m-input"
              placeholder="例如：微信发来的签署版合同 / 电脑端待安装..."
              value={note}
              disabled={sending}
              onChange={(e) => setNote(e.target.value)}
            />
          </div>

          {errorMessage && <div className="m-error-box">{errorMessage}</div>}

          {/* Primary Confirm Action literally labeled "发送" */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.8fr', gap: 10 }}>
            <button
              id="m-share-cancel-btn"
              type="button"
              className="m-btn"
              disabled={sending}
              onClick={() => void onCancel()}
            >
              <span>取消</span>
            </button>

            <button
              id="m-share-send-btn"
              data-testid="mobile-share-send-confirm-btn"
              type="button"
              className="m-btn m-btn-primary"
              disabled={sending}
              onClick={() => void onConfirmSend({ note: note.trim() })}
            >
              <Send size={16} />
              <span>{sending ? '加密发送中...' : '发送'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};
