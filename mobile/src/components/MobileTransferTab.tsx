import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Archive,
  ArrowUpRight,
  CheckCircle2,
  Code2,
  Copy,
  Download,
  File as FileIcon,
  FileText,
  Film,
  Image as ImageIcon,
  Laptop,
  Lock,
  Music,
  Package,
  Paperclip,
  Play,
  Reply,
  Search,
  Send,
  ShieldCheck,
  Smartphone,
  Star,
  Trash2,
  X,
} from 'lucide-react';
import type {
  CreateTransferTextRequest,
  MediaKind,
  TransferDevicePlatform,
  TransferFileCategory,
  TransferItem,
  UpdateTransferRequest,
} from '@shared/types';
import type { PrivateSpaceMobileClient } from '../syncClient';
import { formatBytes } from '../utils/mobileFormat';

export interface MobileTransferTabProps {
  client: PrivateSpaceMobileClient;
  transfers: TransferItem[];
  uploadingTasks: Array<{ id: string; name: string; progress: number }>;
  onSendText: (input: CreateTransferTextRequest) => Promise<void>;
  onSendFiles: (
    files: FileList | File[],
    opts?: { text?: string; replyToId?: string | null; replyPreview?: string | null },
  ) => Promise<void>;
  onUpdateTransfer: (id: string, patch: UpdateTransferRequest) => Promise<void>;
  onDeletePermanent: (id: string) => Promise<void>;
  onJumpToMedia: (kind: MediaKind) => void;
  onInspectCipher: (id: string) => void;
  onCopyText: (text: string, label: string) => void;
  onNotify: (msg: string) => void;
  initialSharedText?: { title?: string; content: string } | null;
  onClearSharedText?: () => void;
}

type MobileTransferFilter = 'all' | 'text' | 'file' | 'media' | 'pinned';

const URL_SPLIT_RE = /(https?:\/\/[^\s<>"']+)/gi;

function platformLabel(platform: TransferDevicePlatform): string {
  switch (platform) {
    case 'android':
      return 'Android';
    case 'ios':
      return 'iOS';
    case 'web':
      return '电脑端';
    case 'api':
      return 'API';
  }
}

function PlatformIcon({ platform }: { platform: TransferDevicePlatform }) {
  if (platform === 'android' || platform === 'ios') {
    return <Smartphone size={11} />;
  }
  return <Laptop size={11} />;
}

function FileCategoryGlyph({ category }: { category: TransferFileCategory | null }) {
  switch (category) {
    case 'document':
      return <FileText size={18} />;
    case 'archive':
      return <Archive size={18} />;
    case 'package':
      return <Package size={18} />;
    case 'audio':
      return <Music size={18} />;
    case 'code':
      return <Code2 size={18} />;
    case 'image':
      return <ImageIcon size={18} />;
    case 'video':
      return <Film size={18} />;
    default:
      return <FileIcon size={18} />;
  }
}

function fileExtBadge(filename: string): string {
  const idx = filename.lastIndexOf('.');
  if (idx <= 0 || idx === filename.length - 1) return 'BIN';
  return filename.slice(idx + 1).toUpperCase().slice(0, 6);
}

function formatDayGroup(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '历史记录';
  const now = new Date();
  const sameDay = (a: Date, b: Date) =>
    a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate();
  if (sameDay(d, now)) return '今天';
  const yest = new Date(now);
  yest.setDate(now.getDate() - 1);
  if (sameDay(d, yest)) return '昨天';
  if (d.getFullYear() === now.getFullYear()) {
    return `${d.getMonth() + 1}月${d.getDate()}日`;
  }
  return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`;
}

function formatHm(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}

function summarizeReplyPreview(item: TransferItem): string {
  const sender = item.senderDeviceName || platformLabel(item.senderPlatform);
  if (item.messageKind === 'text') {
    return `${sender}: ${item.text.replace(/\s+/g, ' ').trim().slice(0, 80)}`;
  }
  const tag =
    item.messageKind === 'image'
      ? '[图片]'
      : item.messageKind === 'video'
        ? '[视频]'
        : '[文件]';
  return `${sender}: ${tag} ${item.originalFilename}${item.text ? ` · ${item.text.slice(0, 40)}` : ''}`;
}

function renderLinkedText(text: string): React.ReactNode {
  const parts = text.split(URL_SPLIT_RE);
  return parts.map((part, idx) => {
    if (/^https?:\/\//i.test(part)) {
      return (
        <a
          key={idx}
          href={part}
          target="_blank"
          rel="noopener noreferrer"
          className="m-tr-link"
          onClick={(e) => e.stopPropagation()}
        >
          {part}
        </a>
      );
    }
    return <React.Fragment key={idx}>{part}</React.Fragment>;
  });
}

const MobileTransferMediaPreview: React.FC<{
  client: PrivateSpaceMobileClient;
  item: TransferItem;
  onOpenPreview: (item: TransferItem) => void;
}> = ({ client, item, onOpenPreview }) => {
  const [thumbUrl, setThumbUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setThumbUrl(null);
    const load = item.hasThumbnail
      ? client.loadTransferThumbnailObjectUrl(item)
      : item.messageKind === 'image'
        ? client.loadTransferObjectUrl(item)
        : Promise.resolve<string | null>(null);

    load
      .then((u) => {
        if (!cancelled && u) setThumbUrl(u);
      })
      .catch(() => {
        if (!cancelled) setThumbUrl(null);
      });
    return () => {
      cancelled = true;
    };
  }, [client, item]);

  return (
    <button
      type="button"
      className="m-tr-media-box"
      onClick={() => onOpenPreview(item)}
      aria-label={`预览 ${item.originalFilename}`}
    >
      {thumbUrl ? (
        <img src={thumbUrl} alt={item.originalFilename} loading="lazy" />
      ) : (
        <div className="m-tr-media-fallback">
          {item.messageKind === 'video' ? <Film size={24} /> : <ImageIcon size={24} />}
          <span>{item.originalFilename || '解密预览中...'}</span>
        </div>
      )}
      {item.messageKind === 'video' && (
        <span className="m-tr-video-play">
          <Play size={18} fill="currentColor" />
        </span>
      )}
      <span className="m-tr-media-meta mono">{formatBytes(item.plainSize)}</span>
    </button>
  );
};

export const MobileTransferTab: React.FC<MobileTransferTabProps> = ({
  client,
  transfers,
  uploadingTasks,
  onSendText,
  onSendFiles,
  onUpdateTransfer,
  onDeletePermanent,
  onJumpToMedia,
  onInspectCipher,
  onCopyText,
  onNotify,
  initialSharedText,
  onClearSharedText,
}) => {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<MobileTransferFilter>('all');
  const [draft, setDraft] = useState('');
  const [sending, setSending] = useState(false);
  const [replyTarget, setReplyTarget] = useState<TransferItem | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [previewItem, setPreviewItem] = useState<TransferItem | null>(null);
  const [previewFullUrl, setPreviewFullUrl] = useState<string | null>(null);

  const listEndRef = useRef<HTMLDivElement | null>(null);
  const anyFileInputRef = useRef<HTMLInputElement | null>(null);
  const mediaInputRef = useRef<HTMLInputElement | null>(null);
  const prevCountRef = useRef<number>(0);

  const currentSessionId = client.getSessionId();
  const currentDeviceName = client.getDeviceName();
  const currentPlatform = client.getPlatform();

  useEffect(() => {
    if (initialSharedText?.content) {
      const merged = initialSharedText.title
        ? `${initialSharedText.title}\n${initialSharedText.content}`
        : initialSharedText.content;
      setDraft(merged);
      onClearSharedText?.();
    }
  }, [initialSharedText, onClearSharedText]);

  // Chronological order (oldest -> newest)
  const chronological = useMemo(() => {
    return [...transfers].sort((a, b) => {
      const cmp = a.createdAt.localeCompare(b.createdAt);
      if (cmp !== 0) return cmp;
      return a.syncSeq - b.syncSeq;
    });
  }, [transfers]);

  const counts = useMemo(() => {
    let text = 0;
    let file = 0;
    let media = 0;
    let pinned = 0;
    for (const t of chronological) {
      if (t.messageKind === 'text') text += 1;
      else if (t.messageKind === 'file') file += 1;
      else media += 1;
      if (t.isPinned) pinned += 1;
    }
    return { all: chronological.length, text, file, media, pinned };
  }, [chronological]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return chronological.filter((item) => {
      if (filter === 'text' && item.messageKind !== 'text') return false;
      if (filter === 'file' && item.messageKind !== 'file') return false;
      if (filter === 'media' && item.messageKind !== 'image' && item.messageKind !== 'video') {
        return false;
      }
      if (filter === 'pinned' && !item.isPinned) return false;
      if (!q) return true;
      return (
        item.text.toLowerCase().includes(q) ||
        item.originalFilename.toLowerCase().includes(q) ||
        item.mimeType.toLowerCase().includes(q) ||
        item.senderDeviceName.toLowerCase().includes(q) ||
        item.senderPlatform.toLowerCase().includes(q) ||
        item.sha256.toLowerCase().includes(q) ||
        item.tags.some((t) => t.toLowerCase().includes(q))
      );
    });
  }, [chronological, filter, query]);

  const groupedByDate = useMemo(() => {
    const groups: Array<{ label: string; items: TransferItem[] }> = [];
    for (const item of filtered) {
      const label = formatDayGroup(item.createdAt);
      const last = groups[groups.length - 1];
      if (!last || last.label !== label) {
        groups.push({ label, items: [item] });
      } else {
        last.items.push(item);
      }
    }
    return groups;
  }, [filtered]);

  useEffect(() => {
    if (!query && filter === 'all' && chronological.length !== prevCountRef.current) {
      prevCountRef.current = chronological.length;
      requestAnimationFrame(() => {
        listEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' });
      });
    }
  }, [chronological.length, filter, query]);

  useEffect(() => {
    if (!previewItem) {
      setPreviewFullUrl(null);
      return;
    }
    let cancelled = false;
    setPreviewFullUrl(null);
    client
      .loadTransferObjectUrl(previewItem)
      .then((url) => {
        if (!cancelled) setPreviewFullUrl(url);
      })
      .catch((err) => {
        if (!cancelled) {
          onNotify(err instanceof Error ? err.message : '加载解密原片失败');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [client, previewItem, onNotify]);

  const isSentByThisDevice = (item: TransferItem): boolean => {
    if (currentSessionId && item.senderSessionId) {
      return item.senderSessionId === currentSessionId;
    }
    return (
      item.senderPlatform === currentPlatform &&
      item.senderDeviceName === currentDeviceName
    );
  };

  const handleSubmitText = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed || sending) return;
    setSending(true);
    try {
      await onSendText({
        text: trimmed,
        replyToId: replyTarget?.id ?? null,
        replyPreview: replyTarget ? summarizeReplyPreview(replyTarget) : null,
      });
      setDraft('');
      setReplyTarget(null);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : '发送消息失败');
    } finally {
      setSending(false);
    }
  };

  const handlePickedFiles = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    const picked = Array.from(files);
    const caption = draft.trim();
    const reply = replyTarget;
    setDraft('');
    setReplyTarget(null);
    await onSendFiles(picked, {
      text: caption || undefined,
      replyToId: reply?.id ?? null,
      replyPreview: reply ? summarizeReplyPreview(reply) : null,
    });
  };

  const handleDownload = async (item: TransferItem) => {
    setDownloadingId(item.id);
    try {
      await client.downloadDecryptedTransfer(item);
      onNotify(`已解密导出：${item.originalFilename || '互传文件'}`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : '解密下载失败');
    } finally {
      setDownloadingId(null);
    }
  };

  return (
    <div className="m-tr-shell" data-testid="mobile-transfer-tab">
      {/* Top Search + Filter Header */}
      <div className="m-tr-header">
        <div className="m-search-row" style={{ marginBottom: 8 }}>
          <div className="m-search-box">
            <Search size={15} />
            <input
              id="m-transfer-search"
              type="search"
              className="m-search-input"
              placeholder="搜索聊天、文件名、扩展名或发送设备..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
            {query && (
              <button
                type="button"
                className="m-icon-btn"
                style={{ width: 24, height: 24 }}
                onClick={() => setQuery('')}
                aria-label="清空搜索"
              >
                <X size={13} />
              </button>
            )}
          </div>
        </div>

        <div className="m-chip-rail" style={{ marginBottom: 0 }}>
          {(
            [
              ['all', `全部 ${counts.all}`],
              ['text', `文本 ${counts.text}`],
              ['file', `文件 ${counts.file}`],
              ['media', `图影 ${counts.media}`],
              ['pinned', `星标 ${counts.pinned}`],
            ] as Array<[MobileTransferFilter, string]>
          ).map(([key, label]) => (
            <button
              key={key}
              type="button"
              className={`m-chip ${filter === key ? 'is-active' : ''}`}
              onClick={() => setFilter(key)}
            >
              <span>{label}</span>
            </button>
          ))}
        </div>
      </div>

      {/* Active Upload Progress Strip */}
      {uploadingTasks.length > 0 && (
        <div className="m-tr-upload-strip">
          {uploadingTasks.map((task) => (
            <div key={task.id} className="m-tr-upload-row">
              <div className="m-tr-upload-info">
                <Lock size={12} />
                <span className="m-tr-upload-name">{task.name}</span>
                <span className="mono">{Math.round(task.progress * 100)}%</span>
              </div>
              <div className="m-tr-upload-bar">
                <div
                  className="m-tr-upload-fill"
                  style={{ width: `${Math.max(5, Math.round(task.progress * 100))}%` }}
                />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Chronological Permanent Timeline */}
      <div className="m-tr-timeline">
        {groupedByDate.length === 0 ? (
          <div className="m-tr-empty">
            <div className="m-tr-empty-badge">
              <ShieldCheck size={22} />
            </div>
            <div className="m-tr-empty-title">
              {query || filter !== 'all' ? '未找到匹配的互传记录' : '多端零知识加密互传'}
            </div>
            <div className="m-tr-empty-desc">
              {query || filter !== 'all'
                ? '可尝试清空关键词或切换筛选标签查看全部永久记录。'
                : '电脑与手机随时互发任意格式文件或文字消息，多端实时同步、永久保存；互传的图片与视频自动进入加密图库与影院。'}
            </div>
          </div>
        ) : (
          groupedByDate.map((group) => (
            <div key={group.label} className="m-tr-day-section">
              <div className="m-tr-day-pill">
                <span>{group.label}</span>
              </div>

              {group.items.map((item) => {
                const self = isSentByThisDevice(item);
                const isQueued = item.syncSeq === 0;
                return (
                  <article
                    key={item.id}
                    className={`m-tr-row ${self ? 'is-self' : 'is-peer'}`}
                    data-testid={`mobile-transfer-item-${item.id}`}
                  >
                    <div className="m-tr-sender-line">
                      <span className="m-tr-device-tag">
                        <PlatformIcon platform={item.senderPlatform} />
                        <span>{item.senderDeviceName || platformLabel(item.senderPlatform)}</span>
                      </span>
                      <span className="m-tr-time mono">{formatHm(item.createdAt)}</span>
                      {item.isPinned && (
                        <Star
                          size={11}
                          fill="currentColor"
                          style={{ color: 'var(--m-amber)' }}
                        />
                      )}
                      {isQueued && <span className="m-tr-offline-tag">待同步</span>}
                    </div>

                    <div className="m-tr-bubble">
                      {item.replyPreview && (
                        <div className="m-tr-reply-quote">{item.replyPreview}</div>
                      )}

                      {/* Image or Video with Auto-Archive Link */}
                      {(item.messageKind === 'image' || item.messageKind === 'video') && (
                        <div className="m-tr-media-wrap">
                          <MobileTransferMediaPreview
                            client={client}
                            item={item}
                            onOpenPreview={(it) => setPreviewItem(it)}
                          />
                          <button
                            type="button"
                            className="m-tr-archive-pill"
                            onClick={() =>
                              onJumpToMedia(item.messageKind === 'video' ? 'video' : 'image')
                            }
                          >
                            <CheckCircle2 size={12} />
                            <span>
                              已自动存入{item.messageKind === 'video' ? '影院' : '相册'} · 查看
                            </span>
                            <ArrowUpRight size={12} />
                          </button>
                        </div>
                      )}

                      {/* Arbitrary File Card */}
                      {item.messageKind === 'file' && (
                        <div className="m-tr-file-card">
                          <div className="m-tr-file-icon">
                            <FileCategoryGlyph category={item.fileCategory} />
                            <span className="mono">{fileExtBadge(item.originalFilename)}</span>
                          </div>
                          <div className="m-tr-file-body">
                            <div className="m-tr-file-name">
                              {item.originalFilename || '未命名文件'}
                            </div>
                            <div className="m-tr-file-sub mono">
                              {formatBytes(item.plainSize)} · PSENC001
                              {item.sha256 ? ` · ${item.sha256.slice(0, 8)}` : ''}
                            </div>
                          </div>
                          <button
                            type="button"
                            className="m-tr-dl-btn"
                            disabled={downloadingId === item.id}
                            onClick={() => void handleDownload(item)}
                            aria-label={`解密下载 ${item.originalFilename}`}
                          >
                            <Download size={15} />
                          </button>
                        </div>
                      )}

                      {/* Caption / Chat Text */}
                      {item.text && (
                        <div className="m-tr-text">{renderLinkedText(item.text)}</div>
                      )}

                      {/* Compact Action Strip */}
                      <div className="m-tr-actions">
                        <button
                          type="button"
                          className="m-tr-act-btn"
                          onClick={() => setReplyTarget(item)}
                        >
                          <Reply size={12} />
                          <span>回复</span>
                        </button>
                        <button
                          type="button"
                          className={`m-tr-act-btn ${item.isPinned ? 'is-pinned' : ''}`}
                          onClick={() =>
                            void onUpdateTransfer(item.id, { isPinned: !item.isPinned })
                          }
                        >
                          <Star size={12} fill={item.isPinned ? 'currentColor' : 'none'} />
                          <span>{item.isPinned ? '已藏' : '收藏'}</span>
                        </button>
                        {item.text && (
                          <button
                            type="button"
                            className="m-tr-act-btn"
                            onClick={() => onCopyText(item.text, '互传文本')}
                          >
                            <Copy size={12} />
                            <span>复制</span>
                          </button>
                        )}
                        {(item.messageKind === 'image' || item.messageKind === 'video') && (
                          <button
                            type="button"
                            className="m-tr-act-btn"
                            disabled={downloadingId === item.id}
                            onClick={() => void handleDownload(item)}
                          >
                            <Download size={12} />
                            <span>原片</span>
                          </button>
                        )}
                        <button
                          type="button"
                          className="m-tr-act-btn"
                          onClick={() => onInspectCipher(item.id)}
                        >
                          <Lock size={12} />
                          <span>密文</span>
                        </button>
                        <button
                          type="button"
                          className="m-tr-act-btn is-danger"
                          onClick={() => void onDeletePermanent(item.id)}
                        >
                          <Trash2 size={12} />
                        </button>
                      </div>
                    </div>
                  </article>
                );
              })}
            </div>
          ))
        )}
        <div ref={listEndRef} />
      </div>

      {/* Bottom Encrypted Composer */}
      <form className="m-tr-composer" onSubmit={(e) => void handleSubmitText(e)}>
        {replyTarget && (
          <div className="m-tr-reply-bar">
            <Reply size={13} />
            <span className="m-tr-reply-bar-text">{summarizeReplyPreview(replyTarget)}</span>
            <button
              type="button"
              className="m-icon-btn"
              style={{ width: 22, height: 22 }}
              onClick={() => setReplyTarget(null)}
            >
              <X size={13} />
            </button>
          </div>
        )}

        <div className="m-tr-composer-row">
          <input
            ref={anyFileInputRef}
            type="file"
            multiple
            style={{ display: 'none' }}
            onChange={(e) => {
              void handlePickedFiles(e.target.files);
              e.target.value = '';
            }}
          />
          <input
            ref={mediaInputRef}
            type="file"
            accept="image/*,video/*"
            multiple
            style={{ display: 'none' }}
            onChange={(e) => {
              void handlePickedFiles(e.target.files);
              e.target.value = '';
            }}
          />

          <button
            type="button"
            className="m-tr-attach-btn"
            onClick={() => anyFileInputRef.current?.click()}
            title="发送任意文件"
            aria-label="发送任意文件"
          >
            <Paperclip size={17} />
          </button>

          <button
            type="button"
            className="m-tr-attach-btn"
            onClick={() => mediaInputRef.current?.click()}
            title="发送图片或视频（自动入库）"
            aria-label="发送图片或视频"
          >
            <ImageIcon size={17} />
          </button>

          <input
            id="m-transfer-composer-input"
            type="text"
            className="m-tr-input"
            placeholder="发送加密文字、链接或附言..."
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
          />

          <button
            id="m-transfer-send-btn"
            type="submit"
            className="m-tr-send-btn"
            disabled={!draft.trim() || sending}
            aria-label="发送"
          >
            <Send size={16} />
          </button>
        </div>
      </form>

      {/* Fullscreen Lightbox / Video Modal */}
      {previewItem && (
        <div className="m-sheet-backdrop" onClick={() => setPreviewItem(null)}>
          <div
            className="m-sheet"
            style={{ maxHeight: '90dvh' }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="m-sheet-header">
              <div style={{ minWidth: 0 }}>
                <div
                  style={{
                    fontWeight: 700,
                    fontSize: '0.92rem',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {previewItem.originalFilename}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--m-text-secondary)' }}>
                  来自 {previewItem.senderDeviceName} · {formatBytes(previewItem.plainSize)}
                </div>
              </div>
              <button
                type="button"
                className="m-icon-btn"
                onClick={() => setPreviewItem(null)}
              >
                <X size={18} />
              </button>
            </div>

            <div
              style={{
                background: '#0d1211',
                borderRadius: 12,
                overflow: 'hidden',
                minHeight: 220,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                marginBottom: 12,
              }}
            >
              {!previewFullUrl ? (
                <span style={{ color: '#cbd5d2', fontSize: '0.82rem' }}>
                  正在本地流式解密 PSENC001...
                </span>
              ) : previewItem.messageKind === 'video' ? (
                <video
                  src={previewFullUrl}
                  controls
                  autoPlay
                  playsInline
                  style={{ width: '100%', maxHeight: '58dvh' }}
                />
              ) : (
                <img
                  src={previewFullUrl}
                  alt={previewItem.originalFilename}
                  style={{ width: '100%', maxHeight: '58dvh', objectFit: 'contain' }}
                />
              )}
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                className="m-btn m-btn-secondary"
                style={{ flex: 1 }}
                onClick={() => {
                  const target = previewItem.messageKind === 'video' ? 'video' : 'image';
                  setPreviewItem(null);
                  onJumpToMedia(target);
                }}
              >
                <span>前往{previewItem.messageKind === 'video' ? '加密影院' : '加密相册'}</span>
              </button>
              <button
                type="button"
                className="m-btn m-btn-primary"
                style={{ flex: 1 }}
                onClick={() => void handleDownload(previewItem)}
              >
                <Download size={15} />
                <span>导出解密原片</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
