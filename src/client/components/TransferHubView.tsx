import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeftRight,
  ArrowUpRight,
  CheckCircle2,
  Copy,
  CornerUpLeft,
  Download,
  FileArchive,
  FileAudio,
  FileCode2,
  FileSpreadsheet,
  FileText,
  Film,
  FolderKanban,
  Image as ImageIcon,
  ImagePlus,
  Laptop,
  Menu,
  Package,
  Paperclip,
  Play,
  Search,
  Send,
  ShieldCheck,
  Smartphone,
  Star,
  Trash2,
  UploadCloud,
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
import { api } from '../api/client';
import { formatBytes, formatDuration, formatFullDateTime } from '../utils/format';

export type TransferFilterTab = 'all' | 'text' | 'file' | 'media' | 'pinned';
export type TransferPlatformFilter = 'all' | 'web' | 'android' | 'ios';
type CabinetTab = 'files' | 'media' | 'pinned';

interface UploadingTransferTask {
  id: string;
  name: string;
  progress: number;
}

interface TransferHubViewProps {
  transfers: TransferItem[];
  sseConnected: boolean;
  latestSyncSeq: number;
  uploadingTasks: UploadingTransferTask[];
  onSendText: (input: CreateTransferTextRequest) => Promise<TransferItem>;
  onSendFiles: (
    files: FileList | File[],
    opts?: { text?: string; replyToId?: string | null; replyPreview?: string | null },
  ) => Promise<void>;
  onUpdateTransfer: (id: string, patch: UpdateTransferRequest) => Promise<TransferItem>;
  onDeleteTransfer: (id: string) => Promise<void>;
  onJumpToMedia: (kind: MediaKind, mediaId: string | null) => void;
  onInspectCipher: (id: string) => void;
  onOpenMobileMenu: () => void;
  onNotify: (msg: string) => void;
}

function getFileExtensionBadge(filename: string): string {
  const clean = filename.trim();
  const idx = clean.lastIndexOf('.');
  if (idx <= 0 || idx === clean.length - 1) return 'FILE';
  return clean.slice(idx + 1).toUpperCase().slice(0, 5);
}

function getCategoryLabel(cat: TransferFileCategory | null): string {
  switch (cat) {
    case 'document':
      return '办公文档';
    case 'archive':
      return '压缩归档';
    case 'package':
      return '应用安装包';
    case 'audio':
      return '音频媒体';
    case 'code':
      return '代码与配置';
    case 'image':
      return '高清图片';
    case 'video':
      return '视频媒体';
    default:
      return '加密文件';
  }
}

function renderCategoryIcon(cat: TransferFileCategory | null) {
  switch (cat) {
    case 'archive':
      return <FileArchive size={14} />;
    case 'package':
      return <Package size={14} />;
    case 'audio':
      return <FileAudio size={14} />;
    case 'code':
      return <FileCode2 size={14} />;
    case 'document':
      return <FileSpreadsheet size={14} />;
    default:
      return <FileText size={14} />;
  }
}

function formatDateHeading(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '历史记录';
  const now = new Date();
  const todayKey = `${now.getFullYear()}-${now.getMonth()}-${now.getDate()}`;
  const yest = new Date(now);
  yest.setDate(now.getDate() - 1);
  const yestKey = `${yest.getFullYear()}-${yest.getMonth()}-${yest.getDate()}`;
  const itemKey = `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
  if (itemKey === todayKey) return '今天';
  if (itemKey === yestKey) return '昨天';
  return `${d.getFullYear()}年${d.getMonth() + 1}月${d.getDate()}日`;
}

function formatTimeClock(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString('zh-CN', {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

function renderPlatformLabel(platform: TransferDevicePlatform): string {
  switch (platform) {
    case 'android':
      return 'ANDROID';
    case 'ios':
      return 'iOS';
    case 'web':
      return 'WEB';
    case 'api':
      return 'CLI/API';
    default:
      return 'CLIENT';
  }
}

function renderRichTextWithLinks(text: string): React.ReactNode {
  const urlRegex = /(https?:\/\/[^\s<>"']+)/g;
  const parts = text.split(urlRegex);
  return parts.map((part, idx) => {
    if (/^https?:\/\//i.test(part)) {
      return (
        <a key={idx} href={part} target="_blank" rel="noreferrer">
          {part}
        </a>
      );
    }
    return <React.Fragment key={idx}>{part}</React.Fragment>;
  });
}

const TransferMediaInlineCard: React.FC<{
  item: TransferItem;
  onOpenLightbox: (item: TransferItem, fullUrl: string) => void;
  onJumpToMedia: (kind: MediaKind, mediaId: string | null) => void;
}> = ({ item, onOpenLightbox, onJumpToMedia }) => {
  const [thumbUrl, setThumbUrl] = useState<string | null>(null);
  const [videoPlayingUrl, setVideoPlayingUrl] = useState<string | null>(null);
  const [loadingMedia, setLoadingMedia] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api
      .loadTransferThumbnailObjectUrl(item)
      .then((url) => {
        if (!cancelled) setThumbUrl(url);
      })
      .catch(() => {
        if (item.messageKind === 'image') {
          api
            .loadTransferObjectUrl(item)
            .then((url) => {
              if (!cancelled) setThumbUrl(url);
            })
            .catch(() => undefined);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [item]);

  const handlePreviewClick = async () => {
    if (loadingMedia) return;
    setLoadingMedia(true);
    try {
      const fullUrl = await api.loadTransferObjectUrl(item);
      if (item.messageKind === 'video') {
        setVideoPlayingUrl(fullUrl);
      } else {
        onOpenLightbox(item, fullUrl);
      }
    } finally {
      setLoadingMedia(false);
    }
  };

  const mediaKind: MediaKind = item.messageKind === 'video' ? 'video' : 'image';

  return (
    <div className="pss-transfer-media-box">
      <div
        className="pss-transfer-media-frame"
        onClick={() => {
          if (!videoPlayingUrl) void handlePreviewClick();
        }}
        title={item.messageKind === 'video' ? '点击解密播放视频' : '点击查看高清解密原图'}
      >
        {videoPlayingUrl ? (
          <video src={videoPlayingUrl} controls autoPlay playsInline />
        ) : thumbUrl ? (
          <img src={thumbUrl} alt={item.originalFilename || '加密互传媒体'} loading="lazy" />
        ) : (
          <div
            style={{
              padding: '28px 20px',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: 6,
              color: 'var(--text-tertiary)',
              fontSize: '0.76rem',
            }}
          >
            {item.messageKind === 'video' ? <Film size={22} /> : <ImageIcon size={22} />}
            <span>{loadingMedia ? '正在本地解密...' : '点击解密预览'}</span>
          </div>
        )}

        {item.messageKind === 'video' && !videoPlayingUrl && (
          <>
            <span className="pss-transfer-play-overlay" aria-hidden="true">
              <Play size={18} fill="currentColor" />
            </span>
            <span className="pss-transfer-video-badge">
              <Film size={11} />
              <span>{formatDuration(item.durationMs)}</span>
            </span>
          </>
        )}
      </div>

      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: 8,
          fontSize: '0.74rem',
          color: 'var(--text-secondary)',
        }}
      >
        <span
          style={{
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            fontWeight: 560,
          }}
        >
          {item.originalFilename}
        </span>
        <span className="mono" style={{ color: 'var(--text-tertiary)', flexShrink: 0 }}>
          {item.width > 0 && item.height > 0 ? `${item.width}×${item.height} · ` : ''}
          {formatBytes(item.plainSize)}
        </span>
      </div>

      <button
        type="button"
        className="pss-transfer-library-pill"
        onClick={() => onJumpToMedia(mediaKind, item.linkedMediaId)}
      >
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
          <CheckCircle2 size={13} />
          <span>
            已自动归档至{mediaKind === 'video' ? '私密视频影院' : '私密加密图库'}（零重复密文块）
          </span>
        </span>
        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 2, flexShrink: 0 }}>
          <span>前往查看</span>
          <ArrowUpRight size={13} />
        </span>
      </button>
    </div>
  );
};

export const TransferHubView: React.FC<TransferHubViewProps> = ({
  transfers,
  sseConnected,
  latestSyncSeq,
  uploadingTasks,
  onSendText,
  onSendFiles,
  onUpdateTransfer,
  onDeleteTransfer,
  onJumpToMedia,
  onInspectCipher,
  onOpenMobileMenu,
  onNotify,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [filterTab, setFilterTab] = useState<TransferFilterTab>('all');
  const [platformFilter, setPlatformFilter] = useState<TransferPlatformFilter>('all');
  const [cabinetOpen, setCabinetOpen] = useState(true);
  const [cabinetTab, setCabinetTab] = useState<CabinetTab>('files');

  const [draftText, setDraftText] = useState('');
  const [sendingText, setSendingText] = useState(false);
  const [replyingTo, setReplyingTo] = useState<TransferItem | null>(null);
  const [draggingFiles, setDraggingFiles] = useState(false);
  const [highlightedId, setHighlightedId] = useState<string | null>(null);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [lightbox, setLightbox] = useState<{ item: TransferItem; url: string } | null>(null);

  const anyFileInputRef = useRef<HTMLInputElement | null>(null);
  const mediaFileInputRef = useRef<HTMLInputElement | null>(null);
  const timelineRef = useRef<HTMLDivElement | null>(null);
  const prevCountRef = useRef<number>(transfers.length);
  const dragDepthRef = useRef(0);

  const currentSession = api.getCurrentSession();
  const currentDeviceName = currentSession?.deviceName || '当前电脑 Web 端';

  // Sort chronological ascending for chat timeline
  const chronologicalTransfers = useMemo(
    () =>
      [...transfers].sort(
        (a, b) => a.createdAt.localeCompare(b.createdAt) || a.syncSeq - b.syncSeq,
      ),
    [transfers],
  );

  // Auto-scroll to bottom on initial mount or when new message arrives
  useEffect(() => {
    const el = timelineRef.current;
    if (!el) return;
    if (prevCountRef.current === 0 || transfers.length > prevCountRef.current) {
      requestAnimationFrame(() => {
        el.scrollTop = el.scrollHeight;
      });
    }
    prevCountRef.current = transfers.length;
  }, [transfers.length]);

  const typeCounts = useMemo(() => {
    let text = 0;
    let file = 0;
    let media = 0;
    let pinned = 0;
    for (const t of transfers) {
      if (t.messageKind === 'text') text += 1;
      else if (t.messageKind === 'file') file += 1;
      else media += 1;
      if (t.isPinned) pinned += 1;
    }
    return {
      all: transfers.length,
      text,
      file,
      media,
      pinned,
    };
  }, [transfers]);

  const filteredTransfers = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return chronologicalTransfers.filter((item) => {
      if (filterTab === 'text' && item.messageKind !== 'text') return false;
      if (filterTab === 'file' && item.messageKind !== 'file') return false;
      if (
        filterTab === 'media' &&
        item.messageKind !== 'image' &&
        item.messageKind !== 'video'
      ) {
        return false;
      }
      if (filterTab === 'pinned' && !item.isPinned) return false;

      if (platformFilter !== 'all') {
        if (platformFilter === 'web') {
          if (item.senderPlatform !== 'web' && item.senderPlatform !== 'api') return false;
        } else if (item.senderPlatform !== platformFilter) {
          return false;
        }
      }

      if (q) {
        const haystacks = [
          item.text,
          item.originalFilename,
          item.mimeType,
          item.senderDeviceName,
          item.senderPlatform,
          item.sha256,
          item.replyPreview ?? '',
          ...item.tags,
        ];
        const matched = haystacks.some((h) => h && h.toLowerCase().includes(q));
        if (!matched) return false;
      }

      return true;
    });
  }, [chronologicalTransfers, filterTab, platformFilter, searchQuery]);

  const cabinetItems = useMemo(() => {
    const desc = [...transfers].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
    if (cabinetTab === 'files') {
      return desc.filter((t) => t.messageKind === 'file');
    }
    if (cabinetTab === 'media') {
      return desc.filter((t) => t.messageKind === 'image' || t.messageKind === 'video');
    }
    return desc.filter((t) => t.isPinned);
  }, [transfers, cabinetTab]);

  const scrollToMessage = useCallback((id: string) => {
    const node = document.getElementById(`transfer-msg-${id}`);
    if (node) {
      node.scrollIntoView({ behavior: 'smooth', block: 'center' });
      setHighlightedId(id);
      window.setTimeout(() => {
        setHighlightedId((cur) => (cur === id ? null : cur));
      }, 1800);
    } else {
      setFilterTab('all');
      setPlatformFilter('all');
      setSearchQuery('');
      window.setTimeout(() => {
        const retryNode = document.getElementById(`transfer-msg-${id}`);
        retryNode?.scrollIntoView({ behavior: 'smooth', block: 'center' });
        setHighlightedId(id);
      }, 80);
    }
  }, []);

  const buildReplySnippet = (item: TransferItem): string => {
    const sender = item.senderDeviceName || renderPlatformLabel(item.senderPlatform);
    if (item.messageKind === 'text') {
      return `${sender}: ${item.text.replace(/\s+/g, ' ').slice(0, 80)}`;
    }
    const kindTag =
      item.messageKind === 'image'
        ? '[图片]'
        : item.messageKind === 'video'
          ? '[视频]'
          : '[文件]';
    return `${sender}: ${kindTag} ${item.originalFilename}`;
  };

  const handleSendDraft = async () => {
    const trimmed = draftText.trim();
    if (!trimmed || sendingText) return;
    setSendingText(true);
    try {
      await onSendText({
        text: trimmed,
        replyToId: replyingTo?.id ?? null,
        replyPreview: replyingTo ? buildReplySnippet(replyingTo) : null,
      });
      setDraftText('');
      setReplyingTo(null);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : '发送消息失败');
    } finally {
      setSendingText(false);
    }
  };

  const handleFilesSelected = async (fileList: FileList | File[] | null) => {
    if (!fileList || fileList.length === 0) return;
    const caption = draftText.trim();
    const replyTarget = replyingTo;
    if (caption) setDraftText('');
    if (replyTarget) setReplyingTo(null);

    await onSendFiles(fileList, {
      text: caption || undefined,
      replyToId: replyTarget?.id ?? null,
      replyPreview: replyTarget ? buildReplySnippet(replyTarget) : null,
    });
  };

  const handleDownloadItem = async (item: TransferItem) => {
    setDownloadingId(item.id);
    try {
      await api.downloadDecryptedTransfer(item);
      onNotify(`已本地解密导出：${item.originalFilename}`);
    } catch (err) {
      onNotify(err instanceof Error ? err.message : '解密下载失败');
    } finally {
      setDownloadingId(null);
    }
  };

  const handleTogglePin = async (item: TransferItem) => {
    try {
      await onUpdateTransfer(item.id, { isPinned: !item.isPinned });
      onNotify(item.isPinned ? '已取消星标收藏' : '已加入永久星标收藏');
    } catch (err) {
      onNotify(err instanceof Error ? err.message : '更新星标状态失败');
    }
  };

  return (
    <section className="pss-transfer-view" aria-label="多端加密互传中心">
      {/* Hidden File Inputs */}
      <input
        ref={anyFileInputRef}
        type="file"
        multiple
        style={{ display: 'none' }}
        onChange={(e) => {
          void handleFilesSelected(e.target.files);
          e.target.value = '';
        }}
      />
      <input
        ref={mediaFileInputRef}
        type="file"
        accept="image/*,video/*"
        multiple
        style={{ display: 'none' }}
        onChange={(e) => {
          void handleFilesSelected(e.target.files);
          e.target.value = '';
        }}
      />

      {/* Top Header */}
      <header className="pss-transfer-header">
        <div className="pss-transfer-title-group">
          <button
            type="button"
            className="btn-icon mobile-only-btn"
            onClick={onOpenMobileMenu}
            aria-label="打开空间导航"
          >
            <Menu size={17} />
          </button>

          <span className="pss-transfer-icon-badge" aria-hidden="true">
            <ArrowLeftRight size={17} />
          </span>

          <div className="pss-transfer-heading-text">
            <div className="pss-transfer-title-row">
              <h1 className="pss-transfer-title">多端加密互传</h1>
              <span className="pss-transfer-count-pill">{transfers.length} 条永久记录</span>
            </div>
            <div className="pss-transfer-subtitle">
              <span className="pss-transfer-live-pill">
                <span
                  className="pss-transfer-live-dot"
                  style={{ opacity: sseConnected ? 1 : 0.65 }}
                />
                <span>
                  {sseConnected ? 'SSE 多端实时互联' : '增量游标同步'} · Seq #{latestSyncSeq}
                </span>
              </span>
              <span>·</span>
              <span>当前设备：{currentDeviceName}</span>
              <span>·</span>
              <span>图片与视频自动入库</span>
            </div>
          </div>
        </div>

        <div className="pss-transfer-toolbar">
          <div className="pss-transfer-search-box">
            <Search size={14} className="pss-transfer-search-icon" />
            <input
              id="transfer-search-input"
              type="search"
              className="pss-transfer-search-input"
              placeholder="搜索聊天、文件名、设备、SHA256..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
            />
            {searchQuery && (
              <button
                type="button"
                className="pss-transfer-search-clear"
                onClick={() => setSearchQuery('')}
                aria-label="清除搜索"
              >
                <X size={13} />
              </button>
            )}
          </div>

          <select
            aria-label="按发送设备平台筛选"
            className="pss-transfer-select"
            value={platformFilter}
            onChange={(e) => setPlatformFilter(e.target.value as TransferPlatformFilter)}
          >
            <option value="all">全部设备端</option>
            <option value="web">电脑 Web / 桌面端</option>
            <option value="android">Android 手机端</option>
            <option value="ios">iPhone / iPad 端</option>
          </select>

          <button
            type="button"
            className={`btn btn-secondary ${cabinetOpen ? 'is-active' : ''}`}
            style={{ height: 33, padding: '0 11px', fontSize: '0.79rem' }}
            onClick={() => setCabinetOpen((v) => !v)}
            title="展开或收起永久文件与媒体索引柜"
          >
            <FolderKanban size={14} />
            <span>文件索引柜</span>
          </button>

          <button
            id="transfer-upload-btn"
            type="button"
            className="btn btn-primary"
            style={{ height: 33, padding: '0 12px', fontSize: '0.8rem' }}
            onClick={() => anyFileInputRef.current?.click()}
          >
            <UploadCloud size={15} />
            <span>发送文件</span>
          </button>
        </div>
      </header>

      {/* Filter Bar */}
      <div className="pss-transfer-filter-bar">
        <div className="pss-transfer-filter-pills" role="tablist" aria-label="记录类型筛选">
          {(
            [
              { key: 'all', label: `全部记录 (${typeCounts.all})` },
              { key: 'text', label: `聊天文本 (${typeCounts.text})` },
              { key: 'file', label: `文件传输 (${typeCounts.file})` },
              { key: 'media', label: `图片与视频 (${typeCounts.media})` },
              { key: 'pinned', label: `星标收藏 (${typeCounts.pinned})` },
            ] as Array<{ key: TransferFilterTab; label: string }>
          ).map((tab) => (
            <button
              key={tab.key}
              type="button"
              role="tab"
              aria-selected={filterTab === tab.key}
              className={`pss-transfer-filter-chip ${filterTab === tab.key ? 'is-active' : ''}`}
              onClick={() => setFilterTab(tab.key)}
            >
              <span>{tab.label}</span>
            </button>
          ))}
        </div>

        <div className="pss-transfer-filter-hint">
          <ShieldCheck size={13} style={{ color: 'var(--accent)' }} />
          <span>端到端零知识加密永久保存 · 支持拖拽任意文件或 Ctrl/⌘+V 直接粘贴截图发送</span>
        </div>
      </div>

      {/* Main Split Workspace */}
      <div className={`pss-transfer-workspace ${cabinetOpen ? '' : 'is-cabinet-closed'}`}>
        <div
          className="pss-transfer-main-col"
          onDragEnter={(e) => {
            if (e.dataTransfer.types.includes('Files')) {
              e.preventDefault();
              dragDepthRef.current += 1;
              setDraggingFiles(true);
            }
          }}
          onDragOver={(e) => {
            if (e.dataTransfer.types.includes('Files')) {
              e.preventDefault();
            }
          }}
          onDragLeave={(e) => {
            if (e.dataTransfer.types.includes('Files')) {
              e.preventDefault();
              dragDepthRef.current = Math.max(0, dragDepthRef.current - 1);
              if (dragDepthRef.current === 0) {
                setDraggingFiles(false);
              }
            }
          }}
          onDrop={(e) => {
            e.preventDefault();
            dragDepthRef.current = 0;
            setDraggingFiles(false);
            if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
              void handleFilesSelected(e.dataTransfer.files);
            }
          }}
        >
          {draggingFiles && (
            <div className="pss-transfer-dropzone-overlay">
              <UploadCloud size={32} />
              <strong>松开鼠标立即端到端加密互传</strong>
              <span>任意格式文件永久保存 · 图片与视频自动进入加密图库与视频影院</span>
            </div>
          )}

          {/* Chronological Stream */}
          <div ref={timelineRef} className="pss-transfer-timeline">
            {filteredTransfers.length === 0 ? (
              <div className="pss-transfer-empty">
                <div className="pss-transfer-empty-icon">
                  <ArrowLeftRight size={22} />
                </div>
                <h3>
                  {transfers.length === 0
                    ? '开启电脑与手机零知识加密互传'
                    : '没有找到匹配的互传记录'}
                </h3>
                <p>
                  {transfers.length === 0
                    ? '在电脑 Web、Android 手机或 iPhone 之间随时发送文字、链接、办公文档、安装包、高清原图与长视频。所有记录经 AES-256-GCM 加密永久留存，发送的图片与视频将自动归档至图库与视频影院。'
                    : '请尝试更换搜索关键词，或切换上方设备/类型筛选条件。'}
                </p>
                {transfers.length === 0 && (
                  <div style={{ display: 'flex', gap: 8, marginTop: 4 }}>
                    <button
                      type="button"
                      className="btn btn-primary"
                      onClick={() => anyFileInputRef.current?.click()}
                    >
                      <UploadCloud size={15} />
                      <span>选择文件跨端发送</span>
                    </button>
                  </div>
                )}
              </div>
            ) : (
              filteredTransfers.map((item, idx) => {
                const prev = idx > 0 ? filteredTransfers[idx - 1] : null;
                const dateLabel = formatDateHeading(item.createdAt);
                const prevDateLabel = prev ? formatDateHeading(prev.createdAt) : null;
                const showDateDivider = dateLabel !== prevDateLabel;

                const isSelf = currentSession?.id
                  ? item.senderSessionId === currentSession.id
                  : item.senderPlatform === 'web';
                const isMobileSender =
                  item.senderPlatform === 'android' || item.senderPlatform === 'ios';

                return (
                  <React.Fragment key={item.id}>
                    {showDateDivider && (
                      <div className="pss-transfer-date-divider">
                        <span>{dateLabel}</span>
                      </div>
                    )}

                    <article
                      id={`transfer-msg-${item.id}`}
                      className={`pss-transfer-row ${isSelf ? 'is-self' : 'is-peer'}`}
                    >
                      <div className="pss-transfer-meta-line">
                        <span
                          className={`pss-transfer-device-badge ${
                            isMobileSender ? 'is-mobile' : ''
                          }`}
                        >
                          {isMobileSender ? <Smartphone size={11} /> : <Laptop size={11} />}
                          <span>{item.senderDeviceName || '已授权设备'}</span>
                          <span className="mono" style={{ opacity: 0.78 }}>
                            · {renderPlatformLabel(item.senderPlatform)}
                          </span>
                        </span>
                        <span title={formatFullDateTime(item.createdAt)}>
                          {formatTimeClock(item.createdAt)}
                        </span>
                        <span className="mono" style={{ opacity: 0.7 }}>
                          #{item.syncSeq}
                        </span>
                      </div>

                      <div
                        className={`pss-transfer-bubble ${
                          highlightedId === item.id ? 'is-highlighted' : ''
                        }`}
                      >
                        {item.replyPreview && (
                          <div
                            className="pss-transfer-reply-quote"
                            onClick={() => {
                              if (item.replyToId) scrollToMessage(item.replyToId);
                            }}
                            title="点击定位至原记录"
                          >
                            ↵ {item.replyPreview}
                          </div>
                        )}

                        {/* File Card */}
                        {item.messageKind === 'file' && (
                          <div className="pss-transfer-file-card">
                            <div className="pss-transfer-file-left">
                              <div className="pss-transfer-file-ext">
                                {renderCategoryIcon(item.fileCategory)}
                                <span>{getFileExtensionBadge(item.originalFilename)}</span>
                              </div>
                              <div className="pss-transfer-file-info">
                                <div
                                  className="pss-transfer-filename"
                                  title={item.originalFilename}
                                >
                                  {item.originalFilename}
                                </div>
                                <div className="pss-transfer-file-sub">
                                  <span>{getCategoryLabel(item.fileCategory)}</span>
                                  <span>·</span>
                                  <span className="mono">{formatBytes(item.plainSize)}</span>
                                  {item.sha256 && (
                                    <>
                                      <span>·</span>
                                      <span className="mono" title={`SHA-256: ${item.sha256}`}>
                                        SHA256:{item.sha256.slice(0, 8)}
                                      </span>
                                    </>
                                  )}
                                </div>
                              </div>
                            </div>

                            <button
                              type="button"
                              className="btn btn-secondary"
                              style={{ height: 31, padding: '0 10px', fontSize: '0.76rem', flexShrink: 0 }}
                              disabled={downloadingId === item.id}
                              onClick={() => void handleDownloadItem(item)}
                            >
                              <Download size={13} />
                              <span>{downloadingId === item.id ? '解密中...' : '解密下载'}</span>
                            </button>
                          </div>
                        )}

                        {/* Image or Video Inline Preview + Auto-Ingest Jump Badge */}
                        {(item.messageKind === 'image' || item.messageKind === 'video') && (
                          <TransferMediaInlineCard
                            item={item}
                            onOpenLightbox={(target, url) => setLightbox({ item: target, url })}
                            onJumpToMedia={onJumpToMedia}
                          />
                        )}

                        {/* Text / Caption */}
                        {item.text && (
                          <div className="pss-transfer-text-body">
                            {renderRichTextWithLinks(item.text)}
                          </div>
                        )}

                        {/* Action Bar */}
                        <div className="pss-transfer-actions">
                          <div className="pss-transfer-action-group">
                            {item.text && (
                              <button
                                type="button"
                                className="pss-transfer-act-btn"
                                onClick={() => {
                                  void navigator.clipboard.writeText(item.text);
                                  onNotify('文本内容已复制到剪贴板');
                                }}
                              >
                                <Copy size={11} />
                                <span>复制</span>
                              </button>
                            )}

                            {item.messageKind !== 'text' && (
                              <button
                                type="button"
                                className="pss-transfer-act-btn"
                                onClick={() => void handleDownloadItem(item)}
                              >
                                <Download size={11} />
                                <span>保存原件</span>
                              </button>
                            )}

                            <button
                              type="button"
                              className="pss-transfer-act-btn"
                              onClick={() => setReplyingTo(item)}
                            >
                              <CornerUpLeft size={11} />
                              <span>引用</span>
                            </button>

                            <button
                              type="button"
                              className={`pss-transfer-act-btn ${
                                item.isPinned ? 'is-starred' : ''
                              }`}
                              onClick={() => void handleTogglePin(item)}
                            >
                              <Star
                                size={11}
                                fill={item.isPinned ? 'currentColor' : 'none'}
                              />
                              <span>{item.isPinned ? '已收藏' : '收藏'}</span>
                            </button>
                          </div>

                          <div className="pss-transfer-action-group">
                            <button
                              type="button"
                              className="pss-transfer-act-btn is-cipher"
                              onClick={() => onInspectCipher(item.id)}
                              title="透视该互传记录的 SQLite 密文信封与 .psenc 分块元数据"
                            >
                              <ShieldCheck size={11} />
                              <span>AES-256-GCM</span>
                            </button>

                            <button
                              type="button"
                              className="pss-transfer-act-btn is-danger"
                              onClick={() => void onDeleteTransfer(item.id)}
                              title={
                                item.linkedMediaId
                                  ? '删除此互传气泡（已自动归档至图库/影院的媒体文件仍安全保留）'
                                  : '彻底销毁此互传密文记录'
                              }
                            >
                              <Trash2 size={11} />
                            </button>
                          </div>
                        </div>
                      </div>
                    </article>
                  </React.Fragment>
                );
              })
            )}
          </div>

          {/* Active Upload Progress Strip */}
          {uploadingTasks.length > 0 && (
            <div className="pss-transfer-upload-strip">
              {uploadingTasks.map((task) => (
                <div key={task.id} className="pss-transfer-upload-item">
                  <UploadCloud size={13} style={{ color: 'var(--accent)', flexShrink: 0 }} />
                  <span
                    style={{
                      maxWidth: 240,
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    正在分块加密发送：{task.name}
                  </span>
                  <div className="pss-transfer-upload-bar">
                    <div
                      className="pss-transfer-upload-fill"
                      style={{ width: `${Math.round(task.progress * 100)}%` }}
                    />
                  </div>
                  <span className="mono">{Math.round(task.progress * 100)}%</span>
                </div>
              ))}
            </div>
          )}

          {/* Composer Dock */}
          <footer className="pss-transfer-composer">
            {replyingTo && (
              <div className="pss-transfer-reply-banner">
                <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  正在引用回复：{buildReplySnippet(replyingTo)}
                </span>
                <button
                  type="button"
                  className="btn-icon"
                  style={{ width: 20, height: 20 }}
                  onClick={() => setReplyingTo(null)}
                  aria-label="取消引用回复"
                >
                  <X size={13} />
                </button>
              </div>
            )}

            <div className="pss-transfer-composer-tools">
              <div className="pss-transfer-tool-btns">
                <button
                  type="button"
                  className="pss-transfer-tool-btn"
                  onClick={() => anyFileInputRef.current?.click()}
                >
                  <Paperclip size={13} />
                  <span>发送任意文件 (PDF / ZIP / APK / 文档)</span>
                </button>

                <button
                  type="button"
                  className="pss-transfer-tool-btn"
                  onClick={() => mediaFileInputRef.current?.click()}
                >
                  <ImagePlus size={13} />
                  <span>发送图片 / 视频（自动入库）</span>
                </button>
              </div>

              <span style={{ fontSize: '0.72rem', color: 'var(--text-tertiary)' }}>
                Enter 加密发送 · Shift + Enter 换行
              </span>
            </div>

            <div className="pss-transfer-input-row">
              <textarea
                id="transfer-composer-input"
                className="pss-transfer-textarea"
                rows={2}
                placeholder="输入跨端聊天消息、备忘口令或链接，支持直接粘贴剪贴板图片/文件发送到手机与电脑..."
                value={draftText}
                onChange={(e) => setDraftText(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey && !e.nativeEvent.isComposing) {
                    e.preventDefault();
                    void handleSendDraft();
                  }
                }}
                onPaste={(e) => {
                  const files = e.clipboardData?.files;
                  if (files && files.length > 0) {
                    e.preventDefault();
                    void handleFilesSelected(files);
                  }
                }}
              />

              <button
                id="transfer-send-btn"
                type="button"
                className="btn btn-primary pss-transfer-send-btn"
                disabled={!draftText.trim() || sendingText}
                onClick={() => void handleSendDraft()}
              >
                <Send size={15} />
                <span>{sendingText ? '发送中...' : '发送'}</span>
              </button>
            </div>
          </footer>
        </div>

        {/* Right Collapsible Permanent File & Media Cabinet */}
        {cabinetOpen && (
          <aside className="pss-transfer-cabinet" aria-label="永久文件与星标索引柜">
            <div className="pss-transfer-cabinet-head">
              <div className="pss-transfer-cabinet-title">
                <span>永久互传索引柜</span>
                <span className="mono" style={{ fontSize: '0.71rem', color: 'var(--text-tertiary)' }}>
                  E2EE 永久留存
                </span>
              </div>

              <div className="pss-transfer-cabinet-tabs">
                <button
                  type="button"
                  className={`pss-transfer-cabinet-tab ${cabinetTab === 'files' ? 'is-active' : ''}`}
                  onClick={() => setCabinetTab('files')}
                >
                  文件 ({typeCounts.file})
                </button>
                <button
                  type="button"
                  className={`pss-transfer-cabinet-tab ${cabinetTab === 'media' ? 'is-active' : ''}`}
                  onClick={() => setCabinetTab('media')}
                >
                  图影 ({typeCounts.media})
                </button>
                <button
                  type="button"
                  className={`pss-transfer-cabinet-tab ${cabinetTab === 'pinned' ? 'is-active' : ''}`}
                  onClick={() => setCabinetTab('pinned')}
                >
                  收藏 ({typeCounts.pinned})
                </button>
              </div>
            </div>

            <div className="pss-transfer-cabinet-list">
              {cabinetItems.length === 0 ? (
                <div
                  style={{
                    padding: '26px 12px',
                    textAlign: 'center',
                    fontSize: '0.76rem',
                    color: 'var(--text-tertiary)',
                  }}
                >
                  {cabinetTab === 'files'
                    ? '暂无互传文件记录'
                    : cabinetTab === 'media'
                      ? '暂无互传图片或视频'
                      : '点击消息下方「收藏」可固定常用文本或文件'}
                </div>
              ) : (
                cabinetItems.map((cItem) => (
                  <div key={cItem.id} className="pss-transfer-cabinet-item">
                    <div className="pss-transfer-cabinet-item-top">
                      <span
                        className="pss-transfer-cabinet-name"
                        style={{ cursor: 'pointer' }}
                        onClick={() => scrollToMessage(cItem.id)}
                        title="点击在时间轴中定位"
                      >
                        {cItem.messageKind === 'text'
                          ? cItem.text.replace(/\s+/g, ' ').slice(0, 40) || '文本消息'
                          : cItem.originalFilename}
                      </span>

                      {cItem.messageKind !== 'text' && (
                        <button
                          type="button"
                          className="btn-icon"
                          style={{ width: 22, height: 22, flexShrink: 0 }}
                          onClick={() => void handleDownloadItem(cItem)}
                          title="解密下载原件"
                        >
                          <Download size={12} />
                        </button>
                      )}
                    </div>

                    <div className="pss-transfer-cabinet-meta">
                      <span>
                        {cItem.senderDeviceName || renderPlatformLabel(cItem.senderPlatform)}
                        {cItem.plainSize > 0 ? ` · ${formatBytes(cItem.plainSize)}` : ''}
                      </span>
                      <span>{formatDateHeading(cItem.createdAt)}</span>
                    </div>

                    {(cItem.messageKind === 'image' || cItem.messageKind === 'video') && (
                      <button
                        type="button"
                        style={{
                          alignSelf: 'flex-start',
                          fontSize: '0.69rem',
                          color: 'var(--accent)',
                          fontWeight: 600,
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 3,
                        }}
                        onClick={() =>
                          onJumpToMedia(
                            cItem.messageKind === 'video' ? 'video' : 'image',
                            cItem.linkedMediaId,
                          )
                        }
                      >
                        <span>在{cItem.messageKind === 'video' ? '影院' : '图库'}中查看</span>
                        <ArrowUpRight size={11} />
                      </button>
                    )}
                  </div>
                ))
              )}
            </div>
          </aside>
        )}
      </div>

      {/* High-Res Image Lightbox Modal */}
      {lightbox && (
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setLightbox(null);
          }}
        >
          <div
            style={{
              maxWidth: '90vw',
              maxHeight: '88vh',
              background: 'var(--bg-elevated)',
              borderRadius: 'var(--radius-lg)',
              border: '1px solid var(--border-default)',
              padding: 14,
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
              boxShadow: 'var(--shadow-lg)',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                gap: 12,
              }}
            >
              <div style={{ fontSize: '0.86rem', fontWeight: 620 }}>
                {lightbox.item.originalFilename} · {formatBytes(lightbox.item.plainSize)}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ height: 30, fontSize: '0.76rem' }}
                  onClick={() =>
                    onJumpToMedia('image', lightbox.item.linkedMediaId)
                  }
                >
                  <span>前往加密图库</span>
                  <ArrowUpRight size={13} />
                </button>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ height: 30, fontSize: '0.76rem' }}
                  onClick={() => void handleDownloadItem(lightbox.item)}
                >
                  <Download size={13} />
                  <span>保存原图</span>
                </button>
                <button
                  type="button"
                  className="btn-icon"
                  onClick={() => setLightbox(null)}
                  aria-label="关闭原图预览"
                >
                  <X size={16} />
                </button>
              </div>
            </div>
            <img
              src={lightbox.url}
              alt={lightbox.item.originalFilename}
              style={{
                maxWidth: '84vw',
                maxHeight: '76vh',
                objectFit: 'contain',
                borderRadius: 8,
                background: 'var(--bg-subtle)',
              }}
            />
          </div>
        </div>
      )}
    </section>
  );
};
