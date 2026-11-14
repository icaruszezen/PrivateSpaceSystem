import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  CheckSquare,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  FastForward,
  Film,
  FlipHorizontal,
  FolderPlus,
  Grid,
  Image as ImageIcon,
  Menu,
  Pause,
  PictureInPicture2,
  Play,
  Repeat,
  Rewind,
  RotateCcw,
  RotateCw,
  Search,
  ShieldCheck,
  Star,
  Trash2,
  Upload,
  X,
  ZoomIn,
  ZoomOut,
} from 'lucide-react';
import type { MediaAlbum, MediaItem, MediaKind, UpdateMediaRequest } from '@shared/types';
import { api } from '../api/client';
import { formatBytes, formatDuration, formatFullDateTime, formatShortDate } from '../utils/format';

interface MediaGalleryViewProps {
  kind: MediaKind;
  mediaItems: MediaItem[];
  albums: MediaAlbum[];
  onUploadFiles: (files: FileList | File[], albumId: string | null) => Promise<void>;
  uploadingQueue: Array<{ id: string; name: string; progress: number }>;
  onCreateAlbum: (name: string, kind: MediaKind) => Promise<MediaAlbum>;
  onDeleteAlbum: (id: string) => Promise<void>;
  onUpdateMedia: (id: string, patch: UpdateMediaRequest) => Promise<MediaItem>;
  onDeletePermanent: (id: string) => Promise<void>;
  onEmptyTrash: (kind: MediaKind) => Promise<void>;
  onInspectCipher: (id: string) => void;
  onOpenMobileMenu: () => void;
  onNotify: (msg: string) => void;
}

function useDecryptedMediaUrls(item: MediaItem | null): {
  fullUrl: string | null;
  thumbUrl: string | null;
} {
  const [fullUrl, setFullUrl] = useState<string | null>(null);
  const [thumbUrl, setThumbUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!item) {
      setFullUrl(null);
      setThumbUrl(null);
      return;
    }
    let cancelled = false;
    setFullUrl(null);
    setThumbUrl(null);

    void api
      .loadMediaObjectUrl(item)
      .then((url) => {
        if (!cancelled) setFullUrl(url);
      })
      .catch(() => undefined);

    if (item.hasThumbnail || item.itemType === 'image') {
      void api
        .loadThumbnailObjectUrl(item)
        .then((url) => {
          if (!cancelled) setThumbUrl(url);
        })
        .catch(() => undefined);
    }

    return () => {
      cancelled = true;
    };
  }, [item]);

  return { fullUrl, thumbUrl };
}

const EncryptedThumbImage: React.FC<{
  item: MediaItem;
  className: string;
}> = ({ item, className }) => {
  const [url, setUrl] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setUrl(null);
    void api
      .loadThumbnailObjectUrl(item)
      .then((loaded) => {
        if (!cancelled) setUrl(loaded);
      })
      .catch(() => undefined);
    return () => {
      cancelled = true;
    };
  }, [item]);

  if (!url) {
    return (
      <div className="pss-video-poster-fallback" aria-label={item.title}>
        {item.itemType === 'video' ? <Film size={26} /> : <ImageIcon size={24} />}
      </div>
    );
  }

  return <img src={url} alt={item.title} loading="lazy" className={className} />;
};

export const MediaGalleryView: React.FC<MediaGalleryViewProps> = ({
  kind,
  mediaItems,
  albums,
  onUploadFiles,
  uploadingQueue,
  onCreateAlbum,
  onDeleteAlbum,
  onUpdateMedia,
  onDeletePermanent,
  onEmptyTrash,
  onInspectCipher,
  onOpenMobileMenu,
  onNotify,
}) => {
  const [filterMode, setFilterMode] = useState<'all' | 'starred' | 'trash' | string>('all');
  const [search, setSearch] = useState('');
  const [compactGrid, setCompactGrid] = useState(false);
  const [batchMode, setBatchMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [draggingOver, setDraggingOver] = useState(false);
  const [newAlbumModal, setNewAlbumModal] = useState(false);
  const [newAlbumName, setNewAlbumName] = useState('');
  const [activeViewerId, setActiveViewerId] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const scopedItems = useMemo(
    () => mediaItems.filter((m) => m.itemType === kind),
    [mediaItems, kind],
  );

  const scopedAlbums = useMemo(
    () => albums.filter((a) => a.kind === kind || a.kind === 'mixed'),
    [albums, kind],
  );

  useEffect(() => {
    setFilterMode('all');
    setSearch('');
    setBatchMode(false);
    setSelectedIds(new Set());
    setActiveViewerId(null);
  }, [kind]);

  const visibleItems = useMemo(() => {
    const q = search.trim().toLowerCase();
    return scopedItems.filter((item) => {
      if (filterMode === 'trash') {
        if (!item.isTrashed) return false;
      } else {
        if (item.isTrashed) return false;
        if (filterMode === 'starred' && !item.isPinned) return false;
        if (
          filterMode !== 'all' &&
          filterMode !== 'starred' &&
          item.albumId !== filterMode
        ) {
          return false;
        }
      }

      if (q) {
        const hit =
          item.title.toLowerCase().includes(q) ||
          item.originalFilename.toLowerCase().includes(q) ||
          item.description.toLowerCase().includes(q) ||
          item.tags.some((t) => t.toLowerCase().includes(q));
        if (!hit) return false;
      }
      return true;
    });
  }, [scopedItems, filterMode, search]);

  const activeItemIndex = useMemo(
    () => visibleItems.findIndex((i) => i.id === activeViewerId),
    [visibleItems, activeViewerId],
  );
  const activeItem = activeItemIndex >= 0 ? visibleItems[activeItemIndex] : null;

  const currentAlbumFilterId =
    filterMode !== 'all' && filterMode !== 'starred' && filterMode !== 'trash'
      ? filterMode
      : null;

  function toggleBatchSelect(id: string) {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  async function handleBatchTrash() {
    const ids = [...selectedIds];
    for (const id of ids) {
      await onUpdateMedia(id, { isTrashed: true });
    }
    setSelectedIds(new Set());
    setBatchMode(false);
    onNotify(`已将 ${ids.length} 项加密媒体移入回收站`);
  }

  async function handleCreateAlbumSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!newAlbumName.trim()) return;
    const created = await onCreateAlbum(newAlbumName.trim(), kind);
    setNewAlbumName('');
    setNewAlbumModal(false);
    setFilterMode(created.id);
    onNotify(`加密${kind === 'image' ? '相册' : '视频合集'}已创建`);
  }

  return (
    <main
      className={`pss-gallery-pane ${draggingOver ? 'is-dragging' : ''}`}
      onDragOver={(e) => {
        e.preventDefault();
        setDraggingOver(true);
      }}
      onDragLeave={() => setDraggingOver(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDraggingOver(false);
        if (e.dataTransfer.files?.length) {
          void onUploadFiles(e.dataTransfer.files, currentAlbumFilterId);
        }
      }}
    >
      {/* Top Gallery Header */}
      <header className="pss-gallery-header">
        <div className="pss-gallery-title-row">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <button
              type="button"
              className="btn-icon mobile-only-btn"
              onClick={onOpenMobileMenu}
              aria-label="打开菜单"
            >
              <Menu size={17} />
            </button>
            <h1 className="pss-gallery-title">
              {kind === 'image' ? '私密加密图库' : '私密视频影院'}
            </h1>
            <span className="pss-crypto-pill">
              <ShieldCheck size={12} />
              <span>
                {kind === 'image'
                  ? 'PSENC001 64KiB 分块加密存储'
                  : 'HTTP 206 流式分块认证解密'}
              </span>
            </span>
          </div>

          <div className="pss-gallery-actions">
            {kind === 'image' && (
              <button
                type="button"
                className={`btn btn-secondary ${compactGrid ? 'is-active' : ''}`}
                onClick={() => setCompactGrid((v) => !v)}
              >
                <Grid size={14} />
                <span>{compactGrid ? '标准视图' : '紧凑网格'}</span>
              </button>
            )}
            <button
              type="button"
              className={`btn btn-secondary ${batchMode ? 'is-active' : ''}`}
              onClick={() => {
                setBatchMode((b) => !b);
                setSelectedIds(new Set());
              }}
            >
              <CheckSquare size={14} />
              <span>{batchMode ? '退出批量' : '批量管理'}</span>
            </button>
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => setNewAlbumModal(true)}
            >
              <FolderPlus size={14} />
              <span>{kind === 'image' ? '新建相册' : '新建视频合集'}</span>
            </button>

            <input
              ref={fileInputRef}
              type="file"
              multiple
              accept={kind === 'image' ? 'image/*' : 'video/*'}
              style={{ display: 'none' }}
              onChange={(e) => {
                if (e.target.files?.length) {
                  void onUploadFiles(e.target.files, currentAlbumFilterId);
                }
                e.target.value = '';
              }}
            />
            <button
              id={kind === 'image' ? 'upload-image-btn' : 'upload-video-btn'}
              type="button"
              className="btn btn-primary"
              onClick={() => fileInputRef.current?.click()}
            >
              <Upload size={14} />
              <span>{kind === 'image' ? '上传私密图片' : '分片上传私密视频'}</span>
            </button>
          </div>
        </div>

        <div className="pss-gallery-filter-bar">
          <div className="pss-album-pills">
            <button
              type="button"
              className={`pss-album-pill ${filterMode === 'all' ? 'is-active' : ''}`}
              onClick={() => setFilterMode('all')}
            >
              {kind === 'image' ? '全部图片' : '全部视频'} (
              {scopedItems.filter((i) => !i.isTrashed).length})
            </button>
            <button
              type="button"
              className={`pss-album-pill ${filterMode === 'starred' ? 'is-active' : ''}`}
              onClick={() => setFilterMode('starred')}
            >
              <Star size={12} /> 星标收藏
            </button>

            {scopedAlbums.map((alb) => (
              <div key={alb.id} style={{ display: 'inline-flex', alignItems: 'center', gap: 2 }}>
                <button
                  type="button"
                  className={`pss-album-pill ${filterMode === alb.id ? 'is-active' : ''}`}
                  onClick={() => setFilterMode(alb.id)}
                >
                  {alb.name}
                </button>
                {filterMode === alb.id && (
                  <button
                    type="button"
                    className="btn-icon"
                    style={{ width: 22, height: 22 }}
                    title="删除该相册分组（不删除媒体）"
                    onClick={() => {
                      void onDeleteAlbum(alb.id);
                      setFilterMode('all');
                    }}
                  >
                    <X size={12} />
                  </button>
                )}
              </div>
            ))}

            <button
              type="button"
              className={`pss-album-pill ${filterMode === 'trash' ? 'is-active' : ''}`}
              onClick={() => setFilterMode('trash')}
            >
              <Trash2 size={12} /> 回收站
            </button>
          </div>

          <div className="pss-gallery-search">
            <Search size={14} className="search-icon" />
            <input
              type="search"
              className="search-input"
              placeholder={
                kind === 'image'
                  ? '搜索加密标题、文件名或标签...'
                  : '搜索视频名称、编码或标签...'
              }
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>
        </div>

        {/* Active Resumable Upload Progress Queue */}
        {uploadingQueue.length > 0 && (
          <div className="pss-upload-queue">
            {uploadingQueue.map((task) => (
              <div key={task.id} className="pss-upload-row">
                <span className="mono" style={{ fontSize: '0.78rem' }}>
                  正在分片加密上传：{task.name}
                </span>
                <div className="pss-upload-bar-track">
                  <div
                    className="pss-upload-bar-fill"
                    style={{ width: `${Math.round(task.progress * 100)}%` }}
                  />
                </div>
                <span className="mono" style={{ fontSize: '0.75rem', color: 'var(--accent)' }}>
                  {Math.round(task.progress * 100)}%
                </span>
              </div>
            ))}
          </div>
        )}

        {batchMode && selectedIds.size > 0 && (
          <div className="pss-batch-toolbar">
            <span>已选中 {selectedIds.size} 项加密媒体</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                className="btn btn-danger"
                style={{ height: 30, fontSize: '0.78rem' }}
                onClick={() => void handleBatchTrash()}
              >
                <Trash2 size={13} />
                <span>批量移入回收站</span>
              </button>
            </div>
          </div>
        )}

        {filterMode === 'trash' && visibleItems.length > 0 && (
          <div className="pss-batch-toolbar">
            <span>回收站内共有 {visibleItems.length} 项待销毁密文分片</span>
            <button
              type="button"
              className="btn btn-danger"
              style={{ height: 30, fontSize: '0.78rem' }}
              onClick={() => void onEmptyTrash(kind)}
            >
              <Trash2 size={13} />
              <span>彻底擦除 .psenc 密文块</span>
            </button>
          </div>
        )}
      </header>

      {/* Gallery Grid Body */}
      <div className="pss-gallery-scroll">
        {visibleItems.length === 0 ? (
          <div className="editor-empty-state" style={{ minHeight: 420 }}>
            <div className="editor-empty-icon">
              {kind === 'image' ? <ImageIcon size={28} /> : <Film size={28} />}
            </div>
            <h2>
              {kind === 'image'
                ? '拖拽或上传你的私密原图'
                : '分片上传你的私密高清视频'}
            </h2>
            <p>
              {kind === 'image'
                ? '原图与缩略图均使用 64 KiB 分块 AES-256-GCM 封装为 .psenc 密文文件，文件名与 EXIF 尺寸全部端到端加密。'
                : '支持大体积 4K / 1080p MP4 视频断点续传、FFmpeg 自动加密海报提取，以及 HTTP 206 随机访问毫秒级拖动播放。'}
            </p>
            <button
              type="button"
              className="btn btn-primary"
              style={{ marginTop: 8 }}
              onClick={() => fileInputRef.current?.click()}
            >
              <Upload size={15} />
              <span>立即选择{kind === 'image' ? '图片' : '视频'}加密入库</span>
            </button>
          </div>
        ) : kind === 'image' ? (
          <div className={`pss-photo-grid ${compactGrid ? 'is-compact' : ''}`}>
            {visibleItems.map((item) => {
              const checked = selectedIds.has(item.id);
              return (
                <article
                  key={item.id}
                  className={`pss-media-card ${checked ? 'is-checked' : ''}`}
                  onClick={() => {
                    if (batchMode) toggleBatchSelect(item.id);
                    else setActiveViewerId(item.id);
                  }}
                >
                  <div className="pss-photo-thumb-wrap">
                    <EncryptedThumbImage item={item} className="pss-photo-thumb" />
                    {batchMode && (
                      <span className={`pss-check-dot ${checked ? 'is-on' : ''}`} />
                    )}
                    {item.width > 0 && (
                      <span className="pss-media-overlay-badge mono">
                        {item.width}×{item.height}
                      </span>
                    )}
                  </div>
                  <div className="pss-media-card-body">
                    <div className="pss-media-card-title-row">
                      <span className="pss-media-card-title">{item.title}</span>
                      <button
                        type="button"
                        className="pss-star-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          void onUpdateMedia(item.id, { isPinned: !item.isPinned });
                        }}
                        aria-label="收藏"
                      >
                        <Star
                          size={14}
                          fill={item.isPinned ? 'var(--amber)' : 'none'}
                          style={{ color: item.isPinned ? 'var(--amber)' : 'var(--text-tertiary)' }}
                        />
                      </button>
                    </div>
                    <div className="pss-media-card-sub mono">
                      <span>
                        {formatBytes(item.byteSize)} · {item.chunkCount} 加密块
                      </span>
                      <span>{formatShortDate(item.createdAt)}</span>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        ) : (
          <div className="pss-video-grid">
            {visibleItems.map((item) => {
              const checked = selectedIds.has(item.id);
              const resBadge =
                item.height >= 2160
                  ? '4K'
                  : item.height >= 1080
                    ? '1080p'
                    : item.height >= 720
                      ? '720p'
                      : item.width > 0
                        ? `${item.width}×${item.height}`
                        : 'MP4';
              return (
                <article
                  key={item.id}
                  className={`pss-media-card is-video ${checked ? 'is-checked' : ''}`}
                  onClick={() => {
                    if (batchMode) toggleBatchSelect(item.id);
                    else setActiveViewerId(item.id);
                  }}
                >
                  <div className="pss-video-poster-wrap">
                    {item.hasThumbnail ? (
                      <EncryptedThumbImage item={item} className="pss-video-poster" />
                    ) : (
                      <div className="pss-video-poster-fallback">
                        <Film size={32} />
                      </div>
                    )}
                    <div className="pss-video-play-circle">
                      <Play size={20} fill="#fff" />
                    </div>
                    <span className="pss-video-spec-badge mono">
                      {resBadge}
                      {item.videoCodec ? ` · ${item.videoCodec.toUpperCase()}` : ''}
                    </span>
                    <span className="pss-video-duration-badge mono">
                      {formatDuration(item.durationMs)}
                    </span>
                  </div>
                  <div className="pss-media-card-body">
                    <div className="pss-media-card-title-row">
                      <span className="pss-media-card-title">{item.title}</span>
                      <button
                        type="button"
                        className="pss-star-btn"
                        onClick={(e) => {
                          e.stopPropagation();
                          void onUpdateMedia(item.id, { isPinned: !item.isPinned });
                        }}
                      >
                        <Star
                          size={14}
                          fill={item.isPinned ? 'var(--amber)' : 'none'}
                          style={{ color: item.isPinned ? 'var(--amber)' : 'var(--text-tertiary)' }}
                        />
                      </button>
                    </div>
                    <div className="pss-media-card-sub mono">
                      <span>
                        {formatBytes(item.byteSize)} · {item.chunkCount} 密文块
                      </span>
                      <span>{formatShortDate(item.createdAt)}</span>
                    </div>
                  </div>
                </article>
              );
            })}
          </div>
        )}
      </div>

      {/* Create Encrypted Album Modal */}
      {newAlbumModal && (
        <div
          className="modal-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setNewAlbumModal(false);
          }}
        >
          <div className="modal-dialog" style={{ maxWidth: 420 }}>
            <header className="modal-header">
              <div className="modal-title-wrap">
                <FolderPlus size={18} style={{ color: 'var(--accent)' }} />
                <h2 className="modal-title">
                  {kind === 'image' ? '新建加密相册' : '新建私密视频合集'}
                </h2>
              </div>
              <button
                type="button"
                className="btn-icon"
                onClick={() => setNewAlbumModal(false)}
              >
                <X size={16} />
              </button>
            </header>
            <form className="modal-body" onSubmit={(e) => void handleCreateAlbumSubmit(e)}>
              <div className="field-group">
                <label className="field-label">相册 / 合集名称（AES-256-GCM 加密存储）</label>
                <input
                  type="text"
                  className="field-input"
                  autoFocus
                  placeholder={kind === 'image' ? '例如：北欧与海岸纪行' : '例如：家庭 4K 纪实影像'}
                  value={newAlbumName}
                  onChange={(e) => setNewAlbumName(e.target.value)}
                  required
                />
              </div>
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8, marginTop: 16 }}>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setNewAlbumModal(false)}
                >
                  取消
                </button>
                <button type="submit" className="btn btn-primary">
                  创建加密分组
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Darkroom Image Lightbox OR HTTP 206 Cinema Video Player */}
      {activeItem && (
        <MediaCinemaModal
          item={activeItem}
          index={activeItemIndex}
          total={visibleItems.length}
          albums={scopedAlbums}
          onPrev={
            visibleItems.length > 1
              ? () =>
                  setActiveViewerId(
                    visibleItems[(activeItemIndex - 1 + visibleItems.length) % visibleItems.length]
                      .id,
                  )
              : undefined
          }
          onNext={
            visibleItems.length > 1
              ? () =>
                  setActiveViewerId(visibleItems[(activeItemIndex + 1) % visibleItems.length].id)
              : undefined
          }
          onClose={() => setActiveViewerId(null)}
          onUpdateMedia={onUpdateMedia}
          onDeletePermanent={async (id) => {
            await onDeletePermanent(id);
            setActiveViewerId(null);
          }}
          onInspectCipher={(id) => {
            setActiveViewerId(null);
            onInspectCipher(id);
          }}
          onNotify={onNotify}
        />
      )}
    </main>
  );
};

interface MediaCinemaModalProps {
  item: MediaItem;
  index: number;
  total: number;
  albums: MediaAlbum[];
  onPrev?: () => void;
  onNext?: () => void;
  onClose: () => void;
  onUpdateMedia: (id: string, patch: UpdateMediaRequest) => Promise<MediaItem>;
  onDeletePermanent: (id: string) => Promise<void>;
  onInspectCipher: (id: string) => void;
  onNotify: (msg: string) => void;
}

const MediaCinemaModal: React.FC<MediaCinemaModalProps> = ({
  item,
  index,
  total,
  albums,
  onPrev,
  onNext,
  onClose,
  onUpdateMedia,
  onDeletePermanent,
  onInspectCipher,
  onNotify,
}) => {
  const [zoom, setZoom] = useState(1);
  const [rotate, setRotate] = useState(0);
  const [flipX, setFlipX] = useState(false);
  const [slideshow, setSlideshow] = useState(false);
  const { fullUrl, thumbUrl } = useDecryptedMediaUrls(item);

  // Video controls
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const [playbackRate, setPlaybackRate] = useState(1);
  const [loopVideo, setLoopVideo] = useState(false);

  // Editable encrypted metadata
  const [title, setTitle] = useState(item.title);
  const [albumId, setAlbumId] = useState<string>(item.albumId ?? '');
  const [tagsText, setTagsText] = useState(item.tags.join(', '));
  const [description, setDescription] = useState(item.description);

  useEffect(() => {
    setZoom(1);
    setRotate(0);
    setFlipX(false);
    setTitle(item.title);
    setAlbumId(item.albumId ?? '');
    setTagsText(item.tags.join(', '));
    setDescription(item.description);
  }, [item.id, item.title, item.albumId, item.tags, item.description]);

  useEffect(() => {
    if (!slideshow || !onNext) return;
    const t = window.setInterval(() => onNext(), 3500);
    return () => window.clearInterval(t);
  }, [slideshow, onNext]);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
      else if (e.key === 'ArrowLeft' && onPrev && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
        onPrev();
      } else if (e.key === 'ArrowRight' && onNext && document.activeElement?.tagName !== 'INPUT' && document.activeElement?.tagName !== 'TEXTAREA') {
        onNext();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose, onPrev, onNext]);

  async function handleSaveMeta(e: React.FormEvent) {
    e.preventDefault();
    await onUpdateMedia(item.id, {
      title: title.trim(),
      albumId: albumId || null,
      tags: tagsText
        .split(/[,，]/)
        .map((t) => t.trim())
        .filter(Boolean),
      description,
    });
    onNotify('端到端加密媒体元数据已保存');
  }

  function skipVideo(deltaSec: number) {
    if (!videoRef.current) return;
    videoRef.current.currentTime = Math.max(0, videoRef.current.currentTime + deltaSec);
  }

  function changeSpeed(rate: number) {
    setPlaybackRate(rate);
    if (videoRef.current) {
      videoRef.current.playbackRate = rate;
    }
  }

  return (
    <div className="pss-darkroom-overlay" role="dialog" aria-modal="true">
      {/* Left Darkroom Stage */}
      <div className="pss-darkroom-stage">
        <header className="pss-darkroom-topbar">
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
            <span className="pss-darkroom-title">{item.title}</span>
            <span className="pss-darkroom-counter mono">
              {item.itemType === 'video'
                ? `${item.width ? `${item.width}×${item.height} · ` : ''}${formatDuration(item.durationMs)}`
                : `${index + 1} / ${total}`}
            </span>
          </div>

          <div className="pss-darkroom-controls">
            {item.itemType === 'image' ? (
              <>
                <button
                  type="button"
                  className="pss-dk-btn"
                  onClick={() => setZoom((z) => Math.max(0.5, Number((z - 0.25).toFixed(2))))}
                  title="缩小"
                >
                  <ZoomOut size={15} />
                </button>
                <span className="pss-dk-readout mono">{Math.round(zoom * 100)}%</span>
                <button
                  type="button"
                  className="pss-dk-btn"
                  onClick={() => setZoom((z) => Math.min(3, Number((z + 0.25).toFixed(2))))}
                  title="放大"
                >
                  <ZoomIn size={15} />
                </button>
                <button
                  type="button"
                  className="pss-dk-btn"
                  onClick={() => setRotate((r) => r - 90)}
                  title="向左旋转 90°"
                >
                  <RotateCcw size={15} />
                </button>
                <button
                  type="button"
                  className="pss-dk-btn"
                  onClick={() => setRotate((r) => r + 90)}
                  title="向右旋转 90°"
                >
                  <RotateCw size={15} />
                </button>
                <button
                  type="button"
                  className="pss-dk-btn"
                  onClick={() => setFlipX((f) => !f)}
                  title="水平镜像翻转"
                >
                  <FlipHorizontal size={15} />
                </button>
                {total > 1 && (
                  <button
                    type="button"
                    className={`pss-dk-btn is-labeled ${slideshow ? 'is-active' : ''}`}
                    onClick={() => setSlideshow((s) => !s)}
                  >
                    {slideshow ? <Pause size={14} /> : <Play size={14} />}
                    <span>幻灯片</span>
                  </button>
                )}
              </>
            ) : (
              <>
                <button type="button" className="pss-dk-btn is-labeled" onClick={() => skipVideo(-10)}>
                  <Rewind size={14} />
                  <span>-10s</span>
                </button>
                <button type="button" className="pss-dk-btn is-labeled" onClick={() => skipVideo(10)}>
                  <FastForward size={14} />
                  <span>+10s</span>
                </button>
                {[0.75, 1, 1.25, 1.5, 2].map((r) => (
                  <button
                    key={r}
                    type="button"
                    className={`pss-dk-btn mono ${playbackRate === r ? 'is-active' : ''}`}
                    onClick={() => changeSpeed(r)}
                  >
                    {r}x
                  </button>
                ))}
                <button
                  type="button"
                  className={`pss-dk-btn ${loopVideo ? 'is-active' : ''}`}
                  onClick={() => setLoopVideo((l) => !l)}
                  title="循环播放"
                >
                  <Repeat size={14} />
                </button>
                <button
                  type="button"
                  className="pss-dk-btn is-labeled"
                  onClick={() => {
                    if (videoRef.current && 'requestPictureInPicture' in videoRef.current) {
                      void (
                        videoRef.current as HTMLVideoElement & {
                          requestPictureInPicture: () => Promise<void>;
                        }
                      ).requestPictureInPicture();
                    }
                  }}
                >
                  <PictureInPicture2 size={14} />
                  <span>画中画</span>
                </button>
              </>
            )}

            <button
              type="button"
              className="pss-dk-btn is-accent is-labeled"
              onClick={() => {
                void api
                  .downloadDecryptedMedia(item)
                  .then(() => onNotify('已在浏览器本地完成解密导出'))
                  .catch(() => onNotify('解密导出失败'));
              }}
            >
              <Download size={14} />
              <span>本地解密下载</span>
            </button>

            <button type="button" className="pss-dk-btn" onClick={onClose} aria-label="关闭检视器">
              <X size={16} />
            </button>
          </div>
        </header>

        <div className="pss-darkroom-canvas">
          {onPrev && (
            <button
              type="button"
              className="pss-darkroom-nav is-prev"
              onClick={onPrev}
              aria-label="上一项"
            >
              <ChevronLeft size={20} />
            </button>
          )}

          {item.itemType === 'image' ? (
            fullUrl || thumbUrl ? (
              <img
                src={fullUrl || thumbUrl || ''}
                alt={item.title}
                className="pss-darkroom-img"
                style={{
                  transform: `scale(${zoom}) rotate(${rotate}deg) scaleX(${flipX ? -1 : 1})`,
                }}
              />
            ) : (
              <div className="pss-video-poster-fallback" style={{ color: '#fff' }}>
                正在本地解密 PSENC001 原图...
              </div>
            )
          ) : fullUrl ? (
            <video
              key={item.id}
              ref={videoRef}
              src={fullUrl}
              poster={thumbUrl ?? undefined}
              controls
              autoPlay
              playsInline
              loop={loopVideo}
              className="pss-darkroom-video"
            />
          ) : (
            <div className="pss-video-poster-fallback" style={{ color: '#fff' }}>
              正在本地验证并解密 PSENC001 视频密文块...
            </div>
          )}

          {onNext && (
            <button
              type="button"
              className="pss-darkroom-nav is-next"
              onClick={onNext}
              aria-label="下一项"
            >
              <ChevronRight size={20} />
            </button>
          )}
        </div>
      </div>

      {/* Right Encrypted Metadata & Chunk Inspector Sidebar */}
      <aside className="pss-darkroom-inspector">
        <h3 className="pss-inspector-heading">
          {item.itemType === 'image' ? '加密元数据与存储检视' : '加密视频流与元数据'}
        </h3>

        <form className="pss-inspector-form" onSubmit={(e) => void handleSaveMeta(e)}>
          <div className="pss-dk-field">
            <label>加密标题</label>
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
            />
          </div>

          <div className="pss-dk-field">
            <label>{item.itemType === 'image' ? '所属相册' : '所属视频合集'}</label>
            <select value={albumId} onChange={(e) => setAlbumId(e.target.value)}>
              <option value="">未归入特定分组</option>
              {albums.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name}
                </option>
              ))}
            </select>
          </div>

          <div className="pss-dk-field">
            <label>加密标签（逗号分隔）</label>
            <input
              type="text"
              value={tagsText}
              onChange={(e) => setTagsText(e.target.value)}
              placeholder="旅行, 海岸, 4K"
            />
          </div>

          <div className="pss-dk-field">
            <label>私密备注</label>
            <textarea
              rows={3}
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="加密保存拍摄背景与备注..."
            />
          </div>

          <button type="submit" className="pss-dk-save-btn">
            保存加密元数据
          </button>
        </form>

        <div className="pss-dk-kv-table">
          <div className="pss-dk-kv">
            <span>存储加密算法</span>
            <span className="mono">
              {item.itemType === 'video' ? 'AES-256-GCM 206 Range' : 'PSENC001 AES-256-GCM'}
            </span>
          </div>
          <div className="pss-dk-kv">
            <span>认证密文块数</span>
            <span className="mono">
              {item.chunkCount} × {Math.round(item.chunkSize / 1024)} KiB
            </span>
          </div>
          <div className="pss-dk-kv">
            <span>分辨率{item.itemType === 'video' ? ' / 时长' : ''}</span>
            <span className="mono">
              {item.width > 0 ? `${item.width}×${item.height}` : '—'}
              {item.itemType === 'video' ? ` · ${formatDuration(item.durationMs)}` : ''}
            </span>
          </div>
          {item.itemType === 'video' && (
            <div className="pss-dk-kv">
              <span>音视频编码</span>
              <span className="mono">
                {(item.videoCodec || 'H264').toUpperCase()}
                {item.audioCodec ? ` / ${item.audioCodec.toUpperCase()}` : ''}
              </span>
            </div>
          )}
          <div className="pss-dk-kv">
            <span>原始大小 / 磁盘密文</span>
            <span className="mono">
              {formatBytes(item.byteSize)} / {formatBytes(item.encryptedSize)}
            </span>
          </div>
          <div className="pss-dk-kv">
            <span>采集时间</span>
            <span className="mono">{formatFullDateTime(item.takenAt)}</span>
          </div>
          <div className="pss-dk-kv">
            <span>同步游标</span>
            <span className="mono">Seq #{item.syncSeq}</span>
          </div>
          {item.sha256 && (
            <div className="pss-dk-kv">
              <span>SHA-256 指纹</span>
              <button
                type="button"
                className="pss-sha-copy mono"
                onClick={() => {
                  void navigator.clipboard.writeText(item.sha256);
                  onNotify('SHA-256 完整性指纹已复制');
                }}
              >
                <Copy size={11} />
                <span>{item.sha256.slice(0, 10)}…</span>
              </button>
            </div>
          )}
        </div>

        <button
          type="button"
          className="pss-dk-cipher-btn"
          onClick={() => onInspectCipher(item.id)}
        >
          <ShieldCheck size={14} />
          <span>透视 SQLite 与 .psenc 密文信封</span>
        </button>

        <div style={{ marginTop: 'auto', paddingTop: 12 }}>
          {!item.isTrashed ? (
            <button
              type="button"
              className="pss-dk-danger-btn"
              onClick={() => {
                void onUpdateMedia(item.id, { isTrashed: true }).then(() => {
                  onNotify('已移入媒体回收站');
                  onClose();
                });
              }}
            >
              <Trash2 size={14} />
              <span>移入回收站</span>
            </button>
          ) : (
            <button
              type="button"
              className="pss-dk-danger-btn"
              onClick={() => void onDeletePermanent(item.id)}
            >
              <Trash2 size={14} />
              <span>彻底擦除磁盘密文块</span>
            </button>
          )}
        </div>
      </aside>
    </div>
  );
};
