import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Camera,
  CheckSquare,
  ChevronLeft,
  ChevronRight,
  Download,
  Edit3,
  FlipHorizontal,
  FolderPlus,
  Grid,
  Image as ImageIcon,
  Pause,
  Play,
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
import type { MediaAlbum, MediaItem, UpdateMediaRequest } from '@shared/types';
import type { PrivateSpaceMobileClient } from '../syncClient';
import { formatBytes, formatDateTime } from '../utils/mobileFormat';

interface MobilePhotosTabProps {
  client: PrivateSpaceMobileClient;
  photos: MediaItem[];
  albums: MediaAlbum[];
  uploadingTasks: Array<{ id: string; name: string; progress: number }>;
  onUploadFiles: (files: FileList | File[], albumId: string | null) => Promise<void>;
  onCreateAlbum: (name: string) => Promise<MediaAlbum>;
  onDeleteAlbum: (id: string) => Promise<void>;
  onUpdateMedia: (id: string, patch: UpdateMediaRequest) => Promise<void>;
  onDeletePermanent: (id: string) => Promise<void>;
  onEmptyTrash: () => Promise<void>;
  onInspectCipher: (id: string) => void;
  onNotify: (msg: string) => void;
}

export const MobilePhotosTab: React.FC<MobilePhotosTabProps> = ({
  client,
  photos,
  albums,
  uploadingTasks,
  onUploadFiles,
  onCreateAlbum,
  onDeleteAlbum,
  onUpdateMedia,
  onDeletePermanent,
  onEmptyTrash,
  onInspectCipher,
  onNotify,
}) => {
  const [filter, setFilter] = useState<'all' | 'starred' | 'trash' | string>('all');
  const [search, setSearch] = useState('');
  const [compact, setCompact] = useState(false);
  const [batchMode, setBatchMode] = useState(false);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());

  const [newAlbumSheet, setNewAlbumSheet] = useState(false);
  const [albumNameInput, setAlbumNameInput] = useState('');

  // Darkroom Lightbox state
  const [viewerId, setViewerId] = useState<string | null>(null);
  const [zoom, setZoom] = useState(1);
  const [rotateDeg, setRotateDeg] = useState(0);
  const [flipped, setFlipped] = useState(false);
  const [slideshow, setSlideshow] = useState(false);
  const [editSheetOpen, setEditSheetOpen] = useState(false);

  // Edit metadata form
  const [eTitle, setETitle] = useState('');
  const [eAlbumId, setEAlbumId] = useState<string>('');
  const [eTags, setETags] = useState('');
  const [eDesc, setEDesc] = useState('');

  const galleryInputRef = useRef<HTMLInputElement | null>(null);
  const cameraInputRef = useRef<HTMLInputElement | null>(null);

  const imageAlbums = useMemo(
    () => albums.filter((a) => a.kind === 'image' || a.kind === 'mixed'),
    [albums],
  );

  const visiblePhotos = useMemo(() => {
    const q = search.trim().toLowerCase();
    return photos
      .filter((item) => {
        if (filter === 'trash') {
          if (!item.isTrashed) return false;
        } else {
          if (item.isTrashed) return false;
          if (filter === 'starred' && !item.isPinned) return false;
          if (filter !== 'all' && filter !== 'starred' && item.albumId !== filter) {
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
      })
      .sort((a, b) => {
        if (a.isPinned !== b.isPinned) return a.isPinned ? -1 : 1;
        return b.createdAt.localeCompare(a.createdAt);
      });
  }, [photos, filter, search]);

  const activeIdx = useMemo(
    () => (viewerId ? visiblePhotos.findIndex((p) => p.id === viewerId) : -1),
    [visiblePhotos, viewerId],
  );
  const activePhoto = activeIdx >= 0 ? visiblePhotos[activeIdx] : null;

  useEffect(() => {
    setZoom(1);
    setRotateDeg(0);
    setFlipped(false);
  }, [viewerId]);

  useEffect(() => {
    if (!slideshow || !activePhoto || visiblePhotos.length <= 1) return;
    const t = window.setInterval(() => {
      const nextIdx = (activeIdx + 1) % visiblePhotos.length;
      setViewerId(visiblePhotos[nextIdx].id);
    }, 3200);
    return () => window.clearInterval(t);
  }, [slideshow, activePhoto, activeIdx, visiblePhotos]);

  const currentAlbumId =
    filter !== 'all' && filter !== 'starred' && filter !== 'trash' ? filter : null;

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const handleBatchTrash = async () => {
    const ids = [...selectedIds];
    for (const id of ids) {
      await onUpdateMedia(id, { isTrashed: true });
    }
    setSelectedIds(new Set());
    setBatchMode(false);
    onNotify(`已将 ${ids.length} 张照片移入回收站`);
  };

  const openEditSheet = (item: MediaItem) => {
    setETitle(item.title);
    setEAlbumId(item.albumId ?? '');
    setETags(item.tags.join(', '));
    setEDesc(item.description);
    setEditSheetOpen(true);
  };

  const handleSaveMeta = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!activePhoto) return;
    await onUpdateMedia(activePhoto.id, {
      title: eTitle.trim() || activePhoto.title,
      albumId: eAlbumId || null,
      tags: eTags
        .split(/[,，]/)
        .map((t) => t.trim())
        .filter(Boolean),
      description: eDesc,
    });
    setEditSheetOpen(false);
    onNotify('加密图片元数据已更新');
  };

  const DecryptedPhotoImg: React.FC<{
    item: MediaItem;
    mode: 'thumb' | 'full';
    style?: React.CSSProperties;
  }> = ({ item, mode, style }) => {
    const [src, setSrc] = useState<string | null>(null);
    useEffect(() => {
      let cancelled = false;
      const promise =
        mode === 'thumb'
          ? client.loadThumbnailObjectUrl(item)
          : client.loadMediaObjectUrl(item);
      promise
        .then((url) => {
          if (!cancelled) setSrc(url);
        })
        .catch(() => {
          if (!cancelled) setSrc(null);
        });
      return () => {
        cancelled = true;
      };
    }, [item, mode]);

    if (!src) {
      return (
        <div
          style={{
            width: '100%',
            height: '100%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: 'var(--m-text-tertiary)',
            fontSize: '0.72rem',
            ...style,
          }}
        >
          解密中…
        </div>
      );
    }
    return <img src={src} alt={item.title} loading="lazy" style={style} />;
  };

  return (
    <>
      {/* Upload Queue Progress */}
      {uploadingTasks.map((task) => (
        <div key={task.id} className="m-upload-banner">
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              fontSize: '0.78rem',
              fontWeight: 600,
            }}
          >
            <span>正在分片加密上传：{task.name}</span>
            <span className="mono">{Math.round(task.progress * 100)}%</span>
          </div>
          <div className="m-progress-track">
            <div
              className="m-progress-fill"
              style={{ width: `${Math.max(4, Math.round(task.progress * 100))}%` }}
            />
          </div>
        </div>
      ))}

      {/* Search & Controls */}
      <div className="m-search-row">
        <div className="m-search-box">
          <Search size={15} />
          <input
            type="search"
            className="m-search-input"
            placeholder="搜索加密原图名称、描述或标签..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <button
          type="button"
          className={`m-icon-btn ${compact ? 'is-active' : ''}`}
          onClick={() => setCompact((v) => !v)}
          aria-label="切换紧凑网格"
        >
          <Grid size={17} />
        </button>
        <button
          type="button"
          className={`m-icon-btn ${batchMode ? 'is-active' : ''}`}
          onClick={() => {
            setBatchMode((b) => !b);
            setSelectedIds(new Set());
          }}
          aria-label="批量选择"
        >
          <CheckSquare size={17} />
        </button>
      </div>

      {/* Album Filter Rail */}
      <div className="m-chip-rail">
        <button
          type="button"
          className={`m-chip ${filter === 'all' ? 'is-active' : ''}`}
          onClick={() => setFilter('all')}
        >
          全部原图
        </button>
        <button
          type="button"
          className={`m-chip ${filter === 'starred' ? 'is-active' : ''}`}
          onClick={() => setFilter('starred')}
        >
          <Star size={12} />
          <span>收藏</span>
        </button>
        {imageAlbums.map((alb) => (
          <button
            key={alb.id}
            type="button"
            className={`m-chip ${filter === alb.id ? 'is-active' : ''}`}
            onClick={() => setFilter(alb.id)}
          >
            <span>{alb.name}</span>
          </button>
        ))}
        <button
          type="button"
          className="m-chip"
          onClick={() => setNewAlbumSheet(true)}
        >
          <FolderPlus size={12} />
          <span>新建相册</span>
        </button>
        <button
          type="button"
          className={`m-chip ${filter === 'trash' ? 'is-active' : ''}`}
          onClick={() => setFilter('trash')}
        >
          <Trash2 size={12} />
          <span>回收站</span>
        </button>
      </div>

      {currentAlbumId && (
        <div
          style={{
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
            marginBottom: 10,
            fontSize: '0.78rem',
            color: 'var(--m-text-secondary)',
          }}
        >
          <span>
            当前相册：{imageAlbums.find((a) => a.id === currentAlbumId)?.name} ({visiblePhotos.length}{' '}
            张)
          </span>
          <button
            type="button"
            className="m-btn m-btn-danger m-btn-sm"
            style={{ height: 28 }}
            onClick={async () => {
              await onDeleteAlbum(currentAlbumId);
              setFilter('all');
            }}
          >
            移除分组
          </button>
        </div>
      )}

      {batchMode && selectedIds.size > 0 && (
        <div style={{ marginBottom: 12 }}>
          <button
            type="button"
            className="m-btn m-btn-danger m-btn-sm m-btn-block"
            onClick={() => void handleBatchTrash()}
          >
            <Trash2 size={14} />
            <span>将已选 {selectedIds.size} 张加密图片移入回收站</span>
          </button>
        </div>
      )}

      {filter === 'trash' && visiblePhotos.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <button
            type="button"
            className="m-btn m-btn-danger m-btn-sm m-btn-block"
            onClick={() => void onEmptyTrash()}
          >
            <Trash2 size={14} />
            <span>全零覆写并擦除回收站 ({visiblePhotos.length} 张 .psenc)</span>
          </button>
        </div>
      )}

      {/* Hidden File Inputs for Camera & Gallery */}
      <input
        ref={galleryInputRef}
        type="file"
        accept="image/*"
        multiple
        style={{ display: 'none' }}
        onChange={(e) => {
          if (e.target.files?.length) {
            void onUploadFiles(e.target.files, currentAlbumId);
          }
          e.target.value = '';
        }}
      />
      <input
        ref={cameraInputRef}
        type="file"
        accept="image/*"
        capture="environment"
        style={{ display: 'none' }}
        onChange={(e) => {
          if (e.target.files?.length) {
            void onUploadFiles(e.target.files, currentAlbumId);
          }
          e.target.value = '';
        }}
      />

      {/* Quick Action Strip for Camera + Multi-Upload */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <button
          id="m-photo-camera-btn"
          type="button"
          className="m-btn m-btn-soft m-btn-sm"
          style={{ flex: 1, height: 38 }}
          onClick={() => cameraInputRef.current?.click()}
        >
          <Camera size={15} />
          <span>拍照加密直传</span>
        </button>
        <button
          id="m-photo-upload-btn"
          type="button"
          className="m-btn m-btn-primary m-btn-sm"
          style={{ flex: 1, height: 38 }}
          onClick={() => galleryInputRef.current?.click()}
        >
          <Upload size={15} />
          <span>从手机相册导入</span>
        </button>
      </div>

      {/* Photo Grid */}
      {visiblePhotos.length === 0 ? (
        <div className="m-empty">
          <div className="m-empty-icon">
            <ImageIcon size={24} />
          </div>
          <div style={{ fontWeight: 700, color: 'var(--m-text)' }}>私密相册暂无照片</div>
          <div style={{ fontSize: '0.82rem', marginTop: 4 }}>
            照片将在客户端本地封装为 PSENC001 密文容器，服务端零知识存储
          </div>
        </div>
      ) : (
        <div className={`m-photo-grid ${compact ? 'is-compact' : ''}`}>
          {visiblePhotos.map((img) => {
            const checked = selectedIds.has(img.id);
            return (
              <div
                key={img.id}
                className="m-photo-tile"
                style={checked ? { outline: '3px solid var(--m-accent)' } : undefined}
                onClick={() => {
                  if (batchMode) {
                    toggleSelect(img.id);
                  } else {
                    setViewerId(img.id);
                  }
                }}
              >
                <DecryptedPhotoImg item={img} mode="thumb" />
                {img.isPinned && (
                  <span className="m-photo-badge-top">
                    <Star size={10} fill="#f5b841" color="#f5b841" />
                  </span>
                )}
                {batchMode && (
                  <span
                    className="m-photo-badge-top"
                    style={{
                      left: 6,
                      right: 'auto',
                      background: checked ? 'var(--m-accent)' : 'rgba(0,0,0,0.6)',
                    }}
                  >
                    {checked ? '已选' : '选择'}
                  </span>
                )}
                {!compact && <div className="m-photo-caption">{img.title}</div>}
              </div>
            );
          })}
        </div>
      )}

      {/* ==================== Darkroom Fullscreen Lightbox ==================== */}
      {activePhoto && (
        <div className="m-darkroom" role="dialog" aria-modal="true">
          <div className="m-darkroom-top">
            <button
              type="button"
              className="m-icon-btn"
              style={{ color: '#fff' }}
              onClick={() => {
                setSlideshow(false);
                setViewerId(null);
              }}
              aria-label="退出预览"
            >
              <X size={20} />
            </button>
            <div style={{ textAlign: 'center', minWidth: 0, flex: 1 }}>
              <div
                style={{
                  fontWeight: 700,
                  fontSize: '0.9rem',
                  whiteSpace: 'nowrap',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                }}
              >
                {activePhoto.title}
              </div>
              <div className="mono" style={{ fontSize: '0.7rem', opacity: 0.72 }}>
                {activePhoto.width}×{activePhoto.height} · {formatBytes(activePhoto.byteSize)} ·{' '}
                {activeIdx + 1}/{visiblePhotos.length}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 4 }}>
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: activePhoto.isPinned ? '#f5b841' : '#fff' }}
                onClick={() =>
                  void onUpdateMedia(activePhoto.id, { isPinned: !activePhoto.isPinned })
                }
                aria-label="收藏图片"
              >
                <Star size={18} fill={activePhoto.isPinned ? '#f5b841' : 'none'} />
              </button>
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: '#fff' }}
                onClick={() => openEditSheet(activePhoto)}
                aria-label="编辑图片信息"
              >
                <Edit3 size={18} />
              </button>
            </div>
          </div>

          <div
            className="m-darkroom-stage"
            onDoubleClick={() => setZoom((z) => (z > 1 ? 1 : 2))}
          >
            {visiblePhotos.length > 1 && (
              <button
                type="button"
                className="m-icon-btn"
                style={{
                  position: 'absolute',
                  left: 8,
                  zIndex: 3,
                  background: 'rgba(0,0,0,0.45)',
                  color: '#fff',
                }}
                onClick={() =>
                  setViewerId(
                    visiblePhotos[(activeIdx - 1 + visiblePhotos.length) % visiblePhotos.length].id,
                  )
                }
              >
                <ChevronLeft size={20} />
              </button>
            )}

            <DecryptedPhotoImg
              item={activePhoto}
              mode="full"
              style={{
                maxWidth: '100%',
                maxHeight: '100%',
                objectFit: 'contain',
                transition: 'transform 180ms ease',
                transform: `scale(${zoom}) rotate(${rotateDeg}deg) scaleX(${flipped ? -1 : 1})`,
              }}
            />

            {visiblePhotos.length > 1 && (
              <button
                type="button"
                className="m-icon-btn"
                style={{
                  position: 'absolute',
                  right: 8,
                  zIndex: 3,
                  background: 'rgba(0,0,0,0.45)',
                  color: '#fff',
                }}
                onClick={() =>
                  setViewerId(visiblePhotos[(activeIdx + 1) % visiblePhotos.length].id)
                }
              >
                <ChevronRight size={20} />
              </button>
            )}
          </div>

          <div className="m-darkroom-bottom">
            <div
              style={{
                display: 'flex',
                justifyContent: 'space-around',
                alignItems: 'center',
                marginBottom: 10,
              }}
            >
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: '#fff' }}
                onClick={() => setZoom((z) => Math.max(1, Number((z - 0.5).toFixed(1))))}
                aria-label="缩小"
              >
                <ZoomOut size={18} />
              </button>
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: '#fff' }}
                onClick={() => setZoom((z) => Math.min(3, Number((z + 0.5).toFixed(1))))}
                aria-label="放大"
              >
                <ZoomIn size={18} />
              </button>
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: '#fff' }}
                onClick={() => setRotateDeg((d) => (d + 90) % 360)}
                aria-label="旋转90度"
              >
                <RotateCw size={18} />
              </button>
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: '#fff' }}
                onClick={() => setFlipped((f) => !f)}
                aria-label="水平翻转"
              >
                <FlipHorizontal size={18} />
              </button>
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: slideshow ? '#4dbb9a' : '#fff' }}
                onClick={() => setSlideshow((s) => !s)}
                aria-label="幻灯片播放"
              >
                {slideshow ? <Pause size={18} /> : <Play size={18} />}
              </button>
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: '#fff' }}
                aria-label="本地解密导出原图"
                onClick={() => void client.downloadDecryptedMedia(activePhoto)}
              >
                <Download size={18} />
              </button>
            </div>

            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                className="m-btn m-btn-sm"
                style={{
                  flex: 1,
                  background: 'rgba(255,255,255,0.1)',
                  borderColor: 'rgba(255,255,255,0.2)',
                  color: '#fff',
                }}
                onClick={() => {
                  const id = activePhoto.id;
                  setViewerId(null);
                  onInspectCipher(id);
                }}
              >
                <ShieldCheck size={14} />
                <span>PSENC001 ({activePhoto.chunkCount} 块)</span>
              </button>

              {!activePhoto.isTrashed ? (
                <button
                  type="button"
                  className="m-btn m-btn-danger m-btn-sm"
                  onClick={async () => {
                    const id = activePhoto.id;
                    setViewerId(null);
                    await onUpdateMedia(id, { isTrashed: true });
                    onNotify('已移入图片回收站');
                  }}
                >
                  <Trash2 size={14} />
                  <span>回收站</span>
                </button>
              ) : (
                <>
                  <button
                    type="button"
                    className="m-btn m-btn-soft m-btn-sm"
                    onClick={async () => {
                      const id = activePhoto.id;
                      setViewerId(null);
                      await onUpdateMedia(id, { isTrashed: false });
                      onNotify('图片已恢复');
                    }}
                  >
                    <RotateCcw size={14} />
                    <span>恢复</span>
                  </button>
                  <button
                    type="button"
                    className="m-btn m-btn-danger m-btn-sm"
                    onClick={async () => {
                      const id = activePhoto.id;
                      setViewerId(null);
                      await onDeletePermanent(id);
                    }}
                  >
                    <Trash2 size={14} />
                    <span>彻底擦除</span>
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      {/* ==================== Edit Photo Metadata Sheet ==================== */}
      {editSheetOpen && activePhoto && (
        <div
          className="m-sheet-backdrop"
          style={{ zIndex: 85 }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setEditSheetOpen(false);
          }}
        >
          <div className="m-sheet">
            <div className="m-sheet-handle" />
            <div className="m-sheet-header">
              <h2 className="m-sheet-title">编辑加密原图信息</h2>
              <button
                type="button"
                className="m-icon-btn"
                onClick={() => setEditSheetOpen(false)}
              >
                <X size={18} />
              </button>
            </div>
            <form onSubmit={(e) => void handleSaveMeta(e)} className="m-sheet-body">
              <div className="m-field">
                <label className="m-label">图片标题</label>
                <input
                  type="text"
                  className="m-input"
                  value={eTitle}
                  onChange={(e) => setETitle(e.target.value)}
                />
              </div>
              <div className="m-field">
                <label className="m-label">所属加密相册</label>
                <select
                  className="m-select"
                  value={eAlbumId}
                  onChange={(e) => setEAlbumId(e.target.value)}
                >
                  <option value="">未分类相册</option>
                  {imageAlbums.map((a) => (
                    <option key={a.id} value={a.id}>
                      {a.name}
                    </option>
                  ))}
                </select>
              </div>
              <div className="m-field">
                <label className="m-label">标签（逗号分隔）</label>
                <input
                  type="text"
                  className="m-input"
                  value={eTags}
                  onChange={(e) => setETags(e.target.value)}
                />
              </div>
              <div className="m-field">
                <label className="m-label">拍摄说明</label>
                <textarea
                  className="m-textarea"
                  value={eDesc}
                  onChange={(e) => setEDesc(e.target.value)}
                />
              </div>
              <div
                className="mono"
                style={{ fontSize: '0.7rem', color: 'var(--m-text-tertiary)', marginBottom: 12 }}
              >
                SHA-256: {activePhoto.sha256.slice(0, 24)}… · 入库于{' '}
                {formatDateTime(activePhoto.createdAt)}
              </div>
              <button type="submit" className="m-btn m-btn-primary m-btn-block">
                保存加密信息
              </button>
            </form>
          </div>
        </div>
      )}

      {/* ==================== New Album Sheet ==================== */}
      {newAlbumSheet && (
        <div
          className="m-sheet-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setNewAlbumSheet(false);
          }}
        >
          <div className="m-sheet">
            <div className="m-sheet-handle" />
            <div className="m-sheet-header">
              <h2 className="m-sheet-title">新建加密相册</h2>
              <button
                type="button"
                className="m-icon-btn"
                onClick={() => setNewAlbumSheet(false)}
              >
                <X size={18} />
              </button>
            </div>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                if (!albumNameInput.trim()) return;
                const alb = await onCreateAlbum(albumNameInput.trim());
                setAlbumNameInput('');
                setNewAlbumSheet(false);
                setFilter(alb.id);
              }}
              className="m-sheet-body"
            >
              <div className="m-field">
                <label className="m-label">相册名称（AES-256-GCM 加密存储）</label>
                <input
                  id="m-new-photo-album-input"
                  type="text"
                  className="m-input"
                  placeholder="例如：家庭旅行原片 / 证件扫描件"
                  value={albumNameInput}
                  onChange={(e) => setAlbumNameInput(e.target.value)}
                  required
                />
              </div>
              <button type="submit" className="m-btn m-btn-primary m-btn-block">
                创建相册
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
};
