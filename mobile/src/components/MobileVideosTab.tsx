import React, { useMemo, useRef, useState } from 'react';
import {
  Download,
  Edit3,
  FastForward,
  Film,
  FolderPlus,
  Play,
  Repeat,
  Rewind,
  RotateCcw,
  Search,
  ShieldCheck,
  Star,
  Trash2,
  Upload,
  Video,
  X,
} from 'lucide-react';
import type { MediaAlbum, MediaItem, UpdateMediaRequest } from '@shared/types';
import type { PrivateSpaceMobileClient } from '../syncClient';
import { formatBytes, formatDateTime, formatDurationMs } from '../utils/mobileFormat';

interface MobileVideosTabProps {
  client: PrivateSpaceMobileClient;
  videos: MediaItem[];
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

const SPEED_OPTIONS = [0.75, 1, 1.25, 1.5, 2] as const;

export const MobileVideosTab: React.FC<MobileVideosTabProps> = ({
  client,
  videos,
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
  const [newAlbumSheet, setNewAlbumSheet] = useState(false);
  const [albumNameInput, setAlbumNameInput] = useState('');

  // Cinema Player state
  const [playingId, setPlayingId] = useState<string | null>(null);
  const [playbackRate, setPlaybackRate] = useState<number>(1);
  const [loopEnabled, setLoopEnabled] = useState(false);
  const [editSheetOpen, setEditSheetOpen] = useState(false);

  const [eTitle, setETitle] = useState('');
  const [eAlbumId, setEAlbumId] = useState('');
  const [eTags, setETags] = useState('');
  const [eDesc, setEDesc] = useState('');

  const videoInputRef = useRef<HTMLInputElement | null>(null);
  const cameraVideoRef = useRef<HTMLInputElement | null>(null);
  const videoElRef = useRef<HTMLVideoElement | null>(null);

  const videoAlbums = useMemo(
    () => albums.filter((a) => a.kind === 'video' || a.kind === 'mixed'),
    [albums],
  );

  const visibleVideos = useMemo(() => {
    const q = search.trim().toLowerCase();
    return videos
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
  }, [videos, filter, search]);

  const activeVideo = useMemo(
    () => (playingId ? videos.find((v) => v.id === playingId) ?? null : null),
    [videos, playingId],
  );

  const currentAlbumId =
    filter !== 'all' && filter !== 'starred' && filter !== 'trash' ? filter : null;

  const seekBy = (deltaSeconds: number) => {
    const el = videoElRef.current;
    if (!el) return;
    el.currentTime = Math.max(0, Math.min(el.duration || Infinity, el.currentTime + deltaSeconds));
  };

  const cycleSpeed = () => {
    const idx = SPEED_OPTIONS.indexOf(playbackRate as (typeof SPEED_OPTIONS)[number]);
    const next = SPEED_OPTIONS[(idx + 1) % SPEED_OPTIONS.length];
    setPlaybackRate(next);
    if (videoElRef.current) {
      videoElRef.current.playbackRate = next;
    }
  };

  const openEditSheet = (vid: MediaItem) => {
    setETitle(vid.title);
    setEAlbumId(vid.albumId ?? '');
    setETags(vid.tags.join(', '));
    setEDesc(vid.description);
    setEditSheetOpen(true);
  };

  return (
    <>
      {/* Resumable Upload Progress */}
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
            <span>512KiB 断点续传加密中：{task.name}</span>
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

      {/* Search */}
      <div className="m-search-row">
        <div className="m-search-box">
          <Search size={15} />
          <input
            type="search"
            className="m-search-input"
            placeholder="搜索加密视频标题、编码或标签..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      {/* Collection Rail */}
      <div className="m-chip-rail">
        <button
          type="button"
          className={`m-chip ${filter === 'all' ? 'is-active' : ''}`}
          onClick={() => setFilter('all')}
        >
          全部影院
        </button>
        <button
          type="button"
          className={`m-chip ${filter === 'starred' ? 'is-active' : ''}`}
          onClick={() => setFilter('starred')}
        >
          <Star size={12} />
          <span>收藏</span>
        </button>
        {videoAlbums.map((alb) => (
          <button
            key={alb.id}
            type="button"
            className={`m-chip ${filter === alb.id ? 'is-active' : ''}`}
            onClick={() => setFilter(alb.id)}
          >
            {alb.name}
          </button>
        ))}
        <button type="button" className="m-chip" onClick={() => setNewAlbumSheet(true)}>
          <FolderPlus size={12} />
          <span>新建合集</span>
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
            当前合集：{videoAlbums.find((a) => a.id === currentAlbumId)?.name} ({visibleVideos.length}{' '}
            部)
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
            移除合集
          </button>
        </div>
      )}

      {filter === 'trash' && visibleVideos.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <button
            type="button"
            className="m-btn m-btn-danger m-btn-sm m-btn-block"
            onClick={() => void onEmptyTrash()}
          >
            <Trash2 size={14} />
            <span>擦除回收站全部视频密文 ({visibleVideos.length} 部)</span>
          </button>
        </div>
      )}

      {/* Hidden Video File Inputs */}
      <input
        ref={videoInputRef}
        type="file"
        accept="video/*"
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
        ref={cameraVideoRef}
        type="file"
        accept="video/*"
        capture="environment"
        style={{ display: 'none' }}
        onChange={(e) => {
          if (e.target.files?.length) {
            void onUploadFiles(e.target.files, currentAlbumId);
          }
          e.target.value = '';
        }}
      />

      <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
        <button
          id="m-video-record-btn"
          type="button"
          className="m-btn m-btn-soft m-btn-sm"
          style={{ flex: 1, height: 38 }}
          onClick={() => cameraVideoRef.current?.click()}
        >
          <Video size={15} />
          <span>拍摄加密录像</span>
        </button>
        <button
          id="m-video-upload-btn"
          type="button"
          className="m-btn m-btn-primary m-btn-sm"
          style={{ flex: 1, height: 38 }}
          onClick={() => videoInputRef.current?.click()}
        >
          <Upload size={15} />
          <span>分片上传视频</span>
        </button>
      </div>

      {/* Video Cards */}
      {visibleVideos.length === 0 ? (
        <div className="m-empty">
          <div className="m-empty-icon">
            <Film size={24} />
          </div>
          <div style={{ fontWeight: 700, color: 'var(--m-text)' }}>私密视频影院为空</div>
          <div style={{ fontSize: '0.82rem', marginTop: 4 }}>
            支持 4K/1080P 视频断点续传与 HTTP 206 随机分块实时解密流播，拖动进度条秒开
          </div>
        </div>
      ) : (
        visibleVideos.map((vid) => (
          <article
            key={vid.id}
            className="m-video-card"
            onClick={() => {
              setPlaybackRate(1);
              setPlayingId(vid.id);
            }}
          >
            <div className="m-video-poster">
              {vid.hasThumbnail ? (
                <img
                  src={client.getThumbnailUrl(vid.id, vid.revision)}
                  alt={vid.title}
                  loading="lazy"
                />
              ) : (
                <div
                  style={{
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: 6,
                    color: 'rgba(255,255,255,0.55)',
                  }}
                >
                  <Film size={28} />
                  <span className="mono" style={{ fontSize: '0.7rem' }}>
                    PSENC001 STREAM
                  </span>
                </div>
              )}

              <span className="m-video-res-pill">
                {vid.width && vid.height ? `${vid.width}×${vid.height}` : 'HTTP 206'}
              </span>
              {vid.durationMs ? (
                <span className="m-video-duration-pill">{formatDurationMs(vid.durationMs)}</span>
              ) : null}

              <div className="m-video-play-circle">
                <Play size={20} fill="#ffffff" />
              </div>
            </div>

            <div className="m-video-body">
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  gap: 8,
                }}
              >
                <span
                  style={{
                    fontWeight: 700,
                    fontSize: '0.94rem',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    whiteSpace: 'nowrap',
                  }}
                >
                  {vid.title}
                </span>
                {vid.isPinned && <Star size={14} fill="var(--m-amber)" color="var(--m-amber)" />}
              </div>
              <div
                className="mono"
                style={{
                  fontSize: '0.73rem',
                  color: 'var(--m-text-secondary)',
                  marginTop: 4,
                  display: 'flex',
                  flexWrap: 'wrap',
                  gap: 8,
                }}
              >
                <span>{formatBytes(vid.byteSize)}</span>
                <span>·</span>
                <span>{vid.chunkCount} 加密块</span>
                {vid.videoCodec && (
                  <>
                    <span>·</span>
                    <span>{vid.videoCodec.toUpperCase()}</span>
                  </>
                )}
              </div>
            </div>
          </article>
        ))
      )}

      {/* ==================== Fullscreen Mobile Cinema Player ==================== */}
      {activeVideo && (
        <div className="m-darkroom" role="dialog" aria-modal="true">
          <div className="m-darkroom-top">
            <button
              type="button"
              className="m-icon-btn"
              style={{ color: '#fff' }}
              onClick={() => setPlayingId(null)}
              aria-label="关闭播放器"
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
                {activeVideo.title}
              </div>
              <div className="mono" style={{ fontSize: '0.7rem', opacity: 0.75 }}>
                HTTP 206 流式解密 · {formatBytes(activeVideo.byteSize)}
              </div>
            </div>
            <div style={{ display: 'flex', gap: 4 }}>
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: activeVideo.isPinned ? '#f5b841' : '#fff' }}
                onClick={() =>
                  void onUpdateMedia(activeVideo.id, { isPinned: !activeVideo.isPinned })
                }
              >
                <Star size={18} fill={activeVideo.isPinned ? '#f5b841' : 'none'} />
              </button>
              <button
                type="button"
                className="m-icon-btn"
                style={{ color: '#fff' }}
                onClick={() => openEditSheet(activeVideo)}
              >
                <Edit3 size={18} />
              </button>
            </div>
          </div>

          <div className="m-darkroom-stage" style={{ background: '#000' }}>
            <video
              ref={videoElRef}
              src={client.getStreamUrl(activeVideo.id, activeVideo.revision)}
              poster={
                activeVideo.hasThumbnail
                  ? client.getThumbnailUrl(activeVideo.id, activeVideo.revision)
                  : undefined
              }
              controls
              playsInline
              autoPlay
              loop={loopEnabled}
              style={{ width: '100%', maxHeight: '100%', outline: 'none' }}
            />
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
                className="m-btn m-btn-sm"
                style={{
                  background: 'rgba(255,255,255,0.1)',
                  borderColor: 'transparent',
                  color: '#fff',
                }}
                onClick={() => seekBy(-10)}
              >
                <Rewind size={14} />
                <span>-10s</span>
              </button>
              <button
                type="button"
                className="m-btn m-btn-sm mono"
                style={{
                  background: 'rgba(255,255,255,0.1)',
                  borderColor: 'transparent',
                  color: '#fff',
                }}
                onClick={cycleSpeed}
              >
                {playbackRate}× 倍速
              </button>
              <button
                type="button"
                className="m-btn m-btn-sm"
                style={{
                  background: loopEnabled ? 'rgba(77,187,154,0.28)' : 'rgba(255,255,255,0.1)',
                  borderColor: 'transparent',
                  color: loopEnabled ? '#4dbb9a' : '#fff',
                }}
                onClick={() => setLoopEnabled((v) => !v)}
              >
                <Repeat size={14} />
                <span>循环</span>
              </button>
              <button
                type="button"
                className="m-btn m-btn-sm"
                style={{
                  background: 'rgba(255,255,255,0.1)',
                  borderColor: 'transparent',
                  color: '#fff',
                }}
                onClick={() => seekBy(10)}
              >
                <span>+10s</span>
                <FastForward size={14} />
              </button>
              <a
                href={client.getDownloadUrl(activeVideo.id)}
                download={activeVideo.originalFilename}
                className="m-icon-btn"
                style={{ color: '#fff', textDecoration: 'none' }}
                aria-label="下载原片"
              >
                <Download size={18} />
              </a>
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
                  const id = activeVideo.id;
                  setPlayingId(null);
                  onInspectCipher(id);
                }}
              >
                <ShieldCheck size={14} />
                <span>检视 PSENC001 ({activeVideo.chunkCount} 块)</span>
              </button>

              {!activeVideo.isTrashed ? (
                <button
                  type="button"
                  className="m-btn m-btn-danger m-btn-sm"
                  onClick={async () => {
                    const id = activeVideo.id;
                    setPlayingId(null);
                    await onUpdateMedia(id, { isTrashed: true });
                    onNotify('视频已移入回收站');
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
                      const id = activeVideo.id;
                      setPlayingId(null);
                      await onUpdateMedia(id, { isTrashed: false });
                      onNotify('视频已恢复');
                    }}
                  >
                    <RotateCcw size={14} />
                    <span>恢复</span>
                  </button>
                  <button
                    type="button"
                    className="m-btn m-btn-danger m-btn-sm"
                    onClick={async () => {
                      const id = activeVideo.id;
                      setPlayingId(null);
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

      {/* Edit Video Metadata Sheet */}
      {editSheetOpen && activeVideo && (
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
              <h2 className="m-sheet-title">编辑视频信息</h2>
              <button
                type="button"
                className="m-icon-btn"
                onClick={() => setEditSheetOpen(false)}
              >
                <X size={18} />
              </button>
            </div>
            <form
              onSubmit={async (e) => {
                e.preventDefault();
                await onUpdateMedia(activeVideo.id, {
                  title: eTitle.trim() || activeVideo.title,
                  albumId: eAlbumId || null,
                  tags: eTags
                    .split(/[,，]/)
                    .map((t) => t.trim())
                    .filter(Boolean),
                  description: eDesc,
                });
                setEditSheetOpen(false);
                onNotify('加密视频元数据已更新');
              }}
              className="m-sheet-body"
            >
              <div className="m-field">
                <label className="m-label">视频标题</label>
                <input
                  type="text"
                  className="m-input"
                  value={eTitle}
                  onChange={(e) => setETitle(e.target.value)}
                />
              </div>
              <div className="m-field">
                <label className="m-label">所属视频合集</label>
                <select
                  className="m-select"
                  value={eAlbumId}
                  onChange={(e) => setEAlbumId(e.target.value)}
                >
                  <option value="">未分类合集</option>
                  {videoAlbums.map((a) => (
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
                <label className="m-label">视频简介</label>
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
                SHA-256: {activeVideo.sha256.slice(0, 24)}… · 入库于{' '}
                {formatDateTime(activeVideo.createdAt)}
              </div>
              <button type="submit" className="m-btn m-btn-primary m-btn-block">
                保存视频信息
              </button>
            </form>
          </div>
        </div>
      )}

      {/* New Video Collection Sheet */}
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
              <h2 className="m-sheet-title">新建加密视频合集</h2>
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
                <label className="m-label">合集名称（AES-256-GCM 加密存储）</label>
                <input
                  id="m-new-video-album-input"
                  type="text"
                  className="m-input"
                  placeholder="例如：航拍素材 / 家庭纪录片"
                  value={albumNameInput}
                  onChange={(e) => setAlbumNameInput(e.target.value)}
                  required
                />
              </div>
              <button type="submit" className="m-btn m-btn-primary m-btn-block">
                创建合集
              </button>
            </form>
          </div>
        </div>
      )}
    </>
  );
};
