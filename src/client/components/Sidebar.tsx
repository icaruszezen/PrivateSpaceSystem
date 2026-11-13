import React from 'react';
import {
  Archive,
  FileText,
  Film,
  Hash,
  Image as ImageIcon,
  KeyRound,
  Lock,
  Moon,
  Pin,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Smartphone,
  Sun,
  Trash2,
} from 'lucide-react';
import { formatBytes } from '../utils/format';

export type WorkspaceSection = 'notes' | 'passwords' | 'images' | 'videos';
export type NavFilter = 'all' | 'pinned' | 'archived' | 'trash';

interface SidebarProps {
  vaultName: string;
  keyFingerprint: string | null;
  activeSection: WorkspaceSection;
  activeFilter: NavFilter;
  selectedTag: string | null;
  counts: {
    all: number;
    pinned: number;
    archived: number;
    trash: number;
    passwords: number;
    images: number;
    videos: number;
    totalEncryptedBytes: number;
  };
  tagCounts: Array<{ tag: string; count: number }>;
  latestSyncSeq: number;
  sseConnected: boolean;
  syncing: boolean;
  theme: 'light' | 'dark';
  mobileOpen: boolean;
  onCloseMobile: () => void;
  onSelectSection: (section: WorkspaceSection) => void;
  onSelectFilter: (filter: NavFilter) => void;
  onSelectTag: (tag: string | null) => void;
  onPrimaryCreate: () => void;
  onOpenPalette: () => void;
  onTriggerSync: () => void;
  onOpenSecurity: (tab?: 'cipher' | 'password' | 'sessions') => void;
  onToggleTheme: () => void;
  onLockVault: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  vaultName,
  keyFingerprint,
  activeSection,
  activeFilter,
  selectedTag,
  counts,
  tagCounts,
  latestSyncSeq,
  sseConnected,
  syncing,
  theme,
  mobileOpen,
  onCloseMobile,
  onSelectSection,
  onSelectFilter,
  onSelectTag,
  onPrimaryCreate,
  onOpenPalette,
  onTriggerSync,
  onOpenSecurity,
  onToggleTheme,
  onLockVault,
}) => {
  function handleSection(sec: WorkspaceSection) {
    onSelectSection(sec);
    if (sec === 'notes') {
      onSelectTag(null);
      onSelectFilter('all');
    }
    onCloseMobile();
  }

  function handleNav(filter: NavFilter) {
    onSelectSection('notes');
    onSelectTag(null);
    onSelectFilter(filter);
    onCloseMobile();
  }

  function handleTag(tag: string) {
    onSelectSection('notes');
    if (selectedTag === tag) {
      onSelectTag(null);
    } else {
      onSelectFilter('all');
      onSelectTag(tag);
    }
    onCloseMobile();
  }

  const primaryActionLabel: Record<WorkspaceSection, string> = {
    passwords: '新建加密密码',
    images: '上传私密图片',
    videos: '分片上传视频',
    notes: '新建文本记录',
  };

  return (
    <>
      <div
        className={`mobile-drawer-backdrop ${mobileOpen ? 'is-open' : ''}`}
        onClick={onCloseMobile}
        aria-hidden="true"
      />
      <aside className={`sidebar ${mobileOpen ? 'is-open' : ''}`} aria-label="空间导航栏">
        <div className="sidebar-brand-row">
          <div className="sidebar-brand">
            <span className="sidebar-brand-logo" aria-hidden="true">
              <Lock size={15} strokeWidth={2.2} />
            </span>
            <div className="sidebar-brand-text">
              <span className="sidebar-vault-title">{vaultName}</span>
              <span className="sidebar-vault-fp">
                {keyFingerprint ? `KEY ${keyFingerprint}` : 'AES-256-GCM'}
              </span>
            </div>
          </div>
        </div>

        <div className="sidebar-actions">
          <button
            id="sidebar-new-note-btn"
            type="button"
            className="btn btn-primary sidebar-new-btn"
            onClick={() => {
              onPrimaryCreate();
              onCloseMobile();
            }}
          >
            <Plus size={16} strokeWidth={2.2} />
            <span>{primaryActionLabel[activeSection]}</span>
          </button>

          <button
            id="sidebar-cmd-palette-btn"
            type="button"
            className="sidebar-cmd-btn"
            onClick={() => {
              onOpenPalette();
              onCloseMobile();
            }}
          >
            <span className="sidebar-cmd-left">
              <Search size={14} />
              <span>全局检索与指令</span>
            </span>
            <span className="kbd-hint">⌘K</span>
          </button>
        </div>

        <div className="sidebar-scroll">
          {/* 4 Core Encrypted Storage Spaces */}
          <nav className="sidebar-section" aria-label="核心加密空间">
            <div className="sidebar-section-label">
              <span>核心私密空间</span>
            </div>

            <button
              id="nav-section-passwords"
              type="button"
              className={`nav-item ${activeSection === 'passwords' ? 'is-active' : ''}`}
              onClick={() => handleSection('passwords')}
            >
              <span className="nav-item-left">
                <KeyRound size={15} />
                <span className="nav-item-label">私密密码库</span>
              </span>
              <span className="nav-count">{counts.passwords}</span>
            </button>

            <button
              id="nav-section-images"
              type="button"
              className={`nav-item ${activeSection === 'images' ? 'is-active' : ''}`}
              onClick={() => handleSection('images')}
            >
              <span className="nav-item-left">
                <ImageIcon size={15} />
                <span className="nav-item-label">私密加密图库</span>
              </span>
              <span className="nav-count">{counts.images}</span>
            </button>

            <button
              id="nav-section-videos"
              type="button"
              className={`nav-item ${activeSection === 'videos' ? 'is-active' : ''}`}
              onClick={() => handleSection('videos')}
            >
              <span className="nav-item-left">
                <Film size={15} />
                <span className="nav-item-label">私密视频影院</span>
              </span>
              <span className="nav-count">{counts.videos}</span>
            </button>

            <button
              id="nav-all-notes"
              type="button"
              className={`nav-item ${
                activeSection === 'notes' && activeFilter === 'all' && !selectedTag
                  ? 'is-active'
                  : ''
              }`}
              onClick={() => handleNav('all')}
            >
              <span className="nav-item-left">
                <FileText size={15} />
                <span className="nav-item-label">加密文本记录</span>
              </span>
              <span className="nav-count">{counts.all}</span>
            </button>
          </nav>

          {/* Contextual Note Sub-filters */}
          {activeSection === 'notes' && (
            <>
              <nav className="sidebar-section" aria-label="文本记录筛选">
                <div className="sidebar-section-label">
                  <span>文本视图</span>
                </div>

                <button
                  id="nav-pinned-notes"
                  type="button"
                  className={`nav-item ${activeFilter === 'pinned' ? 'is-active' : ''}`}
                  onClick={() => handleNav('pinned')}
                >
                  <span className="nav-item-left">
                    <Pin size={14} />
                    <span className="nav-item-label">置顶记录</span>
                  </span>
                  <span className="nav-count">{counts.pinned}</span>
                </button>

                <button
                  id="nav-archived-notes"
                  type="button"
                  className={`nav-item ${activeFilter === 'archived' ? 'is-active' : ''}`}
                  onClick={() => handleNav('archived')}
                >
                  <span className="nav-item-left">
                    <Archive size={14} />
                    <span className="nav-item-label">归档收纳</span>
                  </span>
                  <span className="nav-count">{counts.archived}</span>
                </button>

                <button
                  id="nav-trash-notes"
                  type="button"
                  className={`nav-item ${activeFilter === 'trash' ? 'is-active' : ''}`}
                  onClick={() => handleNav('trash')}
                >
                  <span className="nav-item-left">
                    <Trash2 size={14} />
                    <span className="nav-item-label">回收站</span>
                  </span>
                  <span className="nav-count">{counts.trash}</span>
                </button>
              </nav>

              {tagCounts.length > 0 && (
                <div className="sidebar-section">
                  <div className="sidebar-section-label">
                    <span>文本标签</span>
                    {selectedTag && (
                      <button
                        type="button"
                        style={{ fontSize: '0.72rem', color: 'var(--accent)', textTransform: 'none' }}
                        onClick={() => onSelectTag(null)}
                      >
                        清除
                      </button>
                    )}
                  </div>
                  {tagCounts.map(({ tag, count }) => (
                    <button
                      key={tag}
                      type="button"
                      className={`nav-item ${selectedTag === tag ? 'is-active' : ''}`}
                      onClick={() => handleTag(tag)}
                    >
                      <span className="nav-item-left">
                        <Hash size={14} />
                        <span className="nav-item-label">{tag}</span>
                      </span>
                      <span className="nav-count">{count}</span>
                    </button>
                  ))}
                </div>
              )}
            </>
          )}

          {/* Cross-Platform Sync Quick Entry */}
          <div className="sidebar-section">
            <div className="sidebar-section-label">
              <span>跨端协同</span>
            </div>
            <button
              id="nav-multidevice-sync"
              type="button"
              className="nav-item"
              onClick={() => {
                onOpenSecurity('sessions');
                onCloseMobile();
              }}
            >
              <span className="nav-item-left">
                <Smartphone size={15} />
                <span className="nav-item-label">多端同步与设备</span>
              </span>
              <span className="nav-count mono">#{latestSyncSeq}</span>
            </button>

            <a
              id="nav-ios-client"
              href="/ios"
              className="nav-item"
              style={{ textDecoration: 'none' }}
              onClick={onCloseMobile}
            >
              <span className="nav-item-left">
                <Smartphone size={15} />
                <span className="nav-item-label">iOS 移动加密空间</span>
              </span>
              <span className="nav-count mono">iOS</span>
            </a>
          </div>
        </div>

        <div className="sidebar-footer">
          <div className="pss-storage-mini">
            <div className="pss-storage-mini-row">
              <span>加密存储占用</span>
              <span className="mono">{formatBytes(counts.totalEncryptedBytes)}</span>
            </div>
            <div className="pss-storage-mini-sub">
              密 {counts.passwords} · 图 {counts.images} · 影 {counts.videos} · 文 {counts.all}
            </div>
          </div>

          <div className="sync-bar">
            <span className="sync-status-left">
              <span
                className="sync-dot"
                style={{ opacity: sseConnected ? 1 : 0.65 }}
                title={sseConnected ? 'SSE 实时推送已连接' : '增量轮询同步就绪'}
              />
              <span>已加密同步 · Seq #{latestSyncSeq}</span>
            </span>
            <button
              type="button"
              className="btn-icon"
              style={{ width: 24, height: 24 }}
              onClick={onTriggerSync}
              title="增量拉取多端变更"
              aria-label="同步多端变更"
            >
              <RefreshCw
                size={13}
                style={syncing ? { animation: 'spin 0.8s linear infinite' } : undefined}
              />
            </button>
          </div>

          <div className="sidebar-footer-btns">
            <button
              id="sidebar-security-btn"
              type="button"
              className="sidebar-security-btn"
              onClick={() => {
                onOpenSecurity('cipher');
                onCloseMobile();
              }}
              title="查看加密存储透视、修改密码与多端会话"
            >
              <ShieldCheck size={15} />
              <span>安全与加密</span>
            </button>

            <button
              id="sidebar-theme-btn"
              type="button"
              className="btn-icon"
              onClick={onToggleTheme}
              title={theme === 'light' ? '切换深色模式' : '切换浅色模式'}
              aria-label="切换主题"
            >
              {theme === 'light' ? <Moon size={15} /> : <Sun size={15} />}
            </button>

            <button
              id="sidebar-lock-btn"
              type="button"
              className="btn-icon"
              onClick={onLockVault}
              title="立即锁定私密空间并清除会话密钥"
              aria-label="锁定空间"
            >
              <Lock size={15} />
            </button>
          </div>
        </div>
      </aside>
    </>
  );
};
