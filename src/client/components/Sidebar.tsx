import React from 'react';
import {
  Archive,
  FileText,
  Hash,
  Lock,
  Moon,
  Pin,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Sun,
  Trash2,
} from 'lucide-react';

export type NavFilter = 'all' | 'pinned' | 'archived' | 'trash';

interface SidebarProps {
  vaultName: string;
  keyFingerprint: string | null;
  activeFilter: NavFilter;
  selectedTag: string | null;
  counts: {
    all: number;
    pinned: number;
    archived: number;
    trash: number;
  };
  tagCounts: Array<{ tag: string; count: number }>;
  latestSyncSeq: number;
  syncing: boolean;
  theme: 'light' | 'dark';
  mobileOpen: boolean;
  onCloseMobile: () => void;
  onSelectFilter: (filter: NavFilter) => void;
  onSelectTag: (tag: string | null) => void;
  onCreateNote: () => void;
  onOpenPalette: () => void;
  onTriggerSync: () => void;
  onOpenSecurity: () => void;
  onToggleTheme: () => void;
  onLockVault: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  vaultName,
  keyFingerprint,
  activeFilter,
  selectedTag,
  counts,
  tagCounts,
  latestSyncSeq,
  syncing,
  theme,
  mobileOpen,
  onCloseMobile,
  onSelectFilter,
  onSelectTag,
  onCreateNote,
  onOpenPalette,
  onTriggerSync,
  onOpenSecurity,
  onToggleTheme,
  onLockVault,
}) => {
  function handleNav(filter: NavFilter) {
    onSelectTag(null);
    onSelectFilter(filter);
    onCloseMobile();
  }

  function handleTag(tag: string) {
    if (selectedTag === tag) {
      onSelectTag(null);
    } else {
      onSelectFilter('all');
      onSelectTag(tag);
    }
    onCloseMobile();
  }

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
              onCreateNote();
              onCloseMobile();
            }}
          >
            <Plus size={16} strokeWidth={2.2} />
            <span>新建文本记录</span>
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
              <span>快速检索与指令</span>
            </span>
            <span className="kbd-hint">⌘K</span>
          </button>
        </div>

        <div className="sidebar-scroll">
          <nav className="sidebar-section" aria-label="记录视图">
            <div className="sidebar-section-label">
              <span>文本记录</span>
            </div>

            <button
              id="nav-all-notes"
              type="button"
              className={`nav-item ${activeFilter === 'all' && !selectedTag ? 'is-active' : ''}`}
              onClick={() => handleNav('all')}
            >
              <span className="nav-item-left">
                <FileText size={15} />
                <span className="nav-item-label">全部记录</span>
              </span>
              <span className="nav-count">{counts.all}</span>
            </button>

            <button
              id="nav-pinned-notes"
              type="button"
              className={`nav-item ${activeFilter === 'pinned' ? 'is-active' : ''}`}
              onClick={() => handleNav('pinned')}
            >
              <span className="nav-item-left">
                <Pin size={15} />
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
                <Archive size={15} />
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
                <Trash2 size={15} />
                <span className="nav-item-label">回收站</span>
              </span>
              <span className="nav-count">{counts.trash}</span>
            </button>
          </nav>

          <div className="sidebar-section">
            <div className="sidebar-section-label">
              <span>标签分类</span>
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

            {tagCounts.length === 0 ? (
              <div className="sidebar-empty-tags">在记录中添加标签后自动归类</div>
            ) : (
              tagCounts.map(({ tag, count }) => (
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
              ))
            )}
          </div>
        </div>

        <div className="sidebar-footer">
          <div className="sync-bar">
            <span className="sync-status-left">
              <span className="sync-dot" />
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
                onOpenSecurity();
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
