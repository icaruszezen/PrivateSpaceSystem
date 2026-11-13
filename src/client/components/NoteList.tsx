import React from 'react';
import { FileText, Menu, Pin, Plus, Search, Trash2, X } from 'lucide-react';
import type { NoteItem } from '@shared/types';
import { formatShortDate } from '../utils/format';
import type { NavFilter } from './Sidebar';

export type SortMode = 'updated' | 'created' | 'title';

interface NoteListProps {
  notes: NoteItem[];
  selectedNoteId: string | null;
  activeFilter: NavFilter;
  selectedTag: string | null;
  searchQuery: string;
  sortMode: SortMode;
  onSearchChange: (q: string) => void;
  onSortChange: (mode: SortMode) => void;
  onSelectNote: (id: string) => void;
  onCreateNote: () => void;
  onEmptyTrash: () => void;
  onOpenMobileMenu: () => void;
}

const FILTER_TITLES: Record<NavFilter, string> = {
  all: '全部记录',
  pinned: '置顶记录',
  archived: '归档收纳',
  trash: '回收站',
};

export const NoteList: React.FC<NoteListProps> = ({
  notes,
  selectedNoteId,
  activeFilter,
  selectedTag,
  searchQuery,
  sortMode,
  onSearchChange,
  onSortChange,
  onSelectNote,
  onCreateNote,
  onEmptyTrash,
  onOpenMobileMenu,
}) => {
  const heading = selectedTag ? `# ${selectedTag}` : FILTER_TITLES[activeFilter];

  return (
    <section className="notelist-pane" aria-label="文本记录列表">
      <div className="notelist-header">
        <div className="notelist-title-row">
          <div className="notelist-title-group">
            <button
              type="button"
              className="btn-icon mobile-menu-btn"
              onClick={onOpenMobileMenu}
              aria-label="打开导航菜单"
            >
              <Menu size={17} />
            </button>
            <h2 className="notelist-heading">{heading}</h2>
            <span className="notelist-badge">{notes.length}</span>
          </div>

          <div className="notelist-controls">
            {activeFilter === 'trash' && notes.length > 0 ? (
              <button
                type="button"
                className="btn btn-danger"
                style={{ height: 28, padding: '0 9px', fontSize: '0.76rem' }}
                onClick={onEmptyTrash}
              >
                <Trash2 size={13} />
                <span>清空</span>
              </button>
            ) : (
              <>
                <select
                  aria-label="排序方式"
                  className="sort-select"
                  value={sortMode}
                  onChange={(e) => onSortChange(e.target.value as SortMode)}
                >
                  <option value="updated">按更新</option>
                  <option value="created">按创建</option>
                  <option value="title">按标题</option>
                </select>
                <button
                  type="button"
                  className="btn-icon"
                  style={{ width: 28, height: 28 }}
                  onClick={onCreateNote}
                  title="新建记录"
                  aria-label="新建记录"
                >
                  <Plus size={16} />
                </button>
              </>
            )}
          </div>
        </div>

        <div className="search-box">
          <Search size={14} className="search-box-icon" />
          <input
            id="note-search-input"
            type="search"
            className="search-input"
            placeholder="搜索标题、正文或标签..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
          />
          {searchQuery && (
            <button
              type="button"
              className="search-clear-btn"
              onClick={() => onSearchChange('')}
              aria-label="清除搜索"
            >
              <X size={13} />
            </button>
          )}
        </div>
      </div>

      {notes.length === 0 ? (
        <div className="notelist-empty">
          <FileText size={28} strokeWidth={1.5} />
          <p>
            {searchQuery
              ? '没有找到匹配的加密文本记录'
              : activeFilter === 'trash'
                ? '回收站为空'
                : '当前分类暂无文本记录'}
          </p>
          {!searchQuery && activeFilter !== 'trash' && (
            <button
              type="button"
              className="btn btn-secondary"
              style={{ height: 32, fontSize: '0.82rem' }}
              onClick={onCreateNote}
            >
              <Plus size={14} />
              <span>新建第一篇记录</span>
            </button>
          )}
        </div>
      ) : (
        <div className="notelist-items" role="listbox" aria-label="记录项">
          {notes.map((note) => {
            const selected = note.id === selectedNoteId;
            return (
              <button
                key={note.id}
                type="button"
                role="option"
                aria-selected={selected}
                className={`note-card ${selected ? 'is-selected' : ''}`}
                onClick={() => onSelectNote(note.id)}
              >
                <div className="note-card-top">
                  <span className="note-card-title">
                    {note.isPinned && !note.isTrashed && (
                      <Pin size={12} className="pin-marker" fill="currentColor" />
                    )}
                    <span>{note.title || '无标题记录'}</span>
                  </span>
                  <span className="note-card-time">{formatShortDate(note.updatedAt)}</span>
                </div>

                <p className="note-card-excerpt">
                  {note.excerpt || '空白文本记录...'}
                </p>

                {note.tags.length > 0 && (
                  <div className="note-card-tags">
                    {note.tags.slice(0, 3).map((tag) => (
                      <span key={tag} className="tag-chip-mini">
                        #{tag}
                      </span>
                    ))}
                    {note.tags.length > 3 && (
                      <span className="tag-chip-mini">+{note.tags.length - 3}</span>
                    )}
                  </div>
                )}
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
};
