import React, { useEffect, useMemo, useState } from 'react';
import { FilePlus2, FileText, Lock, Moon, Search, ShieldCheck, Sun } from 'lucide-react';
import type { NoteItem } from '@shared/types';
import { formatShortDate } from '../utils/format';

interface CommandPaletteProps {
  open: boolean;
  notes: NoteItem[];
  theme: 'light' | 'dark';
  onClose: () => void;
  onSelectNote: (id: string) => void;
  onCreateNote: () => void;
  onToggleTheme: () => void;
  onOpenSecurity: () => void;
  onLockVault: () => void;
}

interface PaletteEntry {
  id: string;
  label: string;
  sub: string;
  icon: React.ReactNode;
  run: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({
  open,
  notes,
  theme,
  onClose,
  onSelectNote,
  onCreateNote,
  onToggleTheme,
  onOpenSecurity,
  onLockVault,
}) => {
  const [query, setQuery] = useState('');
  const [activeIndex, setActiveIndex] = useState(0);

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIndex(0);
    }
  }, [open]);

  const entries = useMemo<PaletteEntry[]>(() => {
    const q = query.trim().toLowerCase();

    const quickCommands: PaletteEntry[] = [
      {
        id: 'cmd-new',
        label: '新建私密文本记录',
        sub: '快捷键 ⌘N',
        icon: <FilePlus2 size={15} />,
        run: () => {
          onCreateNote();
          onClose();
        },
      },
      {
        id: 'cmd-security',
        label: '打开安全中心与密文存储透视',
        sub: 'AES-256-GCM',
        icon: <ShieldCheck size={15} />,
        run: () => {
          onOpenSecurity();
          onClose();
        },
      },
      {
        id: 'cmd-theme',
        label: theme === 'light' ? '切换至深色外观' : '切换至浅色外观',
        sub: '外观主题',
        icon: theme === 'light' ? <Moon size={15} /> : <Sun size={15} />,
        run: () => {
          onToggleTheme();
          onClose();
        },
      },
      {
        id: 'cmd-lock',
        label: '立即锁定私密空间',
        sub: '销毁会话密钥',
        icon: <Lock size={15} />,
        run: () => {
          onClose();
          onLockVault();
        },
      },
    ];

    const filteredCommands = q
      ? quickCommands.filter(
          (c) => c.label.toLowerCase().includes(q) || c.sub.toLowerCase().includes(q),
        )
      : quickCommands;

    const activeNotes = notes.filter((n) => !n.isTrashed);
    const matchedNotes = (
      q
        ? activeNotes.filter(
            (n) =>
              n.title.toLowerCase().includes(q) ||
              n.content.toLowerCase().includes(q) ||
              n.tags.some((t) => t.toLowerCase().includes(q)),
          )
        : activeNotes.slice(0, 8)
    ).map<PaletteEntry>((n) => ({
      id: `note-${n.id}`,
      label: n.title || '无标题记录',
      sub: formatShortDate(n.updatedAt),
      icon: <FileText size={15} />,
      run: () => {
        onSelectNote(n.id);
        onClose();
      },
    }));

    return [...matchedNotes, ...filteredCommands];
  }, [
    query,
    notes,
    theme,
    onCreateNote,
    onOpenSecurity,
    onToggleTheme,
    onLockVault,
    onSelectNote,
    onClose,
  ]);

  useEffect(() => {
    setActiveIndex(0);
  }, [query]);

  if (!open) return null;

  return (
    <div
      className="modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className="palette-dialog" role="dialog" aria-modal="true" aria-label="快速命令与搜索">
        <div className="palette-input-row">
          <Search size={16} style={{ color: 'var(--text-tertiary)' }} />
          <input
            type="text"
            className="palette-input"
            placeholder="搜索文本记录标题、正文或执行快捷操作..."
            value={query}
            autoFocus
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                onClose();
              } else if (e.key === 'ArrowDown') {
                e.preventDefault();
                setActiveIndex((i) => (entries.length ? (i + 1) % entries.length : 0));
              } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                setActiveIndex((i) =>
                  entries.length ? (i - 1 + entries.length) % entries.length : 0,
                );
              } else if (e.key === 'Enter' && entries[activeIndex]) {
                e.preventDefault();
                entries[activeIndex].run();
              }
            }}
          />
          <span className="kbd-hint">ESC</span>
        </div>

        <div className="palette-list">
          {entries.length === 0 ? (
            <div style={{ padding: '20px 14px', textAlign: 'center', color: 'var(--text-tertiary)', fontSize: '0.86rem' }}>
              没有找到匹配结果
            </div>
          ) : (
            entries.map((entry, idx) => (
              <button
                key={entry.id}
                type="button"
                className={`palette-item ${idx === activeIndex ? 'is-highlighted' : ''}`}
                onMouseEnter={() => setActiveIndex(idx)}
                onClick={() => entry.run()}
              >
                <span className="palette-item-left">
                  {entry.icon}
                  <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {entry.label}
                  </span>
                </span>
                <span className="palette-item-sub">{entry.sub}</span>
              </button>
            ))
          )}
        </div>
      </div>
    </div>
  );
};
