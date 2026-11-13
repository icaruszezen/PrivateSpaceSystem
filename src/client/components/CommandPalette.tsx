import React, { useEffect, useMemo, useState } from 'react';
import {
  FilePlus2,
  FileText,
  Film,
  Image as ImageIcon,
  KeyRound,
  Lock,
  Moon,
  Search,
  ShieldCheck,
  Sun,
} from 'lucide-react';
import type { MediaItem, NoteItem, PasswordItem } from '@shared/types';
import { formatBytes, formatShortDate } from '../utils/format';
import type { WorkspaceSection } from './Sidebar';

interface CommandPaletteProps {
  open: boolean;
  notes: NoteItem[];
  passwords: PasswordItem[];
  mediaItems: MediaItem[];
  theme: 'light' | 'dark';
  onClose: () => void;
  onSelectSection: (sec: WorkspaceSection) => void;
  onSelectNote: (id: string) => void;
  onSelectPassword: (id: string) => void;
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
  passwords,
  mediaItems,
  theme,
  onClose,
  onSelectSection,
  onSelectNote,
  onSelectPassword,
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
        id: 'cmd-sec-passwords',
        label: '前往私密密码库 (TOTP / 强密码审计)',
        sub: '空间切换',
        icon: <KeyRound size={15} />,
        run: () => {
          onSelectSection('passwords');
          onClose();
        },
      },
      {
        id: 'cmd-sec-images',
        label: '前往私密加密图库 (.psenc 分块原图)',
        sub: '空间切换',
        icon: <ImageIcon size={15} />,
        run: () => {
          onSelectSection('images');
          onClose();
        },
      },
      {
        id: 'cmd-sec-videos',
        label: '前往私密视频影院 (HTTP 206 流式播放)',
        sub: '空间切换',
        icon: <Film size={15} />,
        run: () => {
          onSelectSection('videos');
          onClose();
        },
      },
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
        label: '打开安全中心、多端会话与密文透视',
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

    const matchedPasswords = passwords
      .filter(
        (p) =>
          !p.isTrashed &&
          (q
            ? p.title.toLowerCase().includes(q) ||
              p.username.toLowerCase().includes(q) ||
              p.url.toLowerCase().includes(q)
            : true),
      )
      .slice(0, q ? 8 : 4)
      .map<PaletteEntry>((p) => ({
        id: `pwd-${p.id}`,
        label: p.title,
        sub: `密码 · ${p.username || p.url || 'AES-256-GCM'}`,
        icon: <KeyRound size={15} />,
        run: () => {
          onSelectSection('passwords');
          onSelectPassword(p.id);
          onClose();
        },
      }));

    const matchedMedia = mediaItems
      .filter(
        (m) =>
          !m.isTrashed &&
          (q
            ? m.title.toLowerCase().includes(q) ||
              m.originalFilename.toLowerCase().includes(q) ||
              m.tags.some((t) => t.toLowerCase().includes(q))
            : false),
      )
      .slice(0, 6)
      .map<PaletteEntry>((m) => ({
        id: `media-${m.id}`,
        label: m.title,
        sub: `${m.itemType === 'video' ? '视频' : '图片'} · ${formatBytes(m.byteSize)}`,
        icon: m.itemType === 'video' ? <Film size={15} /> : <ImageIcon size={15} />,
        run: () => {
          onSelectSection(m.itemType === 'video' ? 'videos' : 'images');
          onClose();
        },
      }));

    const matchedNotes = notes
      .filter(
        (n) =>
          !n.isTrashed &&
          (q
            ? n.title.toLowerCase().includes(q) ||
              n.content.toLowerCase().includes(q) ||
              n.tags.some((t) => t.toLowerCase().includes(q))
            : true),
      )
      .slice(0, q ? 8 : 4)
      .map<PaletteEntry>((n) => ({
        id: `note-${n.id}`,
        label: n.title || '无标题记录',
        sub: `文本 · ${formatShortDate(n.updatedAt)}`,
        icon: <FileText size={15} />,
        run: () => {
          onSelectSection('notes');
          onSelectNote(n.id);
          onClose();
        },
      }));

    return [...matchedPasswords, ...matchedMedia, ...matchedNotes, ...filteredCommands];
  }, [
    query,
    notes,
    passwords,
    mediaItems,
    theme,
    onSelectSection,
    onSelectNote,
    onSelectPassword,
    onCreateNote,
    onOpenSecurity,
    onToggleTheme,
    onLockVault,
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
            placeholder="全局搜索密码、图片、视频、文本或执行指令..."
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
