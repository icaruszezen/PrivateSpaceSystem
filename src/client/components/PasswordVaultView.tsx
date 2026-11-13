import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  Clock,
  Copy,
  Edit3,
  ExternalLink,
  Eye,
  EyeOff,
  History,
  KeyRound,
  Menu,
  Plus,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Star,
  Trash2,
  Upload,
  X,
} from 'lucide-react';
import { auditPasswordVault, evaluatePasswordEntropy } from '@shared/passwordGenerator';
import { generateTotp } from '@shared/totp';
import type {
  CreatePasswordRequest,
  ImportPasswordEntryInput,
  PasswordCategory,
  PasswordCustomField,
  PasswordItem,
  UpdatePasswordRequest,
} from '@shared/types';
import { formatFullDateTime, formatShortDate } from '../utils/format';
import { PasswordGeneratorModal } from './PasswordGeneratorModal';

export const PASSWORD_CATEGORY_LABELS: Record<PasswordCategory, string> = {
  login: '网站登录',
  finance: '金融银行',
  work: '办公协作',
  dev: '研发与云',
  server: '服务器/SSH',
  social: '社交邮箱',
  other: '其他凭据',
};

interface PasswordVaultViewProps {
  passwords: PasswordItem[];
  selectedId: string | null;
  onSelectId: (id: string | null) => void;
  onCreatePassword: (input: CreatePasswordRequest) => Promise<PasswordItem>;
  onImportPasswords: (entries: ImportPasswordEntryInput[]) => Promise<number>;
  onUpdatePassword: (id: string, patch: UpdatePasswordRequest) => Promise<PasswordItem>;
  onDeletePermanent: (id: string) => Promise<void>;
  onEmptyTrash: () => Promise<void>;
  onInspectCipher: (id: string) => void;
  onOpenMobileMenu: () => void;
  onNotify: (msg: string) => void;
}

type CategoryFilter = 'all' | 'starred' | 'trash' | PasswordCategory;
type AuditFilter = 'none' | 'weak' | 'reused' | 'no2fa';

export const PasswordVaultView: React.FC<PasswordVaultViewProps> = ({
  passwords,
  selectedId,
  onSelectId,
  onCreatePassword,
  onImportPasswords,
  onUpdatePassword,
  onDeletePermanent,
  onEmptyTrash,
  onInspectCipher,
  onOpenMobileMenu,
  onNotify,
}) => {
  const [catFilter, setCatFilter] = useState<CategoryFilter>('all');
  const [auditFilter, setAuditFilter] = useState<AuditFilter>('none');
  const [search, setSearch] = useState('');
  const [revealPassword, setRevealPassword] = useState(false);
  const [revealedFieldIds, setRevealedFieldIds] = useState<Record<string, boolean>>({});
  const [showHistory, setShowHistory] = useState(false);
  const [nowMs, setNowMs] = useState(() => Date.now());

  // Modals
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [formState, setFormState] = useState<{
    open: boolean;
    editing: PasswordItem | null;
  }>({ open: false, editing: null });

  const csvInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  useEffect(() => {
    setRevealPassword(false);
    setRevealedFieldIds({});
    setShowHistory(false);
  }, [selectedId]);

  const audit = useMemo(() => auditPasswordVault(passwords, nowMs), [passwords, nowMs]);

  const visiblePasswords = useMemo(() => {
    const q = search.trim().toLowerCase();
    const weakSet = new Set(audit.weakIds);
    const reusedSet = new Set(audit.reusedIds);
    const no2faSet = new Set(audit.missingTotpIds);

    return passwords
      .filter((item) => {
        if (catFilter === 'trash') {
          if (!item.isTrashed) return false;
        } else {
          if (item.isTrashed) return false;
          if (catFilter === 'starred' && !item.isPinned) return false;
          if (
            catFilter !== 'all' &&
            catFilter !== 'starred' &&
            item.category !== catFilter
          ) {
            return false;
          }
        }

        if (auditFilter === 'weak' && !weakSet.has(item.id)) return false;
        if (auditFilter === 'reused' && !reusedSet.has(item.id)) return false;
        if (auditFilter === 'no2fa' && !no2faSet.has(item.id)) return false;

        if (q) {
          const hit =
            item.title.toLowerCase().includes(q) ||
            item.username.toLowerCase().includes(q) ||
            item.url.toLowerCase().includes(q) ||
            item.tags.some((t) => t.toLowerCase().includes(q));
          if (!hit) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (a.isPinned !== b.isPinned) return a.isPinned ? -1 : 1;
        return b.updatedAt.localeCompare(a.updatedAt);
      });
  }, [passwords, catFilter, auditFilter, search, audit]);

  const selectedItem = useMemo(
    () => passwords.find((p) => p.id === selectedId) ?? visiblePasswords[0] ?? null,
    [passwords, selectedId, visiblePasswords],
  );

  const totpSnapshot = useMemo(() => {
    if (!selectedItem?.totpSecret?.trim()) return null;
    try {
      return generateTotp(selectedItem.totpSecret, nowMs);
    } catch {
      return null;
    }
  }, [selectedItem?.totpSecret, nowMs]);

  const selectedEntropy = useMemo(
    () => evaluatePasswordEntropy(selectedItem?.password ?? ''),
    [selectedItem?.password],
  );

  async function copyText(val: string, label: string) {
    await navigator.clipboard.writeText(val);
    onNotify(`${label}已复制到剪贴板`);
  }

  async function handleCsvFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;

    const text = await file.text();
    const lines = text.split(/\r?\n/).filter((l) => l.trim().length > 0);
    if (lines.length < 2) {
      onNotify('CSV 文件为空或格式不正确');
      return;
    }

    const parseCsvRow = (line: string): string[] => {
      const cols: string[] = [];
      let cur = '';
      let inQuotes = false;
      for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        if (ch === '"') {
          if (inQuotes && line[i + 1] === '"') {
            cur += '"';
            i++;
          } else {
            inQuotes = !inQuotes;
          }
        } else if (ch === ',' && !inQuotes) {
          cols.push(cur.trim());
          cur = '';
        } else {
          cur += ch;
        }
      }
      cols.push(cur.trim());
      return cols;
    };

    const headers = parseCsvRow(lines[0]).map((h) => h.toLowerCase());
    const idxTitle = headers.findIndex((h) => /name|title|标题|名称/.test(h));
    const idxUrl = headers.findIndex((h) => /url|website|网址/.test(h));
    const idxUser = headers.findIndex((h) => /user|login|account|账号|用户名/.test(h));
    const idxPass = headers.findIndex((h) => /pass|密码/.test(h));
    const idxTotp = headers.findIndex((h) => /totp|otp|2fa/.test(h));
    const idxNotes = headers.findIndex((h) => /note|extra|备注/.test(h));

    const entries: ImportPasswordEntryInput[] = [];
    for (let i = 1; i < lines.length; i++) {
      const row = parseCsvRow(lines[i]);
      const password = idxPass >= 0 ? row[idxPass] || '' : '';
      const title = idxTitle >= 0 ? row[idxTitle] || '' : idxUrl >= 0 ? row[idxUrl] || '' : '';
      if (!title && !password) continue;
      entries.push({
        title: title || 'CSV 导入账号',
        url: idxUrl >= 0 ? row[idxUrl] : '',
        username: idxUser >= 0 ? row[idxUser] : '',
        password,
        totpSecret: idxTotp >= 0 ? row[idxTotp] : '',
        notes: idxNotes >= 0 ? row[idxNotes] : '',
      });
    }

    const count = await onImportPasswords(entries);
    onNotify(`成功加密导入 ${count} 条密码记录`);
  }

  return (
    <>
      {/* Column 2: Password Master List & Health Audit */}
      <section className="note-list-pane" aria-label="私密密码列表">
        <header className="list-header">
          <div className="list-title-row">
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <button
                type="button"
                className="btn-icon mobile-only-btn"
                onClick={onOpenMobileMenu}
                aria-label="打开导航菜单"
              >
                <Menu size={17} />
              </button>
              <h1 className="list-heading">私密密码库</h1>
            </div>
            <div style={{ display: 'flex', gap: 6 }}>
              <input
                ref={csvInputRef}
                type="file"
                accept=".csv,text/csv"
                style={{ display: 'none' }}
                onChange={(e) => void handleCsvFile(e)}
              />
              <button
                type="button"
                className="btn-icon"
                title="从浏览器/1Password/Bitwarden CSV 导入"
                onClick={() => csvInputRef.current?.click()}
              >
                <Upload size={15} />
              </button>
              <button
                type="button"
                className="btn-icon"
                title="打开 CSPRNG 密码生成器"
                onClick={() => setGeneratorOpen(true)}
              >
                <Sparkles size={15} />
              </button>
              <button
                id="new-password-btn"
                type="button"
                className="btn btn-primary"
                style={{ height: 30, padding: '0 10px', fontSize: '0.78rem' }}
                onClick={() => setFormState({ open: true, editing: null })}
              >
                <Plus size={14} />
                <span>新建</span>
              </button>
            </div>
          </div>

          {/* Security Health Audit Banner */}
          <div className="pss-health-card">
            <div className="pss-health-top">
              <span className="pss-health-score">
                <ShieldCheck size={14} style={{ color: 'var(--accent)' }} />
                <span>安全评分 {audit.healthScore}/100</span>
              </span>
              {auditFilter !== 'none' && (
                <button
                  type="button"
                  className="pss-link-mini"
                  onClick={() => setAuditFilter('none')}
                >
                  清除筛选
                </button>
              )}
            </div>
            <div className="pss-audit-pills">
              <button
                type="button"
                className={`pss-audit-pill ${auditFilter === 'weak' ? 'is-active' : ''}`}
                onClick={() => setAuditFilter((f) => (f === 'weak' ? 'none' : 'weak'))}
              >
                弱密码 ({audit.weakIds.length})
              </button>
              <button
                type="button"
                className={`pss-audit-pill ${auditFilter === 'reused' ? 'is-active' : ''}`}
                onClick={() => setAuditFilter((f) => (f === 'reused' ? 'none' : 'reused'))}
              >
                重复 ({audit.reusedIds.length})
              </button>
              <button
                type="button"
                className={`pss-audit-pill ${auditFilter === 'no2fa' ? 'is-active' : ''}`}
                onClick={() => setAuditFilter((f) => (f === 'no2fa' ? 'none' : 'no2fa'))}
              >
                未设2FA ({audit.missingTotpIds.length})
              </button>
            </div>
          </div>

          <div className="search-input-wrap">
            <Search size={14} className="search-icon" />
            <input
              type="search"
              className="search-input"
              placeholder="搜索账号标题、用户名、域名或标签..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <div className="pss-filter-strip">
            {(
              [
                ['all', '全部'],
                ['starred', '收藏'],
                ['dev', '研发'],
                ['server', '服务器'],
                ['finance', '金融'],
                ['login', '登录'],
                ['trash', '回收站'],
              ] as Array<[CategoryFilter, string]>
            ).map(([key, label]) => (
              <button
                key={key}
                type="button"
                className={`pss-chip ${catFilter === key ? 'is-active' : ''}`}
                onClick={() => setCatFilter(key)}
              >
                {label}
              </button>
            ))}
          </div>

          {catFilter === 'trash' && visiblePasswords.length > 0 && (
            <button
              type="button"
              className="btn btn-danger"
              style={{ width: '100%', height: 30, fontSize: '0.78rem', marginTop: 4 }}
              onClick={() => void onEmptyTrash()}
            >
              <Trash2 size={13} />
              <span>彻底清空密码回收站 ({visiblePasswords.length})</span>
            </button>
          )}
        </header>

        <div className="note-list-scroll">
          {visiblePasswords.length === 0 ? (
            <div className="list-empty">
              <KeyRound size={26} style={{ opacity: 0.35 }} />
              <p>暂无匹配的加密密码条目</p>
            </div>
          ) : (
            visiblePasswords.map((item) => {
              const isSelected = selectedItem?.id === item.id;
              const initial = (item.title.trim()[0] || 'P').toUpperCase();
              return (
                <button
                  key={item.id}
                  type="button"
                  className={`note-card ${isSelected ? 'is-selected' : ''}`}
                  onClick={() => onSelectId(item.id)}
                >
                  <div className="pss-pwd-card-row">
                    <span className="pss-avatar-badge">{initial}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="note-card-title-row">
                        <span className="note-card-title">{item.title}</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          {item.isPinned && (
                            <Star
                              size={12}
                              fill="var(--amber)"
                              style={{ color: 'var(--amber)', flexShrink: 0 }}
                            />
                          )}
                          {item.totpSecret && <span className="pss-2fa-mini">2FA</span>}
                        </div>
                      </div>
                      <div className="note-card-excerpt" style={{ marginTop: 2 }}>
                        {item.username || item.url || PASSWORD_CATEGORY_LABELS[item.category]}
                      </div>
                    </div>
                  </div>
                </button>
              );
            })
          )}
        </div>
      </section>

      {/* Column 3: Password Detail & Live TOTP Inspector */}
      <main className="editor-pane" aria-label="密码详情检视">
        {!selectedItem ? (
          <div className="editor-empty-state">
            <div className="editor-empty-icon">
              <KeyRound size={26} />
            </div>
            <h2>端到端 AES-256-GCM 密码与 2FA 保险库</h2>
            <p>
              所有账号密码、RFC 6238 动态口令种子与自定义隐藏字段均使用独立子密钥加密存储，支持历史密码回溯与多端增量同步。
            </p>
            <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
              <button
                type="button"
                className="btn btn-primary"
                onClick={() => setFormState({ open: true, editing: null })}
              >
                <Plus size={15} />
                <span>新建第一条密码</span>
              </button>
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setGeneratorOpen(true)}
              >
                <Sparkles size={15} />
                <span>密码生成器</span>
              </button>
            </div>
          </div>
        ) : (
          <div className="pss-detail-scroll">
            <header className="pss-detail-header">
              <div className="pss-detail-title-group">
                <span className="pss-avatar-badge is-lg">
                  {(selectedItem.title.trim()[0] || 'P').toUpperCase()}
                </span>
                <div>
                  <h2 className="pss-detail-title">{selectedItem.title}</h2>
                  <div className="pss-detail-meta">
                    <span className="pss-badge-subtle">
                      {PASSWORD_CATEGORY_LABELS[selectedItem.category]}
                    </span>
                    <button
                      type="button"
                      className="cipher-badge-btn"
                      onClick={() => onInspectCipher(selectedItem.id)}
                      title="透视底层 SQLite AES-256-GCM 原始密文信封"
                    >
                      <ShieldCheck size={12} />
                      <span>AES-256-GCM · Sync #{selectedItem.syncSeq}</span>
                    </button>
                    {selectedItem.tags.map((tag) => (
                      <span key={tag} className="tag-chip-mini">
                        #{tag}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="pss-detail-actions">
                {!selectedItem.isTrashed ? (
                  <>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() =>
                        void onUpdatePassword(selectedItem.id, {
                          isPinned: !selectedItem.isPinned,
                        })
                      }
                    >
                      <Star
                        size={14}
                        fill={selectedItem.isPinned ? 'var(--amber)' : 'none'}
                        style={{ color: selectedItem.isPinned ? 'var(--amber)' : undefined }}
                      />
                      <span>{selectedItem.isPinned ? '已收藏' : '收藏'}</span>
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() => setFormState({ open: true, editing: selectedItem })}
                    >
                      <Edit3 size={14} />
                      <span>编辑</span>
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger"
                      onClick={() =>
                        void onUpdatePassword(selectedItem.id, { isTrashed: true }).then(() =>
                          onNotify('已移入密码回收站'),
                        )
                      }
                    >
                      <Trash2 size={14} />
                      <span>移入回收站</span>
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      onClick={() =>
                        void onUpdatePassword(selectedItem.id, { isTrashed: false }).then(() =>
                          onNotify('密码条目已恢复'),
                        )
                      }
                    >
                      <RotateCcw size={14} />
                      <span>恢复</span>
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger"
                      onClick={() => void onDeletePermanent(selectedItem.id)}
                    >
                      <Trash2 size={14} />
                      <span>彻底销毁密文</span>
                    </button>
                  </>
                )}
              </div>
            </header>

            {/* Live RFC 6238 TOTP Card */}
            {totpSnapshot && (
              <div className="pss-totp-card">
                <div>
                  <div className="pss-totp-label">两步验证动态口令 (RFC 6238 TOTP)</div>
                  <div className="pss-totp-code mono">{totpSnapshot.formattedCode}</div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div className="pss-totp-ring-wrap" title={`剩余 ${totpSnapshot.remainingSeconds} 秒刷新`}>
                    <svg width="32" height="32" viewBox="0 0 32 32">
                      <circle
                        cx="16"
                        cy="16"
                        r="13"
                        fill="none"
                        stroke="var(--border-default)"
                        strokeWidth="2.6"
                      />
                      <circle
                        cx="16"
                        cy="16"
                        r="13"
                        fill="none"
                        stroke={
                          totpSnapshot.remainingSeconds <= 5 ? 'var(--danger)' : 'var(--accent)'
                        }
                        strokeWidth="2.6"
                        strokeDasharray={2 * Math.PI * 13}
                        strokeDashoffset={2 * Math.PI * 13 * totpSnapshot.progress}
                        transform="rotate(-90 16 16)"
                      />
                    </svg>
                    <span className="pss-totp-sec mono">{totpSnapshot.remainingSeconds}s</span>
                  </div>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => void copyText(totpSnapshot.code, '动态验证码')}
                  >
                    <Copy size={14} />
                    <span>复制验证码</span>
                  </button>
                </div>
              </div>
            )}

            {/* Core Credentials Card */}
            <div className="pss-cred-card">
              <div className="pss-cred-row">
                <div>
                  <div className="pss-field-caption">用户名 / 登录账号</div>
                  <div className="pss-field-value mono">{selectedItem.username || '—'}</div>
                </div>
                {selectedItem.username && (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ height: 32, padding: '0 10px' }}
                    onClick={() => void copyText(selectedItem.username, '用户名')}
                  >
                    <Copy size={13} />
                    <span>复制</span>
                  </button>
                )}
              </div>

              <div className="pss-cred-row">
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div className="pss-field-caption" style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span>加密密码</span>
                    <span className={`pss-entropy-pill level-${selectedEntropy.score}`}>
                      {selectedEntropy.label} · {selectedEntropy.entropyBits} bits
                    </span>
                    {audit.reusedIds.includes(selectedItem.id) && (
                      <span className="pss-warn-badge">
                        <AlertTriangle size={11} /> 重复使用
                      </span>
                    )}
                  </div>
                  <div className="pss-field-value mono" style={{ wordBreak: 'break-all' }}>
                    {revealPassword ? (
                      <ColorizedPassword text={selectedItem.password} />
                    ) : (
                      '••••••••••••••••••••'
                    )}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ height: 32, padding: '0 10px' }}
                    onClick={() => setRevealPassword((v) => !v)}
                  >
                    {revealPassword ? <EyeOff size={13} /> : <Eye size={13} />}
                    <span>{revealPassword ? '隐藏' : '显示'}</span>
                  </button>
                  <button
                    type="button"
                    className="btn btn-primary"
                    style={{ height: 32, padding: '0 12px' }}
                    onClick={() => void copyText(selectedItem.password, '密码')}
                  >
                    <Copy size={13} />
                    <span>复制密码</span>
                  </button>
                </div>
              </div>

              {selectedItem.url && (
                <div className="pss-cred-row">
                  <div style={{ minWidth: 0 }}>
                    <div className="pss-field-caption">关联网站 / 服务地址</div>
                    <div
                      className="pss-field-value mono"
                      style={{ overflow: 'hidden', textOverflow: 'ellipsis' }}
                    >
                      {selectedItem.url}
                    </div>
                  </div>
                  <a
                    href={
                      /^https?:\/\//i.test(selectedItem.url)
                        ? selectedItem.url
                        : `https://${selectedItem.url}`
                    }
                    target="_blank"
                    rel="noreferrer"
                    className="btn btn-secondary"
                    style={{ height: 32, padding: '0 10px', textDecoration: 'none' }}
                  >
                    <ExternalLink size={13} />
                    <span>打开</span>
                  </a>
                </div>
              )}
            </div>

            {/* Custom Fields */}
            {selectedItem.customFields.length > 0 && (
              <div className="pss-cred-card">
                {selectedItem.customFields.map((cf) => {
                  const shown = !cf.hidden || Boolean(revealedFieldIds[cf.id]);
                  return (
                    <div key={cf.id} className="pss-cred-row">
                      <div>
                        <div className="pss-field-caption">{cf.label}</div>
                        <div className="pss-field-value mono">
                          {shown ? cf.value : '••••••••••••'}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 6 }}>
                        {cf.hidden && (
                          <button
                            type="button"
                            className="btn-icon"
                            onClick={() =>
                              setRevealedFieldIds((prev) => ({
                                ...prev,
                                [cf.id]: !prev[cf.id],
                              }))
                            }
                          >
                            {shown ? <EyeOff size={14} /> : <Eye size={14} />}
                          </button>
                        )}
                        <button
                          type="button"
                          className="btn-icon"
                          onClick={() => void copyText(cf.value, cf.label)}
                        >
                          <Copy size={14} />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Encrypted Notes */}
            {selectedItem.notes && (
              <div className="pss-cred-card">
                <div className="pss-field-caption">加密私密备注</div>
                <div style={{ whiteSpace: 'pre-wrap', fontSize: '0.9rem', lineHeight: 1.6, marginTop: 4 }}>
                  {selectedItem.notes}
                </div>
              </div>
            )}

            {/* Metadata & Password History */}
            <div className="pss-cred-card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: 'var(--text-tertiary)' }}>
                <span>
                  <Clock size={12} style={{ verticalAlign: '-2px', marginRight: 4 }} />
                  创建于 {formatFullDateTime(selectedItem.createdAt)} · 最近更新{' '}
                  {formatShortDate(selectedItem.updatedAt)}
                </span>
                {selectedItem.history.length > 0 && (
                  <button
                    type="button"
                    className="pss-link-mini"
                    onClick={() => setShowHistory((s) => !s)}
                  >
                    <History size={13} />
                    <span>
                      {showHistory ? '收起历史密码' : `历史旧密码记录 (${selectedItem.history.length} 条)`}
                    </span>
                  </button>
                )}
              </div>

              {showHistory && selectedItem.history.length > 0 && (
                <div className="pss-history-list">
                  {selectedItem.history.map((h, i) => (
                    <div key={`${h.changedAt}-${i}`} className="pss-history-row">
                      <div>
                        <div className="mono" style={{ fontSize: '0.84rem' }}>
                          {h.password}
                        </div>
                        <div style={{ fontSize: '0.73rem', color: 'var(--text-tertiary)' }}>
                          归档于 {formatFullDateTime(h.changedAt)}
                        </div>
                      </div>
                      <button
                        type="button"
                        className="btn-icon"
                        onClick={() => void copyText(h.password, '历史旧密码')}
                      >
                        <Copy size={13} />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      <PasswordGeneratorModal
        open={generatorOpen}
        onClose={() => setGeneratorOpen(false)}
        onNotify={onNotify}
      />

      {formState.open && (
        <PasswordEditorModal
          editing={formState.editing}
          onClose={() => setFormState({ open: false, editing: null })}
          onSave={async (payload) => {
            if (formState.editing) {
              const updated = await onUpdatePassword(formState.editing.id, payload);
              onSelectId(updated.id);
              onNotify('加密密码条目已更新');
            } else {
              const created = await onCreatePassword(payload as CreatePasswordRequest);
              onSelectId(created.id);
              onNotify('新密码条目已加密保存');
            }
            setFormState({ open: false, editing: null });
          }}
          onNotify={onNotify}
        />
      )}
    </>
  );
};

const ColorizedPassword: React.FC<{ text: string }> = ({ text }) => (
  <>
    {[...text].map((ch, idx) => {
      if (/\d/.test(ch)) {
        return (
          <span key={idx} style={{ color: 'var(--accent)', fontWeight: 600 }}>
            {ch}
          </span>
        );
      }
      if (/[^a-zA-Z0-9]/.test(ch)) {
        return (
          <span key={idx} style={{ color: 'var(--amber)', fontWeight: 600 }}>
            {ch}
          </span>
        );
      }
      return <span key={idx}>{ch}</span>;
    })}
  </>
);

interface PasswordEditorModalProps {
  editing: PasswordItem | null;
  onClose: () => void;
  onSave: (input: CreatePasswordRequest | UpdatePasswordRequest) => Promise<void>;
  onNotify: (msg: string) => void;
}

const PasswordEditorModal: React.FC<PasswordEditorModalProps> = ({
  editing,
  onClose,
  onSave,
  onNotify,
}) => {
  const [title, setTitle] = useState(editing?.title ?? '');
  const [category, setCategory] = useState<PasswordCategory>(editing?.category ?? 'login');
  const [username, setUsername] = useState(editing?.username ?? '');
  const [password, setPassword] = useState(editing?.password ?? '');
  const [url, setUrl] = useState(editing?.url ?? '');
  const [totpSecret, setTotpSecret] = useState(editing?.totpSecret ?? '');
  const [tagsText, setTagsText] = useState(editing?.tags.join(', ') ?? '');
  const [notes, setNotes] = useState(editing?.notes ?? '');
  const [customFields, setCustomFields] = useState<PasswordCustomField[]>(
    editing?.customFields ?? [],
  );
  const [genOpen, setGenOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const entropy = useMemo(() => evaluatePasswordEntropy(password), [password]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) {
      setError('请填写账号标题');
      return;
    }
    setSubmitting(true);
    setError(null);
    try {
      await onSave({
        title: title.trim(),
        category,
        username: username.trim(),
        password,
        url: url.trim(),
        totpSecret: totpSecret.trim(),
        tags: tagsText
          .split(/[,，]/)
          .map((t) => t.trim())
          .filter(Boolean),
        notes,
        customFields,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : '保存失败');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <>
      <div
        className="modal-backdrop"
        onClick={(e) => {
          if (e.target === e.currentTarget) onClose();
        }}
      >
        <div className="modal-dialog" style={{ maxWidth: 560 }} role="dialog" aria-modal="true">
          <header className="modal-header">
            <div className="modal-title-wrap">
              <ShieldAlert size={18} style={{ color: 'var(--accent)' }} />
              <h2 className="modal-title">{editing ? '编辑加密密码条目' : '新建私密密码条目'}</h2>
            </div>
            <button type="button" className="btn-icon" onClick={onClose}>
              <X size={17} />
            </button>
          </header>

          <form className="modal-body" onSubmit={(e) => void handleSubmit(e)}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 160px', gap: 12 }}>
              <div className="field-group">
                <label className="field-label">标题名称 *</label>
                <input
                  type="text"
                  className="field-input"
                  placeholder="例如：GitHub Enterprise 主账号"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  required
                />
              </div>
              <div className="field-group">
                <label className="field-label">所属分类</label>
                <select
                  className="field-input"
                  value={category}
                  onChange={(e) => setCategory(e.target.value as PasswordCategory)}
                >
                  {Object.entries(PASSWORD_CATEGORY_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            <div className="field-group" style={{ marginTop: 12 }}>
              <label className="field-label">用户名 / 邮箱 / 卡号</label>
              <input
                type="text"
                className="field-input mono"
                placeholder="user@example.com"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>

            <div className="field-group" style={{ marginTop: 12 }}>
              <div className="field-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>登录密码 ({entropy.label} · {entropy.entropyBits} bits)</span>
                <button
                  type="button"
                  className="pss-link-mini"
                  onClick={() => setGenOpen(true)}
                >
                  <Sparkles size={12} /> 随机生成强密码
                </button>
              </div>
              <input
                type="text"
                className="field-input mono"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="输入或点击右上角生成高强度密码"
              />
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 12 }}>
              <div className="field-group">
                <label className="field-label">关联网址 (URL)</label>
                <input
                  type="text"
                  className="field-input mono"
                  placeholder="https://github.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </div>
              <div className="field-group">
                <label className="field-label">两步验证密钥 (Base32 / otpauth://)</label>
                <input
                  type="text"
                  className="field-input mono"
                  placeholder="JBSWY3DPEHPK3PXP"
                  value={totpSecret}
                  onChange={(e) => setTotpSecret(e.target.value)}
                />
              </div>
            </div>

            <div className="field-group" style={{ marginTop: 12 }}>
              <label className="field-label">加密标签（逗号分隔）</label>
              <input
                type="text"
                className="field-input"
                placeholder="核心研发, 2FA已开启, SSH"
                value={tagsText}
                onChange={(e) => setTagsText(e.target.value)}
              />
            </div>

            <div className="field-group" style={{ marginTop: 12 }}>
              <div className="field-label" style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span>自定义附加字段（如恢复备用码、PIN、私钥口令）</span>
                <button
                  type="button"
                  className="pss-link-mini"
                  onClick={() =>
                    setCustomFields((prev) => [
                      ...prev,
                      { id: crypto.randomUUID(), label: '', value: '', hidden: true },
                    ])
                  }
                >
                  + 添加字段
                </button>
              </div>
              {customFields.map((cf, i) => (
                <div
                  key={cf.id}
                  style={{ display: 'grid', gridTemplateColumns: '140px 1fr auto auto', gap: 8, marginTop: 6, alignItems: 'center' }}
                >
                  <input
                    type="text"
                    className="field-input"
                    style={{ height: 34 }}
                    placeholder="字段名"
                    value={cf.label}
                    onChange={(e) =>
                      setCustomFields((prev) =>
                        prev.map((item, idx) =>
                          idx === i ? { ...item, label: e.target.value } : item,
                        ),
                      )
                    }
                  />
                  <input
                    type="text"
                    className="field-input mono"
                    style={{ height: 34 }}
                    placeholder="字段内容"
                    value={cf.value}
                    onChange={(e) =>
                      setCustomFields((prev) =>
                        prev.map((item, idx) =>
                          idx === i ? { ...item, value: e.target.value } : item,
                        ),
                      )
                    }
                  />
                  <label className="auth-checkbox-row" style={{ fontSize: '0.75rem' }}>
                    <input
                      type="checkbox"
                      checked={cf.hidden}
                      onChange={(e) =>
                        setCustomFields((prev) =>
                          prev.map((item, idx) =>
                            idx === i ? { ...item, hidden: e.target.checked } : item,
                          ),
                        )
                      }
                    />
                    <span>遮罩</span>
                  </label>
                  <button
                    type="button"
                    className="btn-icon"
                    onClick={() => setCustomFields((prev) => prev.filter((_, idx) => idx !== i))}
                  >
                    <X size={14} />
                  </button>
                </div>
              ))}
            </div>

            <div className="field-group" style={{ marginTop: 12 }}>
              <label className="field-label">私密备注</label>
              <textarea
                className="field-input"
                style={{ minHeight: 72, padding: '8px 10px', resize: 'vertical' }}
                placeholder="加密保存恢复指引或硬件密钥备注..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>

            {error && (
              <div className="auth-error" style={{ marginTop: 10 }}>
                {error}
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10, marginTop: 16 }}>
              <button type="button" className="btn btn-secondary" onClick={onClose}>
                取消
              </button>
              <button type="submit" className="btn btn-primary" disabled={submitting}>
                {submitting ? '正在加密写入...' : 'AES-256-GCM 加密保存'}
              </button>
            </div>
          </form>
        </div>
      </div>

      <PasswordGeneratorModal
        open={genOpen}
        onClose={() => setGenOpen(false)}
        onUsePassword={(pwd) => setPassword(pwd)}
        onNotify={onNotify}
      />
    </>
  );
};
