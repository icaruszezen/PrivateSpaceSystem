import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  ChevronDown,
  ChevronRight,
  Clock,
  Copy,
  Edit3,
  ExternalLink,
  Eye,
  EyeOff,
  Globe,
  History,
  KeyRound,
  Menu,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Star,
  Trash2,
  Upload,
  User,
  X,
} from 'lucide-react';
import {
  auditPasswordVault,
  evaluatePasswordEntropy,
  generateSecurePassword,
} from '@shared/passwordGenerator';
import { parseTotpInput, tryGenerateTotp } from '@shared/totp';
import type {
  CreatePasswordRequest,
  ImportPasswordEntryInput,
  PasswordCategory,
  PasswordCustomField,
  PasswordItem,
  UpdatePasswordRequest,
} from '@shared/types';
import { formatBytes, formatFullDateTime, formatShortDate } from '../utils/format';
import { PasswordGeneratorModal } from './PasswordGeneratorModal';

export const PASSWORD_CATEGORY_LABELS: Record<PasswordCategory, string> = {
  login: '网站与应用',
  finance: '金融银行',
  work: '办公协作',
  dev: '研发与云',
  server: '服务器/设备',
  social: '社交邮箱',
  other: '其他凭据',
};

const CATEGORY_SHORT_LABELS: Record<PasswordCategory, string> = {
  login: '网站',
  dev: '研发',
  server: '设备',
  finance: '金融',
  work: '办公',
  social: '社交',
  other: '其他',
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
  onOpenMobileDetail?: () => void;
  onBackToListMobile?: () => void;
  onNotify: (msg: string) => void;
}

type CategoryFilter = 'all' | 'starred' | 'has2fa' | 'trash' | PasswordCategory;
type AuditFilter = 'none' | 'weak' | 'reused' | 'stale';

function extractDisplayHost(rawUrl: string): string {
  if (!rawUrl.trim()) return '';
  try {
    const normalized = /^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`;
    return new URL(normalized).hostname.replace(/^www\./i, '');
  } catch {
    return rawUrl.trim();
  }
}

function toSafeHref(rawUrl: string): string {
  return /^https?:\/\//i.test(rawUrl.trim()) ? rawUrl.trim() : `https://${rawUrl.trim()}`;
}

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
  onOpenMobileDetail,
  onBackToListMobile,
  onNotify,
}) => {
  const [catFilter, setCatFilter] = useState<CategoryFilter>('all');
  const [auditFilter, setAuditFilter] = useState<AuditFilter>('none');
  const [search, setSearch] = useState('');
  const [revealPassword, setRevealPassword] = useState(false);
  const [revealedFieldIds, setRevealedFieldIds] = useState<Record<string, boolean>>({});
  const [showHistory, setShowHistory] = useState(false);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Modals
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [formState, setFormState] = useState<{
    open: boolean;
    editing: PasswordItem | null;
    defaultCategory?: PasswordCategory;
  }>({ open: false, editing: null });

  const csvInputRef = useRef<HTMLInputElement | null>(null);
  const copyTimerRef = useRef<number | null>(null);

  useEffect(() => {
    return () => {
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
    };
  }, []);

  const audit = useMemo(() => auditPasswordVault(passwords), [passwords]);
  const weakSet = useMemo(() => new Set(audit.weakIds), [audit.weakIds]);
  const reusedSet = useMemo(() => new Set(audit.reusedIds), [audit.reusedIds]);
  const staleSet = useMemo(() => new Set(audit.staleIds), [audit.staleIds]);
  const totpSet = useMemo(() => new Set(audit.totpIds), [audit.totpIds]);
  const invalidTotpSet = useMemo(() => new Set(audit.invalidTotpIds), [audit.invalidTotpIds]);

  const trashCount = useMemo(
    () => passwords.reduce((acc, p) => acc + (p.isTrashed ? 1 : 0), 0),
    [passwords],
  );

  const filterChips = useMemo(() => {
    const usedCategories = new Set<PasswordCategory>();
    for (const p of passwords) {
      if (!p.isTrashed) usedCategories.add(p.category);
    }

    const chips: Array<[CategoryFilter, string]> = [
      ['all', '全部'],
      ['starred', '收藏'],
    ];

    if (audit.totpIds.length > 0 || catFilter === 'has2fa') {
      chips.push(['has2fa', `含2FA ${audit.totpIds.length}`]);
    }

    chips.push(
      ['login', CATEGORY_SHORT_LABELS.login],
      ['dev', CATEGORY_SHORT_LABELS.dev],
      ['server', CATEGORY_SHORT_LABELS.server],
      ['finance', CATEGORY_SHORT_LABELS.finance],
    );

    for (const extra of ['work', 'social', 'other'] as PasswordCategory[]) {
      if (usedCategories.has(extra) || catFilter === extra) {
        chips.push([extra, CATEGORY_SHORT_LABELS[extra]]);
      }
    }

    chips.push(['trash', trashCount > 0 ? `回收站 ${trashCount}` : '回收站']);
    return chips;
  }, [passwords, catFilter, trashCount, audit.totpIds.length]);

  const visiblePasswords = useMemo(() => {
    const q = search.trim().toLowerCase();

    return passwords
      .filter((item) => {
        if (catFilter === 'trash') {
          if (!item.isTrashed) return false;
        } else {
          if (item.isTrashed) return false;
          if (catFilter === 'starred' && !item.isPinned) return false;
          if (catFilter === 'has2fa' && !totpSet.has(item.id)) return false;
          if (
            catFilter !== 'all' &&
            catFilter !== 'starred' &&
            catFilter !== 'has2fa' &&
            item.category !== catFilter
          ) {
            return false;
          }
        }

        if (auditFilter === 'weak' && !weakSet.has(item.id)) return false;
        if (auditFilter === 'reused' && !reusedSet.has(item.id)) return false;
        if (auditFilter === 'stale' && !staleSet.has(item.id)) return false;

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
  }, [passwords, catFilter, auditFilter, search, weakSet, reusedSet, staleSet, totpSet]);

  const selectedItem = useMemo(() => {
    if (visiblePasswords.length === 0) return null;
    return visiblePasswords.find((p) => p.id === selectedId) ?? visiblePasswords[0];
  }, [visiblePasswords, selectedId]);

  // Only tick the 1-second clock when viewing an entry with an active optional 2FA secret
  const selectedHasValidTotp = Boolean(selectedItem && totpSet.has(selectedItem.id));
  useEffect(() => {
    if (!selectedHasValidTotp) return;
    setNowMs(Date.now());
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [selectedHasValidTotp, selectedItem?.id]);

  useEffect(() => {
    const nextId = selectedItem?.id ?? null;
    if (nextId !== selectedId) {
      onSelectId(nextId);
    }
  }, [selectedItem, selectedId, onSelectId]);

  useEffect(() => {
    setRevealPassword(false);
    setRevealedFieldIds({});
    setShowHistory(false);
  }, [selectedItem?.id]);

  const totpSnapshot = useMemo(
    () => tryGenerateTotp(selectedItem?.totpSecret, nowMs),
    [selectedItem?.totpSecret, nowMs],
  );

  const selectedEntropy = useMemo(
    () => evaluatePasswordEntropy(selectedItem?.password ?? ''),
    [selectedItem?.password],
  );

  const hasAnyFilter =
    catFilter !== 'all' || auditFilter !== 'none' || search.trim().length > 0;

  function resetAllFilters() {
    setCatFilter('all');
    setAuditFilter('none');
    setSearch('');
  }

  function openCreateModal(presetCategory?: PasswordCategory) {
    const cat =
      presetCategory ??
      (catFilter !== 'all' &&
      catFilter !== 'starred' &&
      catFilter !== 'has2fa' &&
      catFilter !== 'trash'
        ? catFilter
        : 'login');
    setFormState({ open: true, editing: null, defaultCategory: cat });
  }

  async function copyText(val: string, label: string, feedbackKey?: string) {
    await navigator.clipboard.writeText(val);
    if (feedbackKey) {
      setCopiedKey(feedbackKey);
      if (copyTimerRef.current !== null) {
        window.clearTimeout(copyTimerRef.current);
      }
      copyTimerRef.current = window.setTimeout(() => {
        setCopiedKey(null);
      }, 1600);
    }
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

  const healthTone =
    audit.totalCount === 0
      ? 'neutral'
      : audit.healthScore >= 80
        ? 'good'
        : audit.healthScore >= 55
          ? 'warn'
          : 'danger';

  const healthBadgeLabel =
    audit.totalCount === 0
      ? '待添加凭据'
      : audit.healthScore >= 85
        ? '安全极佳'
        : audit.healthScore >= 65
          ? '总体良好'
          : '建议加固';

  return (
    <>
      {/* Column 2: Password Master List & Health Audit */}
      <section className="notelist-pane pss-pwd-list-pane" aria-label="私密密码列表">
        <header className="notelist-header pss-pwd-list-header">
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
              <h1 className="notelist-heading">私密密码库</h1>
              <span className="notelist-badge">{visiblePasswords.length}</span>
            </div>

            <div className="notelist-controls pss-pwd-header-actions">
              <input
                ref={csvInputRef}
                type="file"
                accept=".csv,text/csv"
                style={{ display: 'none' }}
                onChange={(e) => void handleCsvFile(e)}
              />
              <button
                type="button"
                className="btn-icon pss-header-icon-btn"
                title="从浏览器 / 1Password / Bitwarden CSV 导入"
                aria-label="CSV 批量导入密码"
                onClick={() => csvInputRef.current?.click()}
              >
                <Upload size={15} />
              </button>
              <button
                type="button"
                className="btn-icon pss-header-icon-btn"
                title="打开 CSPRNG 密码生成器"
                aria-label="打开密码生成器"
                onClick={() => setGeneratorOpen(true)}
              >
                <Sparkles size={15} />
              </button>
              <button
                id="new-password-btn"
                type="button"
                className="btn btn-primary pss-new-pwd-btn"
                onClick={() => openCreateModal()}
              >
                <Plus size={14} strokeWidth={2.2} />
                <span>新建</span>
              </button>
            </div>
          </div>

          {/* Security Health Audit Banner (Password Strength, Reuse & Rotation — 2FA never penalized) */}
          <div className="pss-health-card">
            <div className="pss-health-top">
              <span className="pss-health-score">
                {healthTone === 'danger' || healthTone === 'warn' ? (
                  <ShieldAlert
                    size={14}
                    style={{
                      color: healthTone === 'danger' ? 'var(--danger)' : 'var(--amber)',
                    }}
                  />
                ) : (
                  <ShieldCheck size={14} style={{ color: 'var(--accent)' }} />
                )}
                <span>密码健康分</span>
                <strong className="mono pss-health-num">{audit.healthScore}/100</strong>
              </span>

              {auditFilter !== 'none' ? (
                <button
                  type="button"
                  className="pss-link-mini"
                  onClick={() => setAuditFilter('none')}
                >
                  清除筛选
                </button>
              ) : (
                <span className={`pss-health-tag is-${healthTone}`}>{healthBadgeLabel}</span>
              )}
            </div>

            <div className="pss-health-bar" aria-hidden="true">
              <span
                className={`pss-health-bar-fill is-${healthTone}`}
                style={{
                  width: `${audit.totalCount === 0 ? 100 : Math.max(6, audit.healthScore)}%`,
                }}
              />
            </div>

            <div className="pss-audit-pills">
              <button
                type="button"
                className={`pss-audit-pill ${auditFilter === 'weak' ? 'is-active' : ''} ${
                  audit.weakIds.length > 0 ? 'has-issue' : ''
                }`}
                onClick={() => setAuditFilter((f) => (f === 'weak' ? 'none' : 'weak'))}
              >
                弱密码 ({audit.weakIds.length})
              </button>
              <button
                type="button"
                className={`pss-audit-pill ${auditFilter === 'reused' ? 'is-active' : ''} ${
                  audit.reusedIds.length > 0 ? 'has-issue' : ''
                }`}
                onClick={() => setAuditFilter((f) => (f === 'reused' ? 'none' : 'reused'))}
              >
                重复 ({audit.reusedIds.length})
              </button>
              <button
                type="button"
                className={`pss-audit-pill ${auditFilter === 'stale' ? 'is-active' : ''} ${
                  audit.staleIds.length > 0 ? 'has-issue' : ''
                }`}
                onClick={() => setAuditFilter((f) => (f === 'stale' ? 'none' : 'stale'))}
                title="超过 180 天未更新的密码"
              >
                久未换 ({audit.staleIds.length})
              </button>
            </div>
          </div>

          <div className="search-box">
            <Search size={14} className="search-box-icon" />
            <input
              id="password-search-input"
              type="search"
              className="search-input"
              placeholder="搜索名称、账号、域名或标签..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
            {search && (
              <button
                type="button"
                className="search-clear-btn"
                onClick={() => setSearch('')}
                aria-label="清除搜索"
              >
                <X size={13} />
              </button>
            )}
          </div>

          <div className="pss-filter-strip" role="tablist" aria-label="密码分类筛选">
            {filterChips.map(([key, label]) => (
              <button
                key={key}
                type="button"
                role="tab"
                aria-selected={catFilter === key}
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
              style={{ width: '100%', height: 30, fontSize: '0.78rem' }}
              onClick={() => void onEmptyTrash()}
            >
              <Trash2 size={13} />
              <span>彻底清空密码回收站 ({visiblePasswords.length})</span>
            </button>
          )}
        </header>

        {visiblePasswords.length === 0 ? (
          <div className="notelist-empty pss-list-empty">
            <div className="pss-list-empty-icon">
              {catFilter === 'trash' ? (
                <Trash2 size={20} strokeWidth={1.7} />
              ) : (
                <KeyRound size={20} strokeWidth={1.7} />
              )}
            </div>
            {catFilter === 'trash' ? (
              <>
                <p className="pss-list-empty-title">密码回收站为空</p>
                <span className="pss-list-empty-sub">已删除的密码条目可在此恢复或彻底销毁</span>
              </>
            ) : search.trim() || auditFilter !== 'none' ? (
              <>
                <p className="pss-list-empty-title">未找到匹配的加密密码</p>
                <span className="pss-list-empty-sub">尝试更换关键词或清除安全审计筛选</span>
                <button
                  type="button"
                  className="btn btn-secondary"
                  style={{ height: 30, padding: '0 12px', fontSize: '0.8rem', marginTop: 4 }}
                  onClick={resetAllFilters}
                >
                  <span>清除筛选条件</span>
                </button>
              </>
            ) : catFilter !== 'all' ? (
              <>
                <p className="pss-list-empty-title">当前筛选暂无密码条目</p>
                {catFilter !== 'starred' && catFilter !== 'has2fa' && (
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ height: 30, padding: '0 12px', fontSize: '0.8rem', marginTop: 4 }}
                    onClick={() => openCreateModal(catFilter as PasswordCategory)}
                  >
                    <Plus size={13} />
                    <span>在此分类新建</span>
                  </button>
                )}
              </>
            ) : (
              <>
                <p className="pss-list-empty-title">暂无加密密码条目</p>
                <span className="pss-list-empty-sub">
                  点击右上角「新建」或导入 CSV 开始加密托管网站与应用密码
                </span>
              </>
            )}
          </div>
        ) : (
          <div className="notelist-items" role="listbox" aria-label="密码列表条目">
            {visiblePasswords.map((item) => {
              const isSelected = selectedItem?.id === item.id;
              const initial = (item.title.trim()[0] || 'P').toUpperCase();
              const hasValidTotp = totpSet.has(item.id);
              const hasInvalidTotp = invalidTotpSet.has(item.id);
              const hasRisk =
                weakSet.has(item.id) || reusedSet.has(item.id) || hasInvalidTotp;
              const host = extractDisplayHost(item.url);
              const subtitle = item.username
                ? item.username
                : host
                  ? host
                  : '仅密码凭据';
              const riskTooltip = weakSet.has(item.id)
                ? '弱密码风险'
                : reusedSet.has(item.id)
                  ? '存在重复使用密码'
                  : '两步验证密钥格式有误';

              return (
                <div
                  key={item.id}
                  role="option"
                  tabIndex={0}
                  aria-selected={isSelected}
                  className={`note-card pss-pwd-card ${isSelected ? 'is-selected' : ''}`}
                  onClick={() => {
                    onSelectId(item.id);
                    onOpenMobileDetail?.();
                  }}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelectId(item.id);
                      onOpenMobileDetail?.();
                    }
                  }}
                >
                  <div className="pss-pwd-card-row">
                    <span className="pss-avatar-badge">{initial}</span>
                    <div className="pss-pwd-card-body">
                      <div className="pss-pwd-card-top">
                        <span className="pss-pwd-card-title">{item.title}</span>
                        <span className="pss-pwd-card-badges">
                          {hasRisk && !item.isTrashed && (
                            <span className="pss-risk-dot" title={riskTooltip} />
                          )}
                          {item.isPinned && (
                            <Star
                              size={12}
                              fill="var(--amber)"
                              style={{ color: 'var(--amber)', flexShrink: 0 }}
                            />
                          )}
                          {hasValidTotp && (
                            <span className="pss-2fa-mini" title="已启用可选两步验证 (2FA)">
                              2FA
                            </span>
                          )}
                          {hasInvalidTotp && (
                            <span className="pss-2fa-mini is-invalid" title="2FA 密钥格式有误">
                              2FA异常
                            </span>
                          )}
                        </span>
                      </div>
                      <div className="pss-pwd-card-sub">
                        <span className="pss-pwd-card-account">{subtitle}</span>
                        <span className="pss-pwd-card-right-meta">
                          {!item.isTrashed && (
                            <span className="pss-card-quick-actions">
                              {item.username && (
                                <button
                                  type="button"
                                  className={`pss-quick-copy-btn ${
                                    copiedKey === `list-u-${item.id}` ? 'is-copied' : ''
                                  }`}
                                  title={`复制账号：${item.username}`}
                                  aria-label={`复制 ${item.title} 的账号`}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    void copyText(item.username, '账号', `list-u-${item.id}`);
                                  }}
                                >
                                  {copiedKey === `list-u-${item.id}` ? (
                                    <Check size={12} />
                                  ) : (
                                    <User size={12} />
                                  )}
                                </button>
                              )}
                              {item.password && (
                                <button
                                  type="button"
                                  className={`pss-quick-copy-btn ${
                                    copiedKey === `list-p-${item.id}` ? 'is-copied' : ''
                                  }`}
                                  title="快速复制密码"
                                  aria-label={`复制 ${item.title} 的密码`}
                                  onClick={(e) => {
                                    e.stopPropagation();
                                    void copyText(item.password, '密码', `list-p-${item.id}`);
                                  }}
                                >
                                  {copiedKey === `list-p-${item.id}` ? (
                                    <Check size={12} />
                                  ) : (
                                    <Copy size={12} />
                                  )}
                                </button>
                              )}
                            </span>
                          )}
                          <span className="pss-pwd-card-cat">
                            {CATEGORY_SHORT_LABELS[item.category]}
                          </span>
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Column 3: Password Detail Inspector (Password-First Hierarchy) */}
      <main className="editor-pane pss-detail-pane" aria-label="密码详情检视">
        {!selectedItem ? (
          <div className="editor-empty-state pss-vault-empty-state">
            {catFilter === 'trash' ? (
              <>
                <div className="editor-empty-icon">
                  <ShieldCheck size={24} />
                </div>
                <h2>密码回收站为空</h2>
                <p>所有已删除的加密凭据均已清理完毕，主库中的密码持续受 AES-256-GCM 保护。</p>
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setCatFilter('all')}
                >
                  <span>返回全部密码</span>
                </button>
              </>
            ) : audit.totalCount > 0 && hasAnyFilter ? (
              <>
                <div className="editor-empty-icon">
                  <Search size={24} />
                </div>
                <h2>没有符合当前筛选条件的密码</h2>
                <p>当前密码库共有 {audit.totalCount} 条有效加密凭据，可重置筛选条件或新建条目。</p>
                <div className="pss-empty-cta-row">
                  <button type="button" className="btn btn-secondary" onClick={resetAllFilters}>
                    <span>重置全部筛选</span>
                  </button>
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => openCreateModal()}
                  >
                    <Plus size={15} />
                    <span>新建加密密码</span>
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="editor-empty-icon">
                  <KeyRound size={25} />
                </div>
                <h2>端到端 AES-256-GCM 私密密码库</h2>
                <p>
                  安全托管各类网站、应用、路由器与服务器的登录账号与密码。内置
                  CSPRNG 随机口令生成与强度审计，并支持为需要的账号按需选配两步验证 (2FA)。
                </p>

                <div className="pss-empty-features" aria-label="安全特性概览">
                  <span className="pss-feature-pill">
                    <ShieldCheck size={13} /> HKDF 独立子密钥
                  </span>
                  <span className="pss-feature-pill">
                    <Sparkles size={13} /> CSPRNG 强口令审计
                  </span>
                  <span className="pss-feature-pill">
                    <Clock size={13} /> 两步验证按需选配
                  </span>
                </div>

                <div className="pss-empty-cta-row">
                  <button
                    type="button"
                    className="btn btn-primary"
                    onClick={() => openCreateModal()}
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
                  <button
                    type="button"
                    className="btn btn-secondary"
                    onClick={() => csvInputRef.current?.click()}
                  >
                    <Upload size={15} />
                    <span>导入 CSV</span>
                  </button>
                </div>
              </>
            )}
          </div>
        ) : (
          <>
            {/* Unified Topbar matching NoteEditor */}
            <header className="editor-topbar">
              <div className="editor-topbar-left">
                {onBackToListMobile && (
                  <button
                    type="button"
                    className="btn-icon mobile-back-btn"
                    onClick={onBackToListMobile}
                    aria-label="返回密码列表"
                  >
                    <ArrowLeft size={17} />
                  </button>
                )}
                <button
                  type="button"
                  className="cipher-pill"
                  onClick={() => onInspectCipher(selectedItem.id)}
                  title="透视底层 SQLite AES-256-GCM 原始密文信封"
                >
                  <ShieldCheck size={14} />
                  <span>AES-256-GCM · Sync #{selectedItem.syncSeq}</span>
                </button>
                <span className="pss-badge-subtle">
                  {PASSWORD_CATEGORY_LABELS[selectedItem.category]}
                </span>
              </div>

              <div className="editor-topbar-right">
                {!selectedItem.isTrashed ? (
                  <>
                    <button
                      type="button"
                      className={`btn-icon ${selectedItem.isPinned ? 'is-active' : ''}`}
                      title={selectedItem.isPinned ? '取消收藏' : '加入收藏'}
                      aria-label={selectedItem.isPinned ? '取消收藏' : '加入收藏'}
                      onClick={() =>
                        void onUpdatePassword(selectedItem.id, {
                          isPinned: !selectedItem.isPinned,
                        })
                      }
                    >
                      <Star
                        size={15}
                        fill={selectedItem.isPinned ? 'var(--amber)' : 'none'}
                        style={{ color: selectedItem.isPinned ? 'var(--amber)' : undefined }}
                      />
                    </button>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      style={{ height: 30, padding: '0 11px', fontSize: '0.8rem' }}
                      onClick={() => setFormState({ open: true, editing: selectedItem })}
                    >
                      <Edit3 size={13} />
                      <span>编辑</span>
                    </button>
                    <button
                      type="button"
                      className="btn-icon"
                      title="移入密码回收站"
                      aria-label="移入密码回收站"
                      onClick={() =>
                        void onUpdatePassword(selectedItem.id, { isTrashed: true }).then(() =>
                          onNotify('已移入密码回收站'),
                        )
                      }
                    >
                      <Trash2 size={15} />
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      type="button"
                      className="btn btn-secondary"
                      style={{ height: 30, padding: '0 11px', fontSize: '0.8rem' }}
                      onClick={() =>
                        void onUpdatePassword(selectedItem.id, { isTrashed: false }).then(() =>
                          onNotify('密码条目已恢复'),
                        )
                      }
                    >
                      <RotateCcw size={13} />
                      <span>恢复</span>
                    </button>
                    <button
                      type="button"
                      className="btn btn-danger"
                      style={{ height: 30, padding: '0 11px', fontSize: '0.8rem' }}
                      onClick={() => void onDeletePermanent(selectedItem.id)}
                    >
                      <Trash2 size={13} />
                      <span>彻底销毁</span>
                    </button>
                  </>
                )}
              </div>
            </header>

            {selectedItem.isTrashed && (
              <div className="trash-banner">
                <span>此加密密码条目位于回收站中，恢复后可重新编辑或正常归类。</span>
                <div className="trash-banner-actions">
                  <button
                    type="button"
                    className="btn btn-secondary"
                    style={{ height: 28, padding: '0 10px', fontSize: '0.78rem' }}
                    onClick={() =>
                      void onUpdatePassword(selectedItem.id, { isTrashed: false }).then(() =>
                        onNotify('密码条目已恢复'),
                      )
                    }
                  >
                    <RotateCcw size={13} />
                    <span>恢复条目</span>
                  </button>
                  <button
                    type="button"
                    className="btn btn-danger"
                    style={{ height: 28, padding: '0 10px', fontSize: '0.78rem' }}
                    onClick={() => void onDeletePermanent(selectedItem.id)}
                  >
                    <Trash2 size={13} />
                    <span>彻底销毁密文</span>
                  </button>
                </div>
              </div>
            )}

            <div className="pss-detail-scroll">
              <div className="pss-detail-inner">
                <header className="pss-detail-header">
                  <div className="pss-detail-title-group">
                    <span className="pss-avatar-badge is-lg">
                      {(selectedItem.title.trim()[0] || 'P').toUpperCase()}
                    </span>
                    <div style={{ minWidth: 0 }}>
                      <h2 className="pss-detail-title">{selectedItem.title}</h2>
                      <div className="pss-detail-meta">
                        {selectedItem.url ? (
                          <a
                            href={toSafeHref(selectedItem.url)}
                            target="_blank"
                            rel="noreferrer"
                            className="pss-host-link mono"
                          >
                            <Globe size={12} />
                            <span>{extractDisplayHost(selectedItem.url)}</span>
                            <ExternalLink size={11} />
                          </a>
                        ) : (
                          <span className="pss-detail-subtext">
                            {PASSWORD_CATEGORY_LABELS[selectedItem.category]}
                          </span>
                        )}
                        {totpSnapshot && (
                          <span className="pss-detail-2fa-pill">已选配 2FA</span>
                        )}
                        {selectedItem.tags.map((tag) => (
                          <span key={tag} className="tag-chip-mini">
                            #{tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>

                  <div className="pss-detail-actions">
                    {selectedItem.username && (
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{ height: 34, padding: '0 12px', fontSize: '0.84rem' }}
                        onClick={() =>
                          void copyText(selectedItem.username, '账号', 'head-username')
                        }
                      >
                        {copiedKey === 'head-username' ? <Check size={13} /> : <Copy size={13} />}
                        <span>{copiedKey === 'head-username' ? '已复制' : '复制账号'}</span>
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn btn-primary"
                      style={{ height: 34, padding: '0 13px', fontSize: '0.84rem' }}
                      onClick={() => void copyText(selectedItem.password, '密码', 'head-password')}
                    >
                      {copiedKey === 'head-password' ? <Check size={13} /> : <Copy size={13} />}
                      <span>{copiedKey === 'head-password' ? '密码已复制' : '复制密码'}</span>
                    </button>
                  </div>
                </header>

                {/* 1. Primary Credentials Card (Always First for Consistent Reading & Copying) */}
                <div className="pss-cred-card">
                  <div className="pss-cred-row">
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="pss-field-caption">用户名 / 登录账号</div>
                      {selectedItem.username ? (
                        <div className="pss-field-value mono" style={{ wordBreak: 'break-all' }}>
                          {selectedItem.username}
                        </div>
                      ) : (
                        <div className="pss-field-value is-empty">未填写账号（仅密码凭据）</div>
                      )}
                    </div>
                    {selectedItem.username && (
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{ height: 31, padding: '0 10px', fontSize: '0.8rem' }}
                        onClick={() =>
                          void copyText(selectedItem.username, '账号', 'row-username')
                        }
                      >
                        {copiedKey === 'row-username' ? <Check size={13} /> : <Copy size={13} />}
                        <span>{copiedKey === 'row-username' ? '已复制' : '复制'}</span>
                      </button>
                    )}
                  </div>

                  <div className="pss-cred-row">
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="pss-field-caption pss-caption-row">
                        <span>登录密码</span>
                        <span className={`pss-entropy-pill level-${selectedEntropy.score}`}>
                          {selectedEntropy.label} · {selectedEntropy.entropyBits} bits
                        </span>
                        {weakSet.has(selectedItem.id) && (
                          <span className="pss-warn-badge is-danger">
                            <AlertTriangle size={11} /> 弱密码风险
                          </span>
                        )}
                        {reusedSet.has(selectedItem.id) && (
                          <span className="pss-warn-badge">
                            <AlertTriangle size={11} /> 重复使用
                          </span>
                        )}
                        {staleSet.has(selectedItem.id) && (
                          <span className="pss-warn-badge">
                            <Clock size={11} /> 久未更换
                          </span>
                        )}
                      </div>
                      <div
                        className={`pss-field-value mono ${!revealPassword ? 'is-masked' : ''}`}
                        style={{ wordBreak: 'break-all' }}
                      >
                        {revealPassword ? (
                          <ColorizedPassword text={selectedItem.password} />
                        ) : (
                          '••••••••••••••••••••'
                        )}
                      </div>
                      {selectedItem.password && (
                        <div className="pss-detail-strength-bars" aria-hidden="true">
                          {[1, 2, 3, 4].map((idx) => (
                            <span
                              key={idx}
                              className={`strength-bar ${
                                selectedEntropy.score >= idx
                                  ? `level-${Math.max(1, selectedEntropy.score)}`
                                  : ''
                              }`}
                            />
                          ))}
                        </div>
                      )}
                    </div>
                    <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{ height: 31, padding: '0 10px', fontSize: '0.8rem' }}
                        onClick={() => setRevealPassword((v) => !v)}
                      >
                        {revealPassword ? <EyeOff size={13} /> : <Eye size={13} />}
                        <span>{revealPassword ? '隐藏' : '显示'}</span>
                      </button>
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{ height: 31, padding: '0 10px', fontSize: '0.8rem' }}
                        onClick={() => void copyText(selectedItem.password, '密码', 'row-password')}
                      >
                        {copiedKey === 'row-password' ? <Check size={13} /> : <Copy size={13} />}
                        <span>{copiedKey === 'row-password' ? '已复制' : '复制'}</span>
                      </button>
                    </div>
                  </div>

                  {selectedItem.url && (
                    <div className="pss-cred-row">
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="pss-field-caption">关联网站 / 服务地址</div>
                        <div
                          className="pss-field-value mono"
                          style={{
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {selectedItem.url}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                        <button
                          type="button"
                          className="btn btn-secondary"
                          style={{ height: 31, padding: '0 10px', fontSize: '0.8rem' }}
                          onClick={() => void copyText(selectedItem.url, '网址', 'row-url')}
                        >
                          {copiedKey === 'row-url' ? <Check size={13} /> : <Copy size={13} />}
                          <span>{copiedKey === 'row-url' ? '已复制' : '复制'}</span>
                        </button>
                        <a
                          href={toSafeHref(selectedItem.url)}
                          target="_blank"
                          rel="noreferrer"
                          className="btn btn-secondary"
                          style={{
                            height: 31,
                            padding: '0 10px',
                            fontSize: '0.8rem',
                            textDecoration: 'none',
                          }}
                        >
                          <ExternalLink size={13} />
                          <span>打开</span>
                        </a>
                      </div>
                    </div>
                  )}
                </div>

                {/* 2. Optional RFC 6238 TOTP Card (Rendered ONLY when user configured 2FA) */}
                {totpSnapshot ? (
                  <div className="pss-totp-card">
                    <div>
                      <div className="pss-totp-label-row">
                        <span className="pss-totp-label">两步验证动态口令 (TOTP)</span>
                        <span className="pss-totp-opt-tag">可选配置</span>
                      </div>
                      <button
                        type="button"
                        className="pss-totp-code mono"
                        title="点击复制动态验证码"
                        onClick={() => void copyText(totpSnapshot.code, '动态验证码', 'row-totp')}
                      >
                        {totpSnapshot.formattedCode}
                      </button>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div
                        className="pss-totp-ring-wrap"
                        title={`剩余 ${totpSnapshot.remainingSeconds} 秒刷新`}
                      >
                        <svg width="30" height="30" viewBox="0 0 32 32">
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
                        className="btn btn-secondary"
                        style={{ height: 32, padding: '0 12px', fontSize: '0.82rem' }}
                        onClick={() => void copyText(totpSnapshot.code, '动态验证码', 'row-totp')}
                      >
                        {copiedKey === 'row-totp' ? <Check size={13} /> : <Copy size={13} />}
                        <span>{copiedKey === 'row-totp' ? '已复制' : '复制动态码'}</span>
                      </button>
                    </div>
                  </div>
                ) : invalidTotpSet.has(selectedItem.id) ? (
                  <div className="pss-totp-invalid-card">
                    <div className="pss-totp-invalid-text">
                      <AlertTriangle size={15} style={{ color: 'var(--amber)', flexShrink: 0 }} />
                      <div>
                        <strong>两步验证密钥格式有误</strong>
                        <p>
                          当前填写的 2FA 密钥不是合法的 Base32 或 otpauth://
                          格式；若此账号无需两步验证，可在编辑中直接关闭。
                        </p>
                      </div>
                    </div>
                    {!selectedItem.isTrashed && (
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{ height: 31, padding: '0 11px', fontSize: '0.8rem', flexShrink: 0 }}
                        onClick={() => setFormState({ open: true, editing: selectedItem })}
                      >
                        <Edit3 size={13} />
                        <span>编辑修正或关闭</span>
                      </button>
                    )}
                  </div>
                ) : null}

                {/* 3. Custom Fields */}
                {selectedItem.customFields.length > 0 && (
                  <div className="pss-cred-card">
                    <div className="pss-card-section-head">
                      自定义附加字段 ({selectedItem.customFields.length})
                    </div>
                    {selectedItem.customFields.map((cf) => {
                      const shown = !cf.hidden || Boolean(revealedFieldIds[cf.id]);
                      const cfCopyKey = `cf-${cf.id}`;
                      return (
                        <div key={cf.id} className="pss-cred-row">
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div className="pss-field-caption">{cf.label || '未命名字段'}</div>
                            <div
                              className={`pss-field-value mono ${!shown ? 'is-masked' : ''}`}
                              style={{ wordBreak: 'break-all' }}
                            >
                              {shown ? cf.value : '••••••••••••'}
                            </div>
                          </div>
                          <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                            {cf.hidden && (
                              <button
                                type="button"
                                className="btn-icon"
                                title={shown ? '隐藏内容' : '显示内容'}
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
                              title="复制字段值"
                              onClick={() =>
                                void copyText(cf.value, cf.label || '字段内容', cfCopyKey)
                              }
                            >
                              {copiedKey === cfCopyKey ? <Check size={14} /> : <Copy size={14} />}
                            </button>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* 4. Encrypted Notes */}
                {selectedItem.notes.trim().length > 0 && (
                  <div className="pss-section-card">
                    <div className="pss-field-caption">加密私密备注</div>
                    <div className="pss-notes-body">{selectedItem.notes}</div>
                  </div>
                )}

                {/* 5. Metadata & Password History */}
                <div className="pss-section-card">
                  <div className="pss-meta-footer-row">
                    <span>
                      <Clock size={12} style={{ verticalAlign: '-2px', marginRight: 5 }} />
                      创建于 {formatFullDateTime(selectedItem.createdAt)} · 更新于{' '}
                      {formatShortDate(selectedItem.updatedAt)} · 密文{' '}
                      {formatBytes(selectedItem.byteSize)}
                    </span>
                    {selectedItem.history.length > 0 && (
                      <button
                        type="button"
                        className="pss-link-mini"
                        onClick={() => setShowHistory((s) => !s)}
                      >
                        <History size={13} />
                        <span>
                          {showHistory
                            ? '收起历史密码'
                            : `历史旧密码记录 (${selectedItem.history.length} 条)`}
                        </span>
                      </button>
                    )}
                  </div>

                  {showHistory && selectedItem.history.length > 0 && (
                    <div className="pss-history-list">
                      {selectedItem.history.map((h, i) => (
                        <div key={`${h.changedAt}-${i}`} className="pss-history-row">
                          <div style={{ minWidth: 0 }}>
                            <div
                              className="mono"
                              style={{ fontSize: '0.84rem', wordBreak: 'break-all' }}
                            >
                              {h.password}
                            </div>
                            <div style={{ fontSize: '0.73rem', color: 'var(--text-tertiary)' }}>
                              归档于 {formatFullDateTime(h.changedAt)}
                            </div>
                          </div>
                          <button
                            type="button"
                            className="btn-icon"
                            title="复制历史旧密码"
                            onClick={() => void copyText(h.password, '历史旧密码', `hist-${i}`)}
                          >
                            {copiedKey === `hist-${i}` ? <Check size={13} /> : <Copy size={13} />}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            </div>
          </>
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
          defaultCategory={formState.defaultCategory}
          onClose={() => setFormState({ open: false, editing: null })}
          onSave={async (payload) => {
            if (formState.editing) {
              const updated = await onUpdatePassword(formState.editing.id, payload);
              onSelectId(updated.id);
              onNotify('加密密码条目已更新');
            } else {
              const created = await onCreatePassword(payload as CreatePasswordRequest);
              if (
                catFilter !== 'all' &&
                catFilter !== 'starred' &&
                !(catFilter === 'has2fa' && Boolean(created.totpSecret.trim())) &&
                created.category !== catFilter
              ) {
                setCatFilter('all');
              }
              onSelectId(created.id);
              onOpenMobileDetail?.();
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
  defaultCategory?: PasswordCategory;
  onClose: () => void;
  onSave: (input: CreatePasswordRequest | UpdatePasswordRequest) => Promise<void>;
  onNotify: (msg: string) => void;
}

const PasswordEditorModal: React.FC<PasswordEditorModalProps> = ({
  editing,
  defaultCategory = 'login',
  onClose,
  onSave,
  onNotify,
}) => {
  const [title, setTitle] = useState(editing?.title ?? '');
  const [category, setCategory] = useState<PasswordCategory>(
    editing?.category ?? defaultCategory,
  );
  const [isPinned, setIsPinned] = useState(editing?.isPinned ?? false);
  const [username, setUsername] = useState(editing?.username ?? '');
  const [password, setPassword] = useState(editing?.password ?? '');
  const [showPwd, setShowPwd] = useState(() => !editing);
  const [url, setUrl] = useState(editing?.url ?? '');

  // Optional 2FA: collapsed/OFF by default unless editing an item that already configured 2FA
  const hadInitialTotp = Boolean(editing?.totpSecret?.trim());
  const [enableTotp, setEnableTotp] = useState(hadInitialTotp);
  const [totpSecret, setTotpSecret] = useState(editing?.totpSecret ?? '');
  const [previewMs, setPreviewMs] = useState(() => Date.now());

  // Optional extras: collapsed by default on new items to keep standard password entry clean
  const [showExtras, setShowExtras] = useState(() =>
    Boolean(editing && (editing.tags.length > 0 || editing.customFields.length > 0)),
  );
  const [tagsText, setTagsText] = useState(editing?.tags.join(', ') ?? '');
  const [notes, setNotes] = useState(editing?.notes ?? '');
  const [customFields, setCustomFields] = useState<PasswordCustomField[]>(
    editing?.customFields ?? [],
  );
  const [genOpen, setGenOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape' && !genOpen) {
        onClose();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [genOpen, onClose]);

  const entropy = useMemo(() => evaluatePasswordEntropy(password), [password]);

  const totpValidation = useMemo(() => {
    if (!enableTotp || !totpSecret.trim()) {
      return { valid: false, config: null, error: null as string | null };
    }
    try {
      const config = parseTotpInput(totpSecret);
      return { valid: true, config, error: null as string | null };
    } catch (err) {
      return {
        valid: false,
        config: null,
        error: err instanceof Error ? err.message : '2FA 密钥格式无效',
      };
    }
  }, [enableTotp, totpSecret]);

  useEffect(() => {
    if (!totpValidation.valid) return;
    setPreviewMs(Date.now());
    const timer = window.setInterval(() => setPreviewMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [totpValidation.valid]);

  const totpPreview = useMemo(
    () => (totpValidation.valid ? tryGenerateTotp(totpSecret, previewMs) : null),
    [totpValidation.valid, totpSecret, previewMs],
  );

  const suggestedHost = useMemo(() => extractDisplayHost(url), [url]);

  const extraCount = useMemo(() => {
    const tagCount = tagsText
      .split(/[,，]/)
      .map((t) => t.trim())
      .filter(Boolean).length;
    const cfCount = customFields.filter((cf) => cf.label.trim() || cf.value.trim()).length;
    return tagCount + cfCount;
  }, [tagsText, customFields]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!title.trim()) {
      setError('请填写网站或应用名称');
      return;
    }
    if (enableTotp && totpSecret.trim() && totpValidation.error) {
      setError(`两步验证密钥格式有误（${totpValidation.error}），请修正或关闭两步验证开关`);
      return;
    }

    const finalTotp = enableTotp ? totpSecret.trim() : '';

    setSubmitting(true);
    setError(null);
    try {
      await onSave({
        title: title.trim(),
        category,
        isPinned,
        username: username.trim(),
        password,
        url: url.trim(),
        totpSecret: finalTotp,
        tags: tagsText
          .split(/[,，]/)
          .map((t) => t.trim())
          .filter(Boolean),
        notes,
        customFields: customFields.filter((cf) => cf.label.trim() || cf.value.trim()),
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
        <form
          className="modal-dialog pss-editor-dialog"
          style={{ maxWidth: 576 }}
          role="dialog"
          aria-modal="true"
          aria-labelledby="pwd-editor-modal-title"
          onSubmit={(e) => void handleSubmit(e)}
        >
          <header className="modal-header">
            <div className="modal-title-wrap">
              <KeyRound size={18} style={{ color: 'var(--accent)' }} />
              <h2 id="pwd-editor-modal-title" className="modal-title">
                {editing ? '编辑加密密码条目' : '新建私密密码条目'}
              </h2>
            </div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              <button
                type="button"
                className={`btn-icon ${isPinned ? 'is-active' : ''}`}
                title={isPinned ? '取消收藏置顶' : '设为收藏置顶'}
                aria-label={isPinned ? '取消收藏置顶' : '设为收藏置顶'}
                onClick={() => setIsPinned((v) => !v)}
              >
                <Star
                  size={16}
                  fill={isPinned ? 'var(--amber)' : 'none'}
                  style={{ color: isPinned ? 'var(--amber)' : undefined }}
                />
              </button>
              <button type="button" className="btn-icon" onClick={onClose} aria-label="关闭">
                <X size={17} />
              </button>
            </div>
          </header>

          <div className="modal-body pss-editor-form-body">
            {/* Row 1: Title + Category */}
            <div className="pss-form-grid-title">
              <div className="field-group">
                <div className="field-label">
                  <label htmlFor="pwd-field-title">网站 / 应用名称 *</label>
                  {!title.trim() && suggestedHost && (
                    <button
                      type="button"
                      className="pss-link-mini"
                      onClick={() => setTitle(suggestedHost)}
                    >
                      填入“{suggestedHost}”
                    </button>
                  )}
                </div>
                <input
                  id="pwd-field-title"
                  type="text"
                  className="field-input pss-modal-input"
                  placeholder="例如：京东商城、哔哩哔哩、家庭软路由"
                  value={title}
                  onChange={(e) => setTitle(e.target.value)}
                  autoFocus
                  required
                />
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="pwd-field-category">
                  所属分类
                </label>
                <select
                  id="pwd-field-category"
                  className="field-input pss-modal-input"
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

            {/* Row 2: Username + Website URL */}
            <div className="pss-form-grid-two">
              <div className="field-group">
                <label className="field-label" htmlFor="pwd-field-username">
                  <span>用户名 / 手机号 / 邮箱</span>
                  <span className="pss-label-opt">选填</span>
                </label>
                <input
                  id="pwd-field-username"
                  type="text"
                  className="field-input pss-modal-input mono"
                  placeholder="账号或留空（仅密码凭据）"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="pwd-field-url">
                  <span>关联网址 (URL)</span>
                  <span className="pss-label-opt">选填</span>
                </label>
                <input
                  id="pwd-field-url"
                  type="text"
                  className="field-input pss-modal-input mono"
                  placeholder="https://example.com 或内网 IP"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </div>
            </div>

            {/* Row 3: Password + Inline Generator */}
            <div className="field-group">
              <div className="field-label">
                <span>
                  登录密码{' '}
                  {password ? (
                    <span className={`pss-entropy-pill level-${entropy.score}`}>
                      {entropy.label} · {entropy.entropyBits} bits
                    </span>
                  ) : null}
                </span>
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 10 }}>
                  <button
                    type="button"
                    className="pss-link-mini"
                    onClick={() => {
                      setPassword(generateSecurePassword({ length: 20 }));
                      setShowPwd(true);
                    }}
                  >
                    <RefreshCw size={12} /> 一键随机
                  </button>
                  <button
                    type="button"
                    className="pss-link-mini"
                    onClick={() => setGenOpen(true)}
                  >
                    <Sparkles size={12} /> 高级生成器
                  </button>
                </span>
              </div>
              <div className="field-input-wrap">
                <input
                  id="pwd-field-password"
                  type={showPwd ? 'text' : 'password'}
                  className="field-input pss-modal-input has-trailing mono"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="输入网站现有密码，或点击右上角生成高强度口令"
                />
                <button
                  type="button"
                  className="field-trailing-btn"
                  onClick={() => setShowPwd((v) => !v)}
                  aria-label={showPwd ? '隐藏密码' : '显示密码'}
                >
                  {showPwd ? <EyeOff size={15} /> : <Eye size={15} />}
                </button>
              </div>
              {password && (
                <div className="strength-bars" style={{ marginTop: 2 }}>
                  {[1, 2, 3, 4].map((idx) => (
                    <span
                      key={idx}
                      className={`strength-bar ${
                        entropy.score >= idx ? `level-${Math.max(1, entropy.score)}` : ''
                      }`}
                    />
                  ))}
                </div>
              )}
            </div>

            {/* Row 4: Notes */}
            <div className="field-group">
              <label className="field-label" htmlFor="pwd-field-notes">
                <span>私密备注</span>
                <span className="pss-label-opt">选填</span>
              </label>
              <textarea
                id="pwd-field-notes"
                className="field-input pss-modal-textarea"
                rows={2}
                placeholder="记录绑定手机号、客服安全问题、SSH 端口等备注信息..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>

            {/* Row 5: Optional 2FA Switch Card (Collapsed by default for normal passwords) */}
            <div className={`pss-optional-card ${enableTotp ? 'is-enabled' : ''}`}>
              <div
                className="pss-optional-head"
                onClick={() => setEnableTotp((v) => !v)}
              >
                <div className="pss-optional-head-text">
                  <div className="pss-optional-title-row">
                    <span>两步验证 (2FA / TOTP 动态口令)</span>
                    <span className="pss-opt-pill">可选项</span>
                  </div>
                  <p className="pss-optional-desc">
                    大多数网站或应用仅需账号密码；目标服务支持身份验证器时再按需开启
                  </p>
                </div>
                <button
                  type="button"
                  role="switch"
                  aria-checked={enableTotp}
                  aria-label="启用两步验证 (2FA)"
                  className={`pss-switch ${enableTotp ? 'is-on' : ''}`}
                  onClick={(e) => {
                    e.stopPropagation();
                    setEnableTotp((v) => !v);
                  }}
                >
                  <span className="pss-switch-thumb" />
                </button>
              </div>

              {enableTotp && (
                <div className="pss-optional-body">
                  <div className="field-group">
                    <div className="field-label">
                      <label htmlFor="pwd-field-totp">Base32 密钥或 otpauth:// 链接</label>
                      {totpValidation.config &&
                        ((!title.trim() && totpValidation.config.issuer) ||
                          (!username.trim() && totpValidation.config.accountName)) && (
                          <button
                            type="button"
                            className="pss-link-mini"
                            onClick={() => {
                              if (!title.trim() && totpValidation.config?.issuer) {
                                setTitle(totpValidation.config.issuer);
                              }
                              if (!username.trim() && totpValidation.config?.accountName) {
                                setUsername(totpValidation.config.accountName);
                              }
                            }}
                          >
                            填入 URI 账号信息
                          </button>
                        )}
                    </div>
                    <input
                      id="pwd-field-totp"
                      type="text"
                      className="field-input pss-modal-input mono"
                      placeholder="例如：JBSWY3DPEHPK3PXP 或 otpauth://totp/..."
                      value={totpSecret}
                      onChange={(e) => {
                        const val = e.target.value;
                        setTotpSecret(val);
                        if (val.trim().toLowerCase().startsWith('otpauth://')) {
                          try {
                            const parsed = parseTotpInput(val);
                            if (!title.trim() && parsed.issuer) setTitle(parsed.issuer);
                            if (!username.trim() && parsed.accountName) {
                              setUsername(parsed.accountName);
                            }
                          } catch {
                            // Ignore until complete URI is entered
                          }
                        }
                      }}
                    />
                  </div>

                  {totpPreview && totpValidation.config ? (
                    <div className="pss-totp-live-preview">
                      <div className="pss-totp-live-left">
                        <span className="pss-totp-live-badge">实时预览</span>
                        <strong className="mono pss-totp-live-code">
                          {totpPreview.formattedCode}
                        </strong>
                      </div>
                      <span className="pss-totp-live-meta mono">
                        {totpPreview.remainingSeconds}s 刷新 · {totpValidation.config.algorithm} ·{' '}
                        {totpValidation.config.digits}位
                      </span>
                    </div>
                  ) : totpValidation.error ? (
                    <div className="pss-totp-inline-error">
                      <AlertTriangle size={13} />
                      <span>{totpValidation.error}（请输入合法 Base32 密钥或 otpauth:// 链接）</span>
                    </div>
                  ) : (
                    <div className="pss-totp-inline-hint">
                      粘贴网站提供的身份验证器密钥即可实时生成验证码；留空或关闭开关则仅保存常规密码。
                    </div>
                  )}
                </div>
              )}

              {!enableTotp && hadInitialTotp && (
                <div className="pss-totp-removed-note">
                  <span>已关闭两步验证，保存后将移除此条目的 2FA 密钥。</span>
                  <button
                    type="button"
                    className="pss-link-mini"
                    onClick={() => setEnableTotp(true)}
                  >
                    撤销
                  </button>
                </div>
              )}
            </div>

            {/* Row 6: Collapsible Extras (Tags & Custom Hidden Fields) */}
            <div className="pss-extras-section">
              <button
                type="button"
                className="pss-extras-toggle"
                aria-expanded={showExtras}
                onClick={() => setShowExtras((v) => !v)}
              >
                <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6 }}>
                  {showExtras ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  <span>更多选填项（标签 / 自定义隐藏字段）</span>
                </span>
                {extraCount > 0 && (
                  <span className="pss-opt-pill is-accent">已填 {extraCount} 项</span>
                )}
              </button>

              {showExtras && (
                <div className="pss-extras-body">
                  <div className="field-group">
                    <label className="field-label" htmlFor="pwd-field-tags">
                      <span>加密标签（逗号分隔）</span>
                      <span className="pss-label-opt">选填</span>
                    </label>
                    <input
                      id="pwd-field-tags"
                      type="text"
                      className="field-input pss-modal-input is-sm"
                      placeholder="例如：日常购物, 家庭网络, 生产环境"
                      value={tagsText}
                      onChange={(e) => setTagsText(e.target.value)}
                    />
                  </div>

                  <div className="field-group">
                    <div className="field-label">
                      <span>自定义附加字段（PIN 码、恢复备用码、API 密钥）</span>
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
                    {customFields.length > 0 && (
                      <div className="pss-custom-fields-stack">
                        {customFields.map((cf, i) => (
                          <div key={cf.id} className="pss-custom-field-row">
                            <input
                              type="text"
                              className="field-input pss-modal-input is-sm"
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
                              className="field-input pss-modal-input is-sm mono"
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
                            <label className="pss-checkbox-item is-compact">
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
                              style={{ width: 28, height: 28 }}
                              aria-label="移除此字段"
                              onClick={() =>
                                setCustomFields((prev) => prev.filter((_, idx) => idx !== i))
                              }
                            >
                              <X size={14} />
                            </button>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            {error && <div className="auth-error">{error}</div>}
          </div>

          <footer className="pss-modal-footer">
            <button type="button" className="btn btn-secondary" onClick={onClose}>
              取消
            </button>
            <button type="submit" className="btn btn-primary" disabled={submitting}>
              <ShieldCheck size={15} />
              <span>{submitting ? '正在加密写入...' : 'AES-256-GCM 加密保存'}</span>
            </button>
          </footer>
        </form>
      </div>

      <PasswordGeneratorModal
        open={genOpen}
        stacked
        onClose={() => setGenOpen(false)}
        onUsePassword={(pwd) => {
          setPassword(pwd);
          setShowPwd(true);
        }}
        onNotify={onNotify}
      />
    </>
  );
};
