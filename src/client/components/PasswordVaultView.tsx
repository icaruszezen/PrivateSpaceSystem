import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  AlertTriangle,
  ArrowLeft,
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
  X,
} from 'lucide-react';
import {
  auditPasswordVault,
  evaluatePasswordEntropy,
  generateSecurePassword,
} from '@shared/passwordGenerator';
import {
  chunkPasswordImportEntries,
  PASSWORD_IMPORT_BATCH_SIZE,
  parsePasswordCsv,
} from '@shared/passwordCsv';
import { generateTotp } from '@shared/totp';
import type {
  CreatePasswordRequest,
  ImportPasswordEntryInput,
  PasswordCategory,
  PasswordCustomField,
  PasswordImportOptions,
  PasswordImportProgress,
  PasswordItem,
  UpdatePasswordRequest,
} from '@shared/types';
import { formatBytes, formatFullDateTime, formatShortDate } from '../utils/format';
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

const CATEGORY_SHORT_LABELS: Record<PasswordCategory, string> = {
  login: '登录',
  dev: '研发',
  server: '服务器',
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
  onImportPasswords: (
    entries: ImportPasswordEntryInput[],
    options?: PasswordImportOptions,
  ) => Promise<{ count: number; batchCount: number }>;
  onUpdatePassword: (id: string, patch: UpdatePasswordRequest) => Promise<PasswordItem>;
  onDeletePermanent: (id: string) => Promise<void>;
  onEmptyTrash: () => Promise<void>;
  onInspectCipher: (id: string) => void;
  onOpenMobileMenu: () => void;
  onOpenMobileDetail?: () => void;
  onBackToListMobile?: () => void;
  onNotify: (msg: string) => void;
}

type CategoryFilter = 'all' | 'starred' | 'trash' | PasswordCategory;
type AuditFilter = 'none' | 'weak' | 'reused' | 'no2fa';

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

  // Modals & CSV Batch Import state
  const [generatorOpen, setGeneratorOpen] = useState(false);
  const [csvModalOpen, setCsvModalOpen] = useState(false);
  const [importProgress, setImportProgress] = useState<PasswordImportProgress | null>(null);
  const [lastBatchSummary, setLastBatchSummary] = useState<{
    count: number;
    batchCount: number;
    sourceName?: string;
  } | null>(null);
  const [formState, setFormState] = useState<{
    open: boolean;
    editing: PasswordItem | null;
    defaultCategory?: PasswordCategory;
  }>({ open: false, editing: null });

  useEffect(() => {
    const timer = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const audit = useMemo(() => auditPasswordVault(passwords, nowMs), [passwords, nowMs]);
  const weakSet = useMemo(() => new Set(audit.weakIds), [audit.weakIds]);
  const reusedSet = useMemo(() => new Set(audit.reusedIds), [audit.reusedIds]);
  const no2faSet = useMemo(() => new Set(audit.missingTotpIds), [audit.missingTotpIds]);

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
      ['login', CATEGORY_SHORT_LABELS.login],
      ['dev', CATEGORY_SHORT_LABELS.dev],
      ['server', CATEGORY_SHORT_LABELS.server],
      ['finance', CATEGORY_SHORT_LABELS.finance],
    ];

    for (const extra of ['work', 'social', 'other'] as PasswordCategory[]) {
      if (usedCategories.has(extra) || catFilter === extra) {
        chips.push([extra, CATEGORY_SHORT_LABELS[extra]]);
      }
    }

    chips.push(['trash', trashCount > 0 ? `回收站 ${trashCount}` : '回收站']);
    return chips;
  }, [passwords, catFilter, trashCount]);

  const visiblePasswords = useMemo(() => {
    const q = search.trim().toLowerCase();

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
  }, [passwords, catFilter, auditFilter, search, weakSet, reusedSet, no2faSet]);

  const selectedItem = useMemo(() => {
    if (visiblePasswords.length === 0) return null;
    return visiblePasswords.find((p) => p.id === selectedId) ?? visiblePasswords[0];
  }, [visiblePasswords, selectedId]);

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
      (catFilter !== 'all' && catFilter !== 'starred' && catFilter !== 'trash'
        ? catFilter
        : 'login');
    setFormState({ open: true, editing: null, defaultCategory: cat });
  }

  async function copyText(val: string, label: string) {
    await navigator.clipboard.writeText(val);
    onNotify(`${label}已复制到剪贴板`);
  }

  async function executeBatchImport(
    entries: ImportPasswordEntryInput[],
    sourceName?: string,
  ): Promise<{ count: number; batchCount: number }> {
    if (entries.length === 0) {
      onNotify('未解析到有效的 CSV 密码记录');
      return { count: 0, batchCount: 0 };
    }

    setLastBatchSummary(null);
    try {
      const res = await onImportPasswords(entries, {
        onProgress: (prog) => {
          setImportProgress(prog);
        },
      });
      setLastBatchSummary({
        count: res.count,
        batchCount: res.batchCount,
        sourceName,
      });
      if (res.batchCount > 1) {
        onNotify(`已自动分 ${res.batchCount} 批加密导入 ${res.count} 条密码记录`);
      } else {
        onNotify(`成功加密导入 ${res.count} 条密码记录`);
      }
      return res;
    } finally {
      setImportProgress(null);
    }
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
              <button
                id="csv-import-btn"
                type="button"
                className="btn-icon pss-header-icon-btn"
                title="从 Google Chrome / Apple 密码 / 1Password / Bitwarden CSV 自动分批导入"
                aria-label="CSV 批量导入密码"
                disabled={Boolean(importProgress)}
                onClick={() => setCsvModalOpen(true)}
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

          {importProgress ? (
            <div className="pss-batch-banner is-running" role="status" aria-live="polite">
              <div className="pss-batch-banner-top">
                <span className="pss-batch-banner-title">
                  <RefreshCw size={13} className="pss-spin" />
                  <span>
                    正在分批加密导入 · 第 {importProgress.batchIndex} / {importProgress.totalBatches}{' '}
                    批
                  </span>
                </span>
                <span className="mono pss-batch-banner-meta">
                  {importProgress.processedCount} / {importProgress.totalCount}
                </span>
              </div>
              <div className="pss-health-bar" aria-hidden="true">
                <span
                  className="pss-health-bar-fill"
                  style={{
                    width: `${Math.max(
                      8,
                      Math.round(
                        ((importProgress.batchIndex -
                          (importProgress.phase === 'uploading' ? 0.35 : 0.7)) /
                          Math.max(1, importProgress.totalBatches)) *
                          100,
                      ),
                    )}%`,
                  }}
                />
              </div>
            </div>
          ) : lastBatchSummary ? (
            <div className="pss-batch-banner is-done" role="status">
              <div className="pss-batch-banner-top">
                <span className="pss-batch-banner-title">
                  <ShieldCheck size={13} style={{ color: 'var(--accent)' }} />
                  <span>
                    {lastBatchSummary.batchCount > 1
                      ? `已自动分 ${lastBatchSummary.batchCount} 批导入 ${lastBatchSummary.count} 条密码`
                      : `已加密导入 ${lastBatchSummary.count} 条密码`}
                  </span>
                </span>
                <button
                  type="button"
                  className="btn-icon"
                  style={{ width: 20, height: 20 }}
                  onClick={() => setLastBatchSummary(null)}
                  aria-label="关闭导入提示"
                >
                  <X size={12} />
                </button>
              </div>
              <span className="pss-batch-banner-sub">
                {lastBatchSummary.sourceName ? `${lastBatchSummary.sourceName} · ` : ''}
                每批上限 {PASSWORD_IMPORT_BATCH_SIZE} 条 · 客户端零知识 AES-256-GCM
              </span>
            </div>
          ) : null}

          {/* Security Health Audit Banner */}
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
                <span>安全评分</span>
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
                style={{ width: `${audit.totalCount === 0 ? 100 : Math.max(6, audit.healthScore)}%` }}
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
                className={`pss-audit-pill ${auditFilter === 'no2fa' ? 'is-active' : ''}`}
                onClick={() => setAuditFilter((f) => (f === 'no2fa' ? 'none' : 'no2fa'))}
              >
                未设2FA ({audit.missingTotpIds.length})
              </button>
            </div>
          </div>

          <div className="search-box">
            <Search size={14} className="search-box-icon" />
            <input
              id="password-search-input"
              type="search"
              className="search-input"
              placeholder="搜索账号标题、用户名、域名或标签..."
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
                <p className="pss-list-empty-title">当前分类暂无密码条目</p>
                {catFilter !== 'starred' && (
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
                  点击右上角「新建」或导入 CSV 开始加密托管
                </span>
              </>
            )}
          </div>
        ) : (
          <div className="notelist-items" role="listbox" aria-label="密码列表条目">
            {visiblePasswords.map((item) => {
              const isSelected = selectedItem?.id === item.id;
              const initial = (item.title.trim()[0] || 'P').toUpperCase();
              const hasRisk = weakSet.has(item.id) || reusedSet.has(item.id);
              const subtitle =
                item.username ||
                extractDisplayHost(item.url) ||
                PASSWORD_CATEGORY_LABELS[item.category];

              return (
                <button
                  key={item.id}
                  type="button"
                  role="option"
                  aria-selected={isSelected}
                  className={`note-card pss-pwd-card ${isSelected ? 'is-selected' : ''}`}
                  onClick={() => {
                    onSelectId(item.id);
                    onOpenMobileDetail?.();
                  }}
                >
                  <div className="pss-pwd-card-row">
                    <span className="pss-avatar-badge">{initial}</span>
                    <div className="pss-pwd-card-body">
                      <div className="pss-pwd-card-top">
                        <span className="pss-pwd-card-title">{item.title}</span>
                        <span className="pss-pwd-card-badges">
                          {hasRisk && !item.isTrashed && (
                            <span
                              className="pss-risk-dot"
                              title={
                                weakSet.has(item.id) ? '弱密码风险' : '存在重复使用密码'
                              }
                            />
                          )}
                          {item.isPinned && (
                            <Star
                              size={12}
                              fill="var(--amber)"
                              style={{ color: 'var(--amber)', flexShrink: 0 }}
                            />
                          )}
                          {item.totpSecret && <span className="pss-2fa-mini">2FA</span>}
                        </span>
                      </div>
                      <div className="pss-pwd-card-sub">
                        <span className="pss-pwd-card-account">{subtitle}</span>
                        <span className="pss-pwd-card-cat">
                          {CATEGORY_SHORT_LABELS[item.category]}
                        </span>
                      </div>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </section>

      {/* Column 3: Password Detail & Live TOTP Inspector */}
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
                <h2>端到端 AES-256-GCM 密码与 2FA 保险库</h2>
                <p>
                  所有账号密码、RFC 6238 动态口令种子与自定义隐藏字段均使用独立 HKDF
                  子密钥加密存储，支持历史密码回溯与多端增量同步。
                </p>

                <div className="pss-empty-features" aria-label="安全特性概览">
                  <span className="pss-feature-pill">
                    <ShieldCheck size={13} /> HKDF 独立子密钥
                  </span>
                  <span className="pss-feature-pill">
                    <Clock size={13} /> RFC 6238 动态口令
                  </span>
                  <span className="pss-feature-pill">
                    <Sparkles size={13} /> CSPRNG 熵值审计
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
                    disabled={Boolean(importProgress)}
                    onClick={() => setCsvModalOpen(true)}
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
                        onClick={() => void copyText(selectedItem.username, '用户名')}
                      >
                        <Copy size={13} />
                        <span>复制账号</span>
                      </button>
                    )}
                    <button
                      type="button"
                      className="btn btn-primary"
                      style={{ height: 34, padding: '0 13px', fontSize: '0.84rem' }}
                      onClick={() => void copyText(selectedItem.password, '密码')}
                    >
                      <Copy size={13} />
                      <span>复制密码</span>
                    </button>
                  </div>
                </header>

                {/* Live RFC 6238 TOTP Card */}
                {totpSnapshot && (
                  <div className="pss-totp-card">
                    <div>
                      <div className="pss-totp-label">两步验证动态口令 (RFC 6238 TOTP)</div>
                      <button
                        type="button"
                        className="pss-totp-code mono"
                        title="点击复制 6 位动态口令"
                        onClick={() => void copyText(totpSnapshot.code, '动态验证码')}
                      >
                        {totpSnapshot.formattedCode}
                      </button>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                      <div
                        className="pss-totp-ring-wrap"
                        title={`剩余 ${totpSnapshot.remainingSeconds} 秒刷新`}
                      >
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
                        style={{ height: 34, padding: '0 13px', fontSize: '0.84rem' }}
                        onClick={() => void copyText(totpSnapshot.code, '动态验证码')}
                      >
                        <Copy size={13} />
                        <span>复制动态码</span>
                      </button>
                    </div>
                  </div>
                )}

                {/* Core Credentials Card */}
                <div className="pss-cred-card">
                  <div className="pss-cred-row">
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="pss-field-caption">用户名 / 登录账号</div>
                      <div className="pss-field-value mono" style={{ wordBreak: 'break-all' }}>
                        {selectedItem.username || '—'}
                      </div>
                    </div>
                    {selectedItem.username && (
                      <button
                        type="button"
                        className="btn btn-secondary"
                        style={{ height: 31, padding: '0 10px', fontSize: '0.8rem' }}
                        onClick={() => void copyText(selectedItem.username, '用户名')}
                      >
                        <Copy size={13} />
                        <span>复制</span>
                      </button>
                    )}
                  </div>

                  <div className="pss-cred-row">
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div className="pss-field-caption pss-caption-row">
                        <span>加密登录密码</span>
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
                        onClick={() => void copyText(selectedItem.password, '密码')}
                      >
                        <Copy size={13} />
                        <span>复制</span>
                      </button>
                    </div>
                  </div>

                  {selectedItem.url && (
                    <div className="pss-cred-row">
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div className="pss-field-caption">关联网站 / 服务地址</div>
                        <div
                          className="pss-field-value mono"
                          style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                        >
                          {selectedItem.url}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                        <button
                          type="button"
                          className="btn btn-secondary"
                          style={{ height: 31, padding: '0 10px', fontSize: '0.8rem' }}
                          onClick={() => void copyText(selectedItem.url, '网址')}
                        >
                          <Copy size={13} />
                          <span>复制</span>
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

                {/* Custom Fields */}
                {selectedItem.customFields.length > 0 && (
                  <div className="pss-cred-card">
                    <div className="pss-card-section-head">
                      自定义附加字段 ({selectedItem.customFields.length})
                    </div>
                    {selectedItem.customFields.map((cf) => {
                      const shown = !cf.hidden || Boolean(revealedFieldIds[cf.id]);
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
                              onClick={() => void copyText(cf.value, cf.label || '字段内容')}
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
                {selectedItem.notes.trim().length > 0 && (
                  <div className="pss-section-card">
                    <div className="pss-field-caption">加密私密备注</div>
                    <div className="pss-notes-body">{selectedItem.notes}</div>
                  </div>
                )}

                {/* Metadata & Password History */}
                <div className="pss-section-card">
                  <div className="pss-meta-footer-row">
                    <span>
                      <Clock size={12} style={{ verticalAlign: '-2px', marginRight: 5 }} />
                      创建于 {formatFullDateTime(selectedItem.createdAt)} · 更新于{' '}
                      {formatShortDate(selectedItem.updatedAt)} · 密文 {formatBytes(selectedItem.byteSize)}
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
            </div>
          </>
        )}
      </main>

      <PasswordGeneratorModal
        open={generatorOpen}
        onClose={() => setGeneratorOpen(false)}
        onNotify={onNotify}
      />

      {csvModalOpen && (
        <PasswordCsvImportModal
          progress={importProgress}
          onClose={() => {
            if (!importProgress) setCsvModalOpen(false);
          }}
          onImport={async (entries, sourceName) => {
            const res = await executeBatchImport(entries, sourceName);
            if (res.count > 0) {
              setCsvModalOpen(false);
            }
          }}
        />
      )}

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
  const [username, setUsername] = useState(editing?.username ?? '');
  const [password, setPassword] = useState(editing?.password ?? '');
  const [showPwd, setShowPwd] = useState(true);
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
          style={{ maxWidth: 580 }}
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
            <button type="button" className="btn-icon" onClick={onClose} aria-label="关闭">
              <X size={17} />
            </button>
          </header>

          <div className="modal-body pss-editor-form-body">
            <div className="pss-form-grid-title">
              <div className="field-group">
                <label className="field-label" htmlFor="pwd-field-title">
                  标题名称 *
                </label>
                <input
                  id="pwd-field-title"
                  type="text"
                  className="field-input pss-modal-input"
                  placeholder="例如：GitHub Enterprise 主账号"
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

            <div className="field-group">
              <label className="field-label" htmlFor="pwd-field-username">
                用户名 / 邮箱 / 登录卡号
              </label>
              <input
                id="pwd-field-username"
                type="text"
                className="field-input pss-modal-input mono"
                placeholder="user@example.com"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>

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
                    onClick={() => setPassword(generateSecurePassword({ length: 20 }))}
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
                  placeholder="输入密码或点击右上角生成高强度随机口令"
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

            <div className="pss-form-grid-two">
              <div className="field-group">
                <label className="field-label" htmlFor="pwd-field-url">
                  关联网址 (URL)
                </label>
                <input
                  id="pwd-field-url"
                  type="text"
                  className="field-input pss-modal-input mono"
                  placeholder="https://github.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                />
              </div>
              <div className="field-group">
                <label className="field-label" htmlFor="pwd-field-totp">
                  两步验证密钥 (Base32 / otpauth)
                </label>
                <input
                  id="pwd-field-totp"
                  type="text"
                  className="field-input pss-modal-input mono"
                  placeholder="JBSWY3DPEHPK3PXP"
                  value={totpSecret}
                  onChange={(e) => setTotpSecret(e.target.value)}
                />
              </div>
            </div>

            <div className="field-group">
              <label className="field-label" htmlFor="pwd-field-tags">
                加密标签（逗号分隔）
              </label>
              <input
                id="pwd-field-tags"
                type="text"
                className="field-input pss-modal-input"
                placeholder="核心研发, 2FA已开启, 生产环境"
                value={tagsText}
                onChange={(e) => setTagsText(e.target.value)}
              />
            </div>

            <div className="field-group">
              <div className="field-label">
                <span>自定义附加字段（恢复备用码、PIN、私钥口令）</span>
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

            <div className="field-group">
              <label className="field-label" htmlFor="pwd-field-notes">
                私密备注
              </label>
              <textarea
                id="pwd-field-notes"
                className="field-input pss-modal-textarea"
                placeholder="加密保存硬件密钥恢复指引、客服安全问题或备注..."
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
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
        onUsePassword={(pwd) => setPassword(pwd)}
        onNotify={onNotify}
      />
    </>
  );
};

interface PasswordCsvImportModalProps {
  progress: PasswordImportProgress | null;
  onClose: () => void;
  onImport: (entries: ImportPasswordEntryInput[], sourceName?: string) => Promise<void>;
}

const PasswordCsvImportModal: React.FC<PasswordCsvImportModalProps> = ({
  progress,
  onClose,
  onImport,
}) => {
  const [csvText, setCsvText] = useState('');
  const [fileName, setFileName] = useState<string>('');
  const [dragOver, setDragOver] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const parsedEntries = useMemo(() => parsePasswordCsv(csvText), [csvText]);
  const batches = useMemo(() => chunkPasswordImportEntries(parsedEntries), [parsedEntries]);
  const isImporting = Boolean(progress);

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape' && !isImporting) {
        onClose();
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [isImporting, onClose]);

  async function loadCsvFile(file: File) {
    setError(null);
    try {
      const content = await file.text();
      setFileName(file.name);
      setCsvText(content);
      if (parsePasswordCsv(content).length === 0) {
        setError('未在该 CSV 文件中识别到有效账号密码，请确认首行包含表头（如 name,url,username,password,note）');
      }
    } catch {
      setError('读取 CSV 文件失败，请检查文件权限或编码格式');
    }
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (parsedEntries.length === 0 || isImporting) return;
    setError(null);
    try {
      await onImport(parsedEntries, fileName || undefined);
    } catch (err) {
      setError(err instanceof Error ? err.message : '分批加密导入失败');
    }
  }

  const progressPercent = progress
    ? Math.min(
        98,
        Math.max(
          8,
          Math.round(
            ((progress.batchIndex - (progress.phase === 'uploading' ? 0.35 : 0.7)) /
              Math.max(1, progress.totalBatches)) *
              100,
          ),
        ),
      )
    : 0;

  return (
    <div
      className="modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget && !isImporting) onClose();
      }}
    >
      <form
        className="modal-dialog pss-editor-dialog"
        style={{ maxWidth: 620 }}
        role="dialog"
        aria-modal="true"
        aria-labelledby="csv-import-modal-title"
        onSubmit={(e) => void handleSubmit(e)}
      >
        <header className="modal-header">
          <div className="modal-title-wrap">
            <Upload size={18} style={{ color: 'var(--accent)' }} />
            <h2 id="csv-import-modal-title" className="modal-title">
              CSV 密码批量加密导入
            </h2>
          </div>
          <button
            type="button"
            className="btn-icon"
            onClick={onClose}
            disabled={isImporting}
            aria-label="关闭"
          >
            <X size={17} />
          </button>
        </header>

        <div className="modal-body pss-editor-form-body">
          <input
            id="csv-file-picker-input"
            ref={fileInputRef}
            type="file"
            accept=".csv,text/csv"
            style={{ display: 'none' }}
            onChange={(e) => {
              const f = e.target.files?.[0];
              e.target.value = '';
              if (f) void loadCsvFile(f);
            }}
          />

          <div
            className={`pss-csv-dropzone ${dragOver ? 'is-dragover' : ''}`}
            onDragOver={(e) => {
              e.preventDefault();
              setDragOver(true);
            }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragOver(false);
              const f = e.dataTransfer.files?.[0];
              if (f) void loadCsvFile(f);
            }}
            onClick={() => {
              if (!isImporting) fileInputRef.current?.click();
            }}
          >
            <div className="pss-csv-dropzone-icon">
              <Upload size={18} />
            </div>
            <div className="pss-csv-dropzone-copy">
              <strong>
                {fileName ? `已载入文件：${fileName}` : '点击选择或拖入 Google Chrome 密码 CSV 文件'}
              </strong>
              <span>
                兼容 Chrome (name,url,username,password,note)、Apple 密码、1Password、Bitwarden；超过{' '}
                {PASSWORD_IMPORT_BATCH_SIZE} 条自动分批加密上传
              </span>
            </div>
            <button
              type="button"
              className="btn btn-secondary"
              style={{ height: 30, padding: '0 11px', fontSize: '0.78rem', flexShrink: 0 }}
              disabled={isImporting}
              onClick={(e) => {
                e.stopPropagation();
                fileInputRef.current?.click();
              }}
            >
              选择文件
            </button>
          </div>

          <div className="field-group">
            <div className="field-label">
              <span>或直接粘贴 CSV 内容（本地内存解析，不上传明文）</span>
              {csvText && !isImporting ? (
                <button
                  type="button"
                  className="pss-link-mini"
                  onClick={() => {
                    setCsvText('');
                    setFileName('');
                    setError(null);
                  }}
                >
                  清空内容
                </button>
              ) : null}
            </div>
            <textarea
              id="csv-import-textarea"
              className="field-input pss-modal-textarea mono"
              style={{ minHeight: 108, fontSize: '0.77rem' }}
              disabled={isImporting}
              placeholder={
                'name,url,username,password,note\nGitHub,https://github.com,dev@example.com,StrongPass!2026,主研发账号\nCloudflare,https://dash.cloudflare.com,ops@example.com,DnsVault#99,生产域名托管'
              }
              value={csvText}
              onChange={(e) => {
                setCsvText(e.target.value);
                if (error) setError(null);
              }}
            />
          </div>

          {parsedEntries.length > 0 && (
            <div className="pss-csv-plan-card" data-testid="csv-batch-plan-card">
              <div className="pss-csv-plan-header">
                <div className="pss-csv-plan-title">
                  <ShieldCheck size={15} style={{ color: 'var(--accent)' }} />
                  <span>
                    已解析 <strong className="mono">{parsedEntries.length}</strong> 条有效凭据
                  </span>
                </div>
                <span className={`pss-health-tag ${batches.length > 1 ? 'is-warn' : 'is-good'}`}>
                  {batches.length > 1
                    ? `超 ${PASSWORD_IMPORT_BATCH_SIZE} 条 · 自动分 ${batches.length} 批导入`
                    : `单批直传 (1 / 1 批)`}
                </span>
              </div>

              {batches.length > 1 && (
                <div className="pss-csv-batch-pills" aria-label="自动分批拆分计划">
                  {batches.slice(0, 6).map((b, idx) => (
                    <span
                      key={idx}
                      className={`pss-csv-batch-pill ${
                        progress && progress.batchIndex === idx + 1 ? 'is-current' : ''
                      } ${progress && progress.batchIndex > idx + 1 ? 'is-completed' : ''}`}
                    >
                      第 {idx + 1} 批 · {b.length} 条
                    </span>
                  ))}
                  {batches.length > 6 && (
                    <span className="pss-csv-batch-pill">… 共 {batches.length} 批</span>
                  )}
                </div>
              )}

              <div className="pss-csv-preview-list" aria-label="解析条目预览">
                {parsedEntries.slice(0, 4).map((entry, idx) => (
                  <div key={idx} className="pss-csv-preview-row">
                    <span className="pss-csv-preview-name">{entry.title}</span>
                    <span className="pss-csv-preview-user mono">
                      {entry.username || extractDisplayHost(entry.url || '') || '—'}
                    </span>
                    <span className="pss-csv-preview-mask mono">••••••••</span>
                  </div>
                ))}
                {parsedEntries.length > 4 && (
                  <div className="pss-csv-preview-more">
                    其余 {parsedEntries.length - 4} 条凭据将在本地逐条派生子密钥并封装为 AES-256-GCM 密文
                  </div>
                )}
              </div>
            </div>
          )}

          {progress && (
            <div className="pss-csv-progress-box" role="status" aria-live="polite">
              <div className="pss-csv-progress-top">
                <span>
                  <RefreshCw size={13} className="pss-spin" /> 正在执行第{' '}
                  <strong className="mono">
                    {progress.batchIndex} / {progress.totalBatches}
                  </strong>{' '}
                  批 ·{' '}
                  {progress.phase === 'encrypting'
                    ? '本地 AES-256-GCM 逐条加密中'
                    : '正在上传加密信封至密文库'}
                </span>
                <span className="mono">
                  已完成 {progress.processedCount} / {progress.totalCount} 条 ({progressPercent}%)
                </span>
              </div>
              <div className="pss-health-bar" style={{ height: 6 }}>
                <span
                  className="pss-health-bar-fill"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
            </div>
          )}

          {error && <div className="auth-error">{error}</div>}
        </div>

        <footer className="pss-modal-footer">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClose}
            disabled={isImporting}
          >
            取消
          </button>
          <button
            id="csv-confirm-import-btn"
            type="submit"
            className="btn btn-primary"
            disabled={parsedEntries.length === 0 || isImporting}
          >
            <ShieldCheck size={15} />
            <span>
              {isImporting
                ? `正在分批加密导入 (${progress?.batchIndex}/${progress?.totalBatches} 批)...`
                : batches.length > 1
                  ? `自动分 ${batches.length} 批加密导入 (${parsedEntries.length} 条)`
                  : `AES-256-GCM 加密导入 (${parsedEntries.length} 条)`}
            </span>
          </button>
        </footer>
      </form>
    </div>
  );
};
