import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Copy,
  Edit3,
  ExternalLink,
  Eye,
  EyeOff,
  History,
  KeyRound,
  Plus,
  RefreshCw,
  RotateCcw,
  Search,
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
  generateMemorablePassphrase,
  generateSecurePassword,
} from '@shared/passwordGenerator';
import { generateTotp } from '@shared/totp';
import type {
  CreatePasswordRequest,
  ImportPasswordEntryInput,
  PasswordCategory,
  PasswordCustomField,
  PasswordItem,
  UpdatePasswordRequest,
} from '@shared/types';
import {
  extractMonogram,
  formatDateTime,
  parsePasswordCsvText,
  PASSWORD_CATEGORIES,
  PASSWORD_CATEGORY_MAP,
} from '../utils/mobileFormat';

interface MobilePasswordsTabProps {
  passwords: PasswordItem[];
  onCreatePassword: (input: CreatePasswordRequest) => Promise<void>;
  onUpdatePassword: (id: string, input: UpdatePasswordRequest) => Promise<void>;
  onDeletePermanent: (id: string) => Promise<void>;
  onEmptyTrash: () => Promise<void>;
  onImportCsv: (entries: ImportPasswordEntryInput[]) => Promise<void>;
  onCopySensitive: (text: string, label: string) => Promise<void>;
  onInspectCipher: (itemId: string) => void;
  onNotify: (msg: string) => void;
  initialDraft?: { title?: string; url?: string; notes?: string } | null;
  onClearInitialDraft?: () => void;
}

type CategoryChip = 'all' | 'starred' | 'trash' | PasswordCategory;
type AuditChip = 'none' | 'weak' | 'reused' | 'no2fa';

export const MobilePasswordsTab: React.FC<MobilePasswordsTabProps> = ({
  passwords,
  onCreatePassword,
  onUpdatePassword,
  onDeletePermanent,
  onEmptyTrash,
  onImportCsv,
  onCopySensitive,
  onInspectCipher,
  onNotify,
  initialDraft,
  onClearInitialDraft,
}) => {
  const [catFilter, setCatFilter] = useState<CategoryChip>('all');
  const [auditFilter, setAuditFilter] = useState<AuditChip>('none');
  const [search, setSearch] = useState('');
  const [nowMs, setNowMs] = useState(() => Date.now());

  const [detailId, setDetailId] = useState<string | null>(null);
  const [revealPwd, setRevealPwd] = useState(false);
  const [revealFields, setRevealFields] = useState<Record<string, boolean>>({});
  const [showHistory, setShowHistory] = useState(false);

  const [editorState, setEditorState] = useState<{
    open: boolean;
    editing: PasswordItem | null;
  }>({ open: false, editing: null });

  const [generatorSheet, setGeneratorSheet] = useState<{
    open: boolean;
    onApply?: (pwd: string) => void;
  }>({ open: false });

  // Editor form state
  const [fTitle, setFTitle] = useState('');
  const [fUsername, setFUsername] = useState('');
  const [fPassword, setFPassword] = useState('');
  const [fUrl, setFUrl] = useState('');
  const [fTotp, setFTotp] = useState('');
  const [fCategory, setFCategory] = useState<PasswordCategory>('login');
  const [fNotes, setFNotes] = useState('');
  const [fTags, setFTags] = useState('');
  const [fPinned, setFPinned] = useState(false);
  const [fCustomFields, setFCustomFields] = useState<PasswordCustomField[]>([]);
  const [savingForm, setSavingForm] = useState(false);

  // Generator state
  const [genMode, setGenMode] = useState<'random' | 'passphrase'>('random');
  const [genLen, setGenLen] = useState(22);
  const [genUpper, setGenUpper] = useState(true);
  const [genLower, setGenLower] = useState(true);
  const [genDigits, setGenDigits] = useState(true);
  const [genSymbols, setGenSymbols] = useState(true);
  const [genNoAmbiguous, setGenNoAmbiguous] = useState(true);
  const [phraseWords, setPhraseWords] = useState(4);
  const [phraseSep, setPhraseSep] = useState<'-' | '.' | '_'>('-');
  const [generatedValue, setGeneratedValue] = useState(() =>
    generateSecurePassword({ length: 22 }),
  );

  const csvRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    const t = window.setInterval(() => setNowMs(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, []);

  useEffect(() => {
    if (initialDraft) {
      openCreateEditor(initialDraft);
      onClearInitialDraft?.();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialDraft]);

  const regenerateCandidate = () => {
    if (genMode === 'random') {
      setGeneratedValue(
        generateSecurePassword({
          length: genLen,
          uppercase: genUpper,
          lowercase: genLower,
          digits: genDigits,
          symbols: genSymbols,
          excludeAmbiguous: genNoAmbiguous,
        }),
      );
    } else {
      setGeneratedValue(
        generateMemorablePassphrase({
          wordCount: phraseWords,
          separator: phraseSep,
          capitalize: true,
          includeNumber: true,
        }),
      );
    }
  };

  useEffect(() => {
    if (generatorSheet.open) {
      regenerateCandidate();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [
    generatorSheet.open,
    genMode,
    genLen,
    genUpper,
    genLower,
    genDigits,
    genSymbols,
    genNoAmbiguous,
    phraseWords,
    phraseSep,
  ]);

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
          if (catFilter !== 'all' && catFilter !== 'starred' && item.category !== catFilter) {
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

  const detailItem = useMemo(
    () => (detailId ? passwords.find((p) => p.id === detailId) ?? null : null),
    [passwords, detailId],
  );

  function openCreateEditor(draft?: { title?: string; url?: string; notes?: string }) {
    setFTitle(draft?.title ?? '');
    setFUsername('');
    setFPassword(generateSecurePassword({ length: 20 }));
    setFUrl(draft?.url ?? '');
    setFTotp('');
    setFCategory('login');
    setFNotes(draft?.notes ?? '');
    setFTags('');
    setFPinned(false);
    setFCustomFields([]);
    setEditorState({ open: true, editing: null });
  }

  function openEditEditor(item: PasswordItem) {
    setFTitle(item.title);
    setFUsername(item.username);
    setFPassword(item.password);
    setFUrl(item.url);
    setFTotp(item.totpSecret);
    setFCategory(item.category);
    setFNotes(item.notes);
    setFTags(item.tags.join(', '));
    setFPinned(item.isPinned);
    setFCustomFields(item.customFields.map((cf) => ({ ...cf })));
    setEditorState({ open: true, editing: item });
  }

  async function handleSaveEditor(e: React.FormEvent) {
    e.preventDefault();
    if (!fTitle.trim() && !fUrl.trim()) {
      onNotify('请填写条目标题或网址');
      return;
    }
    setSavingForm(true);
    try {
      const tags = fTags
        .split(/[,，]/)
        .map((t) => t.trim())
        .filter(Boolean);
      const cleanFields = fCustomFields.filter((cf) => cf.label.trim() || cf.value.trim());

      if (editorState.editing) {
        await onUpdatePassword(editorState.editing.id, {
          title: fTitle.trim() || fUrl.trim(),
          username: fUsername.trim(),
          password: fPassword,
          url: fUrl.trim(),
          totpSecret: fTotp.trim(),
          category: fCategory,
          notes: fNotes,
          tags,
          customFields: cleanFields,
          isPinned: fPinned,
        });
        onNotify('加密凭据已更新');
      } else {
        await onCreatePassword({
          title: fTitle.trim() || fUrl.trim(),
          username: fUsername.trim(),
          password: fPassword,
          url: fUrl.trim(),
          totpSecret: fTotp.trim(),
          category: fCategory,
          notes: fNotes,
          tags,
          customFields: cleanFields,
          isPinned: fPinned,
        });
        onNotify('新密码已加密存入保险箱');
      }
      setEditorState({ open: false, editing: null });
    } finally {
      setSavingForm(false);
    }
  }

  async function handleCsvUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    const text = await file.text();
    const entries = parsePasswordCsvText(text);
    if (entries.length === 0) {
      onNotify('未解析到有效的 CSV 密码记录');
      return;
    }
    await onImportCsv(entries);
  }

  const detailTotp = useMemo(() => {
    if (!detailItem?.totpSecret?.trim()) return null;
    try {
      return generateTotp(detailItem.totpSecret, nowMs);
    } catch {
      return null;
    }
  }, [detailItem?.totpSecret, nowMs]);

  const detailEntropy = useMemo(
    () => evaluatePasswordEntropy(detailItem?.password ?? ''),
    [detailItem?.password],
  );

  const generatedEntropy = useMemo(
    () => evaluatePasswordEntropy(generatedValue),
    [generatedValue],
  );

  return (
    <>
      {/* Security Health Audit Card */}
      <div className="m-health-card">
        <div className={`m-health-score-ring ${audit.healthScore < 75 ? 'is-warn' : ''}`}>
          <span className="m-health-num mono">{audit.healthScore}</span>
          <span className="m-health-unit">健康分</span>
        </div>
        <div className="m-health-meta">
          <div className="m-health-title">
            <ShieldCheck size={14} style={{ color: 'var(--m-accent)' }} />
            <span>密码安全审计 · 共 {audit.totalCount} 项凭据</span>
          </div>
          <div className="m-health-pills">
            <button
              type="button"
              className={`m-mini-pill ${auditFilter === 'weak' ? 'is-active' : ''}`}
              onClick={() => setAuditFilter((f) => (f === 'weak' ? 'none' : 'weak'))}
            >
              弱口令 {audit.weakIds.length}
            </button>
            <button
              type="button"
              className={`m-mini-pill ${auditFilter === 'reused' ? 'is-active' : ''}`}
              onClick={() => setAuditFilter((f) => (f === 'reused' ? 'none' : 'reused'))}
            >
              重复密码 {audit.reusedIds.length}
            </button>
            <button
              type="button"
              className={`m-mini-pill ${auditFilter === 'no2fa' ? 'is-active' : ''}`}
              onClick={() => setAuditFilter((f) => (f === 'no2fa' ? 'none' : 'no2fa'))}
            >
              未启用2FA {audit.missingTotpIds.length}
            </button>
          </div>
        </div>
        <button
          id="m-open-generator-btn"
          type="button"
          className="m-icon-btn is-active"
          onClick={() => setGeneratorSheet({ open: true })}
          title="随机密码生成器"
          aria-label="打开密码生成器"
        >
          <Sparkles size={17} />
        </button>
      </div>

      {/* Search & CSV Import */}
      <div className="m-search-row">
        <div className="m-search-box">
          <Search size={15} />
          <input
            id="m-pw-search-input"
            type="search"
            className="m-search-input"
            placeholder="搜索站点、账号、域名或标签..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
          {search && (
            <button
              type="button"
              className="m-icon-btn"
              style={{ width: 26, height: 26 }}
              onClick={() => setSearch('')}
            >
              <X size={14} />
            </button>
          )}
        </div>

        <input
          ref={csvRef}
          type="file"
          accept=".csv,text/csv"
          style={{ display: 'none' }}
          onChange={(e) => void handleCsvUpload(e)}
        />
        <button
          id="m-pw-import-csv-btn"
          type="button"
          className="m-btn m-btn-sm"
          style={{ height: 40 }}
          onClick={() => csvRef.current?.click()}
          title="导入 CSV 密码表"
        >
          <Upload size={14} />
          <span>导入</span>
        </button>
      </div>

      {/* Category Filter Rail */}
      <div className="m-chip-rail">
        <button
          type="button"
          className={`m-chip ${catFilter === 'all' ? 'is-active' : ''}`}
          onClick={() => setCatFilter('all')}
        >
          全部
        </button>
        <button
          type="button"
          className={`m-chip ${catFilter === 'starred' ? 'is-active' : ''}`}
          onClick={() => setCatFilter('starred')}
        >
          <Star size={12} />
          <span>收藏</span>
        </button>
        {PASSWORD_CATEGORIES.map((c) => (
          <button
            key={c.id}
            type="button"
            className={`m-chip ${catFilter === c.id ? 'is-active' : ''}`}
            onClick={() => setCatFilter(c.id)}
          >
            {c.label}
          </button>
        ))}
        <button
          type="button"
          className={`m-chip ${catFilter === 'trash' ? 'is-active' : ''}`}
          onClick={() => setCatFilter('trash')}
        >
          <Trash2 size={12} />
          <span>回收站</span>
        </button>
      </div>

      {catFilter === 'trash' && visiblePasswords.length > 0 && (
        <div style={{ marginBottom: 12 }}>
          <button
            type="button"
            className="m-btn m-btn-danger m-btn-sm m-btn-block"
            onClick={() => void onEmptyTrash()}
          >
            <Trash2 size={14} />
            <span>彻底销毁回收站全部密码 ({visiblePasswords.length})</span>
          </button>
        </div>
      )}

      {/* Password List */}
      {visiblePasswords.length === 0 ? (
        <div className="m-empty">
          <div className="m-empty-icon">
            <KeyRound size={24} />
          </div>
          <div style={{ fontWeight: 700, color: 'var(--m-text)' }}>暂无匹配的加密凭据</div>
          <div style={{ fontSize: '0.82rem', marginTop: 4 }}>
            点击右下角「新建密码」加密保存账号口令与 TOTP 动态验证码
          </div>
        </div>
      ) : (
        visiblePasswords.map((item) => {
          let totp = null;
          if (item.totpSecret?.trim()) {
            try {
              totp = generateTotp(item.totpSecret, nowMs);
            } catch {
              totp = null;
            }
          }
          return (
            <article
              key={item.id}
              className="m-card m-card-interactive"
              onClick={() => {
                setDetailId(item.id);
                setRevealPwd(false);
                setRevealFields({});
                setShowHistory(false);
              }}
            >
              <div className="m-pw-row">
                <div className="m-monogram">{extractMonogram(item.title, item.url)}</div>
                <div className="m-pw-main">
                  <div className="m-pw-title-line">
                    <span className="m-pw-title">{item.title}</span>
                    {item.isPinned && (
                      <Star
                        size={13}
                        fill="var(--m-amber)"
                        style={{ color: 'var(--m-amber)', flexShrink: 0 }}
                      />
                    )}
                  </div>
                  <div className="m-pw-sub">
                    {item.username || item.url || PASSWORD_CATEGORY_MAP[item.category]}
                  </div>
                </div>
                <button
                  type="button"
                  className="m-btn m-btn-sm m-btn-soft"
                  onClick={(e) => {
                    e.stopPropagation();
                    void onCopySensitive(item.password, `${item.title} 密码`);
                  }}
                >
                  <Copy size={13} />
                  <span>密码</span>
                </button>
              </div>

              {totp && (
                <div className="m-totp-strip">
                  <button
                    type="button"
                    className="m-totp-badge"
                    onClick={(e) => {
                      e.stopPropagation();
                      void onCopySensitive(totp.code, `${item.title} 2FA 验证码`);
                    }}
                  >
                    <span className="m-totp-digits">{totp.formattedCode}</span>
                    <span className="m-totp-remain">{totp.remainingSeconds}s</span>
                    <Copy size={12} />
                  </button>
                  <span style={{ fontSize: '0.72rem', color: 'var(--m-text-tertiary)' }}>
                    {PASSWORD_CATEGORY_MAP[item.category]}
                  </span>
                </div>
              )}
            </article>
          );
        })
      )}

      {/* Floating Create Button */}
      <button
        id="m-fab-new-password"
        type="button"
        className="m-fab"
        onClick={() => openCreateEditor()}
      >
        <Plus size={19} />
        <span>新建密码</span>
      </button>

      {/* ==================== Password Detail Bottom Sheet ==================== */}
      {detailItem && (
        <div
          className="m-sheet-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setDetailId(null);
          }}
        >
          <div className="m-sheet" role="dialog" aria-modal="true">
            <div className="m-sheet-handle" />
            <div className="m-sheet-header">
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, minWidth: 0 }}>
                <div className="m-monogram" style={{ width: 36, height: 36, fontSize: '0.9rem' }}>
                  {extractMonogram(detailItem.title, detailItem.url)}
                </div>
                <div style={{ minWidth: 0 }}>
                  <h2 className="m-sheet-title">{detailItem.title}</h2>
                  <div style={{ fontSize: '0.74rem', color: 'var(--m-text-secondary)' }}>
                    {PASSWORD_CATEGORY_MAP[detailItem.category]} · Rev v{detailItem.revision}
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 4 }}>
                <button
                  type="button"
                  className={`m-icon-btn ${detailItem.isPinned ? 'is-active' : ''}`}
                  onClick={() =>
                    void onUpdatePassword(detailItem.id, { isPinned: !detailItem.isPinned })
                  }
                  aria-label="收藏"
                >
                  <Star size={17} fill={detailItem.isPinned ? 'currentColor' : 'none'} />
                </button>
                <button
                  type="button"
                  className="m-icon-btn"
                  onClick={() => setDetailId(null)}
                  aria-label="关闭"
                >
                  <X size={18} />
                </button>
              </div>
            </div>

            <div className="m-sheet-body">
              {detailTotp && (
                <div
                  className="m-card"
                  style={{
                    background: 'var(--m-accent-soft)',
                    borderColor: 'var(--m-accent-border)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div>
                    <div
                      style={{
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        color: 'var(--m-accent)',
                      }}
                    >
                      动态两步验证码 (RFC 6238 TOTP)
                    </div>
                    <div
                      className="mono"
                      style={{
                        fontSize: '1.55rem',
                        fontWeight: 800,
                        letterSpacing: '0.08em',
                        color: 'var(--m-accent)',
                        marginTop: 2,
                      }}
                    >
                      {detailTotp.formattedCode}
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <svg width="38" height="38" viewBox="0 0 38 38">
                      <circle
                        cx="19"
                        cy="19"
                        r="15"
                        fill="none"
                        stroke="var(--m-border)"
                        strokeWidth="3.5"
                      />
                      <circle
                        cx="19"
                        cy="19"
                        r="15"
                        fill="none"
                        stroke="var(--m-accent)"
                        strokeWidth="3.5"
                        strokeDasharray={2 * Math.PI * 15}
                        strokeDashoffset={2 * Math.PI * 15 * detailTotp.progress}
                        transform="rotate(-90 19 19)"
                        strokeLinecap="round"
                      />
                      <text
                        x="19"
                        y="23"
                        textAnchor="middle"
                        fontSize="10"
                        fontWeight="700"
                        fill="var(--m-accent)"
                      >
                        {detailTotp.remainingSeconds}s
                      </text>
                    </svg>
                    <button
                      type="button"
                      className="m-btn m-btn-primary m-btn-sm"
                      onClick={() =>
                        void onCopySensitive(detailTotp.code, `${detailItem.title} 动态验证码`)
                      }
                    >
                      <Copy size={13} />
                      <span>复制</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Username */}
              {detailItem.username && (
                <div className="m-card" style={{ padding: '10px 12px' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--m-text-tertiary)' }}>
                    用户名 / 登录邮箱
                  </div>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 8,
                      marginTop: 3,
                    }}
                  >
                    <span className="mono" style={{ fontSize: '0.9rem', fontWeight: 600 }}>
                      {detailItem.username}
                    </span>
                    <button
                      type="button"
                      className="m-btn m-btn-sm"
                      onClick={() => void onCopySensitive(detailItem.username, '用户名')}
                    >
                      <Copy size={13} />
                      <span>复制</span>
                    </button>
                  </div>
                </div>
              )}

              {/* Password */}
              <div className="m-card" style={{ padding: '10px 12px' }}>
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    fontSize: '0.72rem',
                    color: 'var(--m-text-tertiary)',
                  }}
                >
                  <span>加密主口令</span>
                  <span className="mono" style={{ color: 'var(--m-accent)', fontWeight: 700 }}>
                    {detailEntropy.label} · {detailEntropy.entropyBits} bits
                  </span>
                </div>
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    gap: 8,
                    marginTop: 5,
                  }}
                >
                  <span
                    className="mono"
                    style={{
                      fontSize: '0.92rem',
                      fontWeight: 700,
                      wordBreak: 'break-all',
                      flex: 1,
                    }}
                  >
                    {revealPwd ? detailItem.password : '••••••••••••••••'}
                  </span>
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    <button
                      type="button"
                      className="m-icon-btn"
                      style={{ width: 34, height: 34 }}
                      onClick={() => setRevealPwd((v) => !v)}
                      aria-label="显示或隐藏密码"
                    >
                      {revealPwd ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                    <button
                      type="button"
                      className="m-btn m-btn-primary m-btn-sm"
                      onClick={() =>
                        void onCopySensitive(detailItem.password, `${detailItem.title} 密码`)
                      }
                    >
                      <Copy size={13} />
                      <span>复制</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Website URL */}
              {detailItem.url && (
                <div className="m-card" style={{ padding: '10px 12px' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--m-text-tertiary)' }}>
                    关联站点地址
                  </div>
                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'space-between',
                      gap: 8,
                      marginTop: 3,
                    }}
                  >
                    <span
                      className="mono"
                      style={{
                        fontSize: '0.82rem',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {detailItem.url}
                    </span>
                    <a
                      href={
                        /^https?:\/\//i.test(detailItem.url)
                          ? detailItem.url
                          : `https://${detailItem.url}`
                      }
                      target="_blank"
                      rel="noopener noreferrer"
                      className="m-btn m-btn-sm"
                      style={{ textDecoration: 'none' }}
                    >
                      <ExternalLink size={13} />
                      <span>打开</span>
                    </a>
                  </div>
                </div>
              )}

              {/* Custom Fields */}
              {detailItem.customFields.length > 0 && (
                <div className="m-card" style={{ padding: '10px 12px' }}>
                  <div
                    style={{
                      fontSize: '0.74rem',
                      fontWeight: 700,
                      color: 'var(--m-text-secondary)',
                      marginBottom: 6,
                    }}
                  >
                    自定义加密字段 ({detailItem.customFields.length})
                  </div>
                  {detailItem.customFields.map((cf) => {
                    const shown = !cf.hidden || revealFields[cf.id];
                    return (
                      <div key={cf.id} className="m-kv-row" style={{ alignItems: 'center' }}>
                        <span className="m-kv-key">{cf.label}</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                          <span className="mono" style={{ fontSize: '0.8rem' }}>
                            {shown ? cf.value : '••••••••'}
                          </span>
                          {cf.hidden && (
                            <button
                              type="button"
                              className="m-icon-btn"
                              style={{ width: 28, height: 28 }}
                              onClick={() =>
                                setRevealFields((prev) => ({ ...prev, [cf.id]: !prev[cf.id] }))
                              }
                            >
                              {shown ? <EyeOff size={14} /> : <Eye size={14} />}
                            </button>
                          )}
                          <button
                            type="button"
                            className="m-icon-btn"
                            style={{ width: 28, height: 28 }}
                            onClick={() => void onCopySensitive(cf.value, cf.label)}
                          >
                            <Copy size={14} />
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* Notes */}
              {detailItem.notes && (
                <div className="m-card" style={{ padding: '10px 12px' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--m-text-tertiary)' }}>
                    加密备注
                  </div>
                  <div
                    style={{
                      fontSize: '0.85rem',
                      whiteSpace: 'pre-wrap',
                      marginTop: 4,
                    }}
                  >
                    {detailItem.notes}
                  </div>
                </div>
              )}

              {/* Password History */}
              {detailItem.history.length > 0 && (
                <div style={{ marginBottom: 12 }}>
                  <button
                    type="button"
                    className="m-btn m-btn-sm m-btn-block"
                    onClick={() => setShowHistory((v) => !v)}
                  >
                    <History size={14} />
                    <span>
                      {showHistory ? '收起历史密码版本' : `查看历史密码 (${detailItem.history.length} 个版本)`}
                    </span>
                  </button>
                  {showHistory && (
                    <div className="m-card" style={{ marginTop: 8, padding: '8px 12px' }}>
                      {detailItem.history.map((h, i) => (
                        <div key={i} className="m-kv-row" style={{ alignItems: 'center' }}>
                          <div>
                            <div className="mono" style={{ fontSize: '0.8rem', fontWeight: 600 }}>
                              {h.password}
                            </div>
                            <div style={{ fontSize: '0.68rem', color: 'var(--m-text-tertiary)' }}>
                              {formatDateTime(h.changedAt)}
                            </div>
                          </div>
                          <button
                            type="button"
                            className="m-btn m-btn-sm"
                            onClick={() => void onCopySensitive(h.password, '历史密码')}
                          >
                            <Copy size={12} />
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Bottom Actions */}
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 6 }}>
                {!detailItem.isTrashed ? (
                  <>
                    <button
                      type="button"
                      className="m-btn m-btn-soft"
                      style={{ flex: 1 }}
                      onClick={() => {
                        const target = detailItem;
                        setDetailId(null);
                        openEditEditor(target);
                      }}
                    >
                      <Edit3 size={15} />
                      <span>编辑</span>
                    </button>
                    <button
                      type="button"
                      className="m-btn"
                      style={{ flex: 1 }}
                      onClick={() => {
                        const id = detailItem.id;
                        setDetailId(null);
                        onInspectCipher(id);
                      }}
                    >
                      <ShieldCheck size={15} />
                      <span>密文透视</span>
                    </button>
                    <button
                      type="button"
                      className="m-btn m-btn-danger"
                      onClick={async () => {
                        await onUpdatePassword(detailItem.id, { isTrashed: true });
                        setDetailId(null);
                        onNotify('已移入密码回收站');
                      }}
                    >
                      <Trash2 size={15} />
                    </button>
                  </>
                ) : (
                  <>
                    <button
                      type="button"
                      className="m-btn m-btn-soft"
                      style={{ flex: 1 }}
                      onClick={async () => {
                        await onUpdatePassword(detailItem.id, { isTrashed: false });
                        setDetailId(null);
                        onNotify('密码记录已恢复');
                      }}
                    >
                      <RotateCcw size={15} />
                      <span>恢复记录</span>
                    </button>
                    <button
                      type="button"
                      className="m-btn m-btn-danger"
                      style={{ flex: 1 }}
                      onClick={async () => {
                        const id = detailItem.id;
                        setDetailId(null);
                        await onDeletePermanent(id);
                      }}
                    >
                      <Trash2 size={15} />
                      <span>彻底销毁</span>
                    </button>
                  </>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ==================== Create / Edit Password Sheet ==================== */}
      {editorState.open && (
        <div
          className="m-sheet-backdrop"
          onClick={(e) => {
            if (e.target === e.currentTarget) setEditorState({ open: false, editing: null });
          }}
        >
          <div className="m-sheet" role="dialog" aria-modal="true">
            <div className="m-sheet-handle" />
            <div className="m-sheet-header">
              <h2 className="m-sheet-title">
                {editorState.editing ? '编辑加密凭据' : '新建加密密码'}
              </h2>
              <button
                type="button"
                className="m-icon-btn"
                onClick={() => setEditorState({ open: false, editing: null })}
              >
                <X size={18} />
              </button>
            </div>

            <form onSubmit={(e) => void handleSaveEditor(e)} className="m-sheet-body">
              <div className="m-field">
                <label className="m-label">
                  <span>站点或服务名称 *</span>
                </label>
                <input
                  id="m-pw-form-title"
                  type="text"
                  className="m-input"
                  value={fTitle}
                  onChange={(e) => setFTitle(e.target.value)}
                  placeholder="例如：GitHub / 招商银行 / AWS Root"
                  required
                />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                <div className="m-field">
                  <label className="m-label">
                    <span>分类</span>
                  </label>
                  <select
                    className="m-select"
                    value={fCategory}
                    onChange={(e) => setFCategory(e.target.value as PasswordCategory)}
                  >
                    {PASSWORD_CATEGORIES.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.label}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="m-field">
                  <label className="m-label">
                    <span>用户名 / 邮箱</span>
                  </label>
                  <input
                    id="m-pw-form-username"
                    type="text"
                    className="m-input"
                    value={fUsername}
                    onChange={(e) => setFUsername(e.target.value)}
                    autoCapitalize="none"
                    placeholder="user@example.com"
                  />
                </div>
              </div>

              <div className="m-field">
                <label className="m-label">
                  <span>登录密码</span>
                  <button
                    type="button"
                    onClick={() =>
                      setGeneratorSheet({
                        open: true,
                        onApply: (pwd) => setFPassword(pwd),
                      })
                    }
                    style={{
                      border: 'none',
                      background: 'transparent',
                      color: 'var(--m-accent)',
                      fontWeight: 700,
                      fontSize: '0.75rem',
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 4,
                      cursor: 'pointer',
                      padding: 0,
                    }}
                  >
                    <Sparkles size={12} />
                    <span>CSPRNG 随机生成</span>
                  </button>
                </label>
                <input
                  id="m-pw-form-password"
                  type="text"
                  className="m-input mono"
                  value={fPassword}
                  onChange={(e) => setFPassword(e.target.value)}
                  placeholder="输入或生成高强度随机密码"
                />
              </div>

              <div className="m-field">
                <label className="m-label">
                  <span>两步验证密钥 (TOTP Secret 或 otpauth://)</span>
                </label>
                <input
                  id="m-pw-form-totp"
                  type="text"
                  className="m-input mono"
                  value={fTotp}
                  onChange={(e) => setFTotp(e.target.value)}
                  autoCapitalize="none"
                  placeholder="JBSWY3DPEHPK3PXP 或 otpauth://totp/..."
                />
              </div>

              <div className="m-field">
                <label className="m-label">
                  <span>关联网址 URL</span>
                </label>
                <input
                  id="m-pw-form-url"
                  type="text"
                  className="m-input mono"
                  value={fUrl}
                  onChange={(e) => setFUrl(e.target.value)}
                  autoCapitalize="none"
                  placeholder="https://github.com"
                />
              </div>

              <div className="m-field">
                <label className="m-label">
                  <span>标签（逗号分隔）</span>
                </label>
                <input
                  type="text"
                  className="m-input"
                  value={fTags}
                  onChange={(e) => setFTags(e.target.value)}
                  placeholder="核心生产, 2FA, 云主机"
                />
              </div>

              {/* Custom Hidden Fields */}
              <div className="m-field">
                <div className="m-label">
                  <span>自定义加密字段（恢复码 / API Key）</span>
                  <button
                    type="button"
                    onClick={() =>
                      setFCustomFields((prev) => [
                        ...prev,
                        {
                          id: crypto.randomUUID(),
                          label: '',
                          value: '',
                          hidden: true,
                        },
                      ])
                    }
                    style={{
                      border: 'none',
                      background: 'transparent',
                      color: 'var(--m-accent)',
                      fontWeight: 700,
                      fontSize: '0.75rem',
                      cursor: 'pointer',
                      padding: 0,
                    }}
                  >
                    + 添加字段
                  </button>
                </div>
                {fCustomFields.map((cf, idx) => (
                  <div
                    key={cf.id}
                    style={{ display: 'flex', gap: 6, marginBottom: 6, alignItems: 'center' }}
                  >
                    <input
                      type="text"
                      className="m-input"
                      style={{ flex: 1, height: 38 }}
                      placeholder="字段名"
                      value={cf.label}
                      onChange={(e) =>
                        setFCustomFields((prev) =>
                          prev.map((p, i) => (i === idx ? { ...p, label: e.target.value } : p)),
                        )
                      }
                    />
                    <input
                      type="text"
                      className="m-input mono"
                      style={{ flex: 1.3, height: 38 }}
                      placeholder="字段值"
                      value={cf.value}
                      onChange={(e) =>
                        setFCustomFields((prev) =>
                          prev.map((p, i) => (i === idx ? { ...p, value: e.target.value } : p)),
                        )
                      }
                    />
                    <button
                      type="button"
                      className="m-icon-btn"
                      style={{ width: 32, height: 32 }}
                      onClick={() =>
                        setFCustomFields((prev) => prev.filter((_, i) => i !== idx))
                      }
                    >
                      <X size={14} />
                    </button>
                  </div>
                ))}
              </div>

              <div className="m-field">
                <label className="m-label">
                  <span>备注说明</span>
                </label>
                <textarea
                  className="m-textarea"
                  value={fNotes}
                  onChange={(e) => setFNotes(e.target.value)}
                  placeholder="加密存储恢复码、SSH 端口等敏感备注..."
                />
              </div>

              <button
                id="m-pw-form-submit"
                type="submit"
                className="m-btn m-btn-primary m-btn-block"
                disabled={savingForm}
              >
                <ShieldCheck size={16} />
                <span>{savingForm ? '正在 AES-256-GCM 加密保存...' : '加密保存凭据'}</span>
              </button>
            </form>
          </div>
        </div>
      )}

      {/* ==================== CSPRNG Password & Passphrase Generator Sheet ==================== */}
      {generatorSheet.open && (
        <div
          className="m-sheet-backdrop"
          style={{ zIndex: 70 }}
          onClick={(e) => {
            if (e.target === e.currentTarget) setGeneratorSheet({ open: false });
          }}
        >
          <div className="m-sheet" role="dialog" aria-modal="true">
            <div className="m-sheet-handle" />
            <div className="m-sheet-header">
              <h2 className="m-sheet-title">CSPRNG 高强度密码生成器</h2>
              <button
                type="button"
                className="m-icon-btn"
                onClick={() => setGeneratorSheet({ open: false })}
              >
                <X size={18} />
              </button>
            </div>
            <div className="m-sheet-body">
              <div style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                <button
                  type="button"
                  className={`m-btn m-btn-sm ${genMode === 'random' ? 'm-btn-primary' : ''}`}
                  style={{ flex: 1 }}
                  onClick={() => setGenMode('random')}
                >
                  随机字符密码
                </button>
                <button
                  type="button"
                  className={`m-btn m-btn-sm ${genMode === 'passphrase' ? 'm-btn-primary' : ''}`}
                  style={{ flex: 1 }}
                  onClick={() => setGenMode('passphrase')}
                >
                  易记助记词组
                </button>
              </div>

              <div
                className="m-card"
                style={{
                  background: 'var(--m-bg-code)',
                  textAlign: 'center',
                  padding: 16,
                }}
              >
                <div
                  className="mono"
                  style={{
                    fontSize: '1.08rem',
                    fontWeight: 700,
                    wordBreak: 'break-all',
                    color: 'var(--m-accent)',
                  }}
                >
                  {generatedValue}
                </div>
                <div
                  className="mono"
                  style={{ fontSize: '0.74rem', color: 'var(--m-text-secondary)', marginTop: 6 }}
                >
                  熵值评估：{generatedEntropy.entropyBits} bits · {generatedEntropy.label}
                </div>
              </div>

              {genMode === 'random' ? (
                <>
                  <div className="m-field">
                    <div className="m-label">
                      <span>密码长度</span>
                      <span className="mono">{genLen} 位</span>
                    </div>
                    <input
                      type="range"
                      min={8}
                      max={64}
                      value={genLen}
                      onChange={(e) => setGenLen(Number(e.target.value))}
                      style={{ width: '100%', accentColor: 'var(--m-accent)' }}
                    />
                  </div>
                  <div className="m-chip-rail" style={{ flexWrap: 'wrap' }}>
                    <button
                      type="button"
                      className={`m-chip ${genUpper ? 'is-active' : ''}`}
                      onClick={() => setGenUpper((v) => !v)}
                    >
                      A-Z 大写
                    </button>
                    <button
                      type="button"
                      className={`m-chip ${genLower ? 'is-active' : ''}`}
                      onClick={() => setGenLower((v) => !v)}
                    >
                      a-z 小写
                    </button>
                    <button
                      type="button"
                      className={`m-chip ${genDigits ? 'is-active' : ''}`}
                      onClick={() => setGenDigits((v) => !v)}
                    >
                      0-9 数字
                    </button>
                    <button
                      type="button"
                      className={`m-chip ${genSymbols ? 'is-active' : ''}`}
                      onClick={() => setGenSymbols((v) => !v)}
                    >
                      !@# 符号
                    </button>
                    <button
                      type="button"
                      className={`m-chip ${genNoAmbiguous ? 'is-active' : ''}`}
                      onClick={() => setGenNoAmbiguous((v) => !v)}
                    >
                      排除易混淆字符
                    </button>
                  </div>
                </>
              ) : (
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div className="m-field">
                    <label className="m-label">词组数量 ({phraseWords} 词)</label>
                    <input
                      type="range"
                      min={3}
                      max={8}
                      value={phraseWords}
                      onChange={(e) => setPhraseWords(Number(e.target.value))}
                      style={{ width: '100%', accentColor: 'var(--m-accent)' }}
                    />
                  </div>
                  <div className="m-field">
                    <label className="m-label">连接符</label>
                    <select
                      className="m-select"
                      value={phraseSep}
                      onChange={(e) => setPhraseSep(e.target.value as '-' | '.' | '_')}
                    >
                      <option value="-">连字符 (-)</option>
                      <option value=".">圆点 (.)</option>
                      <option value="_">下划线 (_)</option>
                    </select>
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
                <button
                  type="button"
                  className="m-btn"
                  onClick={regenerateCandidate}
                  aria-label="重新生成"
                >
                  <RefreshCw size={16} />
                </button>
                {generatorSheet.onApply ? (
                  <button
                    type="button"
                    className="m-btn m-btn-primary"
                    style={{ flex: 1 }}
                    onClick={() => {
                      generatorSheet.onApply?.(generatedValue);
                      setGeneratorSheet({ open: false });
                    }}
                  >
                    填入当前密码框
                  </button>
                ) : (
                  <button
                    type="button"
                    className="m-btn m-btn-primary"
                    style={{ flex: 1 }}
                    onClick={() => {
                      void onCopySensitive(generatedValue, '随机生成密码');
                      setGeneratorSheet({ open: false });
                    }}
                  >
                    <Copy size={15} />
                    <span>复制密码</span>
                  </button>
                )}
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
