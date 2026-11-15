import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ArrowLeft,
  ArrowUpRight,
  BookOpen,
  Moon,
  Search,
  Sun,
  X,
} from 'lucide-react';
import {
  DISGUISE_ESSAYS,
  ESSAY_CATEGORIES,
  groupEssaysByYear,
  READING_EXCERPTS,
  type DisguiseEssay,
  type EssayCategory,
} from '../content/disguiseEssays';
import {
  DEFAULT_UNLOCK_PHRASE,
  isDisguiseShortcutEvent,
  matchesDisguiseUnlockPhrase,
  MultiTapTracker,
  type DisguiseConfig,
} from '../utils/disguiseConfig';
import { AuthorPortalModal } from './AuthorPortalModal';

type JournalSection = 'essays' | 'archive' | 'excerpts' | 'about';

interface DisguiseHomeViewProps {
  disguiseConfig: DisguiseConfig;
  theme: 'light' | 'dark';
  initialVaultInitialized: boolean | null;
  defaultVaultName: string;
  onToggleTheme: () => void;
  onAuthenticated: (payload: {
    vaultName: string;
    keyFingerprint: string;
    initialized: boolean;
  }) => Promise<void> | void;
  onStatusResolved?: (payload: {
    initialized: boolean;
    vaultName: string;
    keyFingerprint: string | null;
  }) => void;
}

const PineEmblem: React.FC = () => (
  <svg
    className="journal-pine-svg"
    viewBox="0 0 32 32"
    fill="none"
    aria-hidden="true"
  >
    <rect width="32" height="32" rx="8" fill="currentColor" className="journal-pine-bg" />
    <path
      d="M16 6.8L9.6 15.8H14.1L8.8 22.5H23.2L17.9 15.8H22.4L16 6.8Z"
      fill="var(--text-on-accent)"
    />
    <path
      d="M16 22.5V26"
      stroke="var(--text-on-accent)"
      strokeWidth="2.1"
      strokeLinecap="round"
    />
  </svg>
);

export const DisguiseHomeView: React.FC<DisguiseHomeViewProps> = ({
  disguiseConfig,
  theme,
  initialVaultInitialized,
  defaultVaultName,
  onToggleTheme,
  onAuthenticated,
  onStatusResolved,
}) => {
  const [section, setSection] = useState<JournalSection>('essays');
  const [selectedCategory, setSelectedCategory] = useState<'全部' | EssayCategory>('全部');
  const [activeEssayId, setActiveEssayId] = useState<string | null>(null);
  const [relaxedFont, setRelaxedFont] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [portalOpen, setPortalOpen] = useState(false);

  const brandTapTrackerRef = useRef(new MultiTapTracker(5, 3000));
  const footerTapTrackerRef = useRef(new MultiTapTracker(5, 3000));
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  const openPortal = useCallback(() => {
    setPortalOpen(true);
  }, []);

  // Optional private bookmark hash (#author) — opens modal and strips hash immediately
  useEffect(() => {
    if (typeof window === 'undefined') return;
    if (window.location.hash === '#author') {
      setPortalOpen(true);
      window.history.replaceState(
        null,
        '',
        window.location.pathname + window.location.search,
      );
    }
  }, []);

  // Global keyboard shortcut: Ctrl+Shift+L / Cmd+Shift+L
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (isDisguiseShortcutEvent(e)) {
        e.preventDefault();
        setPortalOpen((prev) => !prev);
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, []);

  const handleBrandClick = useCallback(() => {
    if (brandTapTrackerRef.current.recordTap()) {
      openPortal();
      return;
    }
    setActiveEssayId(null);
    setSection('essays');
  }, [openPortal]);

  const handleFooterCopyrightClick = useCallback(() => {
    if (footerTapTrackerRef.current.recordTap()) {
      openPortal();
    }
  }, [openPortal]);

  const handleSearchSubmit = useCallback(
    (e: React.FormEvent) => {
      e.preventDefault();
      if (
        matchesDisguiseUnlockPhrase(searchQuery, disguiseConfig.unlockPhrase) ||
        matchesDisguiseUnlockPhrase(searchQuery, DEFAULT_UNLOCK_PHRASE)
      ) {
        setSearchQuery('');
        searchInputRef.current?.blur();
        openPortal();
      }
    },
    [searchQuery, disguiseConfig.unlockPhrase, openPortal],
  );

  // Treat leading ':' command input quietly without collapsing the normal essay list
  const effectiveFilterQuery = useMemo(() => {
    const trimmed = searchQuery.trim();
    if (!trimmed || trimmed.startsWith(':')) {
      return '';
    }
    return trimmed.toLowerCase();
  }, [searchQuery]);

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = { 全部: DISGUISE_ESSAYS.length };
    for (const essay of DISGUISE_ESSAYS) {
      counts[essay.category] = (counts[essay.category] || 0) + 1;
    }
    return counts;
  }, []);

  const filteredEssays = useMemo(() => {
    return DISGUISE_ESSAYS.filter((essay) => {
      if (selectedCategory !== '全部' && essay.category !== selectedCategory) {
        return false;
      }
      if (!effectiveFilterQuery) {
        return true;
      }
      const inTitle = essay.title.toLowerCase().includes(effectiveFilterQuery);
      const inSub = essay.subtitle.toLowerCase().includes(effectiveFilterQuery);
      const inExcerpt = essay.excerpt.toLowerCase().includes(effectiveFilterQuery);
      const inTags = essay.tags.some((t) => t.toLowerCase().includes(effectiveFilterQuery));
      const inBody = essay.blocks.some((b) => {
        if (b.type === 'list') {
          return b.items.some((it) => it.toLowerCase().includes(effectiveFilterQuery));
        }
        if (b.type === 'code') {
          return b.code.toLowerCase().includes(effectiveFilterQuery);
        }
        return b.text.toLowerCase().includes(effectiveFilterQuery);
      });
      return inTitle || inSub || inExcerpt || inTags || inBody;
    });
  }, [selectedCategory, effectiveFilterQuery]);

  const filteredExcerpts = useMemo(() => {
    if (!effectiveFilterQuery) return READING_EXCERPTS;
    return READING_EXCERPTS.filter(
      (item) =>
        item.bookTitle.toLowerCase().includes(effectiveFilterQuery) ||
        item.author.toLowerCase().includes(effectiveFilterQuery) ||
        item.quote.toLowerCase().includes(effectiveFilterQuery) ||
        item.note.toLowerCase().includes(effectiveFilterQuery) ||
        item.tags.some((t) => t.toLowerCase().includes(effectiveFilterQuery)),
    );
  }, [effectiveFilterQuery]);

  const archiveGroups = useMemo(() => groupEssaysByYear(DISGUISE_ESSAYS), []);

  const activeEssayIndex = useMemo(
    () =>
      activeEssayId
        ? DISGUISE_ESSAYS.findIndex((item) => item.id === activeEssayId)
        : -1,
    [activeEssayId],
  );

  const activeEssay: DisguiseEssay | null =
    activeEssayIndex >= 0 ? DISGUISE_ESSAYS[activeEssayIndex] : null;
  const prevEssay: DisguiseEssay | null =
    activeEssayIndex > 0 ? DISGUISE_ESSAYS[activeEssayIndex - 1] : null;
  const nextEssay: DisguiseEssay | null =
    activeEssayIndex >= 0 && activeEssayIndex < DISGUISE_ESSAYS.length - 1
      ? DISGUISE_ESSAYS[activeEssayIndex + 1]
      : null;

  const openEssay = useCallback((id: string) => {
    setActiveEssayId(id);
    if (typeof window !== 'undefined') {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }
  }, []);

  const switchSection = useCallback((next: JournalSection) => {
    setSection(next);
    setActiveEssayId(null);
  }, []);

  const featuredEssay =
    !effectiveFilterQuery && selectedCategory === '全部'
      ? filteredEssays.find((e) => e.featured) ?? filteredEssays[0] ?? null
      : null;

  const streamEssays = featuredEssay
    ? filteredEssays.filter((e) => e.id !== featuredEssay.id)
    : filteredEssays;

  return (
    <div className="journal-page">
      <div className="journal-container">
        {/* Editorial Masthead */}
        <header className="journal-masthead">
          <div className="journal-masthead-left">
            <button
              id="disguise-brand-trigger"
              type="button"
              className="journal-brand-btn"
              onClick={handleBrandClick}
              aria-label={`${disguiseConfig.siteTitle} 首页`}
            >
              <PineEmblem />
              <span className="journal-brand-copy">
                <span className="journal-brand-name">{disguiseConfig.siteTitle}</span>
                <span className="journal-brand-latin">
                  {disguiseConfig.siteSubtitleLatin}
                </span>
              </span>
            </button>

            <nav className="journal-nav" aria-label="站点栏目">
              <button
                id="journal-nav-essays"
                type="button"
                className={`journal-nav-link ${
                  section === 'essays' && !activeEssay ? 'is-active' : ''
                }`}
                onClick={() => switchSection('essays')}
              >
                文集
              </button>
              <button
                id="journal-nav-archive"
                type="button"
                className={`journal-nav-link ${section === 'archive' && !activeEssay ? 'is-active' : ''}`}
                onClick={() => switchSection('archive')}
              >
                归档
              </button>
              <button
                id="journal-nav-excerpts"
                type="button"
                className={`journal-nav-link ${section === 'excerpts' && !activeEssay ? 'is-active' : ''}`}
                onClick={() => switchSection('excerpts')}
              >
                摘录
              </button>
              <button
                id="journal-nav-about"
                type="button"
                className={`journal-nav-link ${section === 'about' && !activeEssay ? 'is-active' : ''}`}
                onClick={() => switchSection('about')}
              >
                关于
              </button>
            </nav>
          </div>

          <div className="journal-masthead-right">
            <form className="journal-search-form" onSubmit={handleSearchSubmit} role="search">
              <Search size={14} className="journal-search-icon" aria-hidden="true" />
              <input
                ref={searchInputRef}
                id="disguise-search-input"
                type="text"
                className="journal-search-input"
                value={searchQuery}
                onChange={(e) => {
                  setSearchQuery(e.target.value);
                  if (activeEssayId && !e.target.value.trim().startsWith(':')) {
                    setActiveEssayId(null);
                  }
                }}
                placeholder="检索文章或读书批注..."
                aria-label="检索文章或读书批注"
                autoComplete="off"
                spellCheck={false}
              />
              {searchQuery && (
                <button
                  type="button"
                  className="journal-search-clear"
                  onClick={() => setSearchQuery('')}
                  aria-label="清空搜索"
                >
                  <X size={13} />
                </button>
              )}
            </form>

            <button
              id="disguise-theme-toggle"
              type="button"
              className="btn-icon journal-theme-btn"
              onClick={onToggleTheme}
              title={theme === 'light' ? '切换墨色夜读模式' : '切换纸质日读模式'}
              aria-label="切换阅读明暗外观"
            >
              {theme === 'light' ? <Moon size={16} /> : <Sun size={16} />}
            </button>
          </div>
        </header>

        {/* Main Editorial Stage */}
        <main className="journal-main">
          {activeEssay ? (
            <article
              id="journal-article-reader"
              className={`journal-reader ${relaxedFont ? 'is-relaxed' : ''}`}
            >
              <div className="journal-reader-toolbar">
                <button
                  id="journal-back-to-list"
                  type="button"
                  className="journal-back-btn"
                  onClick={() => setActiveEssayId(null)}
                >
                  <ArrowLeft size={15} />
                  <span>返回文集目录</span>
                </button>

                <button
                  id="journal-font-size-toggle"
                  type="button"
                  className="journal-type-toggle"
                  onClick={() => setRelaxedFont((v) => !v)}
                >
                  字号：{relaxedFont ? '舒朗' : '标准'}
                </button>
              </div>

              <header className="journal-reader-header">
                <div className="journal-entry-meta">
                  <span className="journal-entry-cat">{activeEssay.category}</span>
                  <span className="journal-meta-sep">·</span>
                  <time className="mono" dateTime={activeEssay.publishedAt}>
                    {activeEssay.publishedAt}
                  </time>
                  <span className="journal-meta-sep">·</span>
                  <span>约 {activeEssay.wordCount} 字</span>
                  <span className="journal-meta-sep">·</span>
                  <span>{activeEssay.readingMinutes} 分钟阅读</span>
                </div>

                <h1 className="journal-reader-title">{activeEssay.title}</h1>
                <p className="journal-reader-subtitle">{activeEssay.subtitle}</p>
              </header>

              <div className="journal-reader-body">
                {activeEssay.blocks.map((block, idx) => {
                  if (block.type === 'heading') {
                    return (
                      <h2 key={idx} className="journal-prose-h2">
                        {block.text}
                      </h2>
                    );
                  }
                  if (block.type === 'quote') {
                    return (
                      <blockquote key={idx} className="journal-prose-quote">
                        <p>{block.text}</p>
                        {block.cite && <cite>— {block.cite}</cite>}
                      </blockquote>
                    );
                  }
                  if (block.type === 'code') {
                    return (
                      <pre key={idx} className="journal-prose-pre">
                        <code>{block.code}</code>
                      </pre>
                    );
                  }
                  if (block.type === 'list') {
                    return (
                      <ul key={idx} className="journal-prose-list">
                        {block.items.map((item, liIdx) => (
                          <li key={liIdx}>{item}</li>
                        ))}
                      </ul>
                    );
                  }
                  return (
                    <p key={idx} className="journal-prose-p">
                      {block.text}
                    </p>
                  );
                })}
              </div>

              <footer className="journal-reader-foot">
                <div className="journal-tag-row">
                  {activeEssay.tags.map((tag) => (
                    <span key={tag} className="journal-tag">
                      #{tag}
                    </span>
                  ))}
                </div>

                <div className="journal-signoff">
                  <span>撰稿：{disguiseConfig.authorPenName}</span>
                  <span>·</span>
                  <span>写于杭州城西</span>
                </div>

                <nav className="journal-pager" aria-label="上下篇导航">
                  {prevEssay ? (
                    <button
                      type="button"
                      className="journal-pager-card"
                      onClick={() => openEssay(prevEssay.id)}
                    >
                      <span className="journal-pager-hint">← 较新一篇</span>
                      <span className="journal-pager-title">{prevEssay.title}</span>
                    </button>
                  ) : (
                    <div />
                  )}

                  {nextEssay ? (
                    <button
                      type="button"
                      className="journal-pager-card is-right"
                      onClick={() => openEssay(nextEssay.id)}
                    >
                      <span className="journal-pager-hint">较早一篇 →</span>
                      <span className="journal-pager-title">{nextEssay.title}</span>
                    </button>
                  ) : (
                    <div />
                  )}
                </nav>
              </footer>
            </article>
          ) : section === 'essays' ? (
            <>
              <section className="journal-intro" aria-labelledby="journal-home-heading">
                <p className="journal-kicker">
                  {disguiseConfig.siteTagline} · 独立静态手记
                </p>
                <h1 id="journal-home-heading" className="journal-hero-title">
                  慢下来写字，把复杂留给推演。
                </h1>
                <p className="journal-hero-lead">
                  这里是 {disguiseConfig.authorPenName}{' '}
                  的个人阅读与工程笔记本。平时主要关注单机存储引擎、克制的命令行工具链、旧书页边批注与周末山野步道；不设算法流与追踪脚本，按自己舒服的节奏不定期更新。
                </p>
              </section>

              <div className="journal-filter-bar" role="tablist" aria-label="文章分类筛选">
                {ESSAY_CATEGORIES.map((cat) => (
                  <button
                    key={cat}
                    type="button"
                    role="tab"
                    aria-selected={selectedCategory === cat}
                    className={`journal-cat-btn ${selectedCategory === cat ? 'is-active' : ''}`}
                    onClick={() => setSelectedCategory(cat)}
                  >
                    <span>{cat}</span>
                    <span className="journal-cat-count mono">
                      {categoryCounts[cat] ?? 0}
                    </span>
                  </button>
                ))}
              </div>

              {effectiveFilterQuery && (
                <div className="journal-search-banner">
                  <span>
                    检索“<strong>{searchQuery.trim()}</strong>”：共匹配{' '}
                    {filteredEssays.length} 篇文章、{filteredExcerpts.length} 则读书摘录
                  </span>
                  <button
                    type="button"
                    className="journal-inline-reset"
                    onClick={() => setSearchQuery('')}
                  >
                    重置筛选
                  </button>
                </div>
              )}

              {featuredEssay && (
                <section className="journal-featured" aria-label="近期精选长文">
                  <div className="journal-featured-inner">
                    <div className="journal-entry-meta">
                      <span className="journal-featured-label">近期长文</span>
                      <span className="journal-meta-sep">·</span>
                      <span className="journal-entry-cat">{featuredEssay.category}</span>
                      <span className="journal-meta-sep">·</span>
                      <time className="mono" dateTime={featuredEssay.publishedAt}>
                        {featuredEssay.publishedAt}
                      </time>
                      <span className="journal-meta-sep">·</span>
                      <span>{featuredEssay.readingMinutes} 分钟阅读</span>
                    </div>

                    <h2 className="journal-featured-title">
                      <button
                        type="button"
                        className="journal-title-trigger"
                        onClick={() => openEssay(featuredEssay.id)}
                      >
                        {featuredEssay.title}
                      </button>
                    </h2>

                    <p className="journal-featured-excerpt">{featuredEssay.excerpt}</p>

                    <div className="journal-featured-bottom">
                      <div className="journal-tag-row">
                        {featuredEssay.tags.map((tag) => (
                          <span key={tag} className="journal-tag">
                            #{tag}
                          </span>
                        ))}
                      </div>

                      <button
                        type="button"
                        className="journal-read-more"
                        onClick={() => openEssay(featuredEssay.id)}
                      >
                        <span>阅读全文</span>
                        <ArrowUpRight size={14} />
                      </button>
                    </div>
                  </div>
                </section>
              )}

              {streamEssays.length > 0 ? (
                <section className="journal-stream" aria-label="文章列表">
                  {streamEssays.map((essay) => (
                    <article key={essay.id} className="journal-stream-item">
                      <div className="journal-stream-aside mono">
                        <time dateTime={essay.publishedAt}>{essay.publishedAt}</time>
                        <span>{essay.category}</span>
                      </div>

                      <div className="journal-stream-main">
                        <h2 className="journal-stream-title">
                          <button
                            type="button"
                            className="journal-title-trigger"
                            onClick={() => openEssay(essay.id)}
                          >
                            {essay.title}
                          </button>
                        </h2>
                        <p className="journal-stream-excerpt">{essay.excerpt}</p>
                        <div className="journal-stream-foot">
                          <span>约 {essay.wordCount} 字 · {essay.readingMinutes} 分钟阅读</span>
                          <button
                            type="button"
                            className="journal-read-inline"
                            onClick={() => openEssay(essay.id)}
                          >
                            展卷阅读 →
                          </button>
                        </div>
                      </div>
                    </article>
                  ))}
                </section>
              ) : (
                !featuredEssay && (
                  <div className="journal-empty-state">
                    <BookOpen size={22} />
                    <p>当前筛选条件下暂无匹配手记。</p>
                  </div>
                )
              )}

              {/* Supplemental Reading Marginalia Strip on Home */}
              {(!effectiveFilterQuery || filteredExcerpts.length > 0) && (
                <section className="journal-home-excerpts" aria-label="近期读书批注">
                  <div className="journal-section-head">
                    <h2>书页边角摘录</h2>
                    <button
                      type="button"
                      className="journal-read-inline"
                      onClick={() => switchSection('excerpts')}
                    >
                      查看全部 {READING_EXCERPTS.length} 则批注 →
                    </button>
                  </div>

                  <div className="journal-excerpt-duo">
                    {filteredExcerpts.slice(0, 2).map((ex) => (
                      <blockquote key={ex.id} className="journal-excerpt-sheet">
                        <p className="journal-excerpt-quote">“{ex.quote}”</p>
                        <p className="journal-excerpt-note">批注：{ex.note}</p>
                        <footer className="journal-excerpt-cite">
                          <span>
                            {ex.bookTitle} · {ex.author}
                          </span>
                          <span className="mono">{ex.recordedAt}</span>
                        </footer>
                      </blockquote>
                    ))}
                  </div>
                </section>
              )}
            </>
          ) : section === 'archive' ? (
            <section className="journal-subpage" aria-labelledby="archive-heading">
              <header className="journal-subpage-head">
                <p className="journal-kicker">CHRONOLOGICAL INDEX</p>
                <h1 id="archive-heading" className="journal-subpage-title">
                  按年份归档
                </h1>
                <p className="journal-subpage-desc">
                  截至目前共整理收录 {DISGUISE_ESSAYS.length} 篇长文手记，按成文时间倒序编目。
                </p>
              </header>

              <div className="journal-archive-list">
                {archiveGroups.map((group) => (
                  <div key={group.year} className="journal-archive-year-block">
                    <div className="journal-archive-year-head">
                      <h2 className="mono">{group.year}</h2>
                      <span>{group.items.length} 篇</span>
                    </div>

                    <ul className="journal-archive-rows">
                      {group.items.map((item) => (
                        <li key={item.id} className="journal-archive-row">
                          <time className="journal-archive-date mono" dateTime={item.publishedAt}>
                            {item.publishedAt.slice(5)}
                          </time>
                          <button
                            type="button"
                            className="journal-archive-link"
                            onClick={() => openEssay(item.id)}
                          >
                            {item.title}
                          </button>
                          <span className="journal-archive-leader" aria-hidden="true" />
                          <span className="journal-archive-cat">{item.category}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </section>
          ) : section === 'excerpts' ? (
            <section className="journal-subpage" aria-labelledby="excerpts-heading">
              <header className="journal-subpage-head">
                <p className="journal-kicker">MARGINALIA &amp; COMMONPLACE BOOK</p>
                <h1 id="excerpts-heading" className="journal-subpage-title">
                  书单与页边摘录
                </h1>
                <p className="journal-subpage-desc">
                  翻完纸书数日后凭记忆重抄的段落与随手批注。比起全文划线堆积，只留住真正引发推演的句子。
                </p>
              </header>

              <div className="journal-excerpts-stack">
                {filteredExcerpts.map((item) => (
                  <article key={item.id} className="journal-excerpt-full">
                    <div className="journal-excerpt-full-top">
                      <div>
                        <h2 className="journal-excerpt-book">{item.bookTitle}</h2>
                        <p className="journal-excerpt-source">
                          {item.author} · {item.sourceMeta}
                        </p>
                      </div>
                      <time className="mono journal-excerpt-date" dateTime={item.recordedAt}>
                        {item.recordedAt}
                      </time>
                    </div>

                    <blockquote className="journal-prose-quote">
                      <p>{item.quote}</p>
                    </blockquote>

                    <p className="journal-excerpt-commentary">
                      <strong>随手批注：</strong>
                      {item.note}
                    </p>
                  </article>
                ))}
              </div>
            </section>
          ) : (
            <section className="journal-subpage" aria-labelledby="about-heading">
              <header className="journal-subpage-head">
                <p className="journal-kicker">ABOUT &amp; COLOPHON</p>
                <h1 id="about-heading" className="journal-subpage-title">
                  关于「{disguiseConfig.siteTitle}」
                </h1>
                <p className="journal-subpage-desc">
                  一处安静存放阅读笔记、工程实验记录与山野步行见闻的独立站点。
                </p>
              </header>

              <div className="journal-about-prose">
                <p>
                  你好，我是 <strong>{disguiseConfig.authorPenName}</strong>
                  ，日常从事后端基础设施与存储系统研发。工作之余喜欢翻阅系统设计旧籍、整理极简的终端脚本，天气晴朗的周末常去西湖群山走十几公里石板步道。
                </p>
                <p>
                  建立这个小站的初衷很简单：社交媒体的时间线太碎、太急，许多需要静下心来推导的技术脉络与读书体会，只有写成结构完整的长文才算真正想明白。
                </p>

                <h2>写作与排版原则</h2>
                <ul>
                  <li>不追逐热点资讯，只记录经过自己实践验证或反复重读依然受用的内容。</li>
                  <li>全站零第三方统计脚本、零弹窗广告、零推荐流，保持纸质书般的阅读呼吸感。</li>
                  <li>除特别注明的引用段落外，本站原创文字采用 CC BY-NC-SA 4.0 协议共享。</li>
                </ul>

                <h2>站点版记（Colophon）</h2>
                <p>
                  标题采用衬线宋体排版，正文与代码片段分别搭配无衬线体与等宽字体，支持暖白纸张与深墨夜读两种外观切换。感谢你的驻足阅读。
                </p>
              </div>
            </section>
          )}
        </main>

        {/* Editorial Footer */}
        <footer className="journal-footer">
          <span
            id="disguise-footer-trigger"
            className="journal-copyright"
            onClick={handleFooterCopyrightClick}
          >
            © 2024–2026 {disguiseConfig.siteTitle} · {disguiseConfig.authorPenName} · CC BY-NC-SA 4.0
          </span>

          <div className="journal-footer-links">
            <button type="button" onClick={() => switchSection('essays')}>
              文集
            </button>
            <span>·</span>
            <button type="button" onClick={() => switchSection('archive')}>
              归档
            </button>
            <span>·</span>
            <button type="button" onClick={() => switchSection('about')}>
              版记
            </button>
            <span>·</span>
            <span className="journal-footer-note">纯静态归档 · 无追踪脚本</span>
          </div>
        </footer>
      </div>

      <AuthorPortalModal
        open={portalOpen}
        siteTitle={disguiseConfig.siteTitle}
        initialVaultInitialized={initialVaultInitialized}
        defaultVaultName={defaultVaultName}
        onClose={() => setPortalOpen(false)}
        onAuthenticated={onAuthenticated}
        onStatusResolved={onStatusResolved}
      />
    </div>
  );
};
