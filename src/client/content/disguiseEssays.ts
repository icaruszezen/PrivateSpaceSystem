export type EssayCategory = '系统工程' | '阅读札记' | '器物与效率' | '山行随笔';

export type EssayContentBlock =
  | { type: 'paragraph'; text: string }
  | { type: 'heading'; text: string }
  | { type: 'quote'; text: string; cite?: string }
  | { type: 'code'; language: string; code: string }
  | { type: 'list'; items: string[] };

export interface DisguiseEssay {
  id: string;
  slug: string;
  title: string;
  subtitle: string;
  category: EssayCategory;
  publishedAt: string;
  year: string;
  readingMinutes: number;
  wordCount: number;
  featured?: boolean;
  tags: string[];
  excerpt: string;
  blocks: EssayContentBlock[];
}

export interface ReadingExcerptItem {
  id: string;
  bookTitle: string;
  author: string;
  sourceMeta: string;
  recordedAt: string;
  quote: string;
  note: string;
  tags: string[];
}

export const ESSAY_CATEGORIES: Array<'全部' | EssayCategory> = [
  '全部',
  '系统工程',
  '阅读札记',
  '器物与效率',
  '山行随笔',
];

export const DISGUISE_ESSAYS: DisguiseEssay[] = [
  {
    id: 'essay-lsm-append-log',
    slug: 'append-only-log-and-lsm-tradeoffs',
    title: '从追加写日志到 LSM-Tree：为什么朴素的顺序写总能赢过精巧的原地更新',
    subtitle: '重读存储引擎演进史时记下的几则工程取舍笔记，兼谈写放大与读延迟的边界。',
    category: '系统工程',
    publishedAt: '2026-10-28',
    year: '2026',
    readingMinutes: 7,
    wordCount: 1680,
    featured: true,
    tags: ['存储引擎', 'LSM-Tree', 'WAL', '系统设计'],
    excerpt:
      '几乎所有可靠的单机存储系统，拨开上层索引与缓存的繁复外壳，最底下都躺着一份只追加不修改的字节序列。顺序写不仅顺应了介质物理特性，更把并发崩溃恢复简化成了单一游标的截断问题。',
    blocks: [
      {
        type: 'paragraph',
        text: '过去两个周末在整理几份旧的存储引擎读书笔记时，重新对照了 B+Tree 原地页更新与 LSM-Tree 分层合并在现代 NVMe 固态盘上的表现。一个很有趣的现象是：尽管随机 I/O 与顺序 I/O 在硬件层面的吞吐差距不像机械硬盘时代那样悬殊，但“只追加写（Append-only）”依然是新系统最青睐的基石。',
      },
      {
        type: 'paragraph',
        text: '原因其实并不只在磁盘吞吐，而在于固态介质内部的擦写块（Erase Block）寿命管理，以及软件层面对崩溃一致性（Crash Consistency）的心智负担。原地修改一个 16KB 的数据页，往往意味着要先写双写缓冲区或预写日志，否则断电瞬间的半页写入（Torn Page）足以摧毁整棵索引树的不变量。',
      },
      {
        type: 'quote',
        text: '日志不是数据库的附属品；数据库本身就是一份被持续物化为索引视图的不可变事件流。',
        cite: 'Martin Kleppmann ·《数据密集型应用系统设计》读书批注',
      },
      {
        type: 'heading',
        text: '一、把随机突变转化为不可变段（Immutable Segments）',
      },
      {
        type: 'paragraph',
        text: '当每一次写入都只向活跃的 MemTable 与预写日志尾部追加记录时，写路径上几乎不再需要跨页锁协调。内存表到达阈值后冻结为只读段并顺序刷盘为 SSTable，这个“一旦落盘即不可变”的约束带来了三个极其迷人的工程副产品：',
      },
      {
        type: 'list',
        items: [
          '并发读无需加锁：读者永远访问已落盘的不可变文件快照，引用计数归零前文件不会被回收。',
          '备份与增量复制变得极其自然：只需拷贝新增的段文件与清单游标，无需停机冻结写事务。',
          '校验和粒度清晰：每个固定大小的数据块独立附带校验摘要，静默位翻转能在首次读取时立即暴露。',
        ],
      },
      {
        type: 'code',
        language: 'c',
        code: `// 极简段记录帧结构示意：固定头部 + 变长键值 + 块尾校验
struct segment_entry_header {
  uint32_t crc32c;
  uint64_t seq_no;
  uint32_t key_len;
  uint32_t val_len;
};`,
      },
      {
        type: 'heading',
        text: '二、没有免费的午餐：后台合并的尾延迟治理',
      },
      {
        type: 'paragraph',
        text: '当然，LSM-Tree 把写入时省下的账单转移到了后台 Compaction 线程与点查的布隆过滤器上。工程实践中最容易踩坑的往往不是平均吞吐，而是 L0 层文件堆积触发限流（Write Stall）时的 P99 尾延迟毛刺。保持单层目标体积克制、为后台合并设置平滑的 I/O 速率上限，往往比盲目调大内存缓冲更有效。',
      },
    ],
  },
  {
    id: 'essay-mythical-man-month',
    slug: 'rereading-mythical-man-month-cognitive-load',
    title: '重读《人月神话》五十周年版：银弹依然不存在，但认知负荷可以裁剪',
    subtitle: '工具链换了三代之后，真正拖慢软件交付的依然是偶然复杂度与沟通拓扑。',
    category: '阅读札记',
    publishedAt: '2026-09-16',
    year: '2026',
    readingMinutes: 6,
    wordCount: 1420,
    tags: ['软件工程', '人月神话', '架构演进', '读书笔记'],
    excerpt:
      '布鲁克斯在半个世纪前区分了“本质复杂度”与“偶然复杂度”。今天我们的编译器与自动化部署快了百倍，却又常常在过度拆分的微服务与层层抽象里，亲手制造出新的偶然复杂度。',
    blocks: [
      {
        type: 'paragraph',
        text: '书架第二层那本泛黄的《人月神话》是刚工作第一年买的，当时只记住了“向进度落后的项目增加人手只会使它更落后”这句常被调侃的格言。今年秋分前后重读〈没有银弹〉与〈概念完整性〉两章，才发觉布鲁克斯真正讨论的是人类有限的工作记忆与系统状态空间之间的矛盾。',
      },
      {
        type: 'quote',
        text: '概念完整性是系统设计中最重要的考量。宁可舍弃一些零散而花哨的特性，也要让整个系统反映出统一、自洽的设计哲思。',
        cite: 'Fred Brooks ·《人月神话》第四章',
      },
      {
        type: 'heading',
        text: '裁剪边界比堆砌抽象更难',
      },
      {
        type: 'paragraph',
        text: '在两三个人的小团队或独立维护的项目里，最宝贵的资产其实是“一个人能在脑海中完整装下整条数据流”。每引入一个非必需的中间件、每多绕一层运行时反射配置，都在稀释这种确定性。好的工程手艺，往往体现在敢于删除那些为了“未来也许会用到”而提前预设的脚手架。',
      },
      {
        type: 'paragraph',
        text: '合上书时在扉页补了一行铅笔字：保持接口窄而深，保持依赖少而稳，剩下的交给时间慢慢打磨。',
      },
    ],
  },
  {
    id: 'essay-plain-text-cli-workflow',
    slug: 'seven-plain-text-tools-on-linux',
    title: '克制的终端工作流：我在 Linux 上长期保留的七个纯文本工具',
    subtitle: '不折腾花哨主题与几十个插件，只留下十年后依然能直接打开的文本与脚本。',
    category: '器物与效率',
    publishedAt: '2026-08-04',
    year: '2026',
    readingMinutes: 5,
    wordCount: 1260,
    tags: ['Linux', '终端工具', '纯文本', '工作流'],
    excerpt:
      '每隔几年总会有一批炫目的效率软件兴起又停服。经历过几次专有格式迁移的狼狈之后，我把日常写作、检索与任务编排全部退回到了纯文本与标准输入输出管道。',
    blocks: [
      {
        type: 'paragraph',
        text: '年轻时热衷于给编辑器装满状态栏动画、图标字体与自动补全套件，仿佛配置本身就是生产力。直到有一次在远程无图形界面的低配主机上排查故障，只有最基础的 POSIX 环境可用，才意识到真正顺手的工具应当像空气一样不抢夺注意力。',
      },
      {
        type: 'heading',
        text: '留存至今的最小集合',
      },
      {
        type: 'list',
        items: [
          'tmux：只保留前缀键与分屏绑定，断网重连后上下文分毫不差。',
          'ripgrep (rg)：在数万行代码与陈年手记目录里毫秒级定位任何一句话。',
          'fd + fzf：用模糊匹配代替层层目录跳转，手指几乎不必离开主键区。',
          'jq：处理结构化日志与接口响应的瑞士军刀，一行表达式胜过半页临时脚本。',
          'SQLite CLI：单文件关系型分析器，本地实验统计数据直接落地成可复现查询。',
          'Makefile：写清楚 build、test、clean 三个目标，任何三个月后的自己都能一眼看懂。',
        ],
      },
      {
        type: 'paragraph',
        text: '这套组合最大的好处是零锁定：文稿是 UTF-8 编码的普通文件，配置不超过两百行，换一台新机器五分钟即可原样恢复。器物贵精不贵多，大抵如此。',
      },
    ],
  },
  {
    id: 'essay-jiuxi-trail-after-rain',
    slug: 'jiuxi-valley-walk-after-summer-rain',
    title: '雨后九溪至理安寺步道记：在没有信号的山谷里待一个下午',
    subtitle: '梅雨初歇的周六午后，沿着溪涧石板路慢行十二公里。',
    category: '山行随笔',
    publishedAt: '2026-06-21',
    year: '2026',
    readingMinutes: 4,
    wordCount: 1080,
    tags: ['徒步', '九溪', '山行', '散文'],
    excerpt:
      '连下四天梅雨后终于放晴，溪水漫过第叁道汀步石。把手机调成飞行模式塞进背包侧袋，耳边只剩下水声、竹叶滴水声与鞋底踩过青苔石阶的轻响。',
    blocks: [
      {
        type: 'paragraph',
        text: '清晨六点半出门时，龙井路两侧的枫香与茶园还笼在一层薄薄的水汽里。因为刚下过透雨，往日周末热闹的九溪烟树游人寥寥，涧水比平时丰沛许多，漫过几处低矮的石碇步，水色是极清亮的浅碧。',
      },
      {
        type: 'paragraph',
        text: '过了理安寺旧址再往杨梅岭方向走，山谷渐深，两侧高大的楠木把暑气隔绝在外。找了一处背阴的石凳坐下喝茶，翻开随身带的小开本《山居杂忆》，读了不到二十页便索性合上书页，单看阳光穿过竹梢在青苔上缓慢移动。',
      },
      {
        type: 'quote',
        text: '人一旦离开持续刷新的屏幕两个小时，时间的颗粒度就会重新变粗，原本以为火烧眉毛的琐事，放到山风里看都不过尔尔。',
      },
      {
        type: 'paragraph',
        text: '下山到满觉陇已是傍晚五点，路边人家已经在院子里支起竹匾晾晒新笋干。记下这一笔，提醒自己每月至少留出半日走入山野。',
      },
    ],
  },
  {
    id: 'essay-sqlite-wal-checkpoint',
    slug: 'sqlite-wal-concurrency-and-checkpoint-notes',
    title: 'SQLite WAL 模式下的并发读边界与检查点调优笔记',
    subtitle: '单节点嵌入式数据库在真实业务负载下的几个关键配置参数实测。',
    category: '系统工程',
    publishedAt: '2026-04-12',
    year: '2026',
    readingMinutes: 6,
    wordCount: 1510,
    tags: ['SQLite', 'WAL', '数据库', '性能调优'],
    excerpt:
      '许多人低估了单机 SQLite 的吞吐上限。正确开启 WAL、合理设置 busy_timeout 与 synchronous=NORMAL 之后，单机每秒数万次点查与数千次事务提交完全游刃有余。',
    blocks: [
      {
        type: 'paragraph',
        text: '在中小型自托管服务里，省去独立数据库进程意味着零网络序列化开销与极低的运维复杂度。但默认回滚日志（Rollback Journal）模式下读写互斥，常常让初次使用者误以为 SQLite 无法承受并发请求。',
      },
      {
        type: 'code',
        language: 'sql',
        code: `PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
PRAGMA wal_autocheckpoint = 1000;`,
      },
      {
        type: 'paragraph',
        text: '切换到 WAL 后，读事务只需在共享内存索引（-shm）中记录当前末尾帧号（mxFrame），即可与正在追加的写事务并行不悖。唯一需要留意的是长耗时未关闭的只读游标会阻碍 PASSIVE / TRUNCATE 检查点回收旧帧，导致 -wal 文件持续膨胀。保持短事务、及时释放预编译语句游标，是嵌入式存储稳定运行的铁律。',
      },
    ],
  },
  {
    id: 'essay-long-goodbye-marginalia',
    slug: 'marginalia-on-paperback-books',
    title: '《漫长的告别》与铅笔批注：纸质书边角里的二次阅读',
    subtitle: '为什么我依然习惯在纸书留白处写下日期与天气。',
    category: '阅读札记',
    publishedAt: '2025-12-19',
    year: '2025',
    readingMinutes: 5,
    wordCount: 1190,
    tags: ['雷蒙德·钱德勒', '阅读习惯', '批注', '随笔'],
    excerpt:
      '电子书的划线导出固然整齐，却少了翻开旧书时撞见五年前自己字迹的那一瞬恍惚。用 2B 铅笔在页边记下当时的心境，一本书便成了跨越年份的对话录。',
    blocks: [
      {
        type: 'paragraph',
        text: '冬至前夜重翻南海出版公司那版《漫长的告别》，在第三十二章页脚看到自己 2021 年深秋用铅笔写下的一小行字：“窗外大风，煮陈皮普洱”。那一刻突然记起当时住处狭窄书桌上的台灯暖光，甚至比书里的情节还要鲜活。',
      },
      {
        type: 'paragraph',
        text: '后来我给自己定了一个简单的摘录习惯：读完一本书后，不急着把所有划线原封不动搬进电脑，而是隔三天凭印象挑出真正留下回响的三五处，用自己的话补写几句批注。经过时间筛过一遍的文字，才算真正长进了自己的知识脉络里。',
      },
    ],
  },
];

export const READING_EXCERPTS: ReadingExcerptItem[] = [
  {
    id: 'ex-ddia-simplicity',
    bookTitle: '《数据密集型应用系统设计》',
    author: 'Martin Kleppmann',
    sourceMeta: '第 1 章 · 可靠、可扩展与可维护的应用系统',
    recordedAt: '2026-10-19',
    quote:
      '简化并不意味着减少功能；它意味着消除偶然的复杂性，使系统的心智模型与它实际解决的问题保持对齐。',
    note: '每次想给模块增加一层“通用插件机制”之前，先重读这段话。绝大多数过度设计都始于对虚构需求的防御。',
    tags: ['系统架构', '可维护性'],
  },
  {
    id: 'ex-unix-rule-of-representation',
    bookTitle: '《Unix 编程艺术》',
    author: 'Eric S. Raymond',
    sourceMeta: '第 1.6 节 · 表达原则（Rule of Representation）',
    recordedAt: '2026-08-29',
    quote:
      '把知识叠入数据结构，这样逻辑就可以保持笨拙而健壮（Fold knowledge into data, so program logic can be stupid and robust）。',
    note: '无论是状态机转移表还是路由声明，一旦数据结构设计对了，代码里的条件分支自然会消融大半。',
    tags: ['Unix哲学', '数据结构'],
  },
  {
    id: 'ex-invisible-cities',
    bookTitle: '《看不见的城市》',
    author: '伊塔洛·卡尔维诺',
    sourceMeta: '译林出版社 · 王志弘译本',
    recordedAt: '2026-07-11',
    quote:
      '记忆中的形象一旦被词语固定住，就会在现实中悄然抹去。也许我不愿讲述威尼斯，正是害怕失去它。',
    note: '卡尔维诺对语言精密度与轻逸感的掌控令人叹服，适合在写不出技术文档的深夜翻读两页洗一洗语感。',
    tags: ['文学', '卡尔维诺'],
  },
  {
    id: 'ex-zen-motorcycle-quality',
    bookTitle: '《禅与摩托车维修艺术》',
    author: '罗伯特·M·波西格',
    sourceMeta: '第三部 · 论“良质（Quality）”与耐心',
    recordedAt: '2026-05-03',
    quote:
      '真正的平静不是逃避机器与理性，而是在拧紧每一颗螺丝、推敲每一处边界条件时保持全然的专注。',
    note: '急躁是制造低级缺陷的最大根源。遇到棘手缺陷时，先停下来泡杯热茶，把观测事实列在纸上，答案往往自己会浮现。',
    tags: ['工程心法', '阅读摘录'],
  },
  {
    id: 'ex-philosophy-software-design',
    bookTitle: '《软件设计哲学》',
    author: 'John Ousterhout',
    sourceMeta: '第 4 章 · 模块应当深（Modules Should Be Deep）',
    recordedAt: '2026-02-14',
    quote:
      '最好的模块提供极其简单的外部接口，却在内部封装了相当可观的实现复杂度，替调用者挡住底层细节的风雨。',
    note: 'UNIX 文件描述符 open/read/write/close 就是“深模块”最经典的教科书范例。',
    tags: ['接口设计', '深模块'],
  },
];

export function groupEssaysByYear(
  essays: DisguiseEssay[],
): Array<{ year: string; items: DisguiseEssay[] }> {
  const map = new Map<string, DisguiseEssay[]>();
  for (const item of essays) {
    const bucket = map.get(item.year);
    if (bucket) {
      bucket.push(item);
    } else {
      map.set(item.year, [item]);
    }
  }
  return Array.from(map.entries())
    .sort((a, b) => b[0].localeCompare(a[0]))
    .map(([year, items]) => ({
      year,
      items: [...items].sort((x, y) => y.publishedAt.localeCompare(x.publishedAt)),
    }));
}
