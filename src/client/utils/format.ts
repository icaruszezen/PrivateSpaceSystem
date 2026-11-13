import DOMPurify from 'dompurify';
import { marked } from 'marked';

marked.setOptions({
  gfm: true,
  breaks: true,
});

export function renderSafeMarkdown(markdown: string): string {
  const rawHtml = marked.parse(markdown || '') as string;
  // Enable checkbox inputs so interactive checklists render cleanly while keeping strict XSS safety
  return DOMPurify.sanitize(rawHtml, {
    USE_PROFILES: { html: true },
    ADD_TAGS: ['input'],
    ADD_ATTR: ['type', 'checked', 'disabled'],
  }).replace(/<input([^>]*?)disabled(?:="")?([^>]*?)>/gi, '<input$1$2>');
}

/**
 * Toggles the N-th GFM task list item (`- [ ]` <-> `- [x]`) in raw Markdown source.
 */
export function toggleMarkdownTaskAtIndex(markdown: string, targetIndex: number): string {
  let currentIdx = 0;
  return markdown.replace(/^(\s*[-*+]\s+\[)([ xX])(\]\s+)/gm, (full, prefix, state, suffix) => {
    if (currentIdx === targetIndex) {
      currentIdx += 1;
      const nextChar = state === ' ' ? 'x' : ' ';
      return `${prefix}${nextChar}${suffix}`;
    }
    currentIdx += 1;
    return full;
  });
}

export function formatShortDate(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return '';
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();

  if (diffMs >= 0 && diffMs < 60_000) {
    return '刚刚';
  }

  const sameDay =
    date.getFullYear() === now.getFullYear() &&
    date.getMonth() === now.getMonth() &&
    date.getDate() === now.getDate();

  if (sameDay) {
    return date.toLocaleTimeString('zh-CN', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    });
  }

  if (date.getFullYear() === now.getFullYear()) {
    return `${date.getMonth() + 1}月${date.getDate()}日`;
  }

  return `${date.getFullYear()}/${String(date.getMonth() + 1).padStart(2, '0')}/${String(
    date.getDate(),
  ).padStart(2, '0')}`;
}

export function formatFullDateTime(iso: string): string {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return '0 B';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

export function formatDuration(durationMs: number | null | undefined): string {
  if (!durationMs || durationMs <= 0) return '00:00';
  const totalSeconds = Math.max(1, Math.round(durationMs / 1000));
  const hrs = Math.floor(totalSeconds / 3600);
  const mins = Math.floor((totalSeconds % 3600) / 60);
  const secs = totalSeconds % 60;
  if (hrs > 0) {
    return `${hrs}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  }
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

export function evaluatePasswordStrength(password: string): {
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
} {
  if (!password) return { score: 0, label: '至少 8 位字符' };
  if (password.length < 8) return { score: 1, label: '长度不足 8 位' };

  let points = 1;
  if (password.length >= 12) points += 1;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) points += 1;
  if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password)) points += 1;
  else if (/\d/.test(password) || /[^A-Za-z0-9]/.test(password)) {
    if (password.length >= 14) points += 1;
  }

  const clamped = Math.min(4, Math.max(1, points)) as 1 | 2 | 3 | 4;
  const labels: Record<1 | 2 | 3 | 4, string> = {
    1: '基础强度',
    2: '中等强度',
    3: '高强度密钥派生',
    4: '极高熵值主密码',
  };
  return { score: clamped, label: labels[clamped] };
}

export const WELCOME_NOTE_TEMPLATE = {
  title: '欢迎使用 PrivateSpace 私密空间',
  tags: ['使用指南', '加密架构'],
  isPinned: true,
  content: `# 欢迎来到你的自部署私密空间

这是一处完全归属于你个人的加密记录空间。所有文本标题、正文与标签均在服务端通过 **AES-256-GCM** 认证加密后写入本地数据库，磁盘上不留存任何明文内容。

## 核心安全特性

- **信封加密（Envelope Encryption）**：主密码经 \`scrypt (N=32768, r=8, p=1)\` 派生密钥加密主密钥（KEK），用于包裹 256 位空间主密钥（DEK）。未来修改管理员密码无需重加密全量数据。
- **逐条独立子密钥与防篡改绑定**：每篇记录每次保存均使用 \`HKDF-SHA256\` 派生独立子密钥、全新 96 位随机 Nonce，并将记录 ID 与版本号写入 \`AAD\` 附加认证数据。
- **唯一管理员模型**：数据库底层强制单管理员约束（\`CHECK id = 1\`），杜绝未授权注册。

## 常用快捷操作

- [x] 完成管理员主密码初始化并解锁空间
- [ ] 点击编辑器顶部 **AES-256-GCM 已加密** 徽章，实时透视底层 SQLite 密文信封
- [ ] 使用快捷键 \`Ctrl / ⌘ + K\` 唤起全局搜索与快捷命令面板
- [ ] 使用 \`Ctrl / ⌘ + N\` 快速新建一篇私密记录

> 提示：在「预览」或「分栏」模式下，你可以直接点击上方待办复选框切换完成状态。`,
};
