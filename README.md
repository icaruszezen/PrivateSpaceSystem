# PrivateSpace · 私密空间

[![CI & Docker Build](https://github.com/icaruszezen/PrivateSpaceSystem/actions/workflows/ci.yml/badge.svg)](https://github.com/icaruszezen/PrivateSpaceSystem/actions/workflows/ci.yml)

一个自部署、现代简洁、静态数据全加密（Zero-Plaintext at Rest）的个人 **文本、密码、图片、视频** 存储与 **网页 / Android / iOS** 多端同步空间。

## 核心能力全景

- **全栈信封加密与分块加密存储**：
  - 采用 **信封加密（Envelope Encryption）** + **AES-256-GCM** 认证加密架构。所有笔记、密码、媒体元数据及相册信息均经独立 `HKDF-SHA256` 子密钥加密写入本地 SQLite，并通过 `AAD`（附加认证数据）绑定条目 ID 与版本号防御篡改与回滚。
  - 原图、缩略图与大体积视频采用自研 **`PSENC001` 分块认证加密格式（`64 KiB` / 块 + 独立文件密钥 `FEK`）** 存储为 `.psenc` 密文文件，磁盘零明文留存，永久销毁时执行全零覆写擦除（File Shredding）。
- **唯一管理员登录与会话零残留**：
  - 数据库强制单管理员约束（`CHECK id = 1`），无第三方开放注册；支持网页向导或环境变量 `ADMIN_PASSWORD` 无头自动初始化，内置防暴力破解限流与请求级 `DEK` 内存擦除（`Buffer.fill(0)`）。
- **四大私密存储空间**：
  1. **文本笔记（Notes）**：支持 Markdown / 纯文本、**编辑 / 分栏 / 预览** 视图、可交互待办复选框、置顶、标签、归档、回收站与实时密文信封透视。
  2. **密码保险箱（Passwords）**：加密存储站点、账号、密码、**RFC 6238 动态两步验证码（TOTP `SHA-1` / `SHA-256` 实时倒计时环）**、自定义隐藏字段与最近 15 次历史密码版本；内置 **无偏拒绝采样 CSPRNG 随机密码与助记词组生成器**、**安全健康度审计面板**（弱口令、重复密码、未启用 2FA 筛选）以及主流密码管理器 CSV 批量导入。
  3. **加密相册（Images）**：支持拖拽多图上传、自动解析 PNG/JPEG/GIF/WebP 分辨率、加密相册分类管理、**暗房级灯箱预览**（滚轮/按钮缩放、90° 旋转、水平翻转、幻灯片播放、信息编辑）与 `.psenc` 分块密文透视。
  4. **私密视频影院（Videos）**：支持大文件 **`512 KiB` 分片断点续传 + SHA-256 完整性校验**、基于 `ffmpeg` 的编码探测与加密封面帧提取，以及 **HTTP `206 Partial Content` $O(1)$ 随机块解密流式播放**（秒开拖动进度条、`±10s` 快进退、`0.75×–2×` 倍速、循环、画中画 PiP）。
- **Web / Android / iOS 多端实时增量同步**：
  - 统一单调递增游标协议（`GET /api/v1/sync?since_seq=...`）与 **SSE 实时游标广播**（`/api/v1/sync/stream`），同时支持 `HttpOnly Cookie`（网页端）与 `Bearer pss_...` 令牌（移动端）。仓库内置 [`mobile/`](mobile/README.md) 跨端 TypeScript 同步 SDK 与 React Native（Android / iOS）客户端。
- **Docker 一键部署 & GitHub 自动构建**：GitHub Actions 自动运行全量加密与流媒体测试，并构建 `linux/amd64` 与 `linux/arm64` 多架构镜像（内置 `ffmpeg`）发布至 `ghcr.io/icaruszezen/privatespacesystem`。

---

## 快速开始（Docker 自部署）

### 方式一：直接拉取 GitHub 自动构建镜像（推荐）

```bash
git clone https://github.com/icaruszezen/PrivateSpaceSystem.git
cd PrivateSpaceSystem
cp .env.example .env
docker compose pull && docker compose up -d
```

也可无需克隆仓库单行启动：

```bash
docker run -d --name privatespace -p 8080:8080 -v privatespace_data:/data ghcr.io/icaruszezen/privatespacesystem:latest
```

### 方式二：源码本地构建启动

```bash
git clone https://github.com/icaruszezen/PrivateSpaceSystem.git
cd PrivateSpaceSystem
cp .env.example .env
docker compose up -d --build
```

### 2. 初始化管理员并进入空间

- **方式 A（网页向导初始化，默认）**：浏览器打开 `http://localhost:8080`，设置空间名称与唯一管理员主密码（至少 8 位），系统将自动生成 256 位空间主密钥（DEK）并完成加密封装。
- **方式 B（环境变量自动初始化）**：在启动前编辑 `.env` 设置 `ADMIN_PASSWORD=你的高强度主密码`，容器首次启动时将自动完成管理员初始化，打开网页或移动端后直接输入该密码即可解锁登录。

### 3. 数据持久化与备份

所有加密 SQLite 数据库（`/data/vault.db`）与分块加密媒体文件（`/data/blobs/*.psenc`）均持久化在容器内 `/data` 目录（对应 Docker 命名卷 `privatespace_data`）。磁盘文件全量经由 AES-256-GCM 加密，可直接对 `/data` 卷执行离线或增量快照备份。

---

## 环境变量说明

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `PORT` | `8080` | 服务监听端口 |
| `DATA_DIR` | `/data`（本地开发 `./data`） | 加密 SQLite 数据库与 `.psenc` 分块密文存储目录 |
| `VAULT_NAME` | `PrivateSpace` | 默认空间显示名称 |
| `ADMIN_PASSWORD` | 空 | 可选；首次启动若非空（≥8 位）则自动初始化唯一管理员 |
| `SESSION_TTL_HOURS` | `72` | 设备解锁会话有效期（小时） |
| `COOKIE_SECURE` | `false` | 部署于 HTTPS 反向代理后建议设为 `true` |
| `CORS_ORIGINS` | 空 | 允许跨域访问的客户端 Origin 列表（逗号分隔） |

---

## 本地开发与验证

环境要求：**Node.js >= 24.0.0**（使用内置 `node:sqlite` 与 `node:crypto`），可选安装 `ffmpeg`（用于视频编码探测与自动提取首帧加密封面）。

```bash
# 安装依赖
npm install

# 运行加密引擎、密码库、分块流媒体与多端同步集成测试（含磁盘零明文校验）
npm test

# 全栈类型检查（Web + Server + Mobile Android/iOS SDK）与生产构建
npm run typecheck
npm run build

# 启动生产服务
npm start
```

开发模式下可分别启动前后端热重载：

```bash
npm run dev:server   # 后端监听 http://127.0.0.1:8080
npm run dev:client   # 前端 Vite 监听 http://127.0.0.1:5173 并代理 /api
```

详细加密模型、`.psenc` 分块流式解密与多端增量同步协议设计请参阅 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) 与移动端说明 [mobile/README.md](mobile/README.md)。
