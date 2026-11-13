# PrivateSpace · 私密空间

一个自部署、现代简洁、静态数据全加密的个人私密存储与多端同步空间。

当前版本已完成核心基础底座与第一阶段功能闭环：
- **数据加密存储**：采用 **信封加密（Envelope Encryption）** + **AES-256-GCM** 认证加密架构。所有记录的标题、正文、摘要与标签均经由独立 `HKDF-SHA256` 子密钥加密后写入本地 SQLite 数据库，磁盘文件零明文留存，并通过 `AAD`（附加认证数据）防御密文替换与版本回滚篡改。
- **唯一管理员登录**：数据库底层强制单管理员约束（`CHECK id = 1`），无第三方注册入口。支持首次访问交互式初始化，或通过环境变量 `ADMIN_PASSWORD` 无头自动初始化；内置登录防暴力破解限流与内存级临时密钥自动擦除机制。
- **文本记录空间**：支持 Markdown 与纯文本创作，提供 **编辑 / 分栏 / 预览** 三种视图、自动加密保存、可交互待办复选框、置顶、标签分类、全文瞬时检索、`⌘K` 快捷命令面板、归档收纳、回收站恢复/彻底销毁，以及 **实时 SQLite 密文信封透视面板**。
- **多端同步底座**：提供版本化 REST API 与单调递增游标增量同步协议（`/api/v1/sync?since_seq=...`），同时支持 `HttpOnly Cookie`（网页端）与 `Bearer Token`（面向后续 Android / iOS 原生客户端），并内置响应式移动端布局与 PWA 清单。
- **Docker 一键部署**：基于 Node.js 24 原生内置 `node:sqlite` 与 OpenSSL `node:crypto`，无任何 C++ 原生插件编译依赖，跨 `amd64` / `arm64` 架构开箱即用。

---

## 快速开始（Docker Compose 自部署）

### 1. 启动服务

```bash
git clone https://github.com/icaruszezen/PrivateSpaceSystem.git
cd PrivateSpaceSystem
cp .env.example .env
docker compose up -d --build
```

### 2. 初始化管理员并进入空间

- **方式 A（网页向导初始化，默认）**：浏览器打开 `http://localhost:8080`，设置空间名称与唯一管理员主密码（至少 8 位），系统将自动生成 256 位空间主密钥（DEK）并完成加密封装。
- **方式 B（环境变量自动初始化）**：在启动前编辑 `.env` 设置 `ADMIN_PASSWORD=你的高强度主密码`，容器首次启动时将自动完成管理员初始化，打开网页后直接输入该密码即可解锁登录。

### 3. 数据持久化与备份

所有加密数据与主密钥信封均持久化在容器内 `/data/vault.db`（对应 Docker 命名卷 `privatespace_data`）。由于磁盘数据库已由 AES-256-GCM 全加密，可直接对 `/data` 卷执行常规离线或增量快照备份。

---

## 环境变量说明

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `PORT` | `8080` | 服务监听端口 |
| `DATA_DIR` | `/data`（本地开发 `./data`） | 加密 SQLite 数据库存储目录 |
| `VAULT_NAME` | `PrivateSpace` | 默认空间显示名称 |
| `ADMIN_PASSWORD` | 空 | 可选；首次启动若非空（≥8 位）则自动初始化唯一管理员 |
| `SESSION_TTL_HOURS` | `72` | 设备解锁会话有效期（小时） |
| `COOKIE_SECURE` | `false` | 部署于 HTTPS 反向代理后建议设为 `true` |
| `CORS_ORIGINS` | 空 | 允许跨域访问的客户端 Origin 列表（逗号分隔） |

---

## 本地开发与验证

环境要求：**Node.js >= 24.0.0**（使用内置 `node:sqlite` 与 `node:crypto`）。

```bash
# 安装依赖
npm install

# 运行加密引擎与 API 集成测试（含磁盘零明文校验）
npm test

# 类型检查与生产构建
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

详细加密模型与多端增量同步协议设计请参阅 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
