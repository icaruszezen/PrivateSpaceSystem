# PrivateSpace · 私密空间

[![CI & Docker Build](https://github.com/icaruszezen/PrivateSpaceSystem/actions/workflows/ci.yml/badge.svg)](https://github.com/icaruszezen/PrivateSpaceSystem/actions/workflows/ci.yml)

一个自部署、现代简洁、静态数据全加密（Zero-Plaintext at Rest）的个人 **文本、密码、图片、视频** 存储与 **网页 / iOS / Android** 多端同步空间。

## 核心能力全景

- **全栈信封加密与分块加密存储**：
  - 采用 **信封加密（Envelope Encryption）** + **AES-256-GCM** 认证加密架构。所有笔记、密码、媒体元数据及相册信息均经独立 `HKDF-SHA256` 子密钥加密写入本地 SQLite，并通过 `AAD`（附加认证数据）绑定条目 ID 与版本号防御篡改与回滚。
  - 原图、缩略图与大体积视频采用自研 **`PSENC001` 分块认证加密格式（`64 KiB` / 块 + 独立文件密钥 `FEK`）** 存储为 `.psenc` 密文文件，磁盘零明文留存，永久销毁时执行全零覆写擦除（File Shredding）。
- **唯一管理员登录与会话零残留**：
  - 数据库强制单管理员约束（`CHECK id = 1`），无第三方开放注册；支持网页/iOS 首次向导或环境变量 `ADMIN_PASSWORD` 无头自动初始化，内置防暴力破解限流与请求级 `DEK` 内存擦除（`Buffer.fill(0)`）。
- **四大私密存储空间**：
  1. **文本笔记（Notes）**：支持 Markdown / 纯文本、**编辑 / 分栏 / 预览** 视图、可交互待办复选框、置顶、标签、归档、回收站与实时密文信封透视。
  2. **密码保险箱（Passwords）**：加密存储站点、账号、密码、**RFC 6238 动态两步验证码（TOTP `SHA-1` / `SHA-256` 实时倒计时环）**、自定义隐藏字段与最近 15 次历史密码版本；内置 **无偏拒绝采样 CSPRNG 随机密码与助记词组生成器**、**安全健康度审计面板**（弱口令、重复密码、未启用 2FA 筛选）以及主流密码管理器 CSV 批量导入。
  3. **加密相册（Images）**：支持拖拽与 `PhotosPicker` 多图上传、自动解析分辨率、加密相册分类管理、**暗房级灯箱预览**（缩放、90° 旋转、镜像翻转、幻灯片播放）与 `.psenc` 分块密文透视。
  4. **私密视频影院（Videos）**：支持大文件 **`512 KiB` 分片断点续传 + SHA-256 完整性校验**、基于 `ffmpeg` 的编码探测与加密封面帧提取，以及 **HTTP `206 Partial Content` $O(1)$ 随机块解密流式播放**（秒开拖动进度条、`±10s` 快进退、`0.75×–2×` 倍速、画中画 PiP）。
- **完备的 Apple iOS 客户端体系（原生 SwiftUI + `/ios` 独立应用 + Expo/RN）**：
  - **纯原生 Apple Swift / SwiftUI 工程（[`ios/`](ios/README.md)，iOS 17+）**：
    - `PrivateSpaceKit` 核心 SDK：基于 Apple `CryptoKit` 实现本机 `PSCACHE1`（`HKDF-SHA256` + `AES-256-GCM`）离线加密快照缓存，`Security` Keychain 设备密钥与会话令牌隔离，`LocalAuthentication` **Face ID / Touch ID** 生物识别应用锁与多任务切换器后台隐私高斯遮罩，`URLSessionConfiguration.ephemeral` 零磁盘 HTTP 缓存网络栈，`AVURLAsset` HTTP `206` 视频流式播放，以及原生 W3C SSE 实时同步流。
    - `PrivateSpaceAutoFill` 系统自动填充扩展：实现 `ASCredentialProviderViewController`，配合服务端内置的 `/.well-known/apple-app-site-association`（`webcredentials`），支持在 iOS「设置 → 密码 → 自动填充密码」中启用系统级 Safari 与第三方 App 口令及 2FA 动态码自动填充。
  - **零编译即开即用的 `/ios` 独立移动端入口（Standalone Web App）**：在 iPhone Safari 访问 `https://你的域名/ios` 并「添加到主屏幕」，即可直接获得全屏 5 栏 iOS 原生触感客户端（基于 WebCrypto `AES-256-GCM` 本机加密缓存）；桌面端访问 `/ios` 自动呈现钛金属 iPhone 16 Pro / iPad Mini 交互预览舱。
  - **跨端 React Native / Expo 客户端（[`mobile/`](mobile/README.md)）**：面向 iOS 与 Android 共享同一套 [`PrivateSpaceMobileClient`](mobile/src/syncClient.ts) 同步、离线队列与断点续传引擎。
- **Docker 一键部署 & GitHub 双平台自动验证**：GitHub Actions 在 `ubuntu-latest` 与 `macos-15`（Xcode 16 + SwiftPM + iOS Simulator）上自动执行全栈加密测试与原生 iOS 编译验证，并发布 `linux/amd64` 与 `linux/arm64` 多架构镜像至 `ghcr.io/icaruszezen/privatespacesystem`。

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

### 初始化与多端接入

1. **桌面网页端**：打开 `http://localhost:8080`（首次启动可通过页面向导或 `.env` 中的 `ADMIN_PASSWORD` 初始化唯一管理员主密码）。
2. **iPhone 免编译独立客户端（PWA）**：在 iPhone Safari 打开 `https://你的部署域名/ios`，点击分享 →「添加到主屏幕」即可全屏运行。
3. **iOS 原生 SwiftUI 客户端与系统自动填充**：在 macOS 上进入 `ios/` 目录，执行 `xcodegen generate && open PrivateSpaceIOS.xcodeproj`，配置签名 Team 后编译安装至真机；详见 [`ios/README.md`](ios/README.md)。

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
| `APPLE_APP_ID` | `TEAMID.io.privatespace.ios` | Apple Developer Team ID + Bundle ID，用于生成 `/.well-known/apple-app-site-association` 支持 iOS 自动填充与通用链接 |

---

## 本地开发与验证

环境要求：**Node.js >= 24.0.0**（使用内置 `node:sqlite` 与 `node:crypto`），可选安装 `ffmpeg`；构建原生 iOS 工程需 **macOS 14+ / Xcode 16+ / Swift 5.10+**。

```bash
# 安装依赖
npm install

# 运行加密引擎、密码库、分块流媒体与 iOS 移动客户端集成测试
npm test

# 全栈类型检查（Web + Server + Mobile/iOS SDK）与多入口生产构建
npm run typecheck
npm run build

# 在 macOS 上运行原生 Swift PrivateSpaceKit 单元测试与 Xcode 模拟器构建
swift test --package-path ios
cd ios && xcodegen generate && xcodebuild -project PrivateSpaceIOS.xcodeproj -scheme PrivateSpaceIOS -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO build
```

详细加密模型、`.psenc` 分块流式解密与 iOS 原生安全设计请参阅 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)、[ios/README.md](ios/README.md) 与 [mobile/README.md](mobile/README.md)。
