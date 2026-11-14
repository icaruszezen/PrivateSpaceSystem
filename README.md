# PrivateSpace · 私密空间

[![CI & Docker Build](https://github.com/icaruszezen/PrivateSpaceSystem/actions/workflows/ci.yml/badge.svg)](https://github.com/icaruszezen/PrivateSpaceSystem/actions/workflows/ci.yml)

一个自部署、现代简洁、静态数据全加密（Zero-Plaintext at Rest）的个人 **文本、密码、图片、视频** 存储与 **网页 / Android / iOS** 多端同步空间。

## 核心能力全景

- **全栈信封加密与分块加密存储**：
  - 采用 **信封加密（Envelope Encryption）** + **AES-256-GCM** 认证加密架构。所有笔记、密码、媒体元数据及相册信息均经独立 `HKDF-SHA256` 子密钥加密写入本地 SQLite，并通过 `AAD`（附加认证数据）绑定条目 ID 与版本号防御篡改与回滚。
  - 原图、缩略图与大体积视频采用自研 **`PSENC001` 分块认证加密格式（`64 KiB` / 块 + 独立文件密钥 `FEK`）** 存储为 `.psenc` 密文文件，磁盘零明文留存，永久销毁时执行全零覆写擦除（File Shredding）。
- **唯一管理员登录与会话零残留**：
  - 数据库强制单管理员约束（`CHECK id = 1`），无第三方开放注册；支持网页 / Android / iOS 首次向导或环境变量 `ADMIN_PASSWORD` 无头自动初始化，内置防暴力破解限流与请求级 `DEK` 内存擦除（`Buffer.fill(0)`）。
- **四大私密存储空间**：
  1. **文本笔记（Notes）**：支持 Markdown / 纯文本、**编辑 / 分栏 / 预览** 视图、可交互待办复选框、置顶、标签、归档、回收站与实时密文信封透视。
  2. **密码保险箱（Passwords）**：加密存储站点、账号、密码、**RFC 6238 动态两步验证码（TOTP `SHA-1` / `SHA-256` 实时倒计时环）**、自定义隐藏字段与最近 15 次历史密码版本；内置 **无偏拒绝采样 CSPRNG 随机密码与助记词组生成器**、**安全健康度审计面板**（弱口令、重复密码、未启用 2FA 筛选）以及主流密码管理器 CSV 批量导入。
  3. **加密相册（Images）**：支持拖拽、手机相机直拍与 `PhotosPicker` 多图上传、自动解析 PNG/JPEG/GIF/WebP 分辨率、加密相册分类管理、**暗房级灯箱预览**（缩放、90° 旋转、镜像翻转、幻灯片播放、信息编辑）与 `.psenc` 分块密文透视。
  4. **私密视频影院（Videos）**：支持大文件 **`512 KiB` 分片断点续传 + SHA-256 完整性校验**、基于 `ffmpeg` 的编码探测与加密封面帧提取，以及 **HTTP `206 Partial Content` $O(1)$ 随机块解密流式播放**（秒开拖动进度条、`±10s` 快进退、`0.75×–2×` 倍速、循环、画中画 PiP）。
- **Android 原生手机客户端（[`mobile/`](mobile/README.md)，`com.privatespace.mobile`）**：
  - 基于 **Capacitor 6 + Kotlin 原生安全插件** 构建，支持 **`AndroidKeyStore` 硬件级 `AES-256-GCM` 密钥封装、`BiometricPrompt` 指纹/面容解锁、`FLAG_SECURE` 防截屏与多任务遮蔽、Android 13+ 敏感剪贴板隐私遮罩与 30s 自动擦除、系统分享菜单（`Intent.ACTION_SEND`）直存加密笔记、`privatespace://pair?...` 一键配对、离线变更队列重放、手机相机直拍 `.psenc` 入库及 `HTTP 206` 视频影院**；服务端亦在 `/mobile/` 托管移动端 Web 伴侣包。
- **完备的 Apple iOS 客户端体系（原生 SwiftUI + `/ios` 独立应用）**：
  - **纯原生 Apple Swift / SwiftUI 工程（[`ios/`](ios/README.md)，iOS 17+）**：基于 `CryptoKit` 本机 `PSCACHE1` 离线加密缓存、Keychain 隔离、`LocalAuthentication` **Face ID / Touch ID** 应用锁、`PrivateSpaceAutoFill` 系统密码自动填充扩展（配合 `/.well-known/apple-app-site-association`）及 `AVURLAsset` HTTP `206` 视频流式播放。
  - **零编译即开即用的 `/ios` 独立移动端入口**：在 iPhone Safari 访问 `https://你的域名/ios` 添加到主屏幕即可全屏运行。
- **Web / Android / iOS 实时增量同步 & CI 自动构建**：
  - 统一单调递增游标协议（`GET /api/v1/sync?since_seq=...`）与 **SSE 实时游标广播**（`/api/v1/sync/stream`），支持桌面端一键复制 `privatespace://pair?...` 配对码绑定手机。
  - GitHub Actions 在 `ubuntu-latest` 与 `macos-15` 上自动执行全量加密测试、编译上传原生 **Android APK** 产物、验证原生 **iOS Xcode Simulator** 构建，并发布 `linux/amd64` 与 `linux/arm64` 多架构镜像至 `ghcr.io/icaruszezen/privatespacesystem`。

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

1. **桌面网页端**：打开 `http://localhost:8080`（首次启动可通过页面向导或 `.env` 中的 `ADMIN_PASSWORD` 初始化唯一管理员主密码；在「安全中心 → 多端同步与设备」可一键复制 `privatespace://pair` 配对码）。
2. **Android 原生手机端（APK / `/mobile/`）**：从 GitHub Actions 构建产物或本地 `npm run android:apk` 安装 `app-debug.apk`，粘贴配对码即可解锁同步；亦可直接用手机浏览器访问 `https://你的部署域名/mobile/`；详见 [`mobile/README.md`](mobile/README.md)。
3. **iPhone 免编译独立客户端（PWA）**：在 iPhone Safari 打开 `https://你的部署域名/ios`，点击分享 →「添加到主屏幕」即可全屏运行。
4. **iOS 原生 SwiftUI 客户端与系统自动填充**：在 macOS 上进入 `ios/` 目录，执行 `xcodegen generate && open PrivateSpaceIOS.xcodeproj` 编译安装至真机；详见 [`ios/README.md`](ios/README.md)。

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
| `CORS_ORIGINS` | 空 | 允许跨域访问的客户端 Origin 列表（逗号分隔；默认已内置放行 Capacitor WebView 源） |
| `APPLE_APP_ID` | `TEAMID.io.privatespace.ios` | Apple Developer Team ID + Bundle ID，用于生成 `/.well-known/apple-app-site-association` 支持 iOS 自动填充与通用链接 |

---

## 本地开发与验证

环境要求：**Node.js >= 24.0.0**（使用内置 `node:sqlite` 与 `node:crypto`），可选安装 `ffmpeg`；编译 Android APK 需 **JDK 17 + Android SDK Platform 34**；构建原生 iOS 工程需 **macOS 14+ / Xcode 16+ / Swift 5.10+**。

```bash
# 安装依赖
npm install

# 运行加密引擎、密码库、分块流媒体、Android 与 iOS 移动客户端全量集成测试
npm test

# 全栈类型检查（Web + Server + Android/iOS Mobile SDK）与多入口生产构建
npm run typecheck
npm run build

# 编译 Android 原生 Kotlin 单元测试与可安装 APK
npm run android:test
npm run android:apk

# 在 macOS 上运行原生 Swift PrivateSpaceKit 单元测试与 Xcode 模拟器构建
swift test --package-path ios
cd ios && xcodegen generate && xcodebuild -project PrivateSpaceIOS.xcodeproj -scheme PrivateSpaceIOS -sdk iphonesimulator CODE_SIGNING_ALLOWED=NO build
```

开发模式下可分别启动后端、桌面网页端与安卓手机端热重载：

```bash
npm run dev:server   # 后端监听 http://127.0.0.1:8080
npm run dev:client   # 网页端 + /ios Vite 监听 http://127.0.0.1:5173 并代理 /api
npm run dev:mobile   # 安卓手机端 Vite 监听 http://127.0.0.1:5174 并代理 /api
```

详细加密模型、`.psenc` 分块流式解密与多端原生安全设计请参阅 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)、[mobile/README.md](mobile/README.md) 与 [ios/README.md](ios/README.md)。
