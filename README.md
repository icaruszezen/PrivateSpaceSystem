# PrivateSpace · 私密空间

[![CI & Docker Build](https://github.com/icaruszezen/PrivateSpaceSystem/actions/workflows/ci.yml/badge.svg)](https://github.com/icaruszezen/PrivateSpaceSystem/actions/workflows/ci.yml)

一个自部署、现代简洁、**端到端零知识加密（Zero-Knowledge E2EE v2）** 的个人 **文本、密码、图片、视频** 存储与 **网页 / Android / iOS** 多端同步空间。

## 核心安全与能力全景

- **端到端零知识加密（`ZERO_KNOWLEDGE_E2EE_V2`）—— 即使部署服务器密码/Root 权限泄露也不泄密**：
  - **主密码与密钥永不出端**：客户端本地通过 `PBKDF2-HMAC-SHA256`（默认 `310,000` 次迭代）+ `HKDF-SHA256` 双路隔离派生 **密钥加密密钥（`KEK`）** 与 **认证子密钥（`authKey`）**。服务端仅存储对 `authKey` 二次 `scrypt` 哈希后的校验值与被 `KEK` 加密包裹的 256 位主密钥密文（`wrappedDek`），**从不接触明文主密码、`KEK` 或 `DEK`**。
  - **全量客户端 AEAD 认证加密（`cipherVersion = 2`）**：所有笔记、密码、媒体元数据及相册名称均在设备端经独立 `HKDF-SHA256` 子密钥 + `AES-256-GCM` 加密后再上传，并通过 `AAD`（`{ v: 2, id, type, rev }`）绑定条目 ID、类型与版本号，防御篡改、跨行替换与回滚攻击。
  - **客户端 `PSENC001` 分块加密媒体与盲流式传输**：原图、客户端本地提取的封面缩略图与大体积视频在上传前即按 **`64 KiB` / 块 + 独立随机文件密钥 `FEK`** 封装为 `PSENC001` 密文块；服务端仅盲存与按 `HTTP 206 Range` 转发 `.psenc` 密文字节，永久销毁时执行全零覆写擦除（File Shredding）。
  - **强制拒绝明文接口**：任何尝试向服务端提交明文主密码、明文笔记/密码或未加密文件的请求均被直接拦截（`400 E2EE_REQUIRED`）。
- **唯一管理员约束与无损主密码轮换**：
  - 数据库强制单管理员约束（`CHECK id = 1`），无第三方开放注册；修改主密码时仅在客户端使用新 `KEK` 重封装 32 字节 `DEK`，GB 级加密媒体与全库密文无需重传重加密。
- **四大私密存储空间**：
  1. **文本笔记（Notes）**：支持 Markdown / 纯文本、**编辑 / 分栏 / 预览** 视图、可交互待办复选框、置顶、标签、归档、回收站与实时密文信封透视。
  2. **密码保险箱（Passwords）**：客户端加密存储站点、账号、密码、**RFC 6238 动态两步验证码（TOTP `SHA-1` / `SHA-256` 实时倒计时环）**、自定义隐藏字段与最近 15 次历史密码版本；内置 **无偏拒绝采样 CSPRNG 随机密码与助记词组生成器**、**安全健康度审计面板**（弱口令、重复密码、未启用 2FA 筛选）以及主流密码管理器 CSV 本地加密批量导入。
  3. **加密相册（Images）**：支持拖拽、手机相机直拍与 `PhotosPicker` 多图客户端加密上传、客户端纯本地探测 PNG/JPEG/GIF/WebP 尺寸与生成加密缩略图、加密相册分类管理、**暗房级灯箱预览**（缩放、90° 旋转、镜像翻转、幻灯片播放、信息编辑）与 `.psenc` 分块密文透视。
  4. **私密视频影院（Videos）**：支持大文件 **客户端分片加密断点续传 + SHA-256 完整性校验**、客户端封面帧提取加密，以及 **`PSENC001` HTTP `206` 客户端按需分块解密流式播放**（倍速、`±10s` 快进退、循环、画中画 PiP）。
- **Android 原生手机客户端（[`mobile/`](mobile/README.md)，`com.privatespace.mobile`）**：
  - 基于 **Capacitor 6 + Kotlin 原生安全插件** 构建，支持 **`AndroidKeyStore` 硬件级 `AES-256-GCM` 封装 `{ token, dek }`、`BiometricPrompt` 指纹/面容零知识快锁、`FLAG_SECURE` 防截屏与多任务遮蔽、Android 13+ 敏感剪贴板隐私遮罩与 30s 自动擦除、系统分享直存加密笔记、`privatespace://pair?...` 一键配对、离线加密队列重放与相机直拍 `.psenc` 入库**；服务端亦在 `/mobile/` 托管移动端伴侣包。
- **完备的 Apple iOS 客户端体系（原生 SwiftUI + `/ios` 独立应用）**：
  - **纯原生 Apple Swift / SwiftUI 工程（[`ios/`](ios/README.md)，iOS 17+）**：基于 `CommonCrypto` + `CryptoKit` 原生实现与桌面/安卓端完全互通的零知识 E2EE v2 引擎、Keychain 硬件隔离托管 `DEK`、`LocalAuthentication` **Face ID / Touch ID** 解锁、`PrivateSpaceAutoFill` 系统密码自动填充扩展（配合 `/.well-known/apple-app-site-association`）以及基于 `AVAssetResourceLoaderDelegate`（`psenc-stream://`）的 **原生 `AVPlayer` HTTP `206` 边下边解密零落盘流式播放**。
  - **零编译即开即用的 `/ios` 独立移动端入口**：内置双引擎加密层（WebCrypto + Pure-TS Fallback），即使在局域网 HTTP 环境下也可在 iPhone Safari 全功能完成本地端到端加解密。
- **Web / Android / iOS 实时盲同步 & CI 自动构建**：
  - 统一单调递增密文游标协议（`GET /api/v1/sync?since_seq=...`）与 **SSE 实时游标广播**（`/api/v1/sync/stream`，仅广播序列号、不含任何密钥或明文）。
  - GitHub Actions 在 `ubuntu-latest` 与 `macos-15` 上自动执行零知识密码学测试、容器烟雾测试、编译上传原生 **Android APK** 产物、验证原生 **iOS Swift XCTest & Xcode Simulator** 构建，并发布 `linux/amd64` 与 `linux/arm64` 多架构镜像至 `ghcr.io/icaruszezen/privatespacesystem`。

---

## 快速开始（Docker 自部署）

### 方式一：直接拉取 GitHub 自动构建镜像（推荐）

```bash
git clone https://github.com/icaruszezen/PrivateSpaceSystem.git
cd PrivateSpaceSystem
cp .env.example .env
docker compose pull && docker compose up -d
```

也可无需克隆仓库单行启动（推荐在浏览器首次访问时在本地完成零知识主密钥初始化）：

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

1. **桌面网页端**：打开 `http://localhost:8080`，首次启动在浏览器本地生成 256 位随机 `DEK` 并设置主密码（不会向服务器发送明文密码）；在「安全中心 → 多端同步与设备」可一键复制 `privatespace://pair` 配对码。
2. **Android 原生手机端（APK / `/mobile/`）**：从 GitHub Actions 构建产物或本地 `npm run android:apk` 安装 `app-debug.apk`，粘贴配对码输入主密码即可在手机端本地解封 `DEK` 同步数据；详见 [`mobile/README.md`](mobile/README.md)。
3. **iPhone 免编译独立客户端（PWA）**：在 iPhone Safari 打开 `https://你的部署域名/ios`，点击分享 →「添加到主屏幕」即可全屏运行。
4. **iOS 原生 SwiftUI 客户端与系统自动填充**：在 macOS 上进入 `ios/` 目录，执行 `xcodegen generate && open PrivateSpaceIOS.xcodeproj` 编译安装至真机；详见 [`ios/README.md`](ios/README.md)。

---

## 环境变量说明

| 变量名 | 默认值 | 说明 |
| :--- | :--- | :--- |
| `PORT` | `8080` | 服务监听端口 |
| `DATA_DIR` | `/data`（本地开发 `./data`） | 盲存储 SQLite 密文库与 `.psenc` 分块密文目录 |
| `VAULT_NAME` | `PrivateSpace` | 默认空间显示名称 |
| `ADMIN_PASSWORD` | 空（推荐留空） | 可选一次性无头初始化口令；为获得严格零知识保证建议留空由客户端浏览器/App 首次向导初始化。若设置，首启生成兼容 E2EE v2 信封后立即擦除内存与环境变量（请随后删除宿主机 `.env` 中的该项） |
| `SESSION_TTL_HOURS` | `72` | 盲会话令牌有效期（小时，会话表不存储任何密钥） |
| `COOKIE_SECURE` | `false` | 部署于 HTTPS 反向代理后建议设为 `true` |
| `CORS_ORIGINS` | 空 | 允许跨域访问的客户端 Origin 列表（逗号分隔；默认已内置放行 Capacitor WebView 源） |
| `APPLE_APP_ID` | `TEAMID.io.privatespace.ios` | Apple Developer Team ID + Bundle ID，用于生成 `/.well-known/apple-app-site-association` 支持 iOS 自动填充与通用链接 |

---

## 本地开发与验证

环境要求：**Node.js >= 24.0.0**（使用内置 `node:sqlite` 与 `node:crypto`）；编译 Android APK 需 **JDK 17 + Android SDK Platform 34**；构建原生 iOS 工程需 **macOS 14+ / Xcode 16+ / Swift 5.10+**。

```bash
# 安装依赖
npm install

# 运行零知识密码学、防服务端入侵取证、分块流媒体、Android 与 iOS 客户端全量集成测试
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
npm run dev:server   # 盲存储加密后端监听 http://127.0.0.1:8080
npm run dev:client   # 网页端 + /ios Vite 监听 http://127.0.0.1:5173 并代理 /api
npm run dev:mobile   # 安卓手机端 Vite 监听 http://127.0.0.1:5174 并代理 /api
```

详细零知识威胁模型、`PSENC001` 分块加密规范与多端原生安全设计请参阅 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)、[mobile/README.md](mobile/README.md) 与 [ios/README.md](ios/README.md)。
