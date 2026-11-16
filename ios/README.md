# PrivateSpace Native iOS (`Swift 5.10+` · `SwiftUI` · `iOS 17+`)

`ios/` 是面向 **iPhone 与 iPad** 打造的原生 Apple 生态客户端，基于 **SwiftUI + Observation + CommonCrypto + CryptoKit + Keychain Services + LocalAuthentication + AVKit + AuthenticationServices** 构建，与 PrivateSpace 盲存储后端实现 **100% 端到端零知识加密（`ZERO_KNOWLEDGE_E2EE_V2`）** 与实时增量同步。

## 架构与目录结构

- **`Package.swift` & `Sources/PrivateSpaceKit/`**：跨 iOS / iPadOS / macOS 共享的零知识密码学与同步引擎包：
  - `Models/VaultModels.swift`：与 `src/shared/types.ts` 完全对齐的强类型 `Codable & Sendable` 密文信封模型（`CipherEnvelopeDTO`、`EncryptedVaultRecordDTO`、`MediaBlobKeyBundleDTO`、`WrappedDekDTO`）。
  - `Crypto/VaultE2EECrypto.swift`：原生 Swift 零知识加密核心，基于 `CommonCrypto` (`CCKeyDerivationPBKDF`) + Apple `CryptoKit` (`HKDF<SHA256>`、`HMAC<SHA256>`、`AES.GCM`、`SHA256`) 实现双路 `KEK` / `authKey` 派生、`DEK` 封装/轮换、`cipherVersion = 2` 条目 AEAD 加解密、`ImageIO` 本地缩略图生成以及 `PSENC001` 分块媒体加解密与字节区间映射，与桌面/安卓端共享确定性测试向量字节级互通。
  - `Crypto/TotpGenerator.swift` & `PasswordGenerator.swift`：RFC 6238 动态口令生成器、`SecRandomCopyBytes` 无偏 CSPRNG 随机密码/助记词生成器与密码健康度审计引擎。
  - `Storage/KeychainStore.swift` & `EncryptedLocalVaultStore.swift`：硬件级 iOS Keychain（`WhenUnlockedThisDeviceOnly`）隔离托管盲会话令牌与 `vault_master_dek_raw`（供 Face ID 解锁后恢复内存 `DEK`），并使用 `PSCACHE1` 二次加密存储离线快照与 App Group 自动填充凭据库；锁定应用时立即清空内存 `DEK`，退出登录时全零覆写销毁。
  - `Networking/EncryptedMediaResourceLoader.swift`：自定义 `AVAssetResourceLoaderDelegate` 流式解密代理，拦截 `psenc-stream://` 请求，按需通过 `HTTP 206 Range` 拉取服务端 `.psenc` 覆盖分块并在内存中即时执行 `AES.GCM` 解密喂给原生 `AVPlayer`，实现高清加密视频零明文落盘秒拖播放。
  - `Networking/PrivateSpaceAPIClient.swift`：基于 `URLSessionConfiguration.ephemeral` 的零知识客户端，在设备本地完成初始化、登录、密码轮换、条目加解密、分片加密断点续传及增量密文游标解密同步。
  - `Sync/VaultStore.swift`：`@MainActor @Observable` 全局状态、Face ID 锁屏密钥擦除与离线变更队列（Outbox）协调器。
- **`App/` (`PrivateSpaceIOS`)**：原生 SwiftUI 6 栏移动工作台（进入默认直达「互传」）：
  1. **多端互传空间（`互传`，默认首屏）**：支持通过系统 `fileImporter`（`[.item]`）选择任意格式文件加密发送、按类型筛选检索、客户端 `PSENC001` 解密校验 `SHA-256` 在线预览、`ShareLink` 导出至「文件」或其他 App（退出详情页自动全零覆写清理临时文件）以及密文彻底销毁。
  2. **密码库**：安全健康度审计看板、分类筛选、每秒刷新圆形倒计时环 TOTP、**本地专属 30 秒自动销毁剪贴板**、自定义隐藏字段、历史密码回溯与 CSV 本地加密导入。
  3. **加密相册**：客户端加密相册集管理、`PhotosPicker` 多图本地生成加密缩略图与 `PSENC001` 分片上传、**暗房级全屏灯箱**（双指捏合缩放、双击放大、90° 旋转、水平镜像、`PSENC001` 密文块透视）。
  4. **私密影院**：大体积视频客户端 `PSENC001` 分片断点续传、原生 `AVKit` `VideoPlayer` 配合 `EncryptedMediaResourceLoader` 边下边解密流式播放（秒开拖动、`±10s` 跳转、`0.75×–2.0×` 倍速）。
  5. **加密笔记**：Markdown 编辑 / 交互式待办复选框预览、快捷排版栏、多标签筛选与离线队列自动加密同步。
  6. **安全与同步**：SSE 实时状态与 `sync_seq` 游标、Face ID 与后台自动锁定设置、App 切换器毛玻璃防窥护盾、五维密文存储统计、多端会话远程吊销、客户端零重写主密码轮换与底层 `ZERO_KNOWLEDGE_E2EE_V2` / `PSENC001` 十六进制密文透视镜。
- **`AutoFillExtension/` (`PrivateSpaceAutoFill`)**：系统级 `ASCredentialProviderViewController` 密码自动填充扩展，支持在 Safari 与第三方 App 中按关联域名匹配填充账号密码，并在填充时自动复制 30 秒有效期的 2FA 动态口令。
- **`ShareExtension/` (`PrivateSpaceShareExtension`，显示名称：`发送`)**：系统级 `com.apple.share-services` 任意文件分享扩展（`io.privatespace.ios.share`），通过 App Group（`group.io.privatespace.ios`）读取 `PSCACHE1` 二次加密会话记录，在 iOS 任意应用中点击系统分享并选择 **「发送」** 即可经 Face ID 验证后将任意单/多文件按 `PSENC001` 加密发送至多端互传空间。

---

## 构建、测试与真机安装指南（macOS + Xcode 16+）

### 1. 运行跨语言零知识密码学向量与实时集成测试

```bash
cd ios
swift test
```

### 2. 生成 Xcode 工程并在 iOS 模拟器或真机运行

本目录提供标准 [XcodeGen](https://github.com/yonaskolb/XcodeGen) 工程规范 [`project.yml`](./project.yml)：

```bash
brew install xcodegen
cd ios
xcodegen generate
open PrivateSpaceIOS.xcodeproj
```

命令行无签名构建 iOS Simulator 验证：

```bash
xcodebuild \
  -project PrivateSpaceIOS.xcodeproj \
  -scheme PrivateSpaceIOS \
  -sdk iphonesimulator \
  -destination 'generic/platform=iOS Simulator' \
  CODE_SIGNING_ALLOWED=NO \
  build
```

### 3. 启用系统级密码自动填充（真机）

1. 在 Xcode 的 `Signing & Capabilities` 中为 `PrivateSpaceIOS` 与 `PrivateSpaceAutoFill` 选择您的 Apple Developer Team，并确认 App Group（`group.io.privatespace.ios`）一致；
2. 若需关联自部署域名自动匹配，可在服务端 `.env` 配置 `APPLE_APP_ID=<TeamID>.io.privatespace.ios`（服务端已自动暴露 `/.well-known/apple-app-site-association`）；
3. 安装至 iPhone 后，前往 **系统设置 → 通用 → 自动填充与密码**，开启 **PrivateSpace**。

### 4. iOS 软件自动更新与 GitHub Releases / OTA / TestFlight 配置

- `PrivateSpaceKit` 内置 `SemverVersion` 与 `AppUpdateService`（`Sources/PrivateSpaceKit/Sync/AppUpdateService.swift`），在解锁或切回前台时自动检测自托管服务端 `/api/v1/updates/check?platform=ios` 或指定 GitHub 仓库 Releases，并在「安全与同步」页提供 `itms-services://` 无线 OTA、TestFlight、App Store、AltStore 及 `.ipa` 安装入口与 SHA-256 指纹校验。
- 关于 Apple 证书（`.p12` / Provisioning Profile）、TestFlight API 密钥与服务端 OTA 清单参数的完整配置说明，请参阅 [`../docs/AUTO_UPDATE_GITHUB_CONFIG.md`](../docs/AUTO_UPDATE_GITHUB_CONFIG.md)。

