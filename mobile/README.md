# PrivateSpace Mobile (`iOS` & `Android` · React Native / Expo + Standalone `/ios`)

`mobile/` 提供面向 **iOS** 与 **Android** 的全功能跨端加密同步客户端与 TypeScript SDK（[`PrivateSpaceMobileClient`](./src/syncClient.ts)），同时可直接运行于 Expo / React Native 移动容器以及自部署服务端 `/ios` 独立移动端入口（iPhone Safari 主屏幕 Web App / 桌面 iPhone 16 Pro 交互预览舱）。

> 若需构建含系统级 `ASCredentialProviderViewController` 自动填充扩展与 `LocalAuthentication` / `CryptoKit` Keychain 集成的 **纯原生 Apple Swift / SwiftUI 工程**，请同时参阅仓库根目录下的 [`../ios/README.md`](../ios/README.md)。

## 核心模块与架构

- **[`App.tsx`](./App.tsx)**：5 栏原生触感移动空间主界面（**密码库 · 相册 · 影院 · 笔记 · 安全**），支持首次管理员初始化向导、Face ID 隐私遮蔽快速锁、深浅双色 Mineral Pine 主题。
- **[`src/syncClient.ts`](./src/syncClient.ts)**：
  - `PrivateSpaceMobileClient`：完整封装 `/api/v1/*` 认证、管理员初始化、主密码轮换、设备会话吊销、单调游标增量同步（`since_seq`）、SSE 实时流订阅（`/api/v1/sync/stream`）、离线变更队列（`outbox`）重放、密文信封透视（`inspectCipher`）、四大核心数据空间全量 CRUD 与 `512 KiB` 分片断点续传。
  - `EncryptedWebVaultPersistence`：基于 WebCrypto `AES-256-GCM`（随机 96-bit IV + 256-bit 设备密钥）加密持久化本机快照，杜绝明文 JSON 落入本地存储。
- **[`src/components/IosModals.tsx`](./src/components/IosModals.tsx)**：
  - 凭据详情抽屉（含每秒刷新的 RFC 6238 TOTP 圆环与自定义隐藏字段）、CSPRNG 随机口令/助记词生成器、Apple/Chrome/1Password/Bitwarden CSV 批量导入；
  - 暗房级原图查看器（缩放、90° 旋转、镜像翻转）、HTTP `206 Partial Content` 视频流式播放舱（倍速 `0.75×`–`2×`、±10s 快进退）；
  - Markdown + 交互式待办清单编辑器、SQLite / `PSENC001` 底层密文信封透视器。

## 类型检查与运行验证

```bash
# 在仓库根目录执行完整类型检查与单元测试
npm run typecheck
npm test
```
