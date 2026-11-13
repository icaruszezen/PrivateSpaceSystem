# PrivateSpace Mobile (`Android` & `iOS`)

`mobile/` 提供面向 **Android** 与 **iOS** 的多端增量同步客户端与 TypeScript SDK（[`PrivateSpaceMobileClient`](./src/syncClient.ts)），与服务端 `/api/v1/*` 协议及 Web 端共享核心加密辅助模块（`@shared/totp`、`@shared/passwordGenerator`、`@shared/types`）。

## 核心特性

1. **原生 `Bearer` 设备会话认证**：登录时自动上报 `platform: 'android' | 'ios'` 与设备名称，获取独立 `pss_<sessionId>.<secret>` 令牌，可在任意端「数据加密与多端安全」面板中独立吊销。
2. **单调游标增量同步（`since_seq`）**：持久化本地 `lastSyncSeq`，通过 `GET /api/v1/sync?since_seq=<cursor>` 原子拉取新增/修改的 **文本笔记、密码、图片、视频、相册** 与永久销毁墓碑（`deleted`）。
3. **离线实时 TOTP 两步验证码**：复用零外部依赖的 RFC 6238 实现（`SHA-1` / `SHA-256`），无网环境下仍可每秒刷新 6/8 位动态口令。
4. **蜂窝网络断点续传与原生流式播放**：
   - 大体积 4K 视频与原图按 `512 KiB` 分片上传（`POST /uploads/init` → `PUT /uploads/:id/chunks/:index` → `POST /uploads/:id/complete`），网络中断后自动查询已接收分片继续上传；
   - 生成携带临时认证凭据的 `/api/v1/media/:id/stream?token=...` 地址，直接对接 iOS `AVPlayer` 与 Android `Media3 ExoPlayer` 的 HTTP `206 Partial Content` 分块实时解密流。

## 类型检查与集成

```bash
# 在仓库根目录执行（已集成至 npm run typecheck）
npx tsc -p mobile/tsconfig.json --noEmit
```
