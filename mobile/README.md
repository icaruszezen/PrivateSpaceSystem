# PrivateSpace Mobile (`Android` 原生客户端 `com.privatespace.mobile` & `iOS` 跨端模块)

`mobile/` 同时承载 **PrivateSpace · 私密空间** 的：
1. **原生 Android 手机客户端（[`AndroidApp.tsx`](./AndroidApp.tsx) + [`android/`](./android/)）**：基于 **Capacitor 6 + Kotlin 原生安全插件 + React 19 + TypeScript** 构建，支持直接编译安装 `.apk` 及服务端 `/mobile/` 伴侣端访问；
2. **跨平台离线优先同步 SDK（[`src/syncClient.ts`](./src/syncClient.ts)）**：为 Android 与 iOS 提供统一的 Bearer 会话认证、离线队列重放、单调游标增量同步（`since_seq`）、SSE 实时流订阅与 `512 KiB` 断点续传；
3. **iOS 独立移动端与跨端视图模块（[`App.tsx`](./App.tsx) + [`src/components/IosModals.tsx`](./src/components/IosModals.tsx)）**：供服务端 `/ios` 独立 Web App 与 React Native / Expo 容器复用（纯原生 Apple SwiftUI + AutoFill 工程请另见 [`../ios/README.md`](../ios/README.md)）。

---

## 一、原生 Android 手机客户端架构与安全特性

### 1. Kotlin 硬件级安全插件（[`PrivateSpaceNativePlugin.kt`](./android/app/src/main/java/com/privatespace/mobile/PrivateSpaceNativePlugin.kt)）
- **`AndroidKeyStore` AES-256-GCM 密钥保管库**：使用硬件级 `KeyGenParameterSpec` 生成不可导出的 256 位主密钥，将会话凭据（`pss_...`）与快捷 PIN 元数据封装为 `v1.<iv>.<ciphertext>` 密文保存，设备磁盘零明文令牌残留。
- **`BiometricPrompt` 指纹 / 面容快锁**：集成 `androidx.biometric:biometric`，支持 6 位快捷 PIN 码与系统生物识别秒级解封会话密钥。
- **`FLAG_SECURE` 防截屏与后台遮蔽**：在 `MainActivity.onCreate` 首帧渲染前默认挂载 `WindowManager.LayoutParams.FLAG_SECURE`，防止多任务切换卡片泄密及恶意录屏，可在「安全」页按需切换。
- **Android 13+ 敏感剪贴板遮罩与定时擦除**：复制密码或 2FA 验证码时自动标记 `ClipDescription.EXTRA_IS_SENSITIVE` 隐藏系统悬浮预览，并在 30 秒后通过常量时间 `SHA-256` 摘要比对精准擦除剪贴板。
- **系统分享菜单（`Intent.ACTION_SEND`）与一键配对深链（`privatespace://pair`）**：支持从外部 App 直接将链接/文本「分享」至 PrivateSpace 加密笔记；支持点击或粘贴 `privatespace://pair?server=...&vault=...` 配对码一键填入自部署服务器地址。
- **内网与私有根证书兼容（[`network_security_config.xml`](./android/app/src/main/res/xml/network_security_config.xml)）**：原生信任系统证书与用户自签根证书（mkcert / Caddy Internal CA），兼容家庭局域网与 Tailscale 直连。

### 2. 五大手机触控工作区
1. **密码保险箱（`密码`）**：实时刷新 RFC 6238 动态两步验证码（30s 倒计时）、安全健康评分与风险过滤（弱口令 / 重复密码 / 未开启 2FA）、CSPRNG 随机密码与助记词组生成器、CSV 批量导入、自定义隐藏字段与历史密码版本回溯。
2. **加密相册（`相册`）**：支持手机相机直拍加密入库（`capture="environment"`）与相册多选原图分块上传、相册目录管理、暗房级全屏查看器（90° 旋转、双倍缩放、幻灯片轮播）与 `.psenc` 分块密文透视。
3. **私密影院（`影院`）**：`512 KiB` 分片断点续传 + `SHA-256` 校验上传手机 4K 视频，基于 `HTTP 206 Partial Content` 实现 $O(1)$ 任意进度条秒拖播放、`±10s` 快进退与倍速控制。
4. **私密笔记（`笔记`）**：支持 Markdown 源码编辑与安全渲染预览切换、单手快捷排版工具栏、待办清单交互勾选、置顶/归档/回收站与永久覆写销毁。
5. **安全中心（`安全`）**：深浅双色主题（Warm Editorial Paper / Deep Graphite Ink）、防截屏护盾开关、剪贴板自动擦除开关、6 位 PIN + 生物识别配置、多端在线设备管理与远程一键吊销、主密码无损轮换（KEK 重封装）以及底层 `AES-256-GCM` / `PSENC001` 原始密文十六进制透视器。

---

## 二、离线优先缓存与同步引擎（[`src/syncClient.ts`](./src/syncClient.ts)）

- **`IndexedDbVaultPersistence` & `EncryptedWebVaultPersistence`**：分别面向 Android WebView（按服务器地址隔离命名空间的 `IndexedDB` 缓存与离线变更队列）与 iOS Standalone PWA（基于 WebCrypto `AES-256-GCM` 的加密快照持久化）。
- **离线队列自动重放**：飞行模式或弱网离线时新建/编辑笔记与密码自动进入本地离线队列，恢复联网后在 `syncDelta()` 中自动幂等重放并替换为服务端权威记录。

---

## 三、本地开发、测试与编译 Android APK

### 1. 热重载调试与全量验证
```bash
# 在仓库根目录执行完整类型检查与单元测试（含 Android 与 iOS 客户端测试套件）
npm run typecheck
npm test

# 启动后端（8080）与 Android 手机端 Vite 开发服务器（5174）
npm run dev:server
npm run dev:mobile
```

### 2. 编译原生 Android 安装包（APK）与运行 Kotlin 单元测试
环境要求：**JDK 17** 与 **Android SDK（Platform 34）**（设置环境变量 `ANDROID_HOME`）。

```bash
# 构建 dist/mobile、同步 Capacitor Android 工程并运行 Kotlin JUnit 单元测试
npm run android:test

# 编译可直接安装至安卓手机的 Debug APK
npm run android:apk

# 通过 adb 安装至已开启 USB 调试的安卓真机
adb install -r mobile/android/app/build/outputs/apk/debug/app-debug.apk
```
生成的 APK 位于：`mobile/android/app/build/outputs/apk/debug/app-debug.apk`。
