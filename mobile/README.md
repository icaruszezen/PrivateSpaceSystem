# PrivateSpace Mobile (`Android` 原生客户端 `com.privatespace.mobile` & `iOS` 跨端模块)

`mobile/` 同时承载 **PrivateSpace · 私密空间** 的：
1. **原生 Android 手机客户端（[`AndroidApp.tsx`](./AndroidApp.tsx) + [`android/`](./android/)）**：基于 **Capacitor 6 + Kotlin 原生安全插件 + React 19 + TypeScript** 构建，完整实现 **`ZERO_KNOWLEDGE_E2EE_V2` 客户端端到端零知识加密**，支持直接编译安装 `.apk` 及服务端 `/mobile/` 伴侣端访问；
2. **跨平台零知识离线同步 SDK（[`src/syncClient.ts`](./src/syncClient.ts)）**：在设备本地完成 `PBKDF2-HMAC-SHA256`（`310,000` 次迭代）+ `HKDF-SHA256` 密钥派生、`DEK` 解封、离线加密队列重放、密文增量游标同步（`since_seq`）及 `PSENC001` 分块加密断点续传与按需解密；
3. **iOS 独立移动端与跨端视图模块（[`App.tsx`](./App.tsx) + [`src/components/IosModals.tsx`](./src/components/IosModals.tsx)）**：供服务端 `/ios` 独立 Web App 与 React Native / Expo 容器复用（纯原生 Apple SwiftUI + AutoFill 工程请另见 [`../ios/README.md`](../ios/README.md)）。

---

## 一、原生 Android 零知识客户端架构与安全特性

### 1. 客户端零知识密钥生命周期 + Kotlin 硬件安全插件（[`PrivateSpaceNativePlugin.kt`](./android/app/src/main/java/com/privatespace/mobile/PrivateSpaceNativePlugin.kt)）
- **主密码与 `DEK` 永不出端**：主密码仅在手机本地派生 `KEK`（解封 256 位 `DEK`）与 `authKey`（向服务端完成零知识认证），服务端永不接触明文密码或加密密钥。
- **`AndroidKeyStore` 硬件级密钥封装**：使用硬件级 `KeyGenParameterSpec` 生成不可导出的 256 位设备密钥，将盲会话令牌与 `DEK`（`{ token, dekBase64 }`）封装为 `AES-256-GCM` 密文保存；锁屏期间内存 `DEK` 立即擦除，设备磁盘零明文密钥残留。
- **`BiometricPrompt` 指纹 / 面容快锁**：集成 `androidx.biometric:biometric`，支持 6 位快捷 PIN 码与系统生物识别秒级恢复内存 `DEK` 解锁保险库。
- **`FLAG_SECURE` 防截屏与后台遮蔽**：在 `MainActivity.onCreate` 首帧渲染前默认挂载 `WindowManager.LayoutParams.FLAG_SECURE`，防止多任务切换卡片泄密及恶意录屏，可在「安全」页按需切换。
- **Android 13+ 敏感剪贴板遮罩与定时擦除**：复制密码或 2FA 验证码时自动标记 `ClipDescription.EXTRA_IS_SENSITIVE` 隐藏系统悬浮预览，并在 30 秒后通过常量时间 `SHA-256` 摘要比对精准擦除剪贴板。
- **系统分享菜单（`Intent.ACTION_SEND`）与一键配对深链（`privatespace://pair`）**：支持从外部 App 直接将链接/文本「分享」至 PrivateSpace 客户端加密入库；支持点击或粘贴 `privatespace://pair?server=...&vault=...` 配对码一键填入自部署服务器地址。
- **局域网 HTTP 与私有根证书双兼容**：内置 WebCrypto + Pure-TS 双引擎密码学原语与 [`network_security_config.xml`](./android/app/src/main/res/xml/network_security_config.xml)，在家庭局域网 HTTP、Tailscale 或自签证书 HTTPS 下均能完整执行客户端端到端加密。

### 2. 五大手机触控工作区
1. **密码保险箱（`密码`）**：客户端解密渲染、实时刷新 RFC 6238 动态两步验证码（30s 倒计时）、安全健康评分与风险过滤（弱口令 / 重复密码 / 未开启 2FA）、CSPRNG 随机密码与助记词组生成器、CSV 本地加密批量导入、自定义隐藏字段与历史密码版本回溯。
2. **加密相册（`相册`）**：支持手机相机直拍与相册多选原图在本地提取缩略图并封装为 `PSENC001` 密文上传、加密相册目录管理、暗房级全屏查看器（90° 旋转、双倍缩放、幻灯片轮播）与 `.psenc` 分块密文透视。
3. **私密影院（`影院`）**：`512 KiB` 客户端分片加密断点续传 + `SHA-256` 校验上传手机 4K 视频，客户端拉取 `.psenc` 密文流并在本机内存执行 `AES-256-GCM` 解密播放、支持 `±10s` 快进退与倍速控制。
4. **私密笔记（`笔记`）**：支持 Markdown 源码编辑与安全渲染预览切换、单手快捷排版工具栏、待办清单交互勾选、置顶/归档/回收站与永久覆写销毁。
5. **安全中心（`安全`）**：深浅双色主题、防截屏护盾开关、剪贴板自动擦除开关、6 位 PIN + 生物识别配置、多端在线设备管理与远程一键吊销、客户端零重写主密码轮换（KEK 重封装）以及底层 `ZERO_KNOWLEDGE_E2EE_V2` / `PSENC001` 密文十六进制透视器。

---

## 二、本地二次加密持久化与离线同步引擎（[`src/syncClient.ts`](./src/syncClient.ts)）

- **`IndexedDbVaultPersistence` & `EncryptedWebVaultPersistence`**：分别面向 Android WebView（按服务器地址隔离命名空间的 `IndexedDB` 缓存与离线队列）与 `/ios` Standalone PWA（基于设备独立 `AES-256-GCM` 密钥加密存储 `snapshot_enc` 与 `dek_enc`，`localStorage` 零明文）。
- **离线队列自动加密重放**：飞行模式或弱网离线时新建/编辑笔记与密码自动进入本地队列，恢复联网后在 `syncDelta()` 中使用内存 `DEK` 逐条加密为 `v2` AEAD 信封推送至服务端。

---

## 三、本地开发、测试与编译 Android APK

### 1. 热重载调试与全量验证
```bash
# 在仓库根目录执行完整类型检查与单元测试（含 Android 与 iOS 零知识客户端测试套件）
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
