package com.privatespace.mobile

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.provider.Settings
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.view.WindowManager
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.content.FileProvider
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import java.io.File
import java.io.FileOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyStore
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicReference
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@CapacitorPlugin(name = "PrivateSpaceNative")
class PrivateSpaceNativePlugin : Plugin() {

    companion object {
        const val PREFS_NAME = "privatespace_secure_prefs_v1"
        const val PREF_FLAG_SECURE = "meta_flag_secure_enabled"
        private const val KEYSTORE_PROVIDER = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS = "privatespace_vault_master_v1"
        private const val AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val GCM_TAG_BITS = 128
        private const val EXTRA_IS_SENSITIVE_COMPAT = "android.content.extra.IS_SENSITIVE"

        private val pendingSharedNote = AtomicReference<SharedInboundNote?>(null)
        private val pendingVerifiedApkFile = AtomicReference<File?>(null)
    }

    private val mainHandler = Handler(Looper.getMainLooper())
    private val downloadExecutor = Executors.newSingleThreadExecutor()
    private var pendingClipboardClearTask: Runnable? = null

    override fun handleOnNewIntent(intent: Intent?) {
        super.handleOnNewIntent(intent)
        if (intent == null) return

        when (intent.action) {
            Intent.ACTION_SEND -> {
                if (intent.type?.startsWith("text/") == true) {
                    val rawText = intent.getStringExtra(Intent.EXTRA_TEXT)
                    val rawSubject = intent.getStringExtra(Intent.EXTRA_SUBJECT)
                    val normalized = PrivateSpaceCryptoHelper.normalizeInboundShare(
                        mimeType = intent.type,
                        rawSubject = rawSubject,
                        rawText = rawText,
                    )
                    // Prevent duplicate consumption on configuration change / activity recreation
                    intent.action = Intent.ACTION_MAIN
                    intent.removeExtra(Intent.EXTRA_TEXT)
                    if (normalized != null) {
                        deliverOrQueueInboundShare(normalized)
                    }
                }
            }
            Intent.ACTION_VIEW -> {
                val dataUri = intent.dataString
                val pairing = PrivateSpaceCryptoHelper.parsePairingDeepLink(dataUri)
                intent.action = Intent.ACTION_MAIN
                intent.data = null
                if (pairing != null && dataUri != null) {
                    deliverOrQueueInboundShare(
                        SharedInboundNote(
                            mimeType = "application/x-privatespace-pair",
                            subject = pairing.vaultLabel ?: "PrivateSpace 配对链接",
                            text = dataUri,
                        )
                    )
                }
            }
        }
    }

    private fun deliverOrQueueInboundShare(shared: SharedInboundNote) {
        val payload = shared.toJSObject()
        if (hasListeners("shareReceived")) {
            notifyListeners("shareReceived", payload)
        } else {
            pendingSharedNote.set(shared)
        }
    }

    private fun SharedInboundNote.toJSObject(): JSObject {
        val obj = JSObject()
        obj.put("mimeType", mimeType)
        if (subject != null) {
            obj.put("subject", subject)
        }
        obj.put("text", text)
        return obj
    }

    private fun getPrefs() =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    @Synchronized
    private fun getOrCreateMasterKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val existing = keyStore.getEntry(KEYSTORE_ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) {
            return existing.secretKey
        }

        val keyGenerator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            KEYSTORE_PROVIDER,
        )
        val spec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .build()

        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    @PluginMethod
    fun getDeviceMetadata(call: PluginCall) {
        val biometricManager = BiometricManager.from(context)
        val authStatus = biometricManager.canAuthenticate(
            BiometricManager.Authenticators.BIOMETRIC_STRONG or
                BiometricManager.Authenticators.BIOMETRIC_WEAK
        )
        val biometricAvailable = authStatus == BiometricManager.BIOMETRIC_SUCCESS

        val currentWindow = activity?.window
        val flagSecureActive = if (currentWindow != null) {
            (currentWindow.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
        } else {
            getPrefs().getBoolean(PREF_FLAG_SECURE, true)
        }

        val deviceName = PrivateSpaceCryptoHelper.formatDeviceModelLabel(
            manufacturer = Build.MANUFACTURER,
            model = Build.MODEL,
            androidRelease = Build.VERSION.RELEASE,
        )

        val pkgInfo = try {
            context.packageManager.getPackageInfo(context.packageName, 0)
        } catch (_: Exception) {
            null
        }
        val appVersionName = pkgInfo?.versionName ?: "0.4.0"
        val appVersionCode = if (pkgInfo != null) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                pkgInfo.longVersionCode.toInt()
            } else {
                @Suppress("DEPRECATION")
                pkgInfo.versionCode
            }
        } else {
            400
        }
        val canInstallPackages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.packageManager.canRequestPackageInstalls()
        } else {
            true
        }

        val ret = JSObject().apply {
            put("deviceName", deviceName)
            put("sdkInt", Build.VERSION.SDK_INT)
            put("biometricAvailable", biometricAvailable)
            put("screenshotProtected", flagSecureActive)
            put("appVersionName", appVersionName)
            put("appVersionCode", appVersionCode)
            put("packageName", context.packageName)
            put("canInstallPackages", canInstallPackages)
        }
        call.resolve(ret)
    }

    @PluginMethod
    fun secureSet(call: PluginCall) {
        val key = call.getString("key")?.trim()
        val value = call.getString("value")
        if (key.isNullOrEmpty() || value == null) {
            call.reject("Both key and value are required for secureSet")
            return
        }

        try {
            val secretKey = getOrCreateMasterKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            val ciphertext = cipher.doFinal(value.toByteArray(StandardCharsets.UTF_8))
            val envelope = PrivateSpaceCryptoHelper.encodeKeystoreEnvelope(cipher.iv, ciphertext)

            getPrefs().edit().putString("sec_$key", envelope).apply()
            call.resolve(JSObject().put("ok", true))
        } catch (ex: Exception) {
            call.reject("AndroidKeyStore encryption failed: ${ex.message}", ex)
        }
    }

    @PluginMethod
    fun secureGet(call: PluginCall) {
        val key = call.getString("key")?.trim()
        if (key.isNullOrEmpty()) {
            call.reject("key is required for secureGet")
            return
        }

        val serialized = getPrefs().getString("sec_$key", null)
        if (serialized == null) {
            call.resolve(JSObject().put("value", JSObject.NULL))
            return
        }

        val decoded = PrivateSpaceCryptoHelper.decodeKeystoreEnvelope(serialized)
        if (decoded == null) {
            getPrefs().edit().remove("sec_$key").apply()
            call.resolve(JSObject().put("value", JSObject.NULL))
            return
        }

        try {
            val (iv, ciphertext) = decoded
            val secretKey = getOrCreateMasterKey()
            val cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(GCM_TAG_BITS, iv))
            val plaintextBytes = cipher.doFinal(ciphertext)
            val plaintext = String(plaintextBytes, StandardCharsets.UTF_8)
            call.resolve(JSObject().put("value", plaintext))
        } catch (_: Exception) {
            // Key invalidated (e.g. biometric enrollment reset) -> purge stale cipher entry safely
            getPrefs().edit().remove("sec_$key").apply()
            call.resolve(JSObject().put("value", JSObject.NULL))
        }
    }

    @PluginMethod
    fun secureRemove(call: PluginCall) {
        val key = call.getString("key")?.trim()
        if (!key.isNullOrEmpty()) {
            getPrefs().edit().remove("sec_$key").apply()
        }
        call.resolve(JSObject().put("ok", true))
    }

    @PluginMethod
    fun authenticateBiometric(call: PluginCall) {
        val hostActivity = activity
        if (hostActivity == null) {
            call.resolve(JSObject().put("verified", false))
            return
        }

        val title = call.getString("title")?.takeIf { it.isNotBlank() }
            ?: "解锁 PrivateSpace 私密空间"
        val subtitle = call.getString("subtitle")?.takeIf { it.isNotBlank() }
            ?: "验证指纹或面容以恢复加密保险库会话"

        hostActivity.runOnUiThread {
            try {
                val executor = ContextCompat.getMainExecutor(context)
                var settled = false
                val prompt = BiometricPrompt(
                    hostActivity,
                    executor,
                    object : BiometricPrompt.AuthenticationCallback() {
                        override fun onAuthenticationSucceeded(
                            result: BiometricPrompt.AuthenticationResult,
                        ) {
                            if (!settled) {
                                settled = true
                                vibrateInternal("success")
                                call.resolve(JSObject().put("verified", true))
                            }
                        }

                        override fun onAuthenticationError(
                            errorCode: Int,
                            errString: CharSequence,
                        ) {
                            if (!settled) {
                                settled = true
                                call.resolve(JSObject().put("verified", false))
                            }
                        }
                    },
                )

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle(title)
                    .setSubtitle(subtitle)
                    .setNegativeButtonText("使用 PIN 码解锁")
                    .setAllowedAuthenticators(
                        BiometricManager.Authenticators.BIOMETRIC_STRONG or
                            BiometricManager.Authenticators.BIOMETRIC_WEAK
                    )
                    .setConfirmationRequired(false)
                    .build()

                prompt.authenticate(promptInfo)
            } catch (_: Exception) {
                call.resolve(JSObject().put("verified", false))
            }
        }
    }

    @PluginMethod
    fun setScreenshotProtection(call: PluginCall) {
        val enabled = call.getBoolean("enabled", true) ?: true
        getPrefs().edit().putBoolean(PREF_FLAG_SECURE, enabled).apply()

        val hostActivity = activity
        if (hostActivity == null) {
            call.resolve(JSObject().put("screenshotProtected", enabled))
            return
        }

        hostActivity.runOnUiThread {
            if (enabled) {
                hostActivity.window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
            } else {
                hostActivity.window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
            }
            val active =
                (hostActivity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE) != 0
            call.resolve(JSObject().put("screenshotProtected", active))
        }
    }

    @PluginMethod
    fun copySensitiveSecret(call: PluginCall) {
        val text = call.getString("text")
        val label = call.getString("label") ?: "PrivateSpace Secret"
        val autoClearMs = call.getInt("autoClearMs", 30_000) ?: 30_000

        if (text == null) {
            call.reject("text is required for copySensitiveSecret")
            return
        }

        val clipboard = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        if (clipboard == null) {
            call.reject("ClipboardManager unavailable")
            return
        }

        val clip = ClipData.newPlainText(label, text)
        val sensitiveMasked = Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU
        if (sensitiveMasked) {
            val extras = PersistableBundle().apply {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    putBoolean(ClipDescription.EXTRA_IS_SENSITIVE, true)
                } else {
                    putBoolean(EXTRA_IS_SENSITIVE_COMPAT, true)
                }
            }
            clip.description.extras = extras
        }

        clipboard.setPrimaryClip(clip)
        vibrateInternal("light")

        pendingClipboardClearTask?.let { mainHandler.removeCallbacks(it) }
        pendingClipboardClearTask = null

        if (autoClearMs > 0) {
            val expectedDigest = PrivateSpaceCryptoHelper.sha256Hex(text)
            val clearTask = Runnable {
                try {
                    val primary = clipboard.primaryClip
                    val currentText = if (primary != null && primary.itemCount > 0) {
                        primary.getItemAt(0)?.coerceToText(context)
                    } else {
                        null
                    }
                    if (PrivateSpaceCryptoHelper.matchesClipboardDigest(expectedDigest, currentText)) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                            clipboard.clearPrimaryClip()
                        } else {
                            clipboard.setPrimaryClip(ClipData.newPlainText("", ""))
                        }
                    }
                } catch (_: Exception) {
                    // Ignore background clipboard restriction on OEM ROMs
                }
            }
            pendingClipboardClearTask = clearTask
            mainHandler.postDelayed(clearTask, autoClearMs.toLong())
        }

        val res = JSObject().apply {
            put("ok", true)
            put("sensitiveMasked", sensitiveMasked)
        }
        call.resolve(res)
    }

    @PluginMethod
    fun triggerHaptic(call: PluginCall) {
        val style = call.getString("style") ?: "light"
        vibrateInternal(style)
        call.resolve()
    }

    @PluginMethod
    fun consumePendingShare(call: PluginCall) {
        val pending = pendingSharedNote.getAndSet(null)
        val res = JSObject()
        if (pending != null) {
            res.put("shared", pending.toJSObject())
        } else {
            res.put("shared", JSObject.NULL)
        }
        call.resolve(res)
    }

    @PluginMethod
    fun openUnknownSourcesSettings(call: PluginCall) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                val intent = Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${context.packageName}"),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
            } catch (_: Exception) {
                val fallback = Intent(Settings.ACTION_SECURITY_SETTINGS)
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(fallback)
            }
        }
        val allowed = Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
            context.packageManager.canRequestPackageInstalls()
        call.resolve(JSObject().put("canInstallPackages", allowed))
    }

    @PluginMethod
    fun installPendingApk(call: PluginCall) {
        val apkFile = pendingVerifiedApkFile.get()
        if (apkFile == null || !apkFile.exists()) {
            call.reject("当前无已校验通过的待安装 APK 包，请重新下载")
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
            !context.packageManager.canRequestPackageInstalls()
        ) {
            openUnknownSourcesSettingsInternal()
            call.resolve(
                JSObject().apply {
                    put("status", "permission_required")
                    put("canInstallPackages", false)
                }
            )
            return
        }
        try {
            launchPackageInstaller(apkFile)
            call.resolve(
                JSObject().apply {
                    put("status", "installing")
                    put("canInstallPackages", true)
                }
            )
        } catch (ex: Exception) {
            call.reject("唤起系统安装包程序失败: ${ex.message}", ex)
        }
    }

    @PluginMethod
    fun downloadAndInstallApk(call: PluginCall) {
        val rawUrl = call.getString("url")?.trim()
        val expectedSha256 = call.getString("expectedSha256")?.trim()
        val versionName = call.getString("versionName")?.trim()
        val authHeader = call.getString("authorization")?.trim()

        if (rawUrl.isNullOrEmpty() || (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://"))) {
            call.reject("无效的 APK 下载地址")
            return
        }

        downloadExecutor.execute {
            var tempFile: File? = null
            try {
                val updatesDir = File(context.cacheDir, "updates")
                if (!updatesDir.exists()) {
                    updatesDir.mkdirs()
                }
                // Clean stale cached APKs before downloading new release
                updatesDir.listFiles()?.forEach { stale ->
                    if (stale.isFile && stale.name.endsWith(".apk", ignoreCase = true)) {
                        stale.delete()
                    }
                }

                val safeName = PrivateSpaceCryptoHelper.sanitizeApkFileName(versionName)
                val targetFile = File(updatesDir, safeName)
                tempFile = targetFile

                emitUpdateProgress("downloading", 0L, -1L, 0)

                val connection = openRedirectingConnection(rawUrl, authHeader)
                val statusCode = connection.responseCode
                if (statusCode !in 200..299) {
                    connection.disconnect()
                    throw IllegalStateException("APK 下载返回 HTTP $statusCode")
                }

                val totalBytes = connection.contentLengthLong
                val digest = MessageDigest.getInstance("SHA-256")
                var receivedBytes = 0L
                var lastEmitAt = 0L

                connection.inputStream.use { input ->
                    FileOutputStream(targetFile).use { output ->
                        val buffer = ByteArray(32 * 1024)
                        while (true) {
                            val read = input.read(buffer)
                            if (read <= 0) break
                            output.write(buffer, 0, read)
                            digest.update(buffer, 0, read)
                            receivedBytes += read

                            val now = System.currentTimeMillis()
                            if (now - lastEmitAt >= 120) {
                                lastEmitAt = now
                                val pct = if (totalBytes > 0) {
                                    ((receivedBytes * 100L) / totalBytes).toInt().coerceIn(0, 99)
                                } else {
                                    -1
                                }
                                emitUpdateProgress("downloading", receivedBytes, totalBytes, pct)
                            }
                        }
                        output.flush()
                    }
                }
                connection.disconnect()

                emitUpdateProgress("verifying", receivedBytes, totalBytes, 100)

                val actualShaHex = digest.digest().joinToString("") { b -> String.format("%02x", b) }
                if (!PrivateSpaceCryptoHelper.verifyApkSha256(expectedSha256, actualShaHex)) {
                    targetFile.delete()
                    emitUpdateProgress("error", receivedBytes, totalBytes, 0)
                    call.reject("APK SHA-256 签名摘要不匹配，已自动销毁可疑安装包")
                    return@execute
                }

                pendingVerifiedApkFile.set(targetFile)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                    !context.packageManager.canRequestPackageInstalls()
                ) {
                    emitUpdateProgress("permission_required", receivedBytes, totalBytes, 100)
                    mainHandler.post { openUnknownSourcesSettingsInternal() }
                    call.resolve(
                        JSObject().apply {
                            put("status", "permission_required")
                            put("sha256", actualShaHex)
                            put("bytes", receivedBytes)
                            put("canInstallPackages", false)
                        }
                    )
                    return@execute
                }

                emitUpdateProgress("installing", receivedBytes, totalBytes, 100)
                mainHandler.post {
                    try {
                        vibrateInternal("success")
                        launchPackageInstaller(targetFile)
                        call.resolve(
                            JSObject().apply {
                                put("status", "installing")
                                put("sha256", actualShaHex)
                                put("bytes", receivedBytes)
                                put("canInstallPackages", true)
                            }
                        )
                    } catch (installEx: Exception) {
                        call.reject("启动系统安装界面失败: ${installEx.message}", installEx)
                    }
                }
            } catch (ex: Exception) {
                tempFile?.delete()
                emitUpdateProgress("error", 0L, -1L, 0)
                call.reject("下载更新失败: ${ex.message}", ex)
            }
        }
    }

    private fun openRedirectingConnection(initialUrl: String, authHeader: String?): HttpURLConnection {
        var currentUrl = initialUrl
        var redirects = 0
        while (redirects < 6) {
            val conn = (URL(currentUrl).openConnection() as HttpURLConnection).apply {
                connectTimeout = 20_000
                readTimeout = 60_000
                instanceFollowRedirects = false
                setRequestProperty("Accept", "application/octet-stream, application/vnd.android.package-archive, */*")
                setRequestProperty("User-Agent", "PrivateSpace-Android-Updater/2.0")
                if (!authHeader.isNullOrEmpty() && redirects == 0) {
                    setRequestProperty("Authorization", authHeader)
                }
            }
            val code = conn.responseCode
            if (code in listOf(301, 302, 303, 307, 308)) {
                val location = conn.getHeaderField("Location")
                conn.disconnect()
                if (location.isNullOrBlank()) {
                    throw IllegalStateException("APK 重定向缺少 Location 头")
                }
                currentUrl = URL(URL(currentUrl), location).toString()
                redirects += 1
                continue
            }
            return conn
        }
        throw IllegalStateException("APK 下载重定向次数过多")
    }

    private fun emitUpdateProgress(status: String, receivedBytes: Long, totalBytes: Long, percent: Int) {
        val payload = JSObject().apply {
            put("status", status)
            put("receivedBytes", receivedBytes)
            put("totalBytes", totalBytes)
            put("percent", percent)
        }
        mainHandler.post {
            notifyListeners("updateDownloadProgress", payload)
        }
    }

    private fun openUnknownSourcesSettingsInternal() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            try {
                val intent = Intent(
                    Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES,
                    Uri.parse("package:${context.packageName}"),
                ).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                context.startActivity(intent)
            } catch (_: Exception) {
                // ignore
            }
        }
    }

    private fun launchPackageInstaller(apkFile: File) {
        val authority = "${context.packageName}.fileprovider"
        val apkUri = FileProvider.getUriForFile(context, authority, apkFile)
        val installIntent = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(apkUri, "application/vnd.android.package-archive")
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        context.startActivity(installIntent)
    }

    @Suppress("DEPRECATION")
    private fun vibrateInternal(style: String) {
        try {
            val vibrator: Vibrator? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val vm = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager
                vm?.defaultVibrator
            } else {
                context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
            }

            if (vibrator == null || !vibrator.hasVibrator()) return

            val effect = when (style) {
                "warning" -> VibrationEffect.createWaveform(longArrayOf(0, 18, 36, 20), -1)
                "success" -> VibrationEffect.createOneShot(18, VibrationEffect.DEFAULT_AMPLITUDE)
                else -> VibrationEffect.createOneShot(10, 90)
            }
            vibrator.vibrate(effect)
        } catch (_: Exception) {
            // Haptics are non-critical
        }
    }
}
