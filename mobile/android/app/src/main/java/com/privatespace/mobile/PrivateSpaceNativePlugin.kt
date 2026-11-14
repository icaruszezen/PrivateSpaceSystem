package com.privatespace.mobile

import android.content.ClipData
import android.content.ClipDescription
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.view.WindowManager
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import com.getcapacitor.JSObject
import com.getcapacitor.Plugin
import com.getcapacitor.PluginCall
import com.getcapacitor.PluginMethod
import com.getcapacitor.annotation.CapacitorPlugin
import java.nio.charset.StandardCharsets
import java.security.KeyStore
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
    }

    private val mainHandler = Handler(Looper.getMainLooper())
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

        val ret = JSObject().apply {
            put("deviceName", deviceName)
            put("sdkInt", Build.VERSION.SDK_INT)
            put("biometricAvailable", biometricAvailable)
            put("screenshotProtected", flagSecureActive)
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
