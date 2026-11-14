package com.privatespace.mobile

import java.net.URI
import java.net.URLDecoder
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Base64

data class SharedInboundNote(
    val mimeType: String,
    val subject: String?,
    val text: String,
)

data class PairingUriConfig(
    val serverUrl: String,
    val vaultLabel: String?,
)

/**
 * Pure, deterministic cryptographic envelope & Android Share/Pairing helper functions
 * backing [PrivateSpaceNativePlugin], designed for strict verification under JVM JUnit tests.
 */
object PrivateSpaceCryptoHelper {
    private const val ENVELOPE_VERSION = "v1"
    private const val GCM_IV_BYTES = 12

    fun encodeKeystoreEnvelope(iv: ByteArray, ciphertext: ByteArray): String {
        require(iv.size == GCM_IV_BYTES) {
            "AES-256-GCM IV must be exactly $GCM_IV_BYTES bytes (got ${iv.size})"
        }
        require(ciphertext.isNotEmpty()) {
            "Ciphertext payload must not be empty"
        }
        val encoder = Base64.getUrlEncoder().withoutPadding()
        val ivB64 = encoder.encodeToString(iv)
        val cipherB64 = encoder.encodeToString(ciphertext)
        return "$ENVELOPE_VERSION.$ivB64.$cipherB64"
    }

    fun decodeKeystoreEnvelope(serialized: String?): Pair<ByteArray, ByteArray>? {
        if (serialized.isNullOrBlank()) return null
        val parts = serialized.trim().split('.')
        if (parts.size != 3 || parts[0] != ENVELOPE_VERSION) return null
        return try {
            val decoder = Base64.getUrlDecoder()
            val iv = decoder.decode(parts[1])
            val cipher = decoder.decode(parts[2])
            if (iv.size != GCM_IV_BYTES || cipher.isEmpty()) {
                null
            } else {
                Pair(iv, cipher)
            }
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    fun sha256Hex(text: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(text.toByteArray(StandardCharsets.UTF_8))
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) {
            sb.append(String.format("%02x", b))
        }
        return sb.toString()
    }

    /**
     * Constant-time SHA-256 digest match used by scheduled clipboard auto-wipe so we never
     * erase unrelated text copied by the user after copying a vault password/TOTP code.
     */
    fun matchesClipboardDigest(expectedDigestHex: String, currentClipboardText: CharSequence?): Boolean {
        if (expectedDigestHex.length != 64 || currentClipboardText == null) return false
        val actualHex = sha256Hex(currentClipboardText.toString())
        return MessageDigest.isEqual(
            expectedDigestHex.lowercase().toByteArray(StandardCharsets.US_ASCII),
            actualHex.toByteArray(StandardCharsets.US_ASCII),
        )
    }

    fun normalizeInboundShare(
        mimeType: String?,
        rawSubject: String?,
        rawText: String?,
    ): SharedInboundNote? {
        val cleanedText = rawText?.trim().orEmpty()
        if (cleanedText.isEmpty()) return null

        val explicitSubject = rawSubject?.trim()?.takeIf { it.isNotEmpty() }
        val derivedSubject = explicitSubject ?: cleanedText
            .lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() }
            ?.let { firstLine ->
                if (firstLine.startsWith("http://") || firstLine.startsWith("https://")) {
                    "分享链接摘录"
                } else {
                    firstLine.take(40)
                }
            }

        return SharedInboundNote(
            mimeType = mimeType?.trim()?.takeIf { it.isNotEmpty() } ?: "text/plain",
            subject = derivedSubject,
            text = cleanedText,
        )
    }

    fun formatDeviceModelLabel(
        manufacturer: String?,
        model: String?,
        androidRelease: String?,
    ): String {
        val cleanMfg = manufacturer?.trim().orEmpty()
        val cleanModel = model?.trim().orEmpty()
        val baseName = when {
            cleanModel.isEmpty() && cleanMfg.isEmpty() -> "Android Phone"
            cleanMfg.isEmpty() -> cleanModel
            cleanModel.startsWith(cleanMfg, ignoreCase = true) ->
                cleanModel.replaceFirstChar { if (it.isLowerCase()) it.titlecase() else it.toString() }
            else -> {
                val titledMfg = cleanMfg.replaceFirstChar {
                    if (it.isLowerCase()) it.titlecase() else it.toString()
                }
                "$titledMfg $cleanModel"
            }
        }
        val cleanRel = androidRelease?.trim()?.takeIf { it.isNotEmpty() }
        return if (cleanRel != null) {
            "$baseName · Android $cleanRel"
        } else {
            baseName
        }
    }

    fun parsePairingDeepLink(rawUri: String?): PairingUriConfig? {
        val trimmed = rawUri?.trim().orEmpty()
        if (!trimmed.startsWith("privatespace://", ignoreCase = true)) return null
        return try {
            val uri = URI(trimmed)
            if (!uri.host.equals("pair", ignoreCase = true)) return null
            val queryPairs = uri.rawQuery
                ?.split('&')
                ?.mapNotNull { pair ->
                    val idx = pair.indexOf('=')
                    if (idx <= 0) null
                    else {
                        val k = URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8)
                        val v = URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8)
                        k to v
                    }
                }
                ?.toMap()
                .orEmpty()

            val server = queryPairs["server"]?.trim()?.trimEnd('/').orEmpty()
            if (!server.startsWith("http://") && !server.startsWith("https://")) {
                return null
            }
            val vault = queryPairs["vault"]?.trim()?.takeIf { it.isNotEmpty() }
            PairingUriConfig(serverUrl = server, vaultLabel = vault)
        } catch (_: Exception) {
            null
        }
    }
}
