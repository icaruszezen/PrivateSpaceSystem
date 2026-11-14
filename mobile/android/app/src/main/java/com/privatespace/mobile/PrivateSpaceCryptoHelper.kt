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

    /**
     * Constant-time SHA-256 verification for downloaded APK update packages.
     * If expectedSha256 is null/blank, returns true (optional checksum); if present, must be valid 64-hex and match.
     */
    fun verifyApkSha256(expectedSha256: String?, actualSha256: String): Boolean {
        val cleanExpected = expectedSha256?.trim()?.lowercase().orEmpty()
        if (cleanExpected.isEmpty()) return true
        if (cleanExpected.length != 64 || actualSha256.length != 64) return false
        if (!cleanExpected.all { it in '0'..'9' || it in 'a'..'f' }) return false
        return MessageDigest.isEqual(
            cleanExpected.toByteArray(StandardCharsets.US_ASCII),
            actualSha256.trim().lowercase().toByteArray(StandardCharsets.US_ASCII),
        )
    }

    fun sanitizeApkFileName(versionName: String?): String {
        val cleaned = versionName
            ?.trim()
            ?.removePrefix("v")
            ?.removePrefix("V")
            ?.replace(Regex("[^A-Za-z0-9._-]"), "_")
            ?.take(32)
            ?.takeIf { it.isNotEmpty() }
            ?: "latest"
        return "PrivateSpace-v$cleaned.apk"
    }

    /**
     * Pure SemVer 2.0 comparator (1 if a > b, -1 if a < b, 0 if equal).
     */
    fun compareSemver(a: String?, b: String?): Int {
        val pa = parseSemverParts(a)
        val pb = parseSemverParts(b)
        if (pa == null && pb == null) return 0
        if (pa == null) return -1
        if (pb == null) return 1

        if (pa.first[0] != pb.first[0]) return if (pa.first[0] > pb.first[0]) 1 else -1
        if (pa.first[1] != pb.first[1]) return if (pa.first[1] > pb.first[1]) 1 else -1
        if (pa.first[2] != pb.first[2]) return if (pa.first[2] > pb.first[2]) 1 else -1

        val preA = pa.second
        val preB = pb.second
        if (preA.isEmpty() && preB.isEmpty()) return 0
        if (preA.isEmpty()) return 1
        if (preB.isEmpty()) return -1

        val maxLen = maxOf(preA.size, preB.size)
        for (i in 0 until maxLen) {
            val idA = preA.getOrNull(i) ?: return -1
            val idB = preB.getOrNull(i) ?: return 1
            if (idA == idB) continue
            val numA = idA.toLongOrNull()
            val numB = idB.toLongOrNull()
            if (numA != null && numB != null) return if (numA > numB) 1 else -1
            if (numA != null) return -1
            if (numB != null) return 1
            return if (idA > idB) 1 else -1
        }
        return 0
    }

    private fun parseSemverParts(raw: String?): Pair<IntArray, List<String>>? {
        val trimmed = raw?.trim()?.removePrefix("v")?.removePrefix("V")?.substringBefore('+') ?: return null
        if (trimmed.isEmpty()) return null
        val core = trimmed.substringBefore('-')
        val pre = if ('-' in trimmed) trimmed.substringAfter('-').split('.').filter { it.isNotEmpty() } else emptyList()
        val nums = core.split('.')
        if (nums.size < 2 || nums.size > 3) return null
        val major = nums[0].toIntOrNull() ?: return null
        val minor = nums[1].toIntOrNull() ?: return null
        val patch = if (nums.size == 3) (nums[2].toIntOrNull() ?: return null) else 0
        if (major < 0 || minor < 0 || patch < 0) return null
        return IntArray(3).apply {
            this[0] = major
            this[1] = minor
            this[2] = patch
        } to pre
    }
}
