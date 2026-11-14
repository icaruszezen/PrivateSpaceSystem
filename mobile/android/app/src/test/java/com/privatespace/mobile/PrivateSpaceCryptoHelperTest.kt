package com.privatespace.mobile

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.SecureRandom

class PrivateSpaceCryptoHelperTest {

    @Test
    fun keystoreEnvelopeRoundTripsRandomAesGcmBytes() {
        val rng = SecureRandom()
        val iv = ByteArray(12).also { rng.nextBytes(it) }
        val ciphertext = ByteArray(64).also { rng.nextBytes(it) }

        val encoded = PrivateSpaceCryptoHelper.encodeKeystoreEnvelope(iv, ciphertext)
        assertTrue(encoded.startsWith("v1."))

        val decoded = PrivateSpaceCryptoHelper.decodeKeystoreEnvelope(encoded)
        assertNotNull(decoded)
        assertArrayEquals(iv, decoded!!.first)
        assertArrayEquals(ciphertext, decoded.second)
    }

    @Test
    fun keystoreEnvelopeRejectsTamperedOrWrongIvPayloads() {
        assertNull(PrivateSpaceCryptoHelper.decodeKeystoreEnvelope(null))
        assertNull(PrivateSpaceCryptoHelper.decodeKeystoreEnvelope(""))
        assertNull(PrivateSpaceCryptoHelper.decodeKeystoreEnvelope("v2.aaaa.bbbb"))
        assertNull(PrivateSpaceCryptoHelper.decodeKeystoreEnvelope("v1.short_iv.cGF5bG9hZA"))
        assertNull(PrivateSpaceCryptoHelper.decodeKeystoreEnvelope("v1.not-valid-b64!!!.cGF5bG9hZA"))
    }

    @Test
    fun clipboardDigestMatchesExactSecretAndSparesUnrelatedCopies() {
        val secret = "JBSWY3DPEHPK3PXP-942817"
        val digest = PrivateSpaceCryptoHelper.sha256Hex(secret)
        assertEquals(64, digest.length)

        assertTrue(PrivateSpaceCryptoHelper.matchesClipboardDigest(digest, secret))
        assertFalse(
            PrivateSpaceCryptoHelper.matchesClipboardDigest(
                digest,
                "User copied another normal message 10 seconds later",
            ),
        )
        assertFalse(PrivateSpaceCryptoHelper.matchesClipboardDigest(digest, null))
    }

    @Test
    fun inboundShareNormalizerHandlesUrlsAndChineseText() {
        val urlShare = PrivateSpaceCryptoHelper.normalizeInboundShare(
            mimeType = "text/plain",
            rawSubject = null,
            rawText = "  https://nas.homelab.local:8443/docs  ",
        )
        assertNotNull(urlShare)
        assertEquals("分享链接摘录", urlShare!!.subject)
        assertEquals("https://nas.homelab.local:8443/docs", urlShare.text)

        val noteShare = PrivateSpaceCryptoHelper.normalizeInboundShare(
            mimeType = "text/plain",
            rawSubject = "家庭宽带光猫超级密码",
            rawText = "CUAdmin / CUAdmin839201",
        )
        assertNotNull(noteShare)
        assertEquals("家庭宽带光猫超级密码", noteShare!!.subject)
        assertEquals("CUAdmin / CUAdmin839201", noteShare.text)

        assertNull(PrivateSpaceCryptoHelper.normalizeInboundShare("text/plain", null, "   "))
    }

    @Test
    fun deviceModelFormatterAvoidsDuplicateManufacturerPrefix() {
        assertEquals(
            "Xiaomi 2410DPN6CC · Android 15",
            PrivateSpaceCryptoHelper.formatDeviceModelLabel("Xiaomi", "2410DPN6CC", "15"),
        )
        assertEquals(
            "Samsung SM-S9280 · Android 14",
            PrivateSpaceCryptoHelper.formatDeviceModelLabel("samsung", "Samsung SM-S9280", "14"),
        )
    }

    @Test
    fun pairingDeepLinkExtractsServerAndVaultName() {
        val parsed = PrivateSpaceCryptoHelper.parsePairingDeepLink(
            "privatespace://pair?server=https%3A%2F%2Fvault.lan%3A8080%2F&vault=%E5%AE%B6%E5%BA%AD%E7%A7%81%E5%AF%86%E4%BA%91",
        )
        assertNotNull(parsed)
        assertEquals("https://vault.lan:8080", parsed!!.serverUrl)
        assertEquals("家庭私密云", parsed.vaultLabel)

        assertNull(PrivateSpaceCryptoHelper.parsePairingDeepLink("https://example.com"))
        assertNull(PrivateSpaceCryptoHelper.parsePairingDeepLink("privatespace://pair?server=ftp://bad"))
    }
}
