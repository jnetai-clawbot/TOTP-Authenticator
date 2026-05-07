package com.authenticator.app

import android.content.Context
import android.net.Uri
import android.util.Log
import com.authenticator.app.db.Site
import com.authenticator.app.db.SiteDatabase
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.UUID

/**
 * Manages encrypted backup to a user-chosen location via the Storage Access Framework.
 * No Google API keys or Cloud Console required — uses the system file picker so users
 * can save/load from Google Drive, Dropbox, local storage, etc.
 */
class DriveBackupManager(private val context: Context) {

    companion object {
        private const val TAG = "BackupManager"
        private const val BACKUP_MIME_TYPE = "application/octet-stream"
    }

    private val database by lazy { SiteDatabase.getInstance(context) }

    /**
     * Builds a JSON backup of all TOTP sites and encrypts it with the master password.
     */
    fun buildBackupJson(password: String): String {
        val sites = database.siteDao().getAll()

        val entries = JSONArray()
        for (site in sites) {
            val secret = try {
                decryptSiteSecret(site.secret)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to decrypt secret for ${site.name}", e)
                continue
            }

            entries.put(JSONObject().apply {
                put("name", site.name)
                put("secret", secret)
                put("issuer", site.issuer)
                put("digits", site.digits)
                put("period", site.period)
                put("algorithm", site.algorithm)
            })
        }

        val json = JSONObject().apply {
            put("version", 1)
            put("exportedAt", SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.UK).format(Date()))
            put("entries", entries)
        }

        val plaintext = json.toString(2)
        return CryptoUtil.encryptWithPassword(password, plaintext)
    }

    /**
     * Decrypts a backup and imports all sites into the local database.
     * Returns the number of sites imported.
     */
    fun restoreFromBackup(password: String, encryptedBase64: String): Int {
        val plaintext = CryptoUtil.decryptWithPassword(password, encryptedBase64)
        val json = JSONObject(plaintext)
        val entries = json.getJSONArray("entries")

        var imported = 0
        for (i in 0 until entries.length()) {
            try {
                val obj = entries.getJSONObject(i)
                val name = obj.getString("name")
                val secret = obj.getString("secret")
                val encryptedSecret = encryptSiteSecret(secret)

                val site = Site(
                    id = UUID.randomUUID().toString(),
                    name = name,
                    secret = encryptedSecret,
                    issuer = obj.optString("issuer", ""),
                    digits = obj.optInt("digits", 6),
                    period = obj.optInt("period", 30),
                    algorithm = obj.optString("algorithm", "SHA1"),
                    enabled = true,
                    createdAt = System.currentTimeMillis()
                )

                val existing = database.siteDao().getAll().find { it.name == site.name }
                if (existing == null) {
                    database.siteDao().insert(site)
                    imported++
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to import entry $i", e)
            }
        }
        return imported
    }

    // ---- Drive API Operations (replaced by SAF file picker — kept for compat) ----

    fun uploadToDrive(accessToken: String, encryptedContent: String): Boolean {
        Log.w(TAG, "Drive API upload not available — use SAF file picker instead")
        return false
    }

    fun downloadFromDrive(accessToken: String): String? {
        Log.w(TAG, "Drive API download not available — use SAF file picker instead")
        return null
    }

    fun backupExists(accessToken: String): Boolean {
        return false
    }

    // ---- Delegate to existing encrypt/decrypt in MainActivity-style KeyStore ----

    private fun decryptSiteSecret(encrypted: String): String {
        return try {
            val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val key = keyStore.getEntry("totp_key", null)
            if (key !is java.security.KeyStore.SecretKeyEntry) {
                return try { String(android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)) } catch (_: Exception) { "" }
            }
            val secretKey = key.secretKey
            val combined = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)
            if (combined.size < 13) return String(android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP))
            val iv = combined.copyOfRange(0, 12)
            val encryptedBytes = combined.copyOfRange(12, combined.size)
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            val spec = javax.crypto.spec.GCMParameterSpec(128, iv)
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, secretKey, spec)
            String(cipher.doFinal(encryptedBytes))
        } catch (e: Exception) {
            Log.w(TAG, "decryptSiteSecret failed", e)
            try { String(android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)) } catch (_: Exception) { "" }
        }
    }

    private fun encryptSiteSecret(secret: String): String {
        return try {
            val keyStore = java.security.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val key: java.security.KeyStore.SecretKeyEntry? =
                keyStore.getEntry("totp_key", null) as? java.security.KeyStore.SecretKeyEntry
            val secretKey: javax.crypto.SecretKey = key?.secretKey
                ?: throw Exception("Key not found")
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, secretKey)
            val encrypted = cipher.doFinal(secret.toByteArray())
            val iv = cipher.iv
            val combined = iv + encrypted
            android.util.Base64.encodeToString(combined, android.util.Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e(TAG, "encryptSiteSecret failed", e)
            android.util.Base64.encodeToString(secret.toByteArray(), android.util.Base64.NO_WRAP)
        }
    }
}
