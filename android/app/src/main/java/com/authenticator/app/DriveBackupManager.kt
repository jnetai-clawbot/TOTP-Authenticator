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
 * Manages encrypted backup to Google Drive using the Drive API v3.
 * No Firebase dependency — uses raw Google Sign-In + Drive scope.
 */
class DriveBackupManager(private val context: Context) {

    companion object {
        private const val TAG = "DriveBackup"
        private const val BACKUP_FILE_NAME = "totp-backup.enc"
        private const val BACKUP_MIME_TYPE = "application/octet-stream"
        private const val BACKUP_FOLDER_NAME = "AuthenticatorBackups"
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
                // The secrets in the DB are encrypted with Android KeyStore.
                // We need to decrypt them first.
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

                // Encrypt secret with local Android KeyStore before storing
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

                // Avoid duplicates with same name
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

    // ---- Drive API Operations ----

    /**
     * Uploads an encrypted backup string to Google Drive as "totp-backup.enc".
     * Scoped to the authenticated account from the Drive service.
     *
     * Uses manual HTTP requests against the Drive API v3 since we don't have
     * the google-api-client dependency. This is cleaner than adding the full
     * client library which has many transitive dependencies.
     */
    fun uploadToDrive(accessToken: String, encryptedContent: String): Boolean {
        return try {
            // 1. Search for existing backup to get its file ID
            val existingId = findExistingBackupFileId(accessToken)

            // 2. If exists, delete it (Drive API v3 - update requires full metadata too)
            if (existingId != null) {
                deleteFile(accessToken, existingId)
            }

            // 3. Upload new file
            uploadFile(accessToken, encryptedContent)
            true
        } catch (e: Exception) {
            Log.e(TAG, "Upload to Drive failed", e)
            false
        }
    }

    /**
     * Downloads the encrypted backup from Google Drive.
     * Returns the encrypted content as a Base64 string, or null if no backup exists.
     */
    fun downloadFromDrive(accessToken: String): String? {
        return try {
            val fileId = findExistingBackupFileId(accessToken) ?: return null
            downloadFile(accessToken, fileId)
        } catch (e: Exception) {
            Log.e(TAG, "Download from Drive failed", e)
            null
        }
    }

    /**
     * Checks if a backup file exists on Drive.
     */
    fun backupExists(accessToken: String): Boolean {
        return try {
            findExistingBackupFileId(accessToken) != null
        } catch (e: Exception) {
            Log.e(TAG, "Failed to check backup existence", e)
            false
        }
    }

    // ---- Internal Drive API v3 HTTP Methods ----

    private fun findExistingBackupFileId(accessToken: String): String? {
        val url = "https://www.googleapis.com/drive/v3/files" +
                "?q=name='$BACKUP_FILE_NAME' and trashed=false" +
                "&fields=files(id,name)" +
                "&pageSize=1"

        val json = executeGet(url, accessToken)
        val files = json.optJSONArray("files")
        if (files != null && files.length() > 0) {
            return files.getJSONObject(0).getString("id")
        }
        return null
    }

    private fun uploadFile(accessToken: String, content: String): String? {
        val metadataUrl = "https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart"

        val boundary = "Boundary_${System.currentTimeMillis()}"
        val lineEnd = "\r\n"

        val bodyBuilder = StringBuilder()
        // Metadata part
        bodyBuilder.append("--$boundary$lineEnd")
        bodyBuilder.append("Content-Type: application/json; charset=UTF-8$lineEnd$lineEnd")
        bodyBuilder.append("{\"name\":\"$BACKUP_FILE_NAME\",\"mimeType\":\"$BACKUP_MIME_TYPE\"}$lineEnd")
        // Content part
        bodyBuilder.append("--$boundary$lineEnd")
        bodyBuilder.append("Content-Type: $BACKUP_MIME_TYPE$lineEnd$lineEnd")
        bodyBuilder.append(content)
        bodyBuilder.append(lineEnd)
        bodyBuilder.append("--$boundary--$lineEnd")

        val bodyBytes = bodyBuilder.toString().toByteArray(Charsets.UTF_8)
        val contentType = "multipart/related; boundary=$boundary"

        val result = executePostBytes(metadataUrl, accessToken, contentType, bodyBytes)
        return result.optString("id", null)
    }

    private fun downloadFile(accessToken: String, fileId: String): String {
        val url = "https://www.googleapis.com/drive/v3/files/$fileId?alt=media"
        return executeGetRaw(url, accessToken)
    }

    private fun deleteFile(accessToken: String, fileId: String): Boolean {
        val url = "https://www.googleapis.com/drive/v3/files/$fileId"
        executeDelete(url, accessToken)
        return true
    }

    // ---- HTTP Helpers ----

    private fun executeGet(url: String, accessToken: String): JSONObject {
        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        conn.requestMethod = "GET"
        conn.setRequestProperty("Authorization", "Bearer $accessToken")
        conn.connect()

        try {
            val reader = BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8))
            val response = reader.readText()
            reader.close()
            return JSONObject(response)
        } catch (e: Exception) {
            // Try reading error stream
            try {
                val reader = BufferedReader(InputStreamReader(conn.errorStream, Charsets.UTF_8))
                val error = reader.readText()
                reader.close()
                Log.e(TAG, "GET error response: $error")
            } catch (_: Exception) {}
            throw e
        } finally {
            conn.disconnect()
        }
    }

    private fun executeGetRaw(url: String, accessToken: String): String {
        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        conn.requestMethod = "GET"
        conn.setRequestProperty("Authorization", "Bearer $accessToken")
        conn.connect()

        try {
            val reader = BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8))
            val response = reader.readText()
            reader.close()
            return response
        } catch (e: Exception) {
            try {
                val reader = BufferedReader(InputStreamReader(conn.errorStream, Charsets.UTF_8))
                val error = reader.readText()
                reader.close()
                Log.e(TAG, "GET raw error response: $error")
            } catch (_: Exception) {}
            throw e
        } finally {
            conn.disconnect()
        }
    }

    private fun executePostBytes(
        url: String,
        accessToken: String,
        contentType: String,
        body: ByteArray
    ): JSONObject {
        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        conn.requestMethod = "POST"
        conn.doOutput = true
        conn.setRequestProperty("Authorization", "Bearer $accessToken")
        conn.setRequestProperty("Content-Type", contentType)
        if (android.os.Build.VERSION.SDK_INT >= 24) {
            conn.setFixedLengthStreamingMode(body.size)
        } else {
            conn.setChunkedStreamingMode(0)
        }
        conn.connect()

        try {
            conn.outputStream.use { it.write(body) }
            val reader = BufferedReader(InputStreamReader(conn.inputStream, Charsets.UTF_8))
            val response = reader.readText()
            reader.close()
            return JSONObject(response)
        } catch (e: Exception) {
            try {
                val reader = BufferedReader(InputStreamReader(conn.errorStream, Charsets.UTF_8))
                val error = reader.readText()
                reader.close()
                Log.e(TAG, "POST error response: $error")
            } catch (_: Exception) {}
            throw e
        } finally {
            conn.disconnect()
        }
    }

    private fun executeDelete(url: String, accessToken: String) {
        val conn = java.net.URL(url).openConnection() as java.net.HttpURLConnection
        conn.requestMethod = "DELETE"
        conn.setRequestProperty("Authorization", "Bearer $accessToken")
        conn.connect()
        conn.responseCode // Consume response
        conn.disconnect()
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
