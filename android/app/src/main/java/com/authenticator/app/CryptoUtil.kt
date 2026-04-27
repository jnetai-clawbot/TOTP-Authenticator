package com.authenticator.app

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom
import java.security.spec.KeySpec
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cryptographic utilities for master password and backup encryption.
 * Uses PBKDF2 for key derivation and AES-256-GCM for encryption.
 */
object CryptoUtil {

    private const val PBKDF2_ALGORITHM = "PBKDF2WithHmacSHA256"
    private const val AES_ALGORITHM = "AES/GCM/NoPadding"
    private const val GCM_TAG_LENGTH = 128 // bits
    private const val GCM_IV_LENGTH = 12 // bytes
    private const val PBKDF2_ITERATIONS = 100_000
    private const val KEY_LENGTH = 256 // bits
    private const val SALT_LENGTH = 16 // bytes

    private const val PREFS_NAME = "totp_auth_prefs"
    private const val KEY_SALT = "password_salt"
    private const val KEY_HASH = "password_hash"
    private const val KEY_HAS_PASSWORD = "has_password"

    private var encryptedPrefs: SharedPreferences? = null

    /**
     * Initializes EncryptedSharedPreferences for storing password metadata.
     */
    fun init(context: Context) {
        try {
            val masterKey = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()

            encryptedPrefs = EncryptedSharedPreferences.create(
                context,
                PREFS_NAME,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            )
        } catch (e: Exception) {
            android.util.Log.e("CryptoUtil", "Failed to init EncryptedSharedPreferences", e)
        }
    }

    private fun getPrefs(): SharedPreferences {
        return encryptedPrefs
            ?: throw IllegalStateException("CryptoUtil not initialized. Call init(context) first.")
    }

    // ---- Master Password ----

    /**
     * Returns true if a master password has already been set.
     */
    fun hasPassword(): Boolean {
        return getPrefs().getBoolean(KEY_HAS_PASSWORD, false)
    }

    /**
     * Sets a new master password: derives a salt, hashes the password, and stores the salt + hash.
     */
    fun setPassword(password: String) {
        val salt = ByteArray(SALT_LENGTH).also { SecureRandom().nextBytes(it) }
        val saltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP)
        val hash = hashPassword(password, salt)

        val prefs = getPrefs()
        prefs.edit()
            .putString(KEY_SALT, saltBase64)
            .putString(KEY_HASH, hash)
            .putBoolean(KEY_HAS_PASSWORD, true)
            .apply()
    }

    /**
     * Verifies a password against the stored hash.
     */
    fun verifyPassword(password: String): Boolean {
        val prefs = getPrefs()
        val saltBase64 = prefs.getString(KEY_SALT, null) ?: return false
        val storedHash = prefs.getString(KEY_HASH, null) ?: return false

        val salt = Base64.decode(saltBase64, Base64.NO_WRAP)
        val computedHash = hashPassword(password, salt)
        return computedHash == storedHash
    }

    /**
     * Changes the master password. Re-encrypts the salt+hash with the new password.
     */
    fun changePassword(oldPassword: String, newPassword: String): Boolean {
        if (!verifyPassword(oldPassword)) return false
        setPassword(newPassword)
        return true
    }

    /**
     * Derives an AES-256 key from the master password using PBKDF2.
     */
    fun deriveKey(password: String): SecretKey {
        val prefs = getPrefs()
        val saltBase64 = prefs.getString(KEY_SALT, null)
            ?: throw IllegalStateException("No salt found. Password not set.")

        val salt = Base64.decode(saltBase64, Base64.NO_WRAP)
        val spec: KeySpec = PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH)
        val factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM)
        return SecretKeySpec(factory.generateSecret(spec).encoded, "AES")
    }

    // ---- Encryption/Decryption with Password-Derived Key ----

    /**
     * Encrypts plaintext using AES-256-GCM with a key derived from the master password.
     * Returns Base64-encoded ciphertext (IV + encrypted data).
     */
    fun encryptWithPassword(password: String, plaintext: String): String {
        val key = deriveKey(password)
        val cipher = Cipher.getInstance(AES_ALGORITHM)
        cipher.init(Cipher.ENCRYPT_MODE, key)

        val iv = cipher.iv
        val encrypted = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        val combined = iv + encrypted
        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    /**
     * Decrypts Base64-encoded ciphertext (IV + encrypted data) using a key derived from
     * the master password.
     */
    fun decryptWithPassword(password: String, ciphertextBase64: String): String {
        val key = deriveKey(password)
        val combined = Base64.decode(ciphertextBase64, Base64.NO_WRAP)

        if (combined.size < GCM_IV_LENGTH + 1) {
            throw IllegalArgumentException("Ciphertext too short")
        }

        val iv = combined.copyOfRange(0, GCM_IV_LENGTH)
        val encrypted = combined.copyOfRange(GCM_IV_LENGTH, combined.size)

        val cipher = Cipher.getInstance(AES_ALGORITHM)
        val spec = GCMParameterSpec(GCM_TAG_LENGTH, iv)
        cipher.init(Cipher.DECRYPT_MODE, key, spec)

        return String(cipher.doFinal(encrypted), Charsets.UTF_8)
    }

    // ---- Helpers ----

    /**
     * Hashes a password with a salt using SHA-256, returning a Base64-encoded hash.
     */
    private fun hashPassword(password: String, salt: ByteArray): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        digest.update(salt)
        val hash = digest.digest(password.toByteArray(Charsets.UTF_8))
        return Base64.encodeToString(hash, Base64.NO_WRAP)
    }

    /**
     * Wipes the stored password metadata (for factory reset or password removal).
     */
    fun clearPasswordData() {
        val prefs = getPrefs()
        prefs.edit()
            .remove(KEY_SALT)
            .remove(KEY_HASH)
            .putBoolean(KEY_HAS_PASSWORD, false)
            .apply()
    }
}
