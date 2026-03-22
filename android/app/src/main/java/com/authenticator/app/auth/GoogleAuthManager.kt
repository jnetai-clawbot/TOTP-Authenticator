package com.authenticator.app.auth

import android.content.Context
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInAccount
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.Scope
import com.google.api.client.googleapis.extensions.android.gms.auth.GoogleAccountCredential
import com.google.api.services.oauth2.Oauth2
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

class GoogleAuthManager(private val context: Context) {
    
    private var googleSignInClient: GoogleSignInClient? = null
    private var currentAccount: GoogleSignInAccount? = null
    
    fun initialize() {
        val gso = GoogleSignInOptions.Builder(GoogleSignInOptions.DEFAULT_SIGN_IN)
            .requestEmail()
            .requestProfile()
            .requestScopes(Scope("https://www.googleapis.com/auth/userinfo.email"))
            .build()
        
        googleSignInClient = GoogleSignIn.getClient(context, gso)
    }
    
    fun getSignInClient(): GoogleSignInClient {
        return googleSignInClient ?: throw IllegalStateException("Not initialized")
    }
    
    fun getLastSignedInAccount(): GoogleSignInAccount? {
        return GoogleSignIn.getLastSignedInAccount(context)
    }
    
    fun isSignedIn(): Boolean {
        return getLastSignedInAccount() != null
    }
    
    fun getAccessToken(): String? {
        return currentAccount?.idToken
    }
    
    fun getUserEmail(): String? {
        return currentAccount?.email
    }
    
    fun getUserName(): String? {
        return currentAccount?.displayName
    }
    
    suspend fun refreshToken(): String? = withContext(Dispatchers.IO) {
        try {
            val account = getLastSignedInAccount() ?: return@withContext null
            
            // Note: In production, you'd use Proximity Auth or similar
            // for seamless authentication without password prompt
            
            // For now, return the cached token
            return@withContext account.idToken
        } catch (e: Exception) {
            null
        }
    }
    
    fun signOut(onComplete: () -> Unit) {
        googleSignInClient?.signInIntent?.let {
            // Just clear local data - actual sign out happens via re-authentication
            currentAccount = null
            onComplete()
        }
    }
    
    /**
     * Hash the user's password for local verification
     * Uses SHA-256 as specified in requirements
     */
    fun hashPassword(password: String): String {
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(password.toByteArray())
        return hash.joinToString("") { "%02x".format(it) }
    }
    
    /**
     * Store password hash locally (NOT the actual password)
     * This is used for local app lock, not for OAuth
     */
    fun storePasswordHash(password: String): Boolean {
        val prefs = context.getSharedPreferences("auth_prefs", Context.MODE_PRIVATE)
        val hash = hashPassword(password)
        return prefs.edit().putString("password_hash", hash).commit()
    }
    
    /**
     * Verify password against stored hash
     */
    fun verifyPassword(password: String): Boolean {
        val prefs = context.getSharedPreferences("auth_prefs", Context.MODE_PRIVATE)
        val storedHash = prefs.getString("password_hash", null) ?: return false
        return hashPassword(password) == storedHash
    }
    
    /**
     * Check if password is set up
     */
    fun isPasswordSetUp(): Boolean {
        val prefs = context.getSharedPreferences("auth_prefs", Context.MODE_PRIVATE)
        return prefs.contains("password_hash")
    }
}
