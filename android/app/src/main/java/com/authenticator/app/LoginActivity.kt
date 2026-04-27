package com.authenticator.app

import android.accounts.AccountManager
import android.content.Intent
import android.os.Bundle
import android.text.TextUtils
import android.view.View
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import com.authenticator.app.databinding.ActivityLoginBinding
import com.google.android.gms.auth.api.signin.GoogleSignIn
import com.google.android.gms.auth.api.signin.GoogleSignInClient
import com.google.android.gms.auth.api.signin.GoogleSignInOptions
import com.google.android.gms.common.api.Scope

class LoginActivity : AppCompatActivity() {

    private lateinit var binding: ActivityLoginBinding
    private var isSettingPassword: Boolean = false

    companion object {
        private const val TAG = "LoginActivity"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityLoginBinding.inflate(layoutInflater)
        setContentView(binding.root)

        // Determine mode: first launch (set password) or unlock
        isSettingPassword = !CryptoUtil.hasPassword()

        setupUI()
        setupClickListeners()
    }

    private fun setupUI() {
        if (isSettingPassword) {
            binding.tvSubtitle.text = getString(com.authenticator.app.R.string.set_password_title)
            binding.btnAction.text = getString(com.authenticator.app.R.string.set_password_action)
            binding.inputLayoutConfirmPassword.visibility = View.VISIBLE
        } else {
            binding.tvSubtitle.text = getString(com.authenticator.app.R.string.unlock_title)
            binding.btnAction.text = getString(com.authenticator.app.R.string.unlock_action)
            binding.inputLayoutConfirmPassword.visibility = View.GONE
        }
    }

    private fun setupClickListeners() {
        binding.btnAction.setOnClickListener {
            safeCall("action") { handleAction() }
        }
    }

    private fun handleAction() {
        val password = binding.etPassword.text.toString()

        if (TextUtils.isEmpty(password)) {
            showError(getString(com.authenticator.app.R.string.error_password_required))
            return
        }

        if (isSettingPassword) {
            val confirmPassword = binding.etConfirmPassword.text.toString()
            if (password != confirmPassword) {
                showError(getString(com.authenticator.app.R.string.error_passwords_mismatch))
                return
            }
            if (password.length < 4) {
                showError(getString(com.authenticator.app.R.string.error_password_too_short))
                return
            }
            setPassword(password)
        } else {
            verifyPassword(password)
        }
    }

    private fun setPassword(password: String) {
        try {
            CryptoUtil.setPassword(password)
            proceedToMain()
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to set password", e)
            showError("Failed to set password: ${e.message}")
        }
    }

    private fun verifyPassword(password: String) {
        try {
            if (CryptoUtil.verifyPassword(password)) {
                proceedToMain()
            } else {
                binding.etPassword.text?.clear()
                showError(getString(com.authenticator.app.R.string.error_wrong_password))
            }
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to verify password", e)
            showError("Error: ${e.message}")
        }
    }

    private fun proceedToMain() {
        val intent = Intent(this, MainActivity::class.java)
        intent.putExtra("master_password", binding.etPassword.text.toString())
        startActivity(intent)
        finish()
    }

    private fun showError(message: String) {
        binding.tvError.text = message
        binding.tvError.visibility = View.VISIBLE
    }

    private fun safeCall(tag: String, block: () -> Unit) {
        try {
            block()
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Error in $tag", e)
            Toast.makeText(this, "Error: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }

    /**
     * Called when the user presses back during password setup.
     * We disable back press during initial setup to force password creation.
     */
    override fun onBackPressed() {
        if (isSettingPassword) {
            // First launch — must set a password. Don't allow back.
            Toast.makeText(
                this,
                getString(com.authenticator.app.R.string.password_required_message),
                Toast.LENGTH_SHORT
            ).show()
        } else {
            super.onBackPressed()
        }
    }
}
