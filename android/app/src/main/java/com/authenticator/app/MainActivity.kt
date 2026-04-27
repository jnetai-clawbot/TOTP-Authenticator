package com.authenticator.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.util.Base64
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.authenticator.app.databinding.ActivityMainBinding
import com.authenticator.app.databinding.DialogAddSiteBinding
import com.authenticator.app.databinding.DialogEditSiteBinding
import com.authenticator.app.db.Site
import com.authenticator.app.db.SiteDatabase
import com.authenticator.app.totp.TOTPGenerator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import java.security.KeyStore

class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var database: SiteDatabase
    private lateinit var totpGenerator: TOTPGenerator
    private lateinit var adapter: SitesAdapter
    private lateinit var driveBackupManager: DriveBackupManager

    private var currentCodes = mutableMapOf<String, Pair<String, Int>>()
    private var isRefreshing = false

    // Master password passed from LoginActivity
    private var masterPassword: String = ""

    private var currentAccountName: String? = null
    private var currentAccessToken: String? = null

    private companion object {
        private const val DRIVE_SCOPE = "https://www.googleapis.com/auth/drive.file"
    }
    
    private val importFileLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? -> uri?.let { safeCall("import") { importFromUri(it) } } }
    
    private val exportFileLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri: Uri? -> uri?.let { safeCall("export") { exportToUri(it) } } }

    private val accountPickerLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        safeCall("accountPickerResult") {
            val accountEmail = result.data?.getStringExtra(android.accounts.AccountManager.KEY_ACCOUNT_NAME)
            if (accountEmail != null) {
                currentAccountName = accountEmail
                getDriveToken(accountEmail)
                updateGoogleSignInCard()
                showToast("Signed in as $accountEmail")
                showBackupRestoreDialog()
            } else {
                showToast("Sign in cancelled")
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        try {
            super.onCreate(savedInstanceState)
            binding = ActivityMainBinding.inflate(layoutInflater)
            setContentView(binding.root)

            // Retrieve master password from LoginActivity
            masterPassword = intent.getStringExtra("master_password") ?: ""

            database = SiteDatabase.getInstance(this)
            totpGenerator = TOTPGenerator()
            driveBackupManager = DriveBackupManager(this)

            initAccountManager()

            setupRecyclerView()
            setupClickListeners()
            setupSwipeToDelete()

            loadSites()
            startCodeRefresh()
        } catch (e: Exception) {
            logError("onCreate", e)
            showToast("App failed to start: ${e.message}")
            finish()
        }
    }

    private fun initAccountManager() {
        try {
            val accounts = android.accounts.AccountManager.get(this)
                .getAccountsByType("com.google")
            if (accounts.isNotEmpty()) {
                currentAccountName = accounts[0].name
                getDriveToken(currentAccountName!!)
                updateGoogleSignInCard()
            }
        } catch (e: Exception) {
            logError("initAccountManager", e)
        }
    }

    private fun getDriveToken(accountEmail: String) {
        try {
            val accountManager = android.accounts.AccountManager.get(this)
            val account = android.accounts.Account(accountEmail, "com.google")
            accountManager.getAuthToken(account, DRIVE_SCOPE, null, this,
                { future ->
                    try {
                        val bundle = future.result
                        currentAccessToken = bundle.getString(android.accounts.AccountManager.KEY_AUTHTOKEN)
                        if (currentAccessToken != null) {
                            showToast("Drive access granted")
                        }
                    } catch (e: Exception) {
                        logError("getAuthToken future", e)
                        showToast("Failed to get Drive access: ${e.message}")
                    }
                },
                null
            )
        } catch (e: Exception) {
            logError("getDriveToken", e)
        }
    }
    
    private fun safeCall(tag: String, block: () -> Unit) {
        try { block() } catch (e: Exception) { logError(tag, e); showToast("Error: ${e.message}") }
    }
    
    private fun logError(tag: String, e: Throwable) {
        try {
            android.util.Log.e("Authenticator", "Error in $tag", e)
            val errorFile = File(filesDir, "app_errors.txt")
            val entry = buildString {
                appendLine("[${java.text.SimpleDateFormat("yyyy-MM-dd HH:mm:ss", java.util.Locale.UK).format(java.util.Date())}] $tag")
                appendLine("  ${e.javaClass.name}: ${e.message}")
                for (el in e.stackTrace.take(10)) {
                    appendLine("  at ${el.className}.${el.methodName}(${el.fileName}:${el.lineNumber})")
                }
                e.cause?.let { cause ->
                    appendLine("  Caused by: ${cause.javaClass.name}: ${cause.message}")
                    for (el in cause.stackTrace.take(5)) {
                        appendLine("    at ${el.className}.${el.methodName}(${el.fileName}:${el.lineNumber})")
                    }
                }
                appendLine()
            }
            errorFile.appendText(entry)
        } catch (_: Exception) {}
    }
    
    private fun showToast(msg: String) {
        try { Toast.makeText(this, msg, Toast.LENGTH_SHORT).show() } catch (_: Exception) {}
    }
    
    private fun setupRecyclerView() {
        try {
            adapter = SitesAdapter(
                onCopyClick = { site -> safeCall("copyCode") { copyCode(site.name) } },
                onEditClick = { site -> safeCall("editSite") { showEditDialog(site) } }
            )
            binding.recyclerSites.layoutManager = LinearLayoutManager(this)
            binding.recyclerSites.adapter = adapter
        } catch (e: Exception) {
            logError("setupRecyclerView", e)
        }
    }
    
    private fun setupClickListeners() {
        try {
            binding.fabAddSite.setOnClickListener { showAddDialog() }
            binding.btnGoogleSignIn.setOnClickListener { performGoogleSignIn() }
            updateGoogleSignInCard()

            // Search functionality
            var searchTimer: Job? = null
            binding.etSearch.addTextChangedListener(object : android.text.TextWatcher {
                override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
                override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
                override fun afterTextChanged(s: android.text.Editable?) {
                    searchTimer?.cancel()
                    searchTimer = lifecycleScope.launch {
                        kotlinx.coroutines.delay(300) // debounce
                        val query = s?.toString()?.trim()?.lowercase() ?: ""
                        binding.btnClearSearch.visibility = if (query.isNotEmpty()) android.view.View.VISIBLE else android.view.View.GONE
                        filterSites(query)
                    }
                }
            })
            binding.btnClearSearch.setOnClickListener {
                binding.etSearch.text?.clear()
            }
            // Show search bar if there are sites
            showSearchIfNeeded()
        } catch (e: Exception) {
            logError("setupClickListeners", e)
        }
    }

    private var allSites: List<Site> = emptyList()

    private fun showSearchIfNeeded() {
        try {
            binding.cardSearch.visibility = if (allSites.isNotEmpty()) android.view.View.VISIBLE else android.view.View.GONE
        } catch (e: Exception) {
            logError("showSearchIfNeeded", e)
        }
    }

    private fun filterSites(query: String) {
        try {
            val filtered = if (query.isEmpty()) allSites
            else allSites.filter { it.name.lowercase().contains(query) || it.issuer.lowercase().contains(query) }
            adapter.submitList(filtered)
            binding.tvEmptyState.visibility = if (filtered.isEmpty() && allSites.isNotEmpty())
                android.view.View.VISIBLE else android.view.View.GONE
            if (filtered.isEmpty() && allSites.isNotEmpty()) {
                binding.tvEmptyState.text = "No sites matching \"$query\""
            }
        } catch (e: Exception) {
            logError("filterSites", e)
        }
    }

    private fun updateGoogleSignInCard() {
        try {
            if (currentAccountName != null) {
                binding.tvSignedInAs.text = currentAccountName
                binding.btnGoogleSignIn.text = getString(com.authenticator.app.R.string.sign_out_google)
            } else {
                binding.tvSignedInAs.text = "Not signed in"
                binding.btnGoogleSignIn.text = getString(com.authenticator.app.R.string.sign_in_google)
            }
        } catch (e: Exception) {
            logError("updateGoogleSignInCard", e)
        }
    }

    private fun performGoogleSignIn() {
        try {
            if (currentAccountName != null) {
                showBackupRestoreDialog()
            } else {
                // Show Google account picker (no Firebase needed)
                val intent = android.accounts.AccountManager.newChooseAccountIntent(
                    null, null, arrayOf("com.google"),
                    false, null,
                    null, null, null
                )
                accountPickerLauncher.launch(intent)
            }
        } catch (e: Exception) {
            logError("performGoogleSignIn", e)
        }
    }
    
    private fun setupSwipeToDelete() {
        try {
            val swipeHandler = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.LEFT) {
                override fun onMove(r: RecyclerView, v: RecyclerView.ViewHolder, t: RecyclerView.ViewHolder) = false
                override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                    try {
                        val position = viewHolder.bindingAdapterPosition
                        if (position >= 0) {
                            val site = adapter.currentList[position]
                            showDeleteConfirmation(site)
                        }
                    } catch (e: Exception) {
                        logError("onSwiped", e)
                    }
                }
            }
            ItemTouchHelper(swipeHandler).attachToRecyclerView(binding.recyclerSites)
        } catch (e: Exception) {
            logError("setupSwipeToDelete", e)
        }
    }
    
    private fun loadSites() {
        try {
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val sites = database.siteDao().getAll()
                    allSites = sites
                    withContext(Dispatchers.Main) {
                        try {
                            adapter.submitList(sites)
                            binding.tvEmptyState.visibility = if (sites.isEmpty()) View.VISIBLE else View.GONE
                            binding.recyclerSites.visibility = if (sites.isEmpty()) View.GONE else View.VISIBLE
                            showSearchIfNeeded()
                            // Reload search if there's an active query
                            val currentQuery = binding.etSearch.text?.trim().toString()
                            if (currentQuery.isNotEmpty()) filterSites(currentQuery.lowercase())
                        } catch (e: Exception) {
                            logError("loadSites UI", e)
                        }
                    }
                } catch (e: Exception) {
                    logError("loadSites DB", e)
                }
            }
        } catch (e: Exception) {
            logError("loadSites", e)
        }
    }
    
    private fun startCodeRefresh() {
        lifecycleScope.launch {
            try {
                while (true) {
                    if (!isRefreshing) refreshCodes()
                    delay(1000)
                }
            } catch (e: Exception) {
                logError("codeRefresh loop", e)
            }
        }
    }
    
    private fun refreshCodes() {
        if (isRefreshing) return
        isRefreshing = true
        
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val sites = database.siteDao().getAll()
                val codes = mutableMapOf<String, Pair<String, Int>>()
                
                for (site in sites) {
                    if (site.enabled) {
                        try {
                            val secret = decryptSecret(site.secret)
                            val code = totpGenerator.generate(secret, site.period, site.digits)
                            val remaining = totpGenerator.getTimeRemaining(site.period)
                            codes[site.name] = code to remaining
                        } catch (e: Exception) {
                            logError("refreshCodes site: ${site.name}", e)
                            codes[site.name] = "ERROR" to 0
                        }
                    }
                }
                
                currentCodes = codes
                withContext(Dispatchers.Main) {
                    try { adapter.updateAllCodes(codes) } catch (e: Exception) { logError("updateAllCodes UI", e) }
                }
            } catch (e: Exception) {
                logError("refreshCodes", e)
            } finally {
                isRefreshing = false
            }
        }
    }
    
    private fun copyCode(name: String) {
        try {
            val codePair = currentCodes[name]
            if (codePair != null) {
                val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                val clip = ClipData.newPlainText("TOTP Code", codePair.first)
                clipboard.setPrimaryClip(clip)
                showToast("Code copied for $name")
            }
        } catch (e: Exception) {
            logError("copyCode", e)
        }
    }
    
    private fun showAddDialog() {
        try {
            val dialogBinding = DialogAddSiteBinding.inflate(layoutInflater)
            AlertDialog.Builder(this)
                .setTitle(getString(com.authenticator.app.R.string.add_site))
                .setView(dialogBinding.root)
                .setPositiveButton(getString(com.authenticator.app.R.string.add_site)) { _, _ ->
                    safeCall("addSiteDialog") {
                        val name = dialogBinding.etName.text.toString().trim()
                        val secret = dialogBinding.etSecret.text.toString().uppercase().replace(" ", "")
                        val issuer = dialogBinding.etIssuer.text.toString().trim()
                        if (name.isNotEmpty() && secret.isNotEmpty()) {
                            addSite(name, secret, issuer)
                        } else {
                            showToast(getString(com.authenticator.app.R.string.error_password_required))
                        }
                    }
                }
                .setNegativeButton(getString(com.authenticator.app.R.string.cancel), null)
                .show()
        } catch (e: Exception) {
            logError("showAddDialog", e)
        }
    }
    
    private fun addSite(name: String, secret: String, issuer: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val site = Site(
                    id = UUID.randomUUID().toString(),
                    name = name,
                    secret = encryptSecret(secret),
                    issuer = issuer,
                    digits = 6,
                    period = 30,
                    algorithm = "SHA1",
                    enabled = true,
                    createdAt = System.currentTimeMillis()
                )
                database.siteDao().insert(site)
                withContext(Dispatchers.Main) { loadSites(); showToast("Site added") }
            } catch (e: Exception) {
                logError("addSite", e)
            }
        }
    }
    
    private fun showEditDialog(site: Site) {
        try {
            val dialogBinding = DialogEditSiteBinding.inflate(layoutInflater)
            dialogBinding.etName.setText(site.name)
            dialogBinding.etIssuer.setText(site.issuer)
            dialogBinding.switchEnabled.isChecked = site.enabled
            
            AlertDialog.Builder(this)
                .setTitle(getString(com.authenticator.app.R.string.edit))
                .setView(dialogBinding.root)
                .setPositiveButton(getString(com.authenticator.app.R.string.save)) { _, _ ->
                    safeCall("editSiteSave") {
                        val newName = dialogBinding.etName.text.toString().trim()
                        val newIssuer = dialogBinding.etIssuer.text.toString().trim()
                        val enabled = dialogBinding.switchEnabled.isChecked
                        updateSite(site.copy(name = newName, issuer = newIssuer, enabled = enabled))
                    }
                }
                .setNegativeButton(getString(com.authenticator.app.R.string.cancel), null)
                .show()
        } catch (e: Exception) {
            logError("showEditDialog", e)
        }
    }
    
    private fun updateSite(site: Site) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                database.siteDao().update(site)
                withContext(Dispatchers.Main) { loadSites(); showToast("Site updated") }
            } catch (e: Exception) {
                logError("updateSite", e)
            }
        }
    }
    
    private fun showDeleteConfirmation(site: Site) {
        try {
            AlertDialog.Builder(this)
                .setTitle(getString(com.authenticator.app.R.string.delete))
                .setMessage(String.format(getString(com.authenticator.app.R.string.delete_site_message), site.name))
                .setPositiveButton(getString(com.authenticator.app.R.string.delete)) { _, _ -> safeCall("deleteSite") { deleteSite(site) } }
                .setNegativeButton(getString(com.authenticator.app.R.string.cancel)) { _, _ -> loadSites() }
                .setOnCancelListener { loadSites() }
                .show()
        } catch (e: Exception) {
            logError("showDeleteConfirmation", e)
        }
    }
    
    private fun deleteSite(site: Site) {
        lifecycleScope.launch(Dispatchers.IO) {
            try {
                database.siteDao().delete(site)
                withContext(Dispatchers.Main) { loadSites(); showToast("Site deleted") }
            } catch (e: Exception) {
                logError("deleteSite", e)
            }
        }
    }
    
    private fun encryptSecret(secret: String): String {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            if (!keyStore.containsAlias("totp_key")) {
                val kg = javax.crypto.KeyGenerator.getInstance(
                    android.security.keystore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
                )
                val spec = android.security.keystore.KeyGenParameterSpec.Builder(
                    "totp_key",
                    android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT
                )
                    .setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setKeySize(256)
                    .build()
                kg.init(spec)
                kg.generateKey()
            }
            
            val key: KeyStore.SecretKeyEntry? = keyStore.getEntry("totp_key", null) as? KeyStore.SecretKeyEntry
            val secretKey: SecretKey = key?.secretKey ?: throw Exception("Key not found")
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, secretKey)
            
            val encrypted = cipher.doFinal(secret.toByteArray())
            val iv = cipher.iv
            val combined = iv + encrypted
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            logError("encryptSecret", e)
            Base64.encodeToString(secret.toByteArray(), Base64.NO_WRAP)
        }
    }
    
    private fun decryptSecret(encrypted: String): String {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            val key = keyStore.getEntry("totp_key", null)
            if (key !is KeyStore.SecretKeyEntry) {
                return try { String(Base64.decode(encrypted, Base64.NO_WRAP)) } catch (_: Exception) { "" }
            }
            val secretKey = key.secretKey
            val combined = Base64.decode(encrypted, Base64.NO_WRAP)
            if (combined.size < 13) return String(Base64.decode(encrypted, Base64.NO_WRAP))
            val iv = combined.copyOfRange(0, 12)
            val encryptedBytes = combined.copyOfRange(12, combined.size)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec)
            String(cipher.doFinal(encryptedBytes))
        } catch (e: Exception) {
            logError("decryptSecret", e)
            try { String(Base64.decode(encrypted, Base64.NO_WRAP)) } catch (_: Exception) { "" }
        }
    }
    
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        return try {
            menuInflater.inflate(com.authenticator.app.R.menu.menu_main, menu)
            true
        } catch (e: Exception) {
            logError("onCreateOptionsMenu", e)
            false
        }
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return try {
            when (item.itemId) {
                com.authenticator.app.R.id.action_import -> { importFileLauncher.launch("application/json"); true }
                com.authenticator.app.R.id.action_export -> { exportFileLauncher.launch("totp_sites.json"); true }
                com.authenticator.app.R.id.action_backup -> { performBackup(); true }
                com.authenticator.app.R.id.action_settings -> { showSettingsDialog(); true }
                com.authenticator.app.R.id.action_about -> { showAboutDialog(); true }
                else -> super.onOptionsItemSelected(item)
            }
        } catch (e: Exception) {
            logError("onOptionsItemSelected", e)
            false
        }
    }
    
    // ---- About Dialog ----

    private fun showAboutDialog() {
        try {
            val versionName = try {
                packageManager.getPackageInfo(packageName, 0).versionName
            } catch (_: Exception) { "1.1.3" }

            val versionCode = try {
                packageManager.getPackageInfo(packageName, 0).versionCode.toString()
            } catch (_: Exception) { "" }

            val message = "TOTP Authenticator\nVersion $versionName (build $versionCode)\n\nMade by jnetai.com"
            val repoUrl = "https://github.com/jnetai-clawbot/TOTP-Authenticator"
            val siteUrl = "https://jnetai.com"

            AlertDialog.Builder(this)
                .setTitle(getString(com.authenticator.app.R.string.about_title))
                .setMessage(message)
                .setPositiveButton("OK", null)
                .setNeutralButton("Share") { _, _ ->
                    try {
                        val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        val clip = ClipData.newPlainText("TOTP Authenticator", repoUrl)
                        clipboard.setPrimaryClip(clip)
                        val shareIntent = Intent(Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(Intent.EXTRA_TEXT, "Check out TOTP Authenticator: $repoUrl")
                        }
                        startActivity(Intent.createChooser(shareIntent, "Share TOTP Authenticator"))
                    } catch (e: Exception) {
                        logError("shareApp", e)
                    }
                }
                .setNegativeButton("Visit") { _, _ ->
                    try {
                        val intent = Intent(Intent.ACTION_VIEW, Uri.parse(siteUrl))
                        startActivity(intent)
                    } catch (e: Exception) {
                        logError("visitSite", e)
                    }
                }
                .show()
        } catch (e: Exception) {
            logError("showAboutDialog", e)
        }
    }

    // ---- Settings Dialog ----

    private fun showSettingsDialog() {
        try {
            val items = mutableListOf<String>()
            val actions = mutableListOf<() -> Unit>()

            // Sign in / account status
            if (currentAccountName != null) {
                items.add(getString(com.authenticator.app.R.string.signed_in_as, currentAccountName))
                actions.add {} // no-op for info item

                items.add(getString(com.authenticator.app.R.string.backup_now))
                actions.add { performBackup() }

                items.add(getString(com.authenticator.app.R.string.restore_from_backup))
                actions.add { confirmAndRestore() }

                items.add(getString(com.authenticator.app.R.string.sign_out_google))
                actions.add { signOut() }
            } else {
                items.add(getString(com.authenticator.app.R.string.sign_in_google))
                actions.add { signIn() }
            }

            items.add(getString(com.authenticator.app.R.string.change_password))
            actions.add { showChangePasswordDialog() }

            AlertDialog.Builder(this)
                .setTitle(getString(com.authenticator.app.R.string.settings))
                .setItems(items.toTypedArray()) { _, which ->
                    if (which < actions.size) {
                        safeCall("settingsDialog") { actions[which].invoke() }
                    }
                }
                .setPositiveButton(getString(com.authenticator.app.R.string.cancel), null)
                .show()
        } catch (e: Exception) {
            logError("showSettingsDialog", e)
        }
    }

    // ---- Google Sign-In / Sign-Out ----

    private fun signIn() {
        try {
            // Show Google account picker
            val intent = android.accounts.AccountManager.newChooseAccountIntent(
                null, null, arrayOf("com.google"),
                false, null, null, null, null
            )
            accountPickerLauncher.launch(intent)
        } catch (e: Exception) {
            logError("signIn", e)
            showToast("Sign in failed: ${e.message}")
        }
    }

    private fun signOut() {
        try {
            currentAccountName = null
            currentAccessToken = null
            updateGoogleSignInCard()
            showToast("Signed out")
        } catch (e: Exception) {
            logError("signOut", e)
        }
    }

    // ---- Backup / Restore ----

    private fun showBackupRestoreDialog() {
        val items = arrayOf(
            getString(com.authenticator.app.R.string.backup_now),
            getString(com.authenticator.app.R.string.restore_from_backup)
        )
        AlertDialog.Builder(this)
            .setTitle(getString(com.authenticator.app.R.string.cloud_backup))
            .setItems(items) { _, which ->
                when (which) {
                    0 -> performBackup()
                    1 -> confirmAndRestore()
                }
            }
            .setNegativeButton(getString(com.authenticator.app.R.string.cancel), null)
            .show()
    }

    private fun performBackup() {
        if (masterPassword.isEmpty()) {
            showToast("No master password set")
            return
        }

        if (currentAccountName == null) {
            showToast("Please sign in to Google first")
            signIn()
            return
        }

        showToast("Backing up...")

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // Build encrypted backup JSON
                val encryptedBackup = driveBackupManager.buildBackupJson(masterPassword)

                // Get access token for current account
                val accessToken = currentAccountName?.let { email ->
                    try {
                        val am = getSystemService(Context.ACCOUNT_SERVICE) as android.accounts.AccountManager
                        val account = android.accounts.Account(email, "com.google")
                        val future = am.getAuthToken(account, "oauth2:https://www.googleapis.com/auth/drive.file", null, false, null, null)
                        val bundle = future.result
                        bundle.getString(android.accounts.AccountManager.KEY_AUTHTOKEN)
                    } catch (e: Exception) {
                        logError("getBackupToken", e)
                        null
                    }
                }

                if (accessToken == null) {
                    withContext(Dispatchers.Main) { showToast("Failed to get Drive access token") }
                    return@launch
                }

                val success = driveBackupManager.uploadToDrive(accessToken, encryptedBackup)
                withContext(Dispatchers.Main) {
                    if (success) {
                        showToast(getString(com.authenticator.app.R.string.backup_success))
                    } else {
                        showToast(getString(com.authenticator.app.R.string.backup_failed))
                    }
                }
            } catch (e: Exception) {
                logError("backup", e)
                withContext(Dispatchers.Main) {
                    showToast("Backup failed: ${e.message}")
                }
            }
        }
    }

    private fun confirmAndRestore() {
        AlertDialog.Builder(this)
            .setTitle(getString(com.authenticator.app.R.string.confirm_restore_title))
            .setMessage(getString(com.authenticator.app.R.string.confirm_restore_message))
            .setPositiveButton(getString(com.authenticator.app.R.string.confirm)) { _, _ ->
                performRestore()
            }
            .setNegativeButton(getString(com.authenticator.app.R.string.cancel), null)
            .show()
    }

    private fun performRestore() {
        if (masterPassword.isEmpty()) {
            showToast("No master password set")
            return
        }

        if (currentAccountName == null) {
            showToast("Please sign in to Google first")
            signIn()
            return
        }

        showToast("Restoring...")

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val accessToken = currentAccountName?.let { email ->
                    try {
                        val am = getSystemService(Context.ACCOUNT_SERVICE) as android.accounts.AccountManager
                        val account = android.accounts.Account(email, "com.google")
                        val future = am.getAuthToken(account, "oauth2:https://www.googleapis.com/auth/drive.file", null, false, null, null)
                        val bundle = future.result
                        bundle.getString(android.accounts.AccountManager.KEY_AUTHTOKEN)
                    } catch (e: Exception) {
                        logError("getRestoreToken", e)
                        null
                    }
                }

                if (accessToken == null) {
                    withContext(Dispatchers.Main) { showToast("Failed to get access token") }
                    return@launch
                }

                val encryptedContent = driveBackupManager.downloadFromDrive(accessToken)
                if (encryptedContent == null) {
                    withContext(Dispatchers.Main) {
                        showToast(getString(com.authenticator.app.R.string.no_backup_found))
                    }
                    return@launch
                }

                val count = driveBackupManager.restoreFromBackup(masterPassword, encryptedContent)

                withContext(Dispatchers.Main) {
                    loadSites()
                    showToast(String.format(getString(com.authenticator.app.R.string.restore_success), count))
                }
            } catch (e: Exception) {
                logError("restore", e)
                withContext(Dispatchers.Main) {
                    showToast(getString(com.authenticator.app.R.string.restore_failed, e.message))
                }
            }
        }
    }

    // ---- Change Password ----

    // ---- Change Password ----

    private fun showChangePasswordDialog() {
        try {
            val builder = AlertDialog.Builder(this)
                .setTitle(getString(com.authenticator.app.R.string.change_password_title))

            val container = LinearLayout(this)
            container.orientation = LinearLayout.VERTICAL
            container.setPadding(48, 24, 48, 24)

            val currentField = com.google.android.material.textfield.TextInputLayout(
                this,
                null,
                com.google.android.material.R.style.Widget_Material3_TextInputLayout_OutlinedBox
            )
            currentField.hint = getString(com.authenticator.app.R.string.current_password_hint)
            currentField.isPasswordVisibilityToggleEnabled = true
            currentField.layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            val currentEdit = com.google.android.material.textfield.TextInputEditText(this)
            currentEdit.inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            currentEdit.maxLines = 1
            currentEdit.setTextColor(getColor(com.authenticator.app.R.color.text_primary))
            currentField.addView(currentEdit)

            val newField = com.google.android.material.textfield.TextInputLayout(
                this,
                null,
                com.google.android.material.R.style.Widget_Material3_TextInputLayout_OutlinedBox
            )
            newField.hint = getString(com.authenticator.app.R.string.new_password_hint)
            newField.isPasswordVisibilityToggleEnabled = true
            newField.layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            val newEdit = com.google.android.material.textfield.TextInputEditText(this)
            newEdit.inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            newEdit.maxLines = 1
            newEdit.setTextColor(getColor(com.authenticator.app.R.color.text_primary))
            newField.addView(newEdit)

            val confirmField = com.google.android.material.textfield.TextInputLayout(
                this,
                null,
                com.google.android.material.R.style.Widget_Material3_TextInputLayout_OutlinedBox
            )
            confirmField.hint = getString(com.authenticator.app.R.string.confirm_new_password_hint)
            confirmField.isPasswordVisibilityToggleEnabled = true
            confirmField.layoutParams = ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            )
            val confirmEdit = com.google.android.material.textfield.TextInputEditText(this)
            confirmEdit.inputType = android.text.InputType.TYPE_CLASS_TEXT or android.text.InputType.TYPE_TEXT_VARIATION_PASSWORD
            confirmEdit.maxLines = 1
            confirmEdit.setTextColor(getColor(com.authenticator.app.R.color.text_primary))
            confirmField.addView(confirmEdit)

            container.addView(currentField)
            container.addView(newField)
            container.addView(confirmField)

            builder.setView(container)
                .setPositiveButton(getString(com.authenticator.app.R.string.save)) { _, _ ->
                    val currentPw = currentEdit.text.toString()
                    val newPw = newEdit.text.toString()
                    val confirmPw = confirmEdit.text.toString()

                    if (currentPw.isEmpty() || newPw.isEmpty()) {
                        showToast("All fields are required")
                        return@setPositiveButton
                    }
                    if (newPw != confirmPw) {
                        showToast(getString(com.authenticator.app.R.string.error_passwords_mismatch))
                        return@setPositiveButton
                    }
                    if (newPw.length < 4) {
                        showToast(getString(com.authenticator.app.R.string.error_password_too_short))
                        return@setPositiveButton
                    }

                    val success = CryptoUtil.changePassword(currentPw, newPw)
                    if (success) {
                        masterPassword = newPw
                        showToast(getString(com.authenticator.app.R.string.password_changed))
                    } else {
                        showToast(getString(com.authenticator.app.R.string.password_change_failed))
                    }
                }
                .setNegativeButton(getString(com.authenticator.app.R.string.cancel), null)
                .show()
        } catch (e: Exception) {
            logError("showChangePasswordDialog", e)
        }
    }
    
    private fun importFromUri(uri: Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            val reader = BufferedReader(InputStreamReader(inputStream))
            val jsonString = reader.readText()
            reader.close()
            
            val jsonArray = if (jsonString.trim().startsWith("[")) JSONArray(jsonString)
            else { val json = JSONObject(jsonString); if (json.has("entries")) json.getJSONArray("entries") else JSONArray() }
            
            var imported = 0
            for (i in 0 until jsonArray.length()) {
                try {
                    val obj = jsonArray.getJSONObject(i)
                    val site = Site(
                        id = UUID.randomUUID().toString(),
                        name = obj.getString("name"),
                        secret = encryptSecret(obj.getString("secret")),
                        issuer = obj.optString("issuer", ""),
                        digits = obj.optInt("digits", 6),
                        period = obj.optInt("period", 30),
                        algorithm = obj.optString("algorithm", "SHA1"),
                        enabled = true,
                        createdAt = System.currentTimeMillis()
                    )
                    val existing = database.siteDao().getAll().find { it.name == site.name }
                    if (existing == null) { database.siteDao().insert(site); imported++ }
                } catch (e: Exception) { logError("import item $i", e) }
            }
            loadSites()
            showToast("Imported $imported sites")
        } catch (e: Exception) {
            logError("importFromUri", e)
            showToast("Import failed: ${e.message}")
        }
    }
    
    private fun exportToUri(uri: Uri) {
        try {
            lifecycleScope.launch(Dispatchers.IO) {
                try {
                    val sites = database.siteDao().getAll()
                    val jsonArray = JSONArray()
                    for (site in sites) {
                        try {
                            jsonArray.put(JSONObject().apply {
                                put("name", site.name)
                                put("secret", decryptSecret(site.secret))
                                put("issuer", site.issuer)
                                put("digits", site.digits)
                                put("period", site.period)
                                put("algorithm", site.algorithm)
                            })
                        } catch (e: Exception) { logError("export ${site.name}", e) }
                    }
                    val jsonObject = JSONObject().apply {
                        put("version", 1); put("app", "totp-authenticator"); put("entries", jsonArray)
                    }
                    withContext(Dispatchers.Main) {
                        try {
                            contentResolver.openOutputStream(uri)?.use { it.write(jsonObject.toString(2).toByteArray()) }
                            showToast("Exported ${sites.size} sites")
                        } catch (e: Exception) { logError("export output", e) }
                    }
                } catch (e: Exception) { logError("export data", e) }
            }
        } catch (e: Exception) { logError("exportToUri", e) }
    }

}
