package com.authenticator.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.os.Bundle
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
import com.google.zxing.integration.android.IntentIntegrator
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity() {
    
    private lateinit var binding: ActivityMainBinding
    private lateinit var database: SiteDatabase
    private lateinit var totpGenerator: TOTPGenerator
    private lateinit var adapter: SitesAdapter

    private var currentCodes = mutableMapOf<String, Pair<String, Int>>()
    private var isRefreshing = false
    
    private val qrScanLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val scanResult = IntentIntegrator.parseActivityResult(result.resultCode, result.data)
            scanResult.contents?.let { uri ->
                parseOTPAuthUri(uri)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        
        database = SiteDatabase.getInstance(this)
        totpGenerator = TOTPGenerator()
        
        setupRecyclerView()
        setupClickListeners()
        setupSwipeToDelete()
        
        loadSites()
        startCodeRefresh()
    }
    
    private fun setupRecyclerView() {
        adapter = SitesAdapter(
            onCopyClick = { site -> copyCode(site.name) },
            onEditClick = { site -> showEditDialog(site) }
        )
        
        binding.recyclerSites.layoutManager = LinearLayoutManager(this)
        binding.recyclerSites.adapter = adapter
    }
    
    private fun setupClickListeners() {
        binding.fabAddSite.setOnClickListener {
            showAddSiteDialog()
        }
        
        binding.btnScanQr.setOnClickListener {
            scanQRCode()
        }
        
        binding.btnRefresh.setOnClickListener {
            refreshCodes()
        }
    }
    
    private fun setupSwipeToDelete() {
        val swipeHandler = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.LEFT) {
            override fun onMove(
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                target: RecyclerView.ViewHolder
            ): Boolean = false
            
            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                val position = viewHolder.adapterPosition
                val site = adapter.currentList[position]
                showDeleteConfirmation(site, position)
            }
        }
        
        ItemTouchHelper(swipeHandler).attachToRecyclerView(binding.recyclerSites)
    }
    
    private fun scanQRCode() {
        val integrator = IntentIntegrator(this)
        integrator.setDesiredBarcodeFormats(IntentIntegrator.QR_CODE)
        integrator.setPrompt("Scan TOTP QR code")
        integrator.setCameraId(0)
        integrator.setBeepEnabled(true)
        integrator.setBarcodeImageEnabled(true)
        qrScanLauncher.launch(integrator.createScanIntent())
    }
    
    private fun parseOTPAuthUri(uri: String) {
        if (!uri.startsWith("otpauth://totp/")) {
            Toast.makeText(this, "Invalid QR code", Toast.LENGTH_SHORT).show()
            return
        }
        
        try {
            val parts = uri.removePrefix("otpauth://totp/").split("?")
            val labelPart = parts[0]
            val params = parts.getOrNull(1)?.split("&")?.associate {
                val kv = it.split("=")
                kv[0] to kv.getOrElse(1) { "" }
            } ?: emptyMap()
            
            val secret = params["secret"] ?: ""
            val issuer = params["issuer"] ?: labelPart.split(":").getOrElse(1) { "" }
            val name = if (labelPart.contains(":")) labelPart.split(":")[0] else labelPart
            
            if (secret.isNotEmpty()) {
                showAddSiteDialog(name, secret, issuer)
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Failed to parse QR code: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun showAddSiteDialog(name: String = "", secret: String = "", issuer: String = "") {
        val dialogBinding = DialogAddSiteBinding.inflate(layoutInflater)
        
        dialogBinding.etName.setText(name)
        dialogBinding.etSecret.setText(secret)
        dialogBinding.etIssuer.setText(issuer)
        
        AlertDialog.Builder(this)
            .setTitle("Add Site")
            .setView(dialogBinding.root)
            .setPositiveButton("Add") { _, _ ->
                val siteName = dialogBinding.etName.text.toString().trim()
                val siteSecret = dialogBinding.etSecret.text.toString().trim().uppercase()
                    .replace(" ", "").replace("-", "")
                val siteIssuer = dialogBinding.etIssuer.text.toString().trim()
                
                if (siteName.isNotEmpty() && siteSecret.isNotEmpty()) {
                    addSite(siteName, siteSecret, siteIssuer)
                } else {
                    Toast.makeText(this, "Name and secret are required", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun addSite(name: String, secret: String, issuer: String) {
        lifecycleScope.launch(Dispatchers.IO) {
            val site = Site(
                id = java.util.UUID.randomUUID().toString(),
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
            
            withContext(Dispatchers.Main) {
                loadSites()
                Toast.makeText(this@MainActivity, "Site added: $name", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun showEditDialog(site: Site) {
        val dialogBinding = DialogEditSiteBinding.inflate(layoutInflater)
        
        dialogBinding.etName.setText(site.name)
        dialogBinding.etIssuer.setText(site.issuer)
        dialogBinding.etSecret.setText("")
        dialogBinding.switchEnabled.isChecked = site.enabled
        
        AlertDialog.Builder(this)
            .setTitle("Edit Site")
            .setView(dialogBinding.root)
            .setPositiveButton("Save") { _, _ ->
                val newName = dialogBinding.etName.text.toString().trim()
                val newIssuer = dialogBinding.etIssuer.text.toString().trim()
                val newSecret = dialogBinding.etSecret.text.toString().trim()
                    .uppercase().replace(" ", "").replace("-", "")
                val enabled = dialogBinding.switchEnabled.isChecked
                
                if (newName.isNotEmpty()) {
                    updateSite(site.copy(
                        name = newName,
                        issuer = newIssuer,
                        secret = if (newSecret.isNotEmpty()) encryptSecret(newSecret) else site.secret,
                        enabled = enabled
                    ))
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun updateSite(site: Site) {
        lifecycleScope.launch(Dispatchers.IO) {
            database.siteDao().update(site)
            withContext(Dispatchers.Main) {
                loadSites()
            }
        }
    }
    
    private fun showDeleteConfirmation(site: Site, position: Int) {
        AlertDialog.Builder(this)
            .setTitle("Delete Site")
            .setMessage("Are you sure you want to delete ${site.name}?")
            .setPositiveButton("Delete") { _, _ ->
                deleteSite(site)
            }
            .setNegativeButton("Cancel") { _, _ ->
                adapter.notifyItemChanged(position)
            }
            .setOnCancelListener {
                adapter.notifyItemChanged(position)
            }
            .show()
    }
    
    private fun deleteSite(site: Site) {
        lifecycleScope.launch(Dispatchers.IO) {
            database.siteDao().delete(site)
            withContext(Dispatchers.Main) {
                loadSites()
                Toast.makeText(this@MainActivity, "Site deleted: ${site.name}", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun loadSites() {
        lifecycleScope.launch(Dispatchers.IO) {
            val sites = database.siteDao().getAll()
            withContext(Dispatchers.Main) {
                adapter.submitList(sites)
                if (sites.isEmpty()) {
                    binding.tvEmptyState.visibility = View.VISIBLE
                    binding.recyclerSites.visibility = View.GONE
                } else {
                    binding.tvEmptyState.visibility = View.GONE
                    binding.recyclerSites.visibility = View.VISIBLE
                }
            }
        }
    }
    
    private fun startCodeRefresh() {
        lifecycleScope.launch {
            while (true) {
                if (!isRefreshing) {
                    refreshCodes()
                }
                delay(1000)
            }
        }
    }
    
    private fun refreshCodes() {
        if (isRefreshing) return
        isRefreshing = true
        
        lifecycleScope.launch(Dispatchers.IO) {
            val sites = database.siteDao().getAll()
            val codes = mutableMapOf<String, Pair<String, Int>>()
            
            for (site in sites) {
                if (site.enabled) {
                    val secret = decryptSecret(site.secret)
                    val code = totpGenerator.generate(secret, site.period, site.digits)
                    val remaining = totpGenerator.getTimeRemaining(site.period)
                    codes[site.name] = code to remaining
                }
            }
            
            currentCodes = codes
            
            withContext(Dispatchers.Main) {
                adapter.updateAllCodes(codes)
                isRefreshing = false
            }
        }
    }
    
    private fun copyCode(name: String) {
        val codePair = currentCodes[name]
        if (codePair != null) {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            val clip = ClipData.newPlainText("TOTP Code", codePair.first)
            clipboard.setPrimaryClip(clip)
            Toast.makeText(this, "Code copied for $name", Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun encryptSecret(secret: String): String {
        val keyStore = android.security.keystore.KeyStore.getInstance("AndroidKeyStore")
        keyStore.load(null)
        
        if (!keyStore.containsAlias("totp_key")) {
            val keyGenerator = android.security.keystore.KeyGenerator.getInstance(
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
            
            keyGenerator.init(spec)
            keyGenerator.generateKey()
        }
        
        val key = keyStore.getKey("totp_key", null) as javax.crypto.SecretKey
        val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key)
        
        val encrypted = cipher.doFinal(secret.toByteArray())
        val iv = cipher.iv
        
        val combined = iv + encrypted
        return android.util.Base64.encodeToString(combined, android.util.Base64.NO_WRAP)
    }
    
    private fun decryptSecret(encrypted: String): String {
        return try {
            val keyStore = android.security.keystore.KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            val key = keyStore.getKey("totp_key", null) as? javax.crypto.SecretKey ?: return ""
            
            val combined = android.util.Base64.decode(encrypted, android.util.Base64.NO_WRAP)
            val iv = combined.copyOfRange(0, 12)
            val encryptedBytes = combined.copyOfRange(12, combined.size)
            
            val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding")
            val spec = javax.crypto.spec.GCMParameterSpec(128, iv)
            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, spec)
            
            String(cipher.doFinal(encryptedBytes))
        } catch (e: Exception) {
            ""
        }
    }
    
    override fun onResume() {
        super.onResume()
        loadSites()
        refreshCodes()
    }
}
