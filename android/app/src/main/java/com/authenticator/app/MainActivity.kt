package com.authenticator.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
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

    private var currentCodes = mutableMapOf<String, Pair<String, Int>>()
    private var isRefreshing = false
    
    private val importFileLauncher = registerForActivityResult(
        ActivityResultContracts.GetContent()
    ) { uri: Uri? -> uri?.let { importFromUri(it) } }
    
    private val exportFileLauncher = registerForActivityResult(
        ActivityResultContracts.CreateDocument("application/json")
    ) { uri: Uri? -> uri?.let { exportToUri(it) } }

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
        binding.fabAddSite.setOnClickListener { showAddDialog() }
    }
    
    private fun setupSwipeToDelete() {
        val swipeHandler = object : ItemTouchHelper.SimpleCallback(0, ItemTouchHelper.LEFT) {
            override fun onMove(r: RecyclerView, v: RecyclerView.ViewHolder, t: RecyclerView.ViewHolder) = false
            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                val position = viewHolder.adapterPosition
                val site = adapter.currentList[position]
                showDeleteConfirmation(site)
            }
        }
        ItemTouchHelper(swipeHandler).attachToRecyclerView(binding.recyclerSites)
    }
    
    private fun loadSites() {
        lifecycleScope.launch(Dispatchers.IO) {
            val sites = database.siteDao().getAll()
            withContext(Dispatchers.Main) {
                adapter.submitList(sites)
                binding.tvEmptyState.visibility = if (sites.isEmpty()) View.VISIBLE else View.GONE
                binding.recyclerSites.visibility = if (sites.isEmpty()) View.GONE else View.VISIBLE
            }
        }
    }
    
    private fun startCodeRefresh() {
        lifecycleScope.launch {
            while (true) {
                if (!isRefreshing) refreshCodes()
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
            adapter.updateAllCodes(codes)
            
            isRefreshing = false
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
    
    private fun showAddDialog() {
        val dialogBinding = DialogAddSiteBinding.inflate(layoutInflater)
        
        AlertDialog.Builder(this)
            .setTitle("Add Site")
            .setView(dialogBinding.root)
            .setPositiveButton("Add") { _, _ ->
                val name = dialogBinding.etName.text.toString().trim()
                val secret = dialogBinding.etSecret.text.toString().trim().uppercase().replace(" ", "")
                val issuer = dialogBinding.etIssuer.text.toString().trim()
                
                if (name.isNotEmpty() && secret.isNotEmpty()) {
                    addSite(name, secret, issuer)
                } else {
                    Toast.makeText(this, "Name and secret required", Toast.LENGTH_SHORT).show()
                }
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun addSite(name: String, secret: String, issuer: String) {
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
        
        lifecycleScope.launch(Dispatchers.IO) {
            database.siteDao().insert(site)
            withContext(Dispatchers.Main) {
                loadSites()
                Toast.makeText(this@MainActivity, "Site added", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun showEditDialog(site: Site) {
        val dialogBinding = DialogEditSiteBinding.inflate(layoutInflater)
        dialogBinding.etName.setText(site.name)
        dialogBinding.etIssuer.setText(site.issuer)
        dialogBinding.switchEnabled.isChecked = site.enabled
        
        AlertDialog.Builder(this)
            .setTitle("Edit Site")
            .setView(dialogBinding.root)
            .setPositiveButton("Save") { _, _ ->
                val newName = dialogBinding.etName.text.toString().trim()
                val newIssuer = dialogBinding.etIssuer.text.toString().trim()
                val enabled = dialogBinding.switchEnabled.isChecked
                updateSite(site.copy(name = newName, issuer = newIssuer, enabled = enabled))
            }
            .setNegativeButton("Cancel", null)
            .show()
    }
    
    private fun updateSite(site: Site) {
        lifecycleScope.launch(Dispatchers.IO) {
            database.siteDao().update(site)
            withContext(Dispatchers.Main) {
                loadSites()
                Toast.makeText(this@MainActivity, "Site updated", Toast.LENGTH_SHORT).show()
            }
        }
    }
    
    private fun showDeleteConfirmation(site: Site) {
        AlertDialog.Builder(this)
            .setTitle("Delete Site")
            .setMessage("Delete ${site.name}?")
            .setPositiveButton("Delete") { _, _ -> deleteSite(site) }
            .setNegativeButton("Cancel") { _, _ -> loadSites() }
            .setOnCancelListener { loadSites() }
            .show()
    }
    
    private fun deleteSite(site: Site) {
        lifecycleScope.launch(Dispatchers.IO) {
            database.siteDao().delete(site)
            withContext(Dispatchers.Main) {
                loadSites()
                Toast.makeText(this@MainActivity, "Site deleted", Toast.LENGTH_SHORT).show()
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
            
            val key: SecretKey = keyStore.getKey("totp_key", null) as SecretKey
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, key)
            
            val encrypted = cipher.doFinal(secret.toByteArray())
            val iv = cipher.iv
            
            val combined = iv + encrypted
            Base64.encodeToString(combined, Base64.NO_WRAP)
        } catch (e: Exception) {
            Base64.encodeToString(secret.toByteArray(), Base64.NO_WRAP)
        }
    }
    
    private fun decryptSecret(encrypted: String): String {
        return try {
            val keyStore = KeyStore.getInstance("AndroidKeyStore")
            keyStore.load(null)
            
            val key: SecretKey = keyStore.getKey("totp_key", null) as? SecretKey ?: return encrypted
            
            val combined = Base64.decode(encrypted, Base64.NO_WRAP)
            val iv = combined.copyOfRange(0, 12)
            val encryptedBytes = combined.copyOfRange(12, combined.size)
            
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            val spec = GCMParameterSpec(128, iv)
            cipher.init(Cipher.DECRYPT_MODE, key, spec)
            
            String(cipher.doFinal(encryptedBytes))
        } catch (e: Exception) {
            try {
                String(Base64.decode(encrypted, Base64.NO_WRAP))
            } catch (e2: Exception) {
                ""
            }
        }
    }
    
    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(com.authenticator.app.R.menu.menu_main, menu)
        return true
    }
    
    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            com.authenticator.app.R.id.action_import -> {
                importFileLauncher.launch("application/json")
                true
            }
            com.authenticator.app.R.id.action_export -> {
                exportFileLauncher.launch("totp_sites.json")
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }
    
    private fun importFromUri(uri: Uri) {
        try {
            val inputStream = contentResolver.openInputStream(uri)
            val reader = BufferedReader(InputStreamReader(inputStream))
            val jsonString = reader.readText()
            reader.close()
            
            val jsonArray = if (jsonString.trim().startsWith("[")) {
                JSONArray(jsonString)
            } else {
                val json = JSONObject(jsonString)
                if (json.has("entries")) json.getJSONArray("entries") else JSONArray()
            }
            
            var imported = 0
            
            for (i in 0 until jsonArray.length()) {
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
                if (existing == null) {
                    database.siteDao().insert(site)
                    imported++
                }
            }
            
            loadSites()
            Toast.makeText(this, "Imported $imported sites", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            Toast.makeText(this, "Import failed: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
    
    private fun exportToUri(uri: Uri) {
        try {
            lifecycleScope.launch(Dispatchers.IO) {
                val sites = database.siteDao().getAll()
                val jsonArray = JSONArray()
                
                for (site in sites) {
                    val obj = JSONObject().apply {
                        put("name", site.name)
                        put("secret", decryptSecret(site.secret))
                        put("issuer", site.issuer)
                        put("digits", site.digits)
                        put("period", site.period)
                        put("algorithm", site.algorithm)
                    }
                    jsonArray.put(obj)
                }
                
                val jsonObject = JSONObject().apply {
                    put("version", 1)
                    put("app", "totp-authenticator")
                    put("entries", jsonArray)
                }
                
                withContext(Dispatchers.Main) {
                    contentResolver.openOutputStream(uri)?.use { outputStream ->
                        outputStream.write(jsonObject.toString(2).toByteArray())
                    }
                    Toast.makeText(this@MainActivity, "Exported ${sites.size} sites", Toast.LENGTH_SHORT).show()
                }
            }
        } catch (e: Exception) {
            Toast.makeText(this, "Export failed: ${e.message}", Toast.LENGTH_SHORT).show()
        }
    }
}
