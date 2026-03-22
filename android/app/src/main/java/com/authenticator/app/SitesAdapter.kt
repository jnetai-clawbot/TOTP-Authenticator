package com.authenticator.app

import android.view.LayoutInflater
import android.view.ViewGroup
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.authenticator.app.databinding.ItemSiteBinding
import com.authenticator.app.db.Site

class SitesAdapter(
    private val onCopyClick: (Site) -> Unit,
    private val onEditClick: (Site) -> Unit
) : ListAdapter<Site, SitesAdapter.SiteViewHolder>(SiteDiffCallback()) {

    private var currentCodes = mutableMapOf<String, Pair<String, Int>>()

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): SiteViewHolder {
        val binding = ItemSiteBinding.inflate(
            LayoutInflater.from(parent.context),
            parent,
            false
        )
        return SiteViewHolder(binding)
    }

    override fun onBindViewHolder(holder: SiteViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    fun updateCode(name: String, code: String, remaining: Int) {
        currentCodes[name] = code to remaining
        val position = currentList.indexOfFirst { it.name == name }
        if (position >= 0) {
            notifyItemChanged(position, code)
        }
    }

    fun updateAllCodes(codes: Map<String, Pair<String, Int>>) {
        currentCodes.clear()
        currentCodes.putAll(codes)
        notifyDataSetChanged()
    }

    inner class SiteViewHolder(
        private val binding: ItemSiteBinding
    ) : RecyclerView.ViewHolder(binding.root) {

        fun bind(site: Site) {
            binding.tvName.text = site.name
            binding.tvIssuer.text = site.issuer.ifEmpty { site.name }

            val codePair = currentCodes[site.name]
            if (codePair != null) {
                binding.tvCode.text = formatCode(codePair.first)
                binding.progressCircular.max = site.period
                binding.progressCircular.progress = codePair.second
            } else {
                binding.tvCode.text = "------"
            }

            binding.btnCopy.setOnClickListener {
                onCopyClick(site)
            }

            binding.btnEdit.setOnClickListener {
                onEditClick(site)
            }
        }

        private fun formatCode(code: String): String {
            return if (code.length == 6) {
                "${code.substring(0, 3)} ${code.substring(3)}"
            } else {
                code
            }
        }
    }

    class SiteDiffCallback : DiffUtil.ItemCallback<Site>() {
        override fun areItemsTheSame(oldItem: Site, newItem: Site): Boolean {
            return oldItem.id == newItem.id
        }

        override fun areContentsTheSame(oldItem: Site, newItem: Site): Boolean {
            return oldItem == newItem
        }
    }
}
