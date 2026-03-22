package com.authenticator.app.db

import androidx.room.Entity
import androidx.room.PrimaryKey

@Entity(tableName = "sites")
data class Site(
    @PrimaryKey
    val id: String,
    val name: String,
    val secret: String,  // Encrypted
    val issuer: String = "",
    val digits: Int = 6,
    val period: Int = 30,
    val algorithm: String = "SHA1",
    val enabled: Boolean = true,
    val notes: String = "",
    val createdAt: Long = System.currentTimeMillis(),
    val updatedAt: Long = System.currentTimeMillis()
)
