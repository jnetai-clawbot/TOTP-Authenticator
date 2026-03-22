package com.authenticator.app.db

import androidx.room.*

@Dao
interface SiteDao {
    @Query("SELECT * FROM sites ORDER BY name ASC")
    fun getAll(): List<Site>

    @Query("SELECT * FROM sites WHERE id = :id")
    fun getById(id: String): Site?

    @Query("SELECT * FROM sites WHERE enabled = 1 ORDER BY name ASC")
    fun getEnabled(): List<Site>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun insert(site: Site)

    @Update
    fun update(site: Site)

    @Delete
    fun delete(site: Site)

    @Query("DELETE FROM sites WHERE id = :id")
    fun deleteById(id: String)
}
