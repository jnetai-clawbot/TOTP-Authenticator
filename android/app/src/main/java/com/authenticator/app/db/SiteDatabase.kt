package com.authenticator.app.db

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(entities = [Site::class], version = 1, exportSchema = false)
abstract class SiteDatabase : RoomDatabase() {
    
    abstract fun siteDao(): SiteDao
    
    companion object {
        @Volatile
        private var INSTANCE: SiteDatabase? = null
        
        fun getInstance(context: Context): SiteDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    SiteDatabase::class.java,
                    "authenticator_db"
                )
                    .fallbackToDestructiveMigration()
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
