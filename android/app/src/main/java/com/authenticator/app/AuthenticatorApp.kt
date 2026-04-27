package com.authenticator.app

import android.app.Application

class AuthenticatorApp : Application() {
    override fun onCreate() {
        super.onCreate()
        
        // Global crash handler — writes stack traces to internal storage
        Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
            try {
                val stackTrace = StringBuilder()
                stackTrace.appendLine("=== CRASH ===")
                stackTrace.appendLine("Thread: ${thread.name}")
                stackTrace.appendLine("Exception: ${throwable.javaClass.name}: ${throwable.message}")
                for (element in throwable.stackTrace) {
                    stackTrace.appendLine("  at ${element.className}.${element.methodName}(${element.fileName}:${element.lineNumber})")
                }
                throwable.cause?.let { cause ->
                    stackTrace.appendLine("Caused by: ${cause.javaClass.name}: ${cause.message}")
                    for (element in cause.stackTrace) {
                        stackTrace.appendLine("  at ${element.className}.${element.methodName}(${element.fileName}:${element.lineNumber})")
                    }
                }
                
                // Write crash to a file
                val crashFile = java.io.File(filesDir, "crash_log.txt")
                crashFile.writeText(stackTrace.toString())
                
                android.util.Log.e("Authenticator", stackTrace.toString())
            } catch (_: Exception) {}
            
            // Let the default handler finish
            val defaultHandler = Thread.getDefaultUncaughtExceptionHandler()
            if (defaultHandler != null) {
                defaultHandler.uncaughtException(thread, throwable)
            }
        }
    }
}
