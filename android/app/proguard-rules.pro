# TOTP Authenticator ProGuard Rules

# Keep Room entities
-keep class com.authenticator.app.db.** { *; }

# Keep TOTP generator
-keep class com.authenticator.app.totp.** { *; }

# Keep Google Sign-In
-keep class com.google.android.gms.** { *; }

# Keep ZXing for QR
-keep class com.google.zxing.** { *; }
-keep class com.journeyapps.barcodescanner.** { *; }

# Keep Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}
