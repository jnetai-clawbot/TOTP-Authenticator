# TOTP Authenticator ProGuard Rules

# Keep the Application class
-keep class com.authenticator.app.AuthenticatorApp { *; }

# Keep Room entities and DAOs
-keep class com.authenticator.app.db.** { *; }

# Keep TOTP generator
-keep class com.authenticator.app.totp.** { *; }

# Keep encryption/decryption - Android KeyStore + Cipher
-keep class javax.crypto.** { *; }
-keep class android.security.keystore.** { *; }
-keep class java.security.KeyStore { *; }
-keepnames class * implements java.security.KeyStore$Entry

# Keep Google Sign-In
-keep class com.google.android.gms.** { *; }
-dontwarn com.google.android.gms.**

# Keep Google API Client
-keep class com.google.api.client.** { *; }
-dontwarn com.google.api.client.**
-keep class com.google.api.services.drive.** { *; }
-dontwarn com.google.api.services.drive.**

# Keep HTTP client used by Drive API
-keep class com.google.http.client.** { *; }
-dontwarn com.google.http.client.**
-dontwarn org.apache.http.**
-dontwarn org.ietf.jgss.**
-dontwarn com.google.api.client.http.**
-dontwarn com.google.api.client.json.**

# Keep ZXing for QR
-keep class com.google.zxing.** { *; }
-keep class com.journeyapps.barcodescanner.** { *; }

# Keep Kotlin coroutines
-keepnames class kotlinx.coroutines.internal.MainDispatcherFactory {}
-keepnames class kotlinx.coroutines.CoroutineExceptionHandler {}

# Keep data binding and view binding
-keep class com.authenticator.app.databinding.** { *; }
