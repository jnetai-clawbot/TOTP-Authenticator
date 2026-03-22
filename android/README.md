# Authenticator App

Android TOTP Authenticator application with GitHub Actions CI/CD.

## Build

```bash
cd android
./gradlew assembleDebug
```

APK will be at `app/build/outputs/apk/debug/app-debug.apk`

## GitHub Actions

Push to `main` branch triggers automatic build of debug and release APKs.

## Features

- Google Sign-In for account linking
- QR code scanning for adding sites
- TOTP code generation
- Encrypted secret storage using Android Keystore
- Dark theme UI
