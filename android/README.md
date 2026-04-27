# Authenticator App

Android TOTP Authenticator application with GitHub Actions CI/CD.

## Build

```bash
cd android
./gradlew assembleDebug
```

APK will be at `./app/build/outputs/apk/debug/app-debug.apk`

make a final release for use with samsung s7 and s8 and pixel 6 and pixel 7 android mobiles and build the apk using github workflows and put the apk file in /home/jay/Documents/Scripts/AI/openclaw/Old-Jobs/TOTP-Authenticator/android/apk/


## GitHub Actions

Push to `main` branch triggers automatic build of debug and release APKs.

## Features

- Google Sign-In for account linking
- QR code scanning for adding sites
- TOTP code generation
- Encrypted secret storage using Android Keystore
- Dark theme UI

dont edit this file

Save changes to changes.txt (create if not exist)

Tell me when this is ready to test


