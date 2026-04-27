# TOTP Authenticator – Android App

Android TOTP Authenticator with master password protection, Google Drive backup/restore, search, and dark theme.

## Project Structure

```
/home/jay/Documents/Scripts/AI/openclaw/Old-Jobs/TOTP-Authenticator
├── android/
│   ├── app/
│   │   ├── build.gradle          ← Version, deps, signing config
│   │   ├── keystore.jks          ← Same keystore for ALL Android apps
│   │   ├── proguard-rules.pro
│   │   └── src/main/
│   │       ├── AndroidManifest.xml
│   │       ├── java/com/authenticator/app/
│   │       │   ├── MainActivity.kt        ← Main TOTP screen + backup/search
│   │       │   ├── LoginActivity.kt       ← Master password set/unlock
│   │       │   ├── AuthenticatorApp.kt    ← Application class + crash handler
│   │       │   ├── CryptoUtil.kt          ← PBKDF2 + AES-256 encryption
│   │       │   ├── DriveBackupManager.kt  ← Google Drive backup/restore
│   │       │   ├── SitesAdapter.kt        ← RecyclerView adapter
│   │       │   ├── totp/TOTPGenerator.kt  ← TOTP code generation
│   │       │   └── db/                    ← Room database
│   │       └── res/
│   │           ├── layout/
│   │           │   ├── activity_main.xml
│   │           │   ├── activity_login.xml
│   │           │   ├── dialog_add_site.xml
│   │           │   ├── dialog_edit_site.xml
│   │           │   └── item_site.xml
│   │           ├── values/strings.xml
│   │           ├── values/colors.xml
│   │           └── values/themes.xml
│   ├── build.gradle
│   ├── gradle.properties
│   ├── gradlew
│   └── local.properties           ← sdk.dir=/home/jay/Android/Sdk
├── .github/workflows/build.yml    ← CI builds + releases
├── apk/                           ← Built APKs stored here
├── README.md                      ← This file
└── changes.txt
```

## Features

1. **Master Password** – PBKDF2 + AES-256-GCM encryption. Set on first launch, unlock on every open
2. **Google Drive Backup** – Sign in with YOUR Google account. Back up and restore encrypted TOTP data
3. **Search** – Filter sites by name/issuer in real-time
4. **About** – Version number, "Made by jnetai.com", Share button, Visit website link
5. **TOTP codes** – Generate 6-digit codes, copy to clipboard, QR scanning, import/export
6. **Dark theme** – Material 3 Dark, gradient accents, glassmorphism cards

## Build Rules

- **NEVER build locally** – always use GitHub Actions CI
- Keystore: `android/app/keystore.jks` (alias: authenticator, password: ClawBot_S3cur3_2026)
- Version code: increment each release. Version name: `1.x.x`
- APK naming: `TOTP-Authenticator.apk` (release) and `TOTP-Authenticator-debug.apk` (debug)
- App ID: `com.authenticator.app`
- minSdk: 24, targetSdk: 34, compileSdk: 34
- Kotlin + ViewBinding, Room database, Material 3

## For Sub-Agents (pass these instructions)

When making changes:

1. Read ALL existing source files before writing code
2. Preserve: crash handler in AuthenticatorApp.kt, Room DB structure, SitesAdapter, TOTPGenerator
3. Always use the SAME keystore for signing
4. Run `./gradlew assembleDebug` to verify compilation
5. Commit and push to `main` branch
6. CI auto-builds and creates a GitHub Release with the APK
7. When done, notify via openclaw message send: "TOTP update done — ready to test"

## Target Devices

Samsung S7, S8, S9, Pixel 6, Pixel 7 (minSdk 24)
