#!/bin/bash
# Push TOTP Authenticator to GitHub
# Run this script to push to GitHub and create a release

REPO_NAME="TOTP-Authenticator"

echo "=== TOTP Authenticator GitHub Push Script ==="
echo ""
echo "Steps to complete:"
echo "1. Go to https://github.com/new and create a new repo named '$REPO_NAME'"
echo "2. Run the commands below:"
echo ""
echo "  cd /home/jay/Documents/Scripts/AI/openclaw/job16"
echo "  git remote add origin https://github.com/jamied_uk/$REPO_NAME.git"
echo "  git branch -M main"
echo "  git push -u origin main"
echo ""
echo "3. To create a release with APK:"
echo "   - Go to https://github.com/jamied_uk/$REPO_NAME/releases/new"
echo "   - Tag: v1.0.0"
echo "   - The APK will be built automatically via GitHub Actions"
echo ""
echo "4. For local APK build:"
echo "   cd /home/jay/Documents/Scripts/AI/openclaw/job16/android"
echo "   ./gradlew assembleDebug"
echo ""
echo "Done!"
