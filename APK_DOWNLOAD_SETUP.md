# APK Download Setup

The system supports analyzing APKs from multiple sources, but **Google Play Store downloads require additional setup**.

## Current Status

✅ **Working:** Direct APK URLs and local files
⚠️ **Requires Setup:** Google Play Store package IDs

## Quick Solution: Use Direct APK URLs

Instead of using `com.instagram.android`, provide a direct APK download URL:

### Option 1: APKMirror (Recommended)
1. Visit https://www.apkmirror.com/
2. Search for the app (e.g., "Instagram")
3. Select the latest version
4. Copy the download link
5. Send to bot or paste in dashboard

Example:
```
https://www.apkmirror.com/apk/...instagram...apk
```

### Option 2: APKPure
1. Visit https://apkpure.com/
2. Search for the app
3. Click "Download APK"
4. Copy the download link

### Option 3: Local APK Files
If you have an APK file on your Mac:
```
/path/to/app.apk
```

## Full Play Store Support Setup

To enable downloading directly from Play Store using package IDs like `com.instagram.android`:

### Install apkeep (via Rust/Cargo)

```bash
# Install Rust if not installed
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install apkeep
cargo install apkeep

# Test
apkeep -a com.instagram.android ~/Downloads/
```

After installing apkeep, the system will automatically:
- Download APKs from Play Store
- Analyze them with APKSlayer
- Send results to Telegram

## Testing

### Test with Direct URL:
```bash
# Send this in Telegram:
https://github.com/your-test-apk.apk
```

### Test with Local File:
```bash
# If you have an APK:
/Users/saijagadeesh/Downloads/app.apk
```

## Current Workaround

**For now, use direct APK URLs from APKMirror or APKPure instead of package IDs.**

The bot will:
1. Download the APK from the URL
2. Run APKSlayer analysis
3. Send you the vulnerability report

All the analysis features work - it's just the Play Store download that needs the additional tool.
