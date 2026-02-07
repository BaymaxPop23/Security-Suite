"""APK Downloader - Download APKs from various sources"""
import re
import subprocess
import logging
from pathlib import Path
from typing import Optional, Tuple
import requests

logger = logging.getLogger(__name__)


def extract_package_id(url: str) -> Optional[str]:
    """Extract package ID from Google Play Store URL"""
    # https://play.google.com/store/apps/details?id=com.example.app
    patterns = [
        r'id=([a-zA-Z0-9._]+)',  # ?id=com.example.app
        r'/apps/([a-zA-Z0-9._]+)',  # /apps/com.example.app
    ]

    for pattern in patterns:
        match = re.search(pattern, url)
        if match:
            return match.group(1)

    return None


def is_play_store_url(url: str) -> bool:
    """Check if URL is a Google Play Store link"""
    return 'play.google.com' in url or 'android.com' in url


def download_from_play_store(url_or_package_id: str, output_dir: Path) -> Tuple[bool, Optional[Path], str]:
    """
    Download APK from Google Play Store using apkeep

    Returns:
        (success, apk_path, message)
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    # Extract package ID if it's a URL
    package_id = url_or_package_id
    if is_play_store_url(url_or_package_id):
        package_id = extract_package_id(url_or_package_id)
        if not package_id:
            return False, None, "Could not extract package ID from URL"

    logger.info(f"Downloading APK for package: {package_id}")

    try:
        # Try using apkeep first
        result = subprocess.run(
            ['apkeep', '-a', package_id, output_dir],
            capture_output=True,
            text=True,
            timeout=300  # 5 minute timeout
        )

        if result.returncode == 0:
            # Find the downloaded APK
            apk_files = list(output_dir.glob(f"{package_id}*.apk"))
            if apk_files:
                return True, apk_files[0], f"Downloaded {package_id}"
            else:
                # apkeep might use different naming
                apk_files = list(output_dir.glob("*.apk"))
                if apk_files:
                    # Get the most recent one
                    latest_apk = max(apk_files, key=lambda p: p.stat().st_mtime)
                    return True, latest_apk, f"Downloaded {package_id}"

        logger.warning(f"apkeep failed: {result.stderr}")

    except FileNotFoundError:
        logger.warning("apkeep not found, trying alternative method")
    except Exception as e:
        logger.error(f"apkeep error: {e}")

    # Fallback: Try using gplaycli
    try:
        result = subprocess.run(
            ['gplaycli', '-d', package_id, '-f', str(output_dir)],
            capture_output=True,
            text=True,
            timeout=300
        )

        if result.returncode == 0:
            apk_files = list(output_dir.glob(f"*{package_id}*.apk"))
            if not apk_files:
                apk_files = list(output_dir.glob("*.apk"))

            if apk_files:
                latest_apk = max(apk_files, key=lambda p: p.stat().st_mtime)
                return True, latest_apk, f"Downloaded {package_id}"

        logger.warning(f"gplaycli failed: {result.stderr}")

    except FileNotFoundError:
        logger.warning("gplaycli not found")
    except Exception as e:
        logger.error(f"gplaycli error: {e}")

    # Fallback: Try APKCombo (most reliable)
    try:
        logger.info(f"Trying APKCombo download for {package_id}")
        return download_from_apkcombo(package_id, output_dir)
    except Exception as e:
        logger.error(f"APKCombo download failed: {e}")

    # Last fallback: APKPure
    try:
        logger.info(f"Trying APKPure download for {package_id}")
        success, path, msg = download_from_apkpure(package_id, output_dir)
        if success:
            return success, path, msg
        else:
            logger.warning(f"APKPure returned failure: {msg}")
    except Exception as e:
        logger.error(f"APKPure download exception: {e}", exc_info=True)

    return False, None, f"Failed to download APK for {package_id}. All download methods (apkeep, gplaycli, APKCombo, APKPure) failed."


def download_from_apkcombo(package_id: str, output_dir: Path) -> Tuple[bool, Optional[Path], str]:
    """
    Download APK using Evozi APK Downloader service (most reliable)
    """
    logger.info(f"Attempting Evozi APK Downloader for {package_id}")

    try:
        # Evozi APK Downloader API
        api_url = "https://apps.evozi.com/apk-downloader/"

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': 'https://apps.evozi.com/apk-downloader/',
        }

        # Construct the Play Store URL
        playstore_url = f"https://play.google.com/store/apps/details?id={package_id}"

        # Request download link from Evozi
        data = {
            'id': playstore_url
        }

        response = requests.post(api_url, data=data, headers=headers, timeout=60)

        if response.status_code == 200:
            result = response.json()

            if result.get('success'):
                download_url = result.get('url')

                if download_url:
                    logger.info(f"Got download URL from Evozi")

                    # Download the APK
                    apk_response = requests.get(download_url, headers=headers, timeout=180, stream=True)

                    if apk_response.status_code == 200:
                        apk_path = output_dir / f"{package_id}.apk"

                        total_size = 0
                        with open(apk_path, 'wb') as f:
                            for chunk in apk_response.iter_content(chunk_size=8192):
                                if chunk:
                                    f.write(chunk)
                                    total_size += len(chunk)

                        if apk_path.exists() and apk_path.stat().st_size > 100000:
                            size_mb = apk_path.stat().st_size / (1024 * 1024)
                            logger.info(f"✅ Downloaded from Evozi: {size_mb:.2f} MB")
                            return True, apk_path, f"Downloaded from Evozi ({size_mb:.2f} MB)"

            error_msg = result.get('error', 'Unknown error')
            logger.warning(f"Evozi error: {error_msg}")

    except Exception as e:
        logger.error(f"Evozi download error: {e}")

    return False, None, "Evozi download failed"


def download_from_apkpure_url(apkpure_url: str, output_dir: Path) -> Tuple[bool, Optional[Path], str]:
    """
    Download APK from APKPure app page URL

    Takes an APKPure app page URL like:
    https://apkpure.com/instagram/com.instagram.android

    Extracts the download link and downloads the APK.
    """
    logger.info(f"Extracting download link from APKPure page: {apkpure_url}")

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Referer': 'https://apkpure.com/'
        }

        # Get the APKPure app page
        response = requests.get(apkpure_url, headers=headers, timeout=30)

        if response.status_code != 200:
            logger.error(f"Failed to fetch APKPure page: HTTP {response.status_code}")
            return False, None, f"Failed to fetch APKPure page: HTTP {response.status_code}"

        # Look for download link patterns
        download_patterns = [
            r'href="(https://download\.apkpure\.com/b/[^"]+\.apk[^"]*)"',
            r'data-dt-url="([^"]+)"',
            r'href="(/dl/[^"]+)"',
            r'class="download_apk_news"[^>]*href="([^"]+)"',
        ]

        download_url = None
        for pattern in download_patterns:
            match = re.search(pattern, response.text)
            if match:
                download_url = match.group(1)
                # Make absolute URL if relative
                if download_url.startswith('/'):
                    download_url = f"https://apkpure.com{download_url}"
                logger.info(f"Found download URL: {download_url[:80]}...")
                break

        if not download_url:
            # Try the /download page
            if not apkpure_url.endswith('/download'):
                download_page_url = f"{apkpure_url.rstrip('/')}/download"
                logger.info(f"Trying download page: {download_page_url}")

                dl_response = requests.get(download_page_url, headers=headers, timeout=30)
                if dl_response.status_code == 200:
                    for pattern in download_patterns:
                        match = re.search(pattern, dl_response.text)
                        if match:
                            download_url = match.group(1)
                            if download_url.startswith('/'):
                                download_url = f"https://apkpure.com{download_url}"
                            logger.info(f"Found download URL on download page: {download_url[:80]}...")
                            break

        if not download_url:
            logger.warning("Could not extract download URL from APKPure page")
            return False, None, "Could not extract download URL from APKPure page"

        # Download the APK
        logger.info(f"Downloading APK from: {download_url[:100]}...")
        output_dir.mkdir(parents=True, exist_ok=True)

        apk_response = requests.get(download_url, headers=headers, timeout=180, stream=True, allow_redirects=True)

        if apk_response.status_code != 200:
            return False, None, f"Download failed: HTTP {apk_response.status_code}"

        # Extract filename
        apk_filename = "downloaded_app.apk"
        content_disp = apk_response.headers.get('Content-Disposition', '')
        if 'filename=' in content_disp:
            filename_match = re.search(r'filename="?([^"]+)"?', content_disp)
            if filename_match:
                apk_filename = filename_match.group(1)
        elif download_url.endswith('.apk'):
            apk_filename = download_url.split('/')[-1].split('?')[0]

        apk_path = output_dir / apk_filename

        # Download with progress
        total_size = 0
        with open(apk_path, 'wb') as f:
            for chunk in apk_response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
                    total_size += len(chunk)

        # Verify it's a valid APK
        if apk_path.exists() and apk_path.stat().st_size > 100000:  # At least 100KB
            size_mb = apk_path.stat().st_size / (1024 * 1024)
            logger.info(f"✅ Downloaded from APKPure: {size_mb:.2f} MB")
            return True, apk_path, f"Downloaded from APKPure ({size_mb:.2f} MB)"
        else:
            logger.warning(f"Downloaded file too small or invalid: {apk_path.stat().st_size} bytes")
            apk_path.unlink(missing_ok=True)
            return False, None, "Downloaded APK is too small or invalid"

    except Exception as e:
        logger.error(f"APKPure URL download error: {e}", exc_info=True)
        return False, None, f"APKPure download failed: {str(e)}"


def download_from_apkpure(package_id: str, output_dir: Path) -> Tuple[bool, Optional[Path], str]:
    """
    Download APK from APKPure - Package ID search not supported

    Use download_from_apkpure_url() instead with a direct APKPure page URL.
    """
    logger.info(f"APKPure package ID search not supported for {package_id}")
    logger.info("Please provide APKPure page URL instead (e.g., https://apkpure.com/instagram/com.instagram.android)")

    return False, None, "APKPure auto-search not available - provide APKPure page URL instead"


def download_apk(url_or_path: str, output_dir: Path) -> Tuple[bool, Optional[Path], str]:
    """
    Universal APK downloader - handles multiple sources

    Supports:
    - Local file paths
    - APKPure page URLs (https://apkpure.com/app-name/package.id)
    - Play Store URLs
    - Direct APK download URLs
    - Package IDs (tries Play Store methods)

    Returns:
        (success, apk_path, message)
    """
    # If it's a local path and exists, return it
    if Path(url_or_path).exists():
        return True, Path(url_or_path), "Local file"

    # If it's an APKPure page URL
    if 'apkpure.com' in url_or_path and url_or_path.startswith('http'):
        logger.info(f"Detected APKPure page URL: {url_or_path}")
        return download_from_apkpure_url(url_or_path, output_dir)

    # If it's a Play Store URL or package ID
    if is_play_store_url(url_or_path) or re.match(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$', url_or_path):
        return download_from_play_store(url_or_path, output_dir)

    # If it's a direct APK download URL
    if url_or_path.startswith('http'):
        try:
            logger.info(f"Downloading APK from URL: {url_or_path}")
            response = requests.get(url_or_path, timeout=60, stream=True)

            if response.status_code == 200:
                # Extract filename from URL or use default
                filename = url_or_path.split('/')[-1].split('?')[0]
                if not filename.endswith('.apk'):
                    filename = 'downloaded_app.apk'

                apk_path = output_dir / filename

                with open(apk_path, 'wb') as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)

                if apk_path.exists() and apk_path.stat().st_size > 100000:
                    return True, apk_path, "Downloaded from URL"
                else:
                    return False, None, "Downloaded file is too small or invalid"

        except Exception as e:
            logger.error(f"URL download error: {e}")
            return False, None, f"Download failed: {str(e)}"

    return False, None, "Unsupported APK source"
