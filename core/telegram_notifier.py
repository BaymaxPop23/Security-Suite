"""Telegram Notification Module"""
import os
import logging
import requests
from pathlib import Path
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8542223821:AAFc3SZAc5PghL0WIzMR_ferPZt4aO_oW2g")
TELEGRAM_API_BASE = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

# Store chat IDs from bot interactions
CHAT_IDS_FILE = Path(__file__).parent.parent / ".telegram_chats"


def get_chat_ids() -> list:
    """Get list of chat IDs to notify"""
    if not CHAT_IDS_FILE.exists():
        return []

    try:
        with open(CHAT_IDS_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"Failed to read chat IDs: {e}")
        return []


def add_chat_id(chat_id: str):
    """Add a chat ID to the notification list"""
    chat_ids = get_chat_ids()
    if str(chat_id) not in chat_ids:
        with open(CHAT_IDS_FILE, 'a') as f:
            f.write(f"{chat_id}\n")
        logger.info(f"Added chat ID: {chat_id}")


def send_message(chat_id: str, text: str, parse_mode: str = "Markdown") -> bool:
    """Send a text message to a chat"""
    try:
        response = requests.post(
            f"{TELEGRAM_API_BASE}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": parse_mode
            },
            timeout=10
        )
        return response.status_code == 200
    except Exception as e:
        logger.error(f"Failed to send message to {chat_id}: {e}")
        return False


def send_document(chat_id: str, file_path: Path, caption: str = "") -> bool:
    """Send a document to a chat"""
    try:
        if not file_path.exists():
            logger.error(f"File not found: {file_path}")
            return False

        with open(file_path, 'rb') as f:
            response = requests.post(
                f"{TELEGRAM_API_BASE}/sendDocument",
                data={
                    "chat_id": chat_id,
                    "caption": caption,
                    "parse_mode": "Markdown"
                },
                files={"document": f},
                timeout=60  # Larger timeout for file uploads
            )

        return response.status_code == 200
    except Exception as e:
        logger.error(f"Failed to send document to {chat_id}: {e}")
        return False


def notify_scan_complete(
    target: str,
    run_id: str,
    html_report_path: Optional[Path] = None,
    json_report_path: Optional[Path] = None,
    results: Optional[Dict[str, Any]] = None
):
    """Notify all registered chats about scan completion"""
    chat_ids = get_chat_ids()

    if not chat_ids:
        logger.warning("No chat IDs registered for notifications")
        return

    # Prepare message
    subdomains = len(results.get('subdomains', [])) if results else 0
    ips = len(results.get('ips', [])) if results else 0

    message = (
        f"✅ *EASD Scan Complete*\n\n"
        f"🎯 Target: `{target}`\n"
        f"🆔 Run ID: `{run_id}`\n"
        f"📊 Results:\n"
        f"  • Subdomains: {subdomains}\n"
        f"  • IPs: {ips}\n\n"
    )

    if html_report_path and html_report_path.exists():
        message += f"📄 HTML Report attached\n"

    message += f"\n🌐 Dashboard: http://localhost:8000/dashboard"

    # Send message and report to all chats
    for chat_id in chat_ids:
        logger.info(f"Sending notification to chat {chat_id}")

        # Send text message
        send_message(chat_id, message)

        # Send HTML report if available
        if html_report_path and html_report_path.exists():
            file_size_mb = html_report_path.stat().st_size / (1024 * 1024)

            # Telegram has a 50MB limit for bots
            if file_size_mb > 50:
                send_message(
                    chat_id,
                    f"⚠️ Report is too large ({file_size_mb:.1f}MB) to send via Telegram.\n"
                    f"Download it from: http://localhost:8000/api/reports/{run_id}/html"
                )
            else:
                caption = f"📄 EASD Report: {target}\n{subdomains} subdomains discovered"
                success = send_document(chat_id, html_report_path, caption)
                if success:
                    logger.info(f"Sent HTML report to chat {chat_id}")
                else:
                    logger.error(f"Failed to send HTML report to chat {chat_id}")


def notify_apk_analysis_complete(
    apk_name: str,
    run_id: str,
    json_report_path: Optional[Path] = None,
    html_report_path: Optional[Path] = None,
    results: Optional[Dict[str, Any]] = None
):
    """Notify all registered chats about APK analysis completion"""
    chat_ids = get_chat_ids()

    if not chat_ids:
        logger.warning("No chat IDs registered for notifications")
        return

    # Prepare message
    findings = results.get('findings', results.get('vulnerabilities', [])) if results else []
    vulns = len(findings)
    total_findings = results.get('total_findings', vulns) if results else 0

    message = (
        f"✅ *APK Analysis Complete*\n\n"
        f"📱 APK: `{apk_name}`\n"
        f"🆔 Run ID: `{run_id}`\n"
        f"⚠️ Vulnerabilities: {vulns}\n"
        f"📊 Total Findings: {total_findings}\n\n"
    )

    if html_report_path and html_report_path.exists():
        message += f"📄 HTML Report attached\n"

    message += f"\n🌐 Dashboard: http://localhost:8000/dashboard"

    # Send to all chats
    for chat_id in chat_ids:
        logger.info(f"Sending APK analysis notification to chat {chat_id}")
        send_message(chat_id, message)

        # Send HTML report if available
        if html_report_path and html_report_path.exists():
            file_size_mb = html_report_path.stat().st_size / (1024 * 1024)

            # Telegram has a 50MB limit for bots
            if file_size_mb > 50:
                send_message(
                    chat_id,
                    f"⚠️ HTML report is too large ({file_size_mb:.1f}MB) to send via Telegram.\n"
                    f"View it at: http://localhost:8000/api/reports/{run_id}/html"
                )
            else:
                caption = f"📱 APK Analysis: {apk_name}\n{vulns} vulnerabilities found"
                success = send_document(chat_id, html_report_path, caption)
                if success:
                    logger.info(f"Sent HTML report to chat {chat_id}")
                else:
                    logger.error(f"Failed to send HTML report to chat {chat_id}")

        # Also send JSON report if available and small enough
        if json_report_path and json_report_path.exists():
            file_size_mb = json_report_path.stat().st_size / (1024 * 1024)
            if file_size_mb <= 50:
                caption = f"📊 JSON Report: {apk_name}"
                send_document(chat_id, json_report_path, caption)
