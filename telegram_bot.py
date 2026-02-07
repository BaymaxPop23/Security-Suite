#!/usr/bin/env python3
"""
Standalone Telegram Bot for Security Suite
EASD Recon & APKSlayer Integration
"""
import os
import re
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import requests

# Setup logging
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Configuration
BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "8542223821:AAFc3SZAc5PghL0WIzMR_ferPZt4aO_oW2g")
API_BASE = "http://localhost:8000/api"

# Import notification system
from core.telegram_notifier import add_chat_id

# Command handlers
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start command"""
    # Register this chat for notifications
    chat_id = update.effective_chat.id
    add_chat_id(str(chat_id))
    logger.info(f"Registered chat {chat_id} for notifications")

    await update.message.reply_text(
        "🛡️ *Security Suite Bot*\n\n"
        "📍 *Domain Scanning (EASD):*\n"
        "• Send a domain: `audible.com`\n"
        "• Or: `/scan audible.com`\n\n"
        "📱 *APK Analysis (APKSlayer):*\n"
        "• 📤 *Upload APK file directly* (easiest!)\n"
        "• Send Play Store link\n"
        "• Send package ID: `com.whatsapp`\n"
        "• Send APK URL or file path\n"
        "• Or: `/analyze <source>`\n\n"
        "📋 *Other Commands:*\n"
        "• `/status` - Check recent runs\n"
        "• `/reports` - List reports\n"
        "• `/help` - Show this help\n\n"
        "📬 You'll get notifications with reports when scans complete!\n"
        "📄 HTML reports sent as documents\n\n"
        "Dashboard: http://localhost:8000/dashboard",
        parse_mode="Markdown"
    )

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Start EASD reconnaissance scan"""
    # Register this chat for notifications
    chat_id = update.effective_chat.id
    add_chat_id(str(chat_id))

    if not context.args:
        await update.message.reply_text(
            "❌ Usage: /scan <domain>\n"
            "Example: /scan audible.com\n\n"
            "Or just send the domain name without /scan!"
        )
        return

    domain = context.args[0].strip()
    logger.info(f"Starting scan for domain: {domain} (Chat ID: {chat_id})")

    try:
        await update.message.reply_text(
            f"🔍 Starting EASD reconnaissance for *{domain}*...\n"
            f"⏳ This may take a few minutes.\n\n"
            f"📬 I'll send you the HTML report when it's ready!",
            parse_mode="Markdown"
        )

        response = requests.post(
            f"{API_BASE}/runs/start",
            json={"domains": [domain], "apks": [], "dry_run": False},
            timeout=10
        )

        if response.status_code != 200:
            await update.message.reply_text(f"❌ API Error: {response.status_code} - {response.text[:200]}")
            return

        data = response.json()
        run_id = data.get('run_id')

        msg = (
            f"✅ *Scan started!*\n\n"
            f"🎯 Target: `{domain}`\n"
            f"🆔 Run ID: `{run_id}`\n"
            f"📊 Status: {data.get('status')}\n\n"
            f"💡 You'll be notified here when the scan completes!\n"
            f"📄 HTML report will be sent automatically\n\n"
            f"Dashboard: http://localhost:8000/dashboard"
        )

        await update.message.reply_text(msg, parse_mode="Markdown")

    except Exception as e:
        logger.error(f"Error in scan command: {str(e)}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def analyze(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Analyze APK with APKSlayer"""
    # Register this chat for notifications
    chat_id = update.effective_chat.id
    add_chat_id(str(chat_id))

    if not context.args:
        await update.message.reply_text(
            "❌ Usage: /analyze <apk_source>\n\n"
            "Examples:\n"
            "• /analyze /path/to/app.apk\n"
            "• /analyze https://example.com/app.apk\n"
            "• /analyze https://play.google.com/store/apps/details?id=com.example.app\n"
            "• /analyze com.example.app"
        )
        return

    apk = " ".join(context.args).strip()
    logger.info(f"Starting APK analysis: {apk} (Chat ID: {chat_id})")

    # Determine what type of source this is
    source_type = "APK"
    if 'play.google.com' in apk:
        source_type = "Play Store app"
    elif apk.startswith('http'):
        source_type = "APK URL"
    elif '.' in apk and '/' not in apk:
        source_type = "Package ID"

    try:
        await update.message.reply_text(
            f"📱 Starting APKSlayer analysis...\n"
            f"📦 Source: {source_type}\n"
            f"⏳ Downloading and analyzing... This may take 5-10 minutes.\n\n"
            f"📬 You'll be notified when analysis completes!",
            parse_mode="Markdown"
        )

        response = requests.post(
            f"{API_BASE}/runs/start",
            json={"domains": [], "apks": [apk], "dry_run": False},
            timeout=10
        )

        if response.status_code != 200:
            await update.message.reply_text(f"❌ API Error: {response.status_code} - {response.text[:200]}")
            return

        data = response.json()
        run_id = data.get('run_id')

        msg = (
            f"✅ *Analysis started!*\n\n"
            f"📱 Source: `{apk[:50]}...`\n"
            f"🆔 Run ID: `{run_id}`\n"
            f"📊 Status: {data.get('status')}\n\n"
            f"💡 You'll be notified here when analysis completes!\n"
            f"📄 Report will be sent automatically\n\n"
            f"Dashboard: http://localhost:8000/dashboard"
        )

        await update.message.reply_text(msg, parse_mode="Markdown")

    except Exception as e:
        logger.error(f"Error in analyze command: {str(e)}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Check recent runs status"""
    try:
        response = requests.get(f"{API_BASE}/runs", timeout=5)
        data = response.json()
        runs = data.get('runs', [])

        if not runs:
            await update.message.reply_text("📊 No runs yet. Use /scan <domain> to start!")
            return

        # Show last 5 runs
        msg = "📊 Recent Runs\n" + "="*30 + "\n\n"

        for run in runs[:5]:
            run_id = run.get('run_id', 'unknown')
            status = run.get('status', 'unknown')
            scope = run.get('scope', {})
            domains = scope.get('domains', [])
            apks = scope.get('apks', [])

            summary = run.get('summary', {})
            completed = summary.get('completed', 0)
            total = summary.get('total_tasks', run.get('total_tasks', 0))

            icon = "✅" if status == "completed" else "🔄"
            target = domains[0] if domains else (apks[0] if apks else "unknown")

            msg += f"{icon} {run_id[:16]}\n"
            msg += f"   Target: {target}\n"
            msg += f"   Status: {status}\n"
            msg += f"   Tasks: {completed}/{total}\n\n"

        msg += "Dashboard: http://localhost:8000/dashboard"
        await update.message.reply_text(msg)

    except Exception as e:
        logger.error(f"Error in status command: {str(e)}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def reports(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """List available reports"""
    try:
        response = requests.get(f"{API_BASE}/reports", timeout=5)
        data = response.json()
        report_list = data.get('reports', [])

        if not report_list:
            await update.message.reply_text("📄 No reports yet. Run a scan first with /scan <domain>")
            return

        msg = "📄 Available Reports\n" + "="*30 + "\n\n"

        for report in report_list[:10]:
            report_type = report.get('type', 'unknown')
            run_id = report.get('run_id', 'unknown')

            if report_type == 'recon':
                target = report.get('target', 'unknown')
                subdomains = report.get('subdomains', 0)
                icon = "🔍"
                msg += f"{icon} EASD: {target}\n"
                msg += f"   Run: {run_id[:16]}\n"
                msg += f"   Subdomains: {subdomains}\n"
            else:
                apk_name = report.get('apk_name', 'unknown')
                vulns = report.get('vulnerabilities', 0)
                icon = "📱"
                msg += f"{icon} APK: {apk_name}\n"
                msg += f"   Run: {run_id[:16]}\n"
                msg += f"   Vulnerabilities: {vulns}\n"

            msg += f"   Download: http://localhost:8000/api/reports/{run_id}/json\n\n"

        msg += "Dashboard: http://localhost:8000/dashboard"
        await update.message.reply_text(msg)

    except Exception as e:
        logger.error(f"Error in reports command: {str(e)}")
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Help command"""
    await start(update, context)

async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle APK file uploads"""
    # Register chat for notifications
    chat_id = update.effective_chat.id
    add_chat_id(str(chat_id))

    document = update.message.document

    # Check if it's an APK file
    if not document.file_name.endswith('.apk'):
        await update.message.reply_text(
            "❌ Please send an APK file (*.apk)\n\n"
            "You can also send:\n"
            "• APK download URL\n"
            "• Package ID (e.g., com.whatsapp)\n"
            "• Domain for reconnaissance"
        )
        return

    try:
        await update.message.reply_text(
            f"📥 Downloading APK: *{document.file_name}*...\n"
            f"⏳ Please wait...",
            parse_mode="Markdown"
        )

        # Download the APK file from Telegram
        file = await context.bot.get_file(document.file_id)

        # Create downloads directory
        import os
        downloads_dir = "telegram_downloads"
        os.makedirs(downloads_dir, exist_ok=True)

        # Download to local path
        local_path = os.path.join(downloads_dir, document.file_name)
        await file.download_to_drive(local_path)

        logger.info(f"Downloaded APK from Telegram: {local_path} ({document.file_size} bytes)")

        # Send confirmation and start analysis
        await update.message.reply_text(
            f"✅ *APK Downloaded!*\n\n"
            f"📱 File: `{document.file_name}`\n"
            f"📊 Size: {document.file_size / (1024*1024):.2f} MB\n\n"
            f"🔬 Starting APKSlayer analysis...\n"
            f"⏳ This may take 5-10 minutes.\n\n"
            f"📬 You'll be notified when complete!",
            parse_mode="Markdown"
        )

        # Trigger analysis via API
        response = requests.post(
            f"{API_BASE}/runs/start",
            json={"domains": [], "apks": [local_path], "dry_run": False},
            timeout=10
        )

        if response.status_code == 200:
            data = response.json()
            run_id = data.get('run_id')

            await update.message.reply_text(
                f"✅ *Analysis Started!*\n\n"
                f"🆔 Run ID: `{run_id}`\n"
                f"📊 Status: {data.get('status')}\n\n"
                f"💡 Results will be sent here automatically!\n"
                f"📄 HTML report will be attached",
                parse_mode="Markdown"
            )
        else:
            await update.message.reply_text(f"❌ API Error: {response.status_code}")

    except Exception as e:
        logger.error(f"Error handling APK upload: {e}")
        await update.message.reply_text(f"❌ Error: {str(e)}")


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle non-command messages - auto-detect domains, APKs, and Play Store links"""
    text = update.message.text.strip()

    # Check if it's a Play Store link or package ID
    if 'play.google.com' in text or re.match(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$', text):
        # Play Store URL or package ID - trigger APK analysis
        logger.info(f"Auto-detected Play Store/Package: {text}")
        context.args = [text]
        await analyze(update, context)
    # Check if it looks like a domain
    elif '.' in text and ' ' not in text and not text.startswith('http') and not text.endswith('.apk'):
        # Likely a domain - trigger scan
        logger.info(f"Auto-detected domain: {text}")
        context.args = [text]
        await scan(update, context)
    elif text.endswith('.apk') or ('http' in text and '.apk' in text):
        # Likely an APK path or URL
        logger.info(f"Auto-detected APK: {text}")
        context.args = [text]
        await analyze(update, context)
    else:
        await update.message.reply_text(
            "💡 Quick commands:\n\n"
            "📍 *Domain scanning:*\n"
            "• Send: `audible.com`\n\n"
            "📱 *APK analysis:*\n"
            "• 📤 Upload APK file directly\n"
            "• Send Play Store URL\n"
            "• Send package ID (e.g., `com.whatsapp`)\n"
            "• Send APK file path or URL\n\n"
            "📋 *Commands:*\n"
            "• /scan <domain> - EASD recon\n"
            "• /analyze <source> - APK analysis\n"
            "• /status - Check runs\n"
            "• /reports - View reports\n"
            "• /help - Full help",
            parse_mode="Markdown"
        )

def main(threaded=False):
    """Start the bot

    Args:
        threaded: If True, runs without signal handlers (for background thread mode)
    """
    logger.info("Starting Security Suite Telegram Bot (EASD & APKSlayer)...")

    application = Application.builder().token(BOT_TOKEN).build()

    # Add command handlers
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("scan", scan))
    application.add_handler(CommandHandler("analyze", analyze))
    application.add_handler(CommandHandler("status", status))
    application.add_handler(CommandHandler("reports", reports))

    # Add document handler for APK file uploads
    application.add_handler(MessageHandler(filters.Document.ALL, handle_document))

    # Add message handler for auto-detection
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    logger.info("✅ Bot started! Send /start to your bot on Telegram.")
    logger.info("🔍 EASD integration active - send domains to scan")
    logger.info("📱 APKSlayer integration active - send APK paths to analyze")
    logger.info("📤 APK file upload active - send .apk files directly")

    # Run without signal handlers when in threaded mode
    if threaded:
        application.run_polling(allowed_updates=Update.ALL_TYPES, stop_signals=None)
    else:
        application.run_polling(allowed_updates=Update.ALL_TYPES)

if __name__ == "__main__":
    main()
