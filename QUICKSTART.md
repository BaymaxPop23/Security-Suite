# 🚀 Quick Start Guide

## Start the System

```bash
cd /Users/saijagadeesh/Desktop/security-suite
source venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload
```

## Access Dashboard

Open browser: **http://localhost:8000/dashboard**

## Run Security Scans

### Via Dashboard:
1. Click "🚀 New Run"
2. Enter targets (domains or APK paths/URLs)
3. Check "Dry Run" for testing
4. Click "Start Run"
5. View results in "📋 Tasks" tab

### Via API:
```bash
# Domain recon (EASD)
curl -X POST http://localhost:8000/api/runs/start \
  -H "Content-Type: application/json" \
  -d '{"domains": ["audible.com"], "apks": [], "dry_run": true}'

# APK analysis (APKSlayer)  
curl -X POST http://localhost:8000/api/runs/start \
  -H "Content-Type: application/json" \
  -d '{"domains": [], "apks": ["/path/to/app.apk"], "dry_run": false}'
```

## Telegram Bot (Optional)

```bash
python telegram_bot.py
```

## Key Endpoints

- Dashboard: http://localhost:8000/dashboard
- API Docs: http://localhost:8000/docs
- Health: http://localhost:8000/api/health
- Tasks: http://localhost:8000/api/tasks
- Runs: http://localhost:8000/api/runs

## Notes

- **Dry Run**: Returns mock data for testing
- **Real Scans**: Set `dry_run: false` for actual EASD/APKSlayer execution
- **Kanban Board**: Click "📋 Tasks" tab to see task status
- **Results**: Check `artifacts/` directory for detailed reports
