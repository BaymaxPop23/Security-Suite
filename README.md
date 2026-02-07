# Security Suite - EASD & APKSlayer Integration

**Simplified security automation suite with two powerful agents**

## 🎯 Agents

### 1. Recon Agent - Powered by EASD
- Subdomain enumeration
- Port scanning (100+ ports)  
- Technology fingerprinting
- Cloud asset discovery
- GitHub intelligence & secrets

### 2. APK Analyzer - Powered by APKSlayer
- 77+ vulnerability patterns
- Manifest & permission analysis
- Hardcoded credentials detection
- Attack surface mapping
- Interactive HTML reports

## 🚀 Quick Start

```bash
# Start API Server
source venv/bin/activate
uvicorn api.main:app --host 0.0.0.0 --port 8000 --reload

# Access Dashboard
open http://localhost:8000/dashboard
```

## 📡 API Usage

```bash
# Test with audible.com (dry run)
curl -X POST http://localhost:8000/api/runs/start \
  -H "Content-Type: application/json" \
  -d '{"domains": ["audible.com"], "apks": [], "dry_run": true}'
```

## ✅ What Works Now

- ✅ EASD integration for domain recon
- ✅ APKSlayer integration for APK analysis
- ✅ Simplified API (domains + APKs)
- ✅ Real-time dashboard
- ✅ Telegram bot integration (preserved)
- ✅ Dry run mode for testing
- ✅ No LLM dependencies required

## 🗑️ What Was Removed

- ❌ Planning Agent
- ❌ Maestro/Forge agents
- ❌ Code review agent
- ❌ Security testing agent
- ❌ Reporting agent
- ❌ Ollama/LLM dependencies

**Result:** Clean, focused tool with 2 agents doing real security work!
