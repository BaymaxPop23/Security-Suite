#!/bin/bash
# Start Telegram Bot and API Server

cd ~/Desktop/security-suite
source venv/bin/activate

# Kill existing processes
pkill -f telegram_bot.py 2>/dev/null
lsof -ti :8000 | xargs kill -9 2>/dev/null

# Start API server
nohup python -m uvicorn api.main:app --host 0.0.0.0 --port 8000 > /tmp/api.log 2>&1 &
sleep 3

# Start Telegram bot
nohup python telegram_bot.py > /tmp/telegram_bot.log 2>&1 &
sleep 2

echo "✅ Services started!"
echo ""
echo "API Server:"
curl -s http://localhost:8000/api/health | jq .
echo ""
echo "Telegram Bot: $(pgrep -f telegram_bot.py > /dev/null && echo 'Running ✅' || echo 'Not running ❌')"
echo ""
echo "Dashboard: http://localhost:8000/dashboard"
echo "Bot: @BaymaxPop23_bot"
echo ""
echo "Logs:"
echo "  API: tail -f /tmp/api.log"
echo "  Bot: tail -f /tmp/telegram_bot.log"
