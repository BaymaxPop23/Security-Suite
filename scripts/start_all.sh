#!/bin/bash
# Start all Security Suite services

echo "🛡️  Starting Security Suite"
echo "==========================="
echo ""

# Check if Ollama is running
if ! pgrep -x "ollama" > /dev/null; then
    echo "Starting Ollama..."
    ollama serve &
    OLLAMA_PID=$!
    sleep 3
fi

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Start API server
echo "Starting API server on port 8000..."
python3 -m uvicorn api.main:app --host 0.0.0.0 --port 8000 &
API_PID=$!

sleep 2

# Check if API is running
if curl -s http://localhost:8000/api/health > /dev/null; then
    echo "✅ API server running"
else
    echo "❌ API server failed to start"
    exit 1
fi

# Open dashboard
echo ""
echo "Opening dashboard..."
open dashboard/v2/index.html || xdg-open dashboard/v2/index.html 2>/dev/null

echo ""
echo "✅ All services started!"
echo ""
echo "Services:"
echo "  - API Server: http://localhost:8000"
echo "  - Dashboard: dashboard/v2/index.html"
echo "  - API Docs: http://localhost:8000/docs"
echo ""
echo "Press Ctrl+C to stop all services"
echo ""

# Wait for interrupt
trap "kill $API_PID 2>/dev/null; kill $OLLAMA_PID 2>/dev/null; exit 0" INT
wait
