#!/bin/bash
# Security Suite Setup Script

set -e

echo "🛡️  Security Suite Setup"
echo "======================="
echo ""

# Check Python version
echo "Checking Python version..."
python3 --version || { echo "Error: Python 3 not found"; exit 1; }

# Create virtual environment
echo ""
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Install Python dependencies
echo ""
echo "Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# Initialize database
echo ""
echo "Initializing database..."
python3 -c "from core.storage.database import get_db; db = get_db(); db.initialize(); print('✅ Database initialized')"

# Create necessary directories
echo ""
echo "Creating directory structure..."
mkdir -p artifacts logs runs reports shared/{targets,recon,plans,findings,reports,knowledge}

# Check if Ollama is installed
echo ""
echo "Checking for Ollama..."
if command -v ollama &> /dev/null; then
    echo "✅ Ollama found"
    echo "Checking for required models..."

    # Check for models
    if ollama list | grep -q "llama3.1:8b"; then
        echo "✅ llama3.1:8b found"
    else
        echo "⚠️  llama3.1:8b not found. Install with: ollama pull llama3.1:8b"
    fi

    if ollama list | grep -q "codellama:7b"; then
        echo "✅ codellama:7b found"
    else
        echo "⚠️  codellama:7b not found. Install with: ollama pull codellama:7b"
    fi
else
    echo "⚠️  Ollama not found. Install from: https://ollama.ai"
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Next steps:"
echo "1. Start Ollama: ollama serve"
echo "2. Pull models: ollama pull llama3.1:8b && ollama pull codellama:7b"
echo "3. Start API: python3 -m uvicorn api.main:app --port 8000"
echo "4. Open dashboard: open dashboard/v2/index.html"
echo ""
