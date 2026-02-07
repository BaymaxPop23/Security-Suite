#!/bin/bash
# Run dry-run smoke test

echo "🧪 Running Dry-Run Smoke Test"
echo "=============================="
echo ""

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# Run the test
python3 -m pytest tests/test_dry_run.py -v -s

echo ""
echo "Test complete!"
