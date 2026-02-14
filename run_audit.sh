#!/bin/bash

# Lambda Security Audit Setup Script
# This script sets up the environment and runs the audit

set -e

echo "🔐 Lambda Security Audit - Setup Script"
echo "========================================"

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.7+"
    exit 1
fi

echo "✅ Python 3 found: $(python3 --version)"

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
    echo "✅ Virtual environment created"
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Install requirements
echo "Installing dependencies..."
pip install --upgrade pip > /dev/null
pip install -r requirements.txt > /dev/null
echo "✅ Dependencies installed"

# Check if credentials.json exists
if [ ! -f "config/credentials.json" ]; then
    echo ""
    echo "⚠️  credentials.json not found!"
    echo "Creating from example template..."
    cp config/credentials.json.example config/credentials.json
    echo ""
    echo "📝 Please edit config/credentials.json with your AWS credentials:"
    echo "   - region: AWS region (e.g., us-east-1)"
    echo "   - access_key_id: Your AWS access key"
    echo "   - secret_access_key: Your AWS secret key"
    echo ""
    echo "Then run: python main.py"
    exit 0
fi

echo ""
echo "✅ Setup complete!"
echo ""
echo "Running Lambda Security Audit..."
echo "========================================"
echo ""

# Run the audit
python main.py "$@"
