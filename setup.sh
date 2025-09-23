#!/bin/bash

# PhishContext AI Setup Script

echo "🚀 Setting up PhishContext AI development environment..."

# Check prerequisites
echo "📋 Checking prerequisites..."

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

NODE_VERSION=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 18 ]; then
    echo "❌ Node.js version 18+ required. Current version: $(node -v)"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed. Please install Python 3.9+ first."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
if ! python3 -c 'import sys; exit(0 if sys.version_info >= (3, 9) else 1)'; then
    echo "❌ Python 3.9+ required. Current version: $PYTHON_VERSION"
    exit 1
fi

echo "✅ Prerequisites check passed"

# Setup backend
echo "🐍 Setting up backend..."
cd backend

if [ ! -d "venv" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing Python dependencies..."
pip install -r requirements.txt

if [ ! -f ".env" ]; then
    echo "Creating backend .env file..."
    cp .env.example .env
    echo "⚠️  Please edit backend/.env with your API keys"
fi

cd ..

# Setup frontend
echo "⚛️  Setting up frontend..."
cd frontend

echo "Installing Node.js dependencies..."
npm install

if [ ! -f ".env.local" ]; then
    echo "Creating frontend .env.local file..."
    cp .env.example .env.local
fi

cd ..

# Setup pre-commit hooks (optional)
if command -v pre-commit &> /dev/null; then
    echo "🔧 Setting up pre-commit hooks..."
    pre-commit install
else
    echo "⚠️  pre-commit not found. Install with: pip install pre-commit"
fi

echo ""
echo "🎉 Setup complete!"
echo ""
echo "Next steps:"
echo "1. Edit backend/.env with your API keys (OpenAI, Anthropic, VirusTotal)"
echo "2. Start the backend: cd backend && source venv/bin/activate && uvicorn app.main:app --reload"
echo "3. Start the frontend: cd frontend && npm run dev"
echo "4. Open http://localhost:3000 in your browser"
echo ""
echo "For detailed instructions, see DEVELOPMENT.md"