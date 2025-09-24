#!/bin/bash

echo "🚀 Starting Full-Stack Sentinel with Python Backend Integration..."

# Kill any existing processes
echo "🧹 Cleaning up existing processes..."
pkill -f "tsx server/index.ts" 2>/dev/null || true
pkill -f "uvicorn" 2>/dev/null || true
pkill -f "python.*main" 2>/dev/null || true

# Create .env for Node.js backend if it doesn't exist
if [ ! -f .env ]; then
    echo "📝 Creating Node.js .env file..."
    cat > .env << 'EOL'
# Database Configuration
DATABASE_URL="postgresql://demo:demo@localhost:5432/demo"

# Python Backend URL
PYTHON_BACKEND_URL="http://localhost:8000"

# Email Configuration (optional for development)
SENDGRID_API_KEY=""

# Environment
NODE_ENV=development
EOL
fi

# Create .env for Python backend
echo "📝 Creating Python backend .env file..."
cat > "backend 20-15-57-708/.env" << 'EOL'
# AI API Keys (at least one required)
OPENAI_API_KEY="your_openai_api_key_here"
ANTHROPIC_API_KEY="your_anthropic_api_key_here"
GOOGLE_API_KEY="your_google_api_key_here"

# VirusTotal API (optional but recommended)
VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"

# Application Settings
ENVIRONMENT="development"
LOG_LEVEL="INFO"
ENABLE_RATE_LIMITING="false"
ENABLE_CACHING="true"
CACHE_TTL="3600"

# Security Settings
ALLOWED_HOSTS="localhost,127.0.0.1"
CORS_ORIGINS="http://localhost:3001,http://localhost:8080,http://localhost:3000"

# Performance Settings
MAX_EMAIL_SIZE="10485760"
REQUEST_TIMEOUT="30"
MAX_CONCURRENT_REQUESTS="10"
EOL

# Start Python backend in background
echo "🐍 Starting Python FastAPI backend on port 8000..."
cd "backend 20-15-57-708"
source venv/bin/activate
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload &
PYTHON_PID=$!
echo "Python backend PID: $PYTHON_PID"

# Wait for Python backend to start
echo "⏳ Waiting for Python backend to start..."
sleep 5

# Go back to root directory
cd ..

# Start Node.js backend
echo "🚀 Starting Node.js Sentinel server on port 3001..."
DATABASE_URL="postgresql://demo:demo@localhost:5432/demo" \
PYTHON_BACKEND_URL="http://localhost:8000" \
PORT=3001 \
NODE_ENV=development \
npx tsx server/index.ts &
NODEJS_PID=$!
echo "Node.js backend PID: $NODEJS_PID"

# Wait for Node.js backend to start
echo "⏳ Waiting for Node.js backend to start..."
sleep 8

# Check if both services are running
echo "🔍 Checking service status..."

# Test Python backend
if curl -s http://localhost:8000/health > /dev/null; then
    echo "✅ Python backend is running on http://localhost:8000"
else
    echo "❌ Python backend failed to start"
fi

# Test Node.js backend
if curl -s http://localhost:3001 > /dev/null; then
    echo "✅ Node.js backend is running on http://localhost:3001"
    echo ""
    echo "🎉 Full-Stack Sentinel is now running!"
    echo "📊 Dashboard: http://localhost:3001"
    echo "📧 Email Analysis: http://localhost:3001/email-analysis"
    echo "🐍 Python API: http://localhost:8000"
    echo ""
    echo "Features enabled:"
    echo "  ✅ Alert Management Dashboard"
    echo "  ✅ Email Phishing Analysis with AI"
    echo "  ✅ VirusTotal IOC Analysis"
    echo "  ✅ MITRE ATT&CK Framework Mapping"
    echo "  ✅ Real-time Threat Intelligence"
    echo ""
    echo "Press Ctrl+C to stop all services"
else
    echo "❌ Node.js backend failed to start"
fi

# Keep script running and handle cleanup
cleanup() {
    echo ""
    echo "🛑 Stopping all services..."
    kill $PYTHON_PID 2>/dev/null || true
    kill $NODEJS_PID 2>/dev/null || true
    pkill -f "tsx server/index.ts" 2>/dev/null || true
    pkill -f "uvicorn" 2>/dev/null || true
    echo "✅ All services stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait for background processes
wait
