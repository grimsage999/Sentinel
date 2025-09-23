#!/bin/bash

# PhishContext AI Backend Startup Script

echo "🚀 Starting PhishContext AI Backend..."

# Navigate to backend directory
cd backend

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "❌ Virtual environment not found. Please run setup.sh first."
    exit 1
fi

# Kill any existing uvicorn processes
echo "🔄 Stopping existing processes..."
pkill -f uvicorn 2>/dev/null || true

# Wait a moment
sleep 2

# Activate virtual environment and start server
echo "🔧 Activating virtual environment..."
source venv/bin/activate

echo "🌐 Starting server on http://localhost:8000..."
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &

# Wait for server to start
sleep 3

# Check if server is running
echo "🔍 Checking server health..."
if curl -s http://localhost:8000/api/health > /dev/null; then
    echo "✅ Backend server is running successfully!"
    echo "📊 Access at: http://localhost:8000"
    echo "🏥 Health check: http://localhost:8000/api/health"
else
    echo "❌ Server failed to start. Check the logs above."
    exit 1
fi