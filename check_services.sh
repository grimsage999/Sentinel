#!/bin/bash

# PhishContext AI Service Status Checker

echo "🔍 PhishContext AI Service Status"
echo "=================================="

# Check Backend
echo "🔧 Backend Service (Port 8000):"
if curl -s http://localhost:8000/api/health > /dev/null; then
    echo "✅ Backend: ONLINE"
    curl -s http://localhost:8000/api/health | jq '.status' 2>/dev/null || echo "  Status: Healthy"
else
    echo "❌ Backend: OFFLINE"
    echo "  💡 Run: ./start_backend.sh"
fi

echo ""

# Check Frontend
echo "🎨 Frontend Service (Port 3000):"
if curl -s http://localhost:3000 > /dev/null; then
    echo "✅ Frontend: ONLINE"
else
    echo "❌ Frontend: OFFLINE"
    echo "  💡 Run: cd frontend && npm run dev"
fi

echo ""

# Check Processes
echo "🔄 Running Processes:"
UVICORN_PID=$(ps aux | grep uvicorn | grep -v grep | awk '{print $2}' | head -1)
VITE_PID=$(ps aux | grep vite | grep -v grep | awk '{print $2}' | head -1)

if [ ! -z "$UVICORN_PID" ]; then
    echo "  🔧 Backend (uvicorn): PID $UVICORN_PID"
else
    echo "  ❌ Backend (uvicorn): Not running"
fi

if [ ! -z "$VITE_PID" ]; then
    echo "  🎨 Frontend (vite): PID $VITE_PID"
else
    echo "  ❌ Frontend (vite): Not running"
fi

echo ""
echo "🌐 Access URLs:"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8000"
echo "  Health:   http://localhost:8000/api/health"