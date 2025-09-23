# Navigate to backend directory
cd backend

# Activate virtual environment and start server
source venv/bin/activate && python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000 &
