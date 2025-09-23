@echo off
echo 🚀 Setting up PhishContext AI development environment...

REM Check Node.js
echo 📋 Checking prerequisites...
node --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Node.js is not installed. Please install Node.js 18+ first.
    exit /b 1
)

REM Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed. Please install Python 3.9+ first.
    exit /b 1
)

echo ✅ Prerequisites check passed

REM Setup backend
echo 🐍 Setting up backend...
cd backend

if not exist "venv" (
    echo Creating Python virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing Python dependencies...
pip install -r requirements.txt

if not exist ".env" (
    echo Creating backend .env file...
    copy .env.example .env
    echo ⚠️  Please edit backend\.env with your API keys
)

cd ..

REM Setup frontend
echo ⚛️  Setting up frontend...
cd frontend

echo Installing Node.js dependencies...
npm install

if not exist ".env.local" (
    echo Creating frontend .env.local file...
    copy .env.example .env.local
)

cd ..

echo.
echo 🎉 Setup complete!
echo.
echo Next steps:
echo 1. Edit backend\.env with your API keys (OpenAI, Anthropic, VirusTotal)
echo 2. Start the backend: cd backend ^&^& venv\Scripts\activate ^&^& uvicorn app.main:app --reload
echo 3. Start the frontend: cd frontend ^&^& npm run dev
echo 4. Open http://localhost:3000 in your browser
echo.
echo For detailed instructions, see DEVELOPMENT.md

pause