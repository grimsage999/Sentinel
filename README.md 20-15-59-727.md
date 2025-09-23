# Sentinel

A web-based tool that leverages Large Language Models (LLMs) to provide rapid, intelligent analysis of phishing emails for SOC analysts.

## Overview

Sentinel accelerates SOC analysts' decision-making process during phishing email analysis by providing AI-generated interpretive analysis of reported phishing emails. The tool reduces analysis time from 10 minutes to under 1 minute per email, enabling analysts to handle 5x more alerts while reducing cognitive load and burnout.

## Features

- **Instant Email Analysis**: Paste raw email content and receive AI-powered analysis within 30 seconds
- **Intent Classification**: Identify phishing intent (credential theft, wire transfer fraud, malware delivery, etc.)
- **Deception Indicators**: Highlight social engineering tactics and suspicious elements
- **Risk Scoring**: Contextual risk assessment with confidence levels
- **IOC Extraction**: Automatic extraction of URLs, IPs, and domains with VirusTotal integration
- **Clean Interface**: Intuitive web interface designed for SOC analysts

## Technology Stack

### Frontend
- React 18+ with TypeScript
- Tailwind CSS for styling
- Vite for build tooling
- Vitest for testing
- React Query for state management

### Backend
- FastAPI (Python) for high-performance async API
- Pydantic for data validation
- OpenAI/Anthropic/Google LLM integration
- VirusTotal API integration

## Quick Start

### Prerequisites
- Node.js 18+
- Python 3.9+
- API keys for LLM providers (OpenAI, Anthropic, or Google)

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd sentinel
   ```

2. **Set up the backend**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   cp .env.example .env
   # Edit .env with your API keys
   ```

3. **Set up the frontend**
   ```bash
   cd frontend
   npm install
   cp .env.example .env.local
   # Edit .env.local if needed
   ```

### Running the Application

1. **Start the backend**
   ```bash
   cd backend
   source venv/bin/activate
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Start the frontend**
   ```bash
   cd frontend
   npm run dev
   ```

3. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

## Configuration

### Environment Variables

#### Backend (.env)
```bash
# LLM Provider Configuration
OPENAI_API_KEY=your_openai_api_key_here
PRIMARY_LLM_PROVIDER=openai
FALLBACK_LLM_PROVIDER=anthropic

# VirusTotal Configuration
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here

# API Configuration
API_HOST=0.0.0.0
API_PORT=8000
CORS_ORIGINS=["http://localhost:3000"]
```

#### Frontend (.env.local)
```bash
VITE_API_BASE_URL=http://localhost:8000
```

## Usage

1. **Paste Email Content**: Copy and paste the raw email content (including headers) into the text area
2. **Analyze**: Click the "Analyze" button to process the email
3. **Review Results**: View the AI-generated analysis including:
   - Primary intent and confidence level
   - Deception indicators with evidence
   - Risk score and reasoning
   - Extracted IOCs with VirusTotal links

## Development

See [DEVELOPMENT.md](DEVELOPMENT.md) for detailed development guidelines, coding standards, and contribution instructions.

### Running Tests

**Frontend:**
```bash
cd frontend
npm run test
```

**Backend:**
```bash
cd backend
pytest
```

### Code Quality

**Frontend:**
```bash
npm run lint
npm run format
```

**Backend:**
```bash
black app/
isort app/
flake8 app/
mypy app/
```

## API Documentation

The backend API provides the following endpoints:

- `POST /api/analyze` - Analyze phishing email content
- `GET /api/health` - Health check endpoint

Full API documentation is available at http://localhost:8000/docs when running the backend.

## Security & Performance Features

### Security
- **Input Sanitization**: XSS prevention and malicious content removal
- **Memory Management**: Automatic cleanup of sensitive email content
- **Request Validation**: Size limits and content validation
- **Security Headers**: Comprehensive security headers on all responses
- **Threat Detection**: Real-time detection of malicious patterns
- **Secure Logging**: Sensitive data filtering in all logs

### Performance
- **Concurrent Processing**: Handles up to 50 concurrent requests
- **Performance Monitoring**: Real-time system and request metrics
- **Rate Limiting**: 60 requests per minute per IP with burst protection
- **Memory Optimization**: Automatic memory cleanup and garbage collection
- **Resource Monitoring**: CPU and memory usage tracking with alerts

For detailed information, see [SECURITY_PERFORMANCE.md](backend/SECURITY_PERFORMANCE.md)

## Performance

- Analysis completes within 30 seconds for typical emails
- Supports concurrent analysis requests
- Optimized LLM prompts for speed and accuracy
- Caching for improved response times

## Contributing

1. Fork the repository
2. Create a feature branch
3. Follow the development guidelines in DEVELOPMENT.md
4. Submit a pull request

## License

[License information to be added]

## Support

For issues and questions:
1. Check the troubleshooting section in DEVELOPMENT.md
2. Search existing issues
3. Create a new issue with detailed information

## Roadmap

- [ ] Additional LLM provider integrations
- [ ] Enhanced IOC analysis
- [ ] Batch email processing
- [ ] Advanced reporting features
- [ ] Integration with SIEM platforms