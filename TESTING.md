# PhishContext AI - Comprehensive Testing Guide

This document provides a complete guide to the testing infrastructure and practices for PhishContext AI.

## Overview

PhishContext AI implements a comprehensive testing strategy covering:

- **Backend Unit Tests**: Core service logic, API endpoints, and data models
- **Frontend Component Tests**: React components, hooks, and user interactions
- **Integration Tests**: API communication and service integration
- **End-to-End Tests**: Complete user workflows and system behavior
- **Performance Tests**: Load testing and performance validation
- **Security Tests**: Input validation and security feature verification

## Test Architecture

### Backend Testing (Python/FastAPI)

```
backend/tests/
├── test_email_parser.py          # Email parsing and validation
├── test_ioc_extractor.py         # IOC extraction and categorization
├── test_llm_analyzer.py          # LLM integration and response parsing
├── test_main.py                  # API endpoints and error handling
├── test_security_features.py     # Security validation
└── conftest.py                   # Test configuration and fixtures
```

**Key Features:**
- Comprehensive unit tests with 90%+ code coverage
- Mocked external dependencies (LLM APIs, VirusTotal)
- Edge case testing for malformed inputs
- Performance and security validation
- Async testing for LLM operations

### Frontend Testing (React/TypeScript)

```
frontend/src/
├── components/*/**.test.tsx      # Component unit tests
├── hooks/**.test.tsx             # Custom hook tests
├── services/**.test.ts           # API service tests
└── e2e/                          # End-to-end tests
    ├── setup.ts                  # Test utilities and mocks
    ├── email-analysis-workflow.test.ts
    ├── performance-load.test.ts
    └── error-scenarios.test.ts
```

**Key Features:**
- React Testing Library for component testing
- User interaction simulation
- API mocking and error scenario testing
- Accessibility testing
- Performance monitoring

## Running Tests

### Backend Tests

```bash
# Run all backend tests
cd backend
python run_tests.py

# Run specific test suites
python run_tests.py --suite unit
python run_tests.py --suite integration
python run_tests.py --suite security

# Run with coverage
python -m pytest tests/ --cov=app --cov-report=html
```

### Frontend Tests

```bash
# Run all frontend tests
cd frontend
node run_tests.js

# Run specific test suites
node run_tests.js --suite=unit
node run_tests.js --suite=e2e
node run_tests.js --suite=performance

# Run with coverage
npm run test:coverage
```

### Full System Tests

```bash
# Run complete test suite (both backend and frontend)
./run_all_tests.sh
```

## Test Categories

### 1. Unit Tests

**Backend Unit Tests:**
- `EmailParser`: Email parsing, header extraction, validation
- `IOCExtractor`: URL/IP/domain extraction, VirusTotal integration
- `LLMAnalyzer`: AI service integration, response parsing, fallback logic
- API endpoints: Request validation, response formatting, error handling

**Frontend Unit Tests:**
- `EmailAnalysisForm`: Form validation, user input handling
- `AnalysisResults`: Result display, data formatting
- `IOCList`: IOC rendering, copy/export functionality
- Custom hooks: API integration, state management

### 2. Integration Tests

**API Integration:**
- End-to-end API request/response cycles
- Service dependency integration
- Error propagation and handling
- Authentication and authorization

**Component Integration:**
- Parent-child component communication
- State management across components
- Event handling and data flow

### 3. End-to-End Tests

**Complete User Workflows:**
- Email input → Analysis → Results display
- Error handling and recovery
- Performance under load
- Accessibility compliance

**Test Scenarios:**
- Valid phishing email analysis
- Invalid input handling
- Network error recovery
- Rate limiting behavior
- Concurrent user simulation

### 4. Performance Tests

**Backend Performance:**
- API response times under load
- Memory usage during analysis
- Concurrent request handling
- LLM service timeout handling

**Frontend Performance:**
- Component rendering performance
- Large email content handling
- Memory leak detection
- UI responsiveness during analysis

### 5. Security Tests

**Input Validation:**
- Malicious email content handling
- XSS prevention
- Input sanitization
- Size limit enforcement

**API Security:**
- Rate limiting
- Request validation
- Error message sanitization
- Sensitive data handling

## Test Data and Fixtures

### Sample Email Content

The test suite includes various email samples:

```python
# Phishing email samples
CREDENTIAL_THEFT_EMAIL = """
From: security@amaz0n.com
Subject: URGENT: Account Verification Required
...
"""

MALWARE_DELIVERY_EMAIL = """
From: it-support@company.com
Subject: Critical Security Update
...
"""

# Edge cases
MALFORMED_EMAIL = "Invalid email format"
LARGE_EMAIL = "From: test@example.com\n" + "x" * 1000000
```

### Mock Responses

Comprehensive mocking for external services:

```python
# LLM API responses
MOCK_ANALYSIS_RESPONSE = {
    "intent": {"primary": "credential_theft", "confidence": "High"},
    "deception_indicators": [...],
    "risk_score": {"score": 8, "confidence": "High"},
    ...
}

# Error responses
MOCK_ERROR_RESPONSES = {
    "timeout": {"code": "TIMEOUT", "message": "Request timed out"},
    "rate_limit": {"code": "RATE_LIMITED", "retryAfter": 60},
    ...
}
```

## Coverage Requirements

### Minimum Coverage Targets

- **Backend**: 90% line coverage, 85% branch coverage
- **Frontend**: 85% line coverage, 80% branch coverage
- **Critical paths**: 95% coverage (authentication, analysis pipeline)

### Coverage Exclusions

- Third-party library code
- Configuration files
- Development utilities
- Generated code

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Test Suite
on: [push, pull_request]

jobs:
  backend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      - name: Install dependencies
        run: |
          cd backend
          pip install -r requirements.txt
      - name: Run tests
        run: |
          cd backend
          python run_tests.py
      - name: Upload coverage
        uses: codecov/codecov-action@v3

  frontend-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Node.js
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      - name: Install dependencies
        run: |
          cd frontend
          npm ci
      - name: Run tests
        run: |
          cd frontend
          node run_tests.js
      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

## Test Environment Setup

### Backend Environment

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
cd backend
pip install -r requirements.txt
pip install -e .

# Set environment variables
export OPENAI_API_KEY="test-key"
export ANTHROPIC_API_KEY="test-key"
export ENVIRONMENT="test"
```

### Frontend Environment

```bash
# Install dependencies
cd frontend
npm install

# Set environment variables
cp .env.example .env.test
# Edit .env.test with test configuration
```

## Debugging Tests

### Backend Debugging

```bash
# Run specific test with verbose output
python -m pytest tests/test_email_parser.py::TestEmailParser::test_parse_valid_email -v -s

# Debug with pdb
python -m pytest tests/test_email_parser.py --pdb

# Run with coverage and open HTML report
python -m pytest tests/ --cov=app --cov-report=html
open htmlcov/index.html
```

### Frontend Debugging

```bash
# Run specific test file
npm run test -- src/components/EmailAnalysisForm/EmailAnalysisForm.test.tsx

# Run tests in watch mode
npm run test:watch

# Debug in browser
npm run test:ui
```

## Performance Benchmarks

### Response Time Targets

- **Email Analysis**: < 30 seconds (95th percentile)
- **API Health Check**: < 500ms
- **IOC Extraction**: < 5 seconds
- **UI Rendering**: < 100ms for initial load

### Load Testing Targets

- **Concurrent Users**: 50 simultaneous analyses
- **Request Rate**: 100 requests/minute sustained
- **Error Rate**: < 1% under normal load
- **Memory Usage**: < 512MB per worker process

## Best Practices

### Writing Tests

1. **Follow AAA Pattern**: Arrange, Act, Assert
2. **Use Descriptive Names**: Test names should explain the scenario
3. **Test Edge Cases**: Include boundary conditions and error cases
4. **Mock External Dependencies**: Isolate units under test
5. **Keep Tests Independent**: Each test should be able to run in isolation

### Test Organization

1. **Group Related Tests**: Use test classes or describe blocks
2. **Use Setup/Teardown**: Clean state between tests
3. **Parameterize Tests**: Use test parameters for similar scenarios
4. **Document Complex Tests**: Add comments for complex test logic

### Maintenance

1. **Update Tests with Code Changes**: Keep tests in sync with implementation
2. **Review Test Coverage**: Regularly check coverage reports
3. **Refactor Test Code**: Apply same quality standards as production code
4. **Monitor Test Performance**: Keep test execution time reasonable

## Troubleshooting

### Common Issues

**Backend Tests:**
- Import errors: Check PYTHONPATH and virtual environment
- API key errors: Ensure test environment variables are set
- Timeout errors: Increase timeout values for slow operations

**Frontend Tests:**
- Module resolution errors: Check tsconfig.json and vite.config.ts
- Async test failures: Ensure proper await/waitFor usage
- DOM cleanup issues: Use proper test cleanup in afterEach

**Integration Tests:**
- Service unavailable: Check if required services are running
- Network errors: Verify test environment network configuration
- Authentication failures: Ensure test credentials are valid

### Getting Help

1. Check test logs for detailed error messages
2. Review test documentation and examples
3. Run tests in isolation to identify specific failures
4. Use debugging tools (pdb, browser dev tools)
5. Consult team members for complex issues

## Metrics and Reporting

### Test Metrics Tracked

- **Test Coverage**: Line and branch coverage percentages
- **Test Execution Time**: Duration of test suites
- **Test Reliability**: Flaky test identification
- **Performance Metrics**: Response times and resource usage

### Reports Generated

- **Coverage Reports**: HTML and JSON coverage reports
- **Test Results**: JUnit XML for CI integration
- **Performance Reports**: Load testing results
- **Security Reports**: Security scan results

### Monitoring

- **CI/CD Integration**: Automated test execution on commits
- **Coverage Tracking**: Coverage trend monitoring
- **Performance Monitoring**: Response time tracking
- **Alert System**: Notifications for test failures

---

This comprehensive testing guide ensures PhishContext AI maintains high quality, reliability, and performance standards through rigorous testing practices.