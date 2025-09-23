# PhishContext AI - Development Guidelines

## Project Structure

This project consists of two main components:
- **Frontend**: React + TypeScript application in the `frontend/` directory
- **Backend**: FastAPI Python application in the `backend/` directory

## Getting Started

### Prerequisites
- Node.js 18+ and npm
- Python 3.9+
- Git

### Initial Setup

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd phishcontext-ai
   ```

2. **Frontend Setup**
   ```bash
   cd frontend
   npm install
   cp .env.example .env.local
   # Edit .env.local with your configuration
   ```

3. **Backend Setup**
   ```bash
   cd backend
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   cp .env.example .env
   # Edit .env with your API keys and configuration
   ```

## Development Workflow

### Running the Application

1. **Start the backend server**
   ```bash
   cd backend
   source venv/bin/activate
   uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```

2. **Start the frontend development server**
   ```bash
   cd frontend
   npm run dev
   ```

3. **Access the application**
   - Frontend: http://localhost:3000
   - Backend API: http://localhost:8000
   - API Documentation: http://localhost:8000/docs

### Code Quality Standards

#### Frontend Standards
- **TypeScript**: All code must be written in TypeScript with proper type definitions
- **ESLint**: Run `npm run lint` before committing
- **Prettier**: Run `npm run format` to format code
- **Testing**: Write tests for all components using Vitest and React Testing Library

#### Backend Standards
- **Type Hints**: All Python code must include proper type hints
- **Black**: Code formatting with `black app/`
- **isort**: Import sorting with `isort app/`
- **Flake8**: Linting with `flake8 app/`
- **MyPy**: Type checking with `mypy app/`
- **Testing**: Write tests using pytest

### Pre-commit Workflow

Before committing code, ensure you run:

**Frontend:**
```bash
npm run lint:fix
npm run format
npm run test:run
```

**Backend:**
```bash
black app/
isort app/
flake8 app/
mypy app/
pytest
```

### Git Workflow

1. **Branch Naming Convention**
   - Feature branches: `feature/task-description`
   - Bug fixes: `bugfix/issue-description`
   - Hotfixes: `hotfix/critical-issue`

2. **Commit Message Format**
   ```
   type(scope): brief description
   
   Detailed explanation if needed
   
   - Bullet points for multiple changes
   - Reference issue numbers: Fixes #123
   ```

   Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

3. **Pull Request Process**
   - Create feature branch from `main`
   - Implement changes with tests
   - Run all quality checks
   - Create PR with descriptive title and description
   - Request code review
   - Address feedback and merge

## File Organization Guidelines

### Frontend File Structure
- Components should be organized in feature-based directories
- Each component should have its own directory with:
  - `ComponentName.tsx` - Main component
  - `ComponentName.types.ts` - Type definitions
  - `ComponentName.test.tsx` - Tests
- Services should be in `src/services/`
- Types should be in `src/types/`
- Utilities should be in `src/utils/`

### Backend File Structure
- API routes in `app/api/routes/`
- Business logic in `app/services/`
- Data models in `app/models/`
- Configuration in `app/core/`
- Utilities in `app/utils/`

### File Size Limits
- **Maximum 400 lines per file**
- Break large files into smaller, focused modules
- Use composition over large monolithic files

## Testing Guidelines

### Frontend Testing
- **Unit Tests**: Test individual components and functions
- **Integration Tests**: Test component interactions
- **E2E Tests**: Test complete user workflows
- **Coverage Target**: Minimum 80% code coverage

### Backend Testing
- **Unit Tests**: Test individual functions and classes
- **Integration Tests**: Test API endpoints
- **Service Tests**: Test business logic
- **Coverage Target**: Minimum 85% code coverage

### Test Data
- Use sanitized, realistic phishing email examples
- Create test fixtures for common scenarios
- Mock external API calls (OpenAI, VirusTotal)

## Security Guidelines

### Environment Variables
- Never commit `.env` files
- Use `.env.example` for documentation
- Rotate API keys regularly
- Use different keys for development and production

### Code Security
- Sanitize all user inputs
- Validate email content size and format
- Implement rate limiting
- Use HTTPS in production
- Clear sensitive data from memory after processing

### API Security
- Implement proper CORS configuration
- Use request timeouts
- Log security events (without sensitive data)
- Implement proper error handling

## Performance Guidelines

### Frontend Performance
- Lazy load components when possible
- Optimize bundle size
- Use React Query for caching
- Implement proper loading states

### Backend Performance
- Use async/await for I/O operations
- Implement request caching where appropriate
- Monitor API response times
- Optimize LLM prompt length

## Deployment Guidelines

### Environment Configuration
- **Development**: Local development with hot reload
- **Staging**: Production-like environment for testing
- **Production**: Optimized build with monitoring

### Build Process
```bash
# Frontend build
cd frontend
npm run build

# Backend preparation
cd backend
pip install -r requirements.txt
```

## Troubleshooting

### Common Issues

1. **Frontend won't start**
   - Check Node.js version (18+)
   - Clear node_modules and reinstall
   - Check for port conflicts

2. **Backend API errors**
   - Verify Python version (3.9+)
   - Check virtual environment activation
   - Verify environment variables

3. **LLM API failures**
   - Check API key configuration
   - Verify network connectivity
   - Check rate limits

### Getting Help

1. Check existing documentation
2. Search closed issues in the repository
3. Create detailed issue with:
   - Steps to reproduce
   - Expected vs actual behavior
   - Environment details
   - Error messages/logs

## Code Review Checklist

### General
- [ ] Code follows project conventions
- [ ] All tests pass
- [ ] Documentation updated if needed
- [ ] No sensitive data in code

### Frontend
- [ ] TypeScript types are properly defined
- [ ] Components are properly tested
- [ ] ESLint and Prettier checks pass
- [ ] Accessibility considerations addressed

### Backend
- [ ] Type hints are complete
- [ ] API endpoints are documented
- [ ] Error handling is comprehensive
- [ ] Security considerations addressed

## Resources

- [React Documentation](https://react.dev/)
- [TypeScript Handbook](https://www.typescriptlang.org/docs/)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [Tailwind CSS Documentation](https://tailwindcss.com/docs)
- [Vitest Documentation](https://vitest.dev/)
- [pytest Documentation](https://docs.pytest.org/)