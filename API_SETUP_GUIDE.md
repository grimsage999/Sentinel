# API Setup Guide for PhishContext AI

## Quick Setup Steps

### 1. Get Your API Keys

#### OpenAI (Required - Primary LLM)
1. Go to https://platform.openai.com/api-keys
2. Sign in or create account
3. Click "Create new secret key"
4. Copy the key (starts with `sk-`)
5. **Note**: You'll need to add billing info for API usage

#### Anthropic (Recommended - Fallback LLM)
1. Go to https://console.anthropic.com/
2. Sign in or create account
3. Navigate to API Keys
4. Create new key
5. Copy the key

#### VirusTotal (Optional - IOC Analysis)
1. Go to https://www.virustotal.com/gui/join-us
2. Sign up for free account
3. Go to Profile → API Key
4. Copy your API key
5. **Note**: Free tier has rate limits but works fine for testing

### 2. Configure Your Keys

Edit the file `backend/.env` and replace the placeholder values:

```bash
# Replace these lines with your actual API keys:
OPENAI_API_KEY=sk-your-actual-openai-key-here
ANTHROPIC_API_KEY=your-actual-anthropic-key-here
VIRUSTOTAL_API_KEY=your-actual-virustotal-key-here
```

### 3. Test Your Configuration

Run the API key tester:

```bash
cd backend
source venv/bin/activate
python test_api_keys.py
```

### 4. Restart the Backend

After updating your API keys:

```bash
# Kill the current backend process
pkill -f uvicorn

# Start it again
cd backend
source venv/bin/activate
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## Minimum Requirements

- **At least 1 LLM provider** (OpenAI or Anthropic) is required
- **VirusTotal is optional** but recommended for better IOC analysis
- **Google API** is optional (not currently used in main flow)

## Cost Considerations

### OpenAI Pricing (as of 2024)
- GPT-4: ~$0.03 per 1K tokens input, ~$0.06 per 1K tokens output
- GPT-3.5-turbo: ~$0.001 per 1K tokens input, ~$0.002 per 1K tokens output
- Typical email analysis: 2-5K tokens total (~$0.10-0.30 per analysis with GPT-4)

### Anthropic Pricing
- Claude-3 Haiku: ~$0.00025 per 1K tokens input, ~$0.00125 per 1K tokens output
- Claude-3 Sonnet: ~$0.003 per 1K tokens input, ~$0.015 per 1K tokens output
- Generally cheaper than OpenAI for similar quality

### VirusTotal
- Free tier: 1,000 requests per day
- Paid plans available for higher volume

## Testing Without API Keys

If you want to test the interface without API keys:
1. The frontend will work normally
2. The backend will start but analysis will fail
3. You'll see proper error messages
4. Good for UI/UX testing

## Troubleshooting

### "Service Offline" in Frontend
- Check if backend is running: `curl http://localhost:8000/api/health`
- Check backend logs for errors
- Verify API keys are configured

### "Analysis Failed" Errors
- Run `python test_api_keys.py` to verify keys
- Check API key billing/quota status
- Try switching primary provider in `.env`

### Rate Limit Errors
- VirusTotal: Wait or upgrade plan
- OpenAI/Anthropic: Check your usage limits
- Reduce analysis frequency