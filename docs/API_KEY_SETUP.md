# API Key Configuration Guide

## For End Users - How to Set Up API Keys

### Option 1: Settings Dialog (Easiest - Recommended)
1. Launch the CyberSentinel Toolkit GUI
2. Click the **⚙️ Settings** button in the top-right corner
3. Select the **API Keys** tab
4. Enter your API keys for the providers you want to use:
   - **Claude (Anthropic)** - Get key from https://console.anthropic.com
   - **ChatGPT (OpenAI)** - Get key from https://platform.openai.com
   - **Gemini (Google)** - Get key from https://aistudio.google.com
5. Click **Save & Close**
6. Your keys are now saved securely in `~/.cybersecurity_toolkit/settings.json`

### Option 2: Environment Variables
Set environment variables before running the application:

**Windows (PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY = "your-api-key"
$env:OPENAI_API_KEY = "your-api-key"
$env:GEMINI_API_KEY = "your-api-key"
python main.py --gui
```

**Windows (Command Prompt):**
```cmd
set ANTHROPIC_API_KEY=your-api-key
set OPENAI_API_KEY=your-api-key
set GEMINI_API_KEY=your-api-key
python main.py --gui
```

**Linux/Mac:**
```bash
export ANTHROPIC_API_KEY="your-api-key"
export OPENAI_API_KEY="your-api-key"
export GEMINI_API_KEY="your-api-key"
python main.py --gui
```

### Option 3: Direct Input During Scan
1. In the scan initialization panel, enable **"Enable AI analysis"** checkbox
2. Select your preferred **AI Provider** from the dropdown
3. Enter your API key in the **API Key** field
4. The key will be automatically saved for future use

## Getting API Keys

### Claude (Anthropic)
1. Visit https://console.anthropic.com
2. Sign up or log in
3. Create an API key in the settings
4. Copy the key and paste it into CyberSentinel

### ChatGPT (OpenAI)
1. Visit https://platform.openai.com
2. Sign up or log in
3. Go to API keys section
4. Create a new secret key
5. Copy the key and paste it into CyberSentinel

### Gemini (Google)
1. Visit https://aistudio.google.com
2. Sign in with your Google account
3. Click "Get API key"
4. Create a new API key
5. Copy the key and paste it into CyberSentinel

## Security Notes

- API keys are stored in `~/.cybersecurity_toolkit/settings.json` with restricted file permissions (readable only by owner)
- Keys are **NOT** logged or transmitted anywhere
- Keys stored in environment variables are more secure as they're only loaded when needed
- Never share your API keys or commit them to version control
- Use a separate API key for this application if possible

## Troubleshooting

**"AI key not found" message:**
- Ensure your API key is correctly entered or set as an environment variable
- Check that you've selected the correct AI provider
- Verify the key hasn't expired or been revoked in the provider's console

**Key isn't being loaded:**
- Check that the key was saved: Open Settings dialog and verify it appears
- Try re-entering the key in the Settings dialog
- Restart the application

**Permission denied errors:**
- On Linux/Mac, ensure you have write permissions to your home directory
- The app will create `~/.cybersecurity_toolkit/` automatically with proper permissions

## Using Different Providers

You can configure all three providers at once:
1. Open **Settings**
2. Enter API keys for Claude, ChatGPT, and Gemini
3. During scans, select which provider to use from the **AI Provider** dropdown

## Changing or Removing Keys

1. Open **Settings** (⚙️ button)
2. To update: Clear the field and enter the new key
3. To remove: Clear the field and leave it empty
4. Click **Save & Close**
