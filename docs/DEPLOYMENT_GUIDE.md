# Deployment & User Setup Guide

## System Requirements
- Python 3.8+
- Internet connection (for AI API calls)
- Administrator/sudo privileges (for network scanning tools)

## Installation Steps for End Users

### 1. Install Python Dependencies
```bash
# Navigate to the application directory
cd path/to/APENT

# Install Python dependencies
pip install -r requirements.txt
```

### 3. Launch the Application
```bash
python main.py --gui
```

## First-Time Setup

### Step 1: Configure API Keys (Optional but Recommended)
1. When you launch the app for the first time, you'll see a message about configuring API keys
2. Click the **⚙️ Settings** button in the top-right corner
3. Choose which AI providers you want to use:
   - **Claude** (Anthropic) - Recommended for security analysis
   - **ChatGPT** (OpenAI) - Good for general analysis
   - **Gemini** (Google) - Free tier available
4. Get your API key from the provider's website
5. Paste the key into the corresponding field in Settings
6. Click **Save & Close**

**See [API_KEY_SETUP.md](API_KEY_SETUP.md) for detailed instructions on getting API keys**

### Step 2: Run Your First Scan
1. In the "Initialize Scan" panel, enter:
   - **Target**: IP address or hostname (e.g., `192.168.1.1`)
   - **Pipeline**: Choose scanning profile (Guided users should use "FULL PENTEST PIPELINE")
   - **Ports**: Default ports (80, 443) or custom ports
   - **Enable AI analysis**: Check this to use AI for analysis
   - **AI Provider**: Select your configured provider (optional)
2. Click **LAUNCH SCAN SEQUENCE**

## File Locations

### Configuration Files
- **Settings Location**: `~/.cybersecurity_toolkit/settings.json`
- **Logs**: `./logs/` (relative to app directory)
- **Reports**: `./reports/` (relative to app directory)

### Configuration Structure
```
~/.cybersecurity_toolkit/
├── settings.json          # Your saved API keys (protected file)
```

## Environment Variables (Advanced)

If you prefer not to store API keys in a config file, set environment variables:

**Windows (PowerShell):**
```powershell
$env:ANTHROPIC_API_KEY = "your-key"
$env:OPENAI_API_KEY = "your-key"
$env:GEMINI_API_KEY = "your-key"
python main.py --gui
```

**Linux/Mac:**
```bash
export ANTHROPIC_API_KEY="your-key"
export OPENAI_API_KEY="your-key"
export GEMINI_API_KEY="your-key"
python main.py --gui
```

## Scanning Workflows

### Guided Mode (Default - Recommended)
- Simple interface for beginners
- Pre-configured scanning profiles
- Automatic report generation
- AI-powered analysis for findings

### Expert Mode
- Toggle with "Guided Mode" button
- Advanced control over scan parameters
- Suitable for experienced penetration testers

## Troubleshooting

### I can't see my saved API keys
- **Check file location**: Settings are saved to `~/.cybersecurity_toolkit/settings.json`
- **On Windows**: This is usually `C:\Users\YourUsername\.cybersecurity_toolkit\settings.json`
- **On Linux/Mac**: This is usually `/home/username/.cybersecurity_toolkit/settings.json`

### Scan won't start
- **Check target**: Ensure you entered a valid IP or hostname
- **Check ports**: Use format like `80,443` or `8000-8100`
- **Check authorization**: Only scan targets you own or have permission to test

### AI analysis not working
- **Check API key**: Click Settings and verify your key is saved
- **Check connectivity**: Ensure you have internet access
- **Check balance**: Some providers charge for API usage; verify you have credits

### Nmap not found
- **Windows**: Install from https://nmap.org/download.html
- **Linux**: `sudo apt-get install nmap`
- **Mac**: `brew install nmap`

## Security Notes

1. **API Keys**:
   - Stored locally in `~/.cybersecurity_toolkit/settings.json`
   - File has restricted permissions (0600 - owner read/write only)
   - Never share your API keys

2. **Scanning Ethics**:
   - Only scan targets you own or have written authorization to test
   - Unauthorized network scanning is illegal in most jurisdictions
   - Always follow local laws and regulations

3. **Data Privacy**:
   - Scan results are stored locally
   - AI analysis sends scan data to the selected provider (encrypted via HTTPS)
   - Scan reports are saved as HTML in `./reports/`

## Advanced Usage

### Command-Line Interface (for automation)
```bash
python main.py --target example.com --ports 80,443 --output report.html
```

### Custom Scanning Profiles
- Modify the pipeline selection in the Settings for different scan depths
- DISCOVERY ONLY: Fast reconnaissance
- WEB ASSESSMENT: Focused on web vulnerabilities
- FULL PENTEST PIPELINE: Comprehensive assessment

## Getting Support

1. Check the console output in the application for detailed error messages
2. Review the [API_KEY_SETUP.md](API_KEY_SETUP.md) for API-related issues
3. Check log files in the `./logs/` directory
4. Consult individual tool documentation:
   - Nmap: https://nmap.org/
   - Subfinder: https://github.com/projectdiscovery/subfinder
   - Dirsearch: https://github.com/maurosoria/dirsearch

## Uninstalling

1. Delete the application directory
2. (Optional) Delete settings: `rm -r ~/.cybersecurity_toolkit/` (Linux/Mac) or delete `C:\Users\YourUsername\.cybersecurity_toolkit\` (Windows)
