# Cerberus Password Manager

A secure, high-performance password manager with a C core for cryptographic operations, featuring a modern TUI, GUI, and browser extensions.

## Features

- **High-performance** cryptographic operations powered by a C core
- **Secure** password storage with zero-knowledge encryption
- **Cross-platform** support (Windows, macOS, Linux)
- **Multiple Interfaces**:
  - Command Line Interface (CLI)
  - Terminal User Interface (TUI)
  - Graphical User Interface (GUI)
  - Browser Extensions (Firefox, Chrome/Edge)
- **Smart Password Management**:
  - Auto-detection of password change forms
  - One-click password rotation
  - Password strength analysis
  - Breach monitoring
- **Browser Integration**:
  - Auto-fill login forms
  - Auto-save new logins
  - Auto-update changed passwords
  - Smart detection of login forms
- **Import/Export** from other password managers
- **Biometric** authentication support
- **Secure Sharing** of passwords (coming soon)
- **CLI, TUI, and GUI** interfaces for all operations

## Installation

### Prerequisites

- Python 3.8+
- CMake 3.10+
- OpenSSL development libraries
- C compiler (GCC/Clang)
- Node.js 16+ (for browser extensions)
- Optional for TUI: `textual`, `rich` (install with extra `ui-tui`)
- Optional for GUI: `PyQt6` (install with extra `ui-gui`)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/srdusr/cerberus.git
cd cerberus

# Install base package
pip install -e .

# Optional extras
# TUI
pip install -e .[ui-tui]
# GUI
pip install -e .[ui-gui]
# Selenium automation (optional)
pip install -e .[automation-selenium]

# Build and install the C core
mkdir -p build && cd build
cmake ..
make
make install

# Initialize your password vault
cerberus init
```

### One-command install (Linux)

Use the provided `scripts/cerberus-install.sh` to automate Python install, C core build, and (optionally) native messaging setup.

```bash
# Base install
bash scripts/cerberus-install.sh

# With extras (TUI, GUI, Selenium) and Firefox native messaging manifest
CERB_EXTRAS="ui-tui,ui-gui,automation-selenium" CERB_INSTALL_FF=1 bash scripts/cerberus-install.sh

# With Chrome native messaging manifest
CERB_INSTALL_CHROME=1 bash scripts/cerberus-install.sh

# Skip C core build (if already built/installed)
CERB_SKIP_BUILD=1 bash scripts/cerberus-install.sh
```

Environment variables:

- `CERB_EXTRAS`: comma-separated extras to install (e.g., `ui-tui,ui-gui,automation-selenium`).
- `CERB_INSTALL_FF=1`: also install Firefox native messaging manifest.
- `CERB_INSTALL_CHROME=1`: also install Chrome native messaging manifest.
- `CERB_SKIP_BUILD=1`: skip building the C core via CMake.

## Usage

### Command Line Interface (CLI)

```bash
# Initialize a new password vault
cerberus init

# Add a new password entry
cerberus add --website example.com --username user@example.com

# Get a password (copies to clipboard)
cerberus get example.com

# List all entries
cerberus list

# Rotate a password (local vault only)
cerberus rotate example.com

# Web-rotate via browser automation with dynamic discovery
# Simulate (dry-run) across all entries
cerberus web-rotate --dry-run --all

# Rotate for a single target using Playwright (default)
cerberus web-rotate example.com

# Use Selenium instead
cerberus web-rotate example.com --engine selenium

# Launch the GUI
pip install -e .[ui-gui]
cerberus gui
```

### Terminal User Interface (TUI)

Launch the TUI with:
```bash
cerberus tui
```

### Graphical User Interface (GUI)

Launch the GUI with:
```bash
cerberus gui
```

### Browser Extensions

Currently, a development Firefox extension is included under `webext/firefox/`.

Manual install steps for development:

1. Open `about:debugging#/runtime/this-firefox` in Firefox
2. Click "Load Temporary Add-on..."
3. Select `webext/firefox/manifest.json`
4. A Cerberus icon will appear in the toolbar
5. Use the popup to fill credentials on the current tab

Note: This extension is a scaffold for development. A native messaging bridge to the local
vault is planned for secure autofill and save. Today it supports simple page form fill.

### Native Messaging (development)

Native messaging lets the browser extension talk to your local Cerberus vault securely.

1) Install the native host (installed as a console script):

```bash
pip install -e .
# The host command will be available as:
which cerberus-native-host
```

2) Install the native messaging manifest for your browser:

- Firefox (Linux): copy the provided manifest and adjust the `path` if needed

```bash
mkdir -p ~/.mozilla/native-messaging-hosts/
cp native/manifests/firefox_com.cerberus.pm.json ~/.mozilla/native-messaging-hosts/com.cerberus.pm.json
# Ensure the path points to your cerberus-native-host binary (e.g., /usr/local/bin/cerberus-native-host)
sed -i "s#/usr/local/bin/cerberus-native-host#$(command -v cerberus-native-host | sed 's#/#\\/#g')#" ~/.mozilla/native-messaging-hosts/com.cerberus.pm.json
```

- Chrome/Edge (Linux): create manifest at the standard location

```bash
mkdir -p ~/.config/google-chrome/NativeMessagingHosts/
cat > ~/.config/google-chrome/NativeMessagingHosts/com.cerberus.pm.json << 'EOF'
{
  "name": "com.cerberus.pm",
  "description": "Cerberus Password Manager Native Messaging Host (dev)",
  "path": "/usr/local/bin/cerberus-native-host",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://REPLACE_WITH_EXTENSION_ID/"
  ]
}
EOF
# Replace the path with $(command -v cerberus-native-host)
sed -i "s#/usr/local/bin/cerberus-native-host#$(command -v cerberus-native-host | sed 's#/#\\/#g')#" ~/.config/google-chrome/NativeMessagingHosts/com.cerberus.pm.json
```

3) Unlocking the vault for native host:

For development, you can pass the master via environment variable (only for local dev!):

```bash
CERB_MASTER='your-master' CERB_DATA_DIR=~/.cerberus cerberus-native-host
# Typically launched by the browser; running manually is for debugging only.
```

In the extension popup, click "Fetch from Vault" to retrieve credentials for the current tab.

## Password Change Automation

Cerberus can automatically detect and handle many password change flows via web automation.
It uses a hybrid approach:

- Tries a site-specific flow when available (e.g., `GithubFlow` in `cerberus/automation/sites/`)
- Falls back to heuristic discovery (`cerberus/automation/discovery.py`):
  - Scans the DOM for common "Change/Reset Password" links/buttons
  - Tries common settings paths like `/settings/security` and `/settings/password`
  - Attempts to locate current/new/confirm password inputs and submit

```bash
# Automatically detect and update password for a website
cerberus web-rotate example.com

# Check for password changes on all supported sites
cerberus web-rotate --all

Tip: Use `--dry-run` first to preview actions without making changes.

Limitations: Some sites require MFA/2FA or complex flows; in those cases the tool will
return a NEEDS_MANUAL status and avoid unsafe actions.
```

## Development

### Setup Development Environment

```bash
# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Run tests
pytest

# Run type checking
mypy .

# Format code
black .

# Lint code
flake8
```

## Contributing

Contributions are welcome! Please read our [Contributing Guidelines](CONTRIBUTING.md) for details.

## Security

NOTE: This program is still in very early stages of development and should not be used in any production environment, use at your own risk.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
