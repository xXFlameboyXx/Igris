#!/usr/bin/env bash
# =============================================================================
# Igris Automated Installer for Linux / macOS
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "===================================================================="
echo "               Installing Igris Malware Analysis Platform            "
echo "===================================================================="
echo "[1/5] Repository location: $SCRIPT_DIR"

# 1. Check Python
echo "[2/5] Checking Python environment..."
if ! command -v python3 >/dev/null 2>&1; then
    echo "Error: Python 3.11+ is required. Please install python3." >&2
    exit 1
fi

# 2. Check Node & npm (Auto-install if missing)
echo "[3/5] Checking Node.js and npm environment..."
if ! command -v npm >/dev/null 2>&1 || ! command -v node >/dev/null 2>&1; then
    echo "Node.js and npm not detected. Attempting automatic installation..."
    
    OS_TYPE="$(uname -s)"
    if [ "$OS_TYPE" = "Linux" ]; then
        if command -v apt-get >/dev/null 2>&1; then
            echo "Installing Node.js & npm via apt..."
            if [ "$(id -u)" -eq 0 ]; then
                apt-get update && apt-get install -y nodejs npm
            elif command -v sudo >/dev/null 2>&1; then
                sudo apt-get update && sudo apt-get install -y nodejs npm
            else
                echo "Error: sudo required to install nodejs with apt." >&2
                exit 1
            fi
        elif command -v dnf >/dev/null 2>&1; then
            echo "Installing Node.js & npm via dnf..."
            if [ "$(id -u)" -eq 0 ]; then
                dnf install -y nodejs npm
            elif command -v sudo >/dev/null 2>&1; then
                sudo dnf install -y nodejs npm
            fi
        elif command -v yum >/dev/null 2>&1; then
            echo "Installing Node.js & npm via yum..."
            if [ "$(id -u)" -eq 0 ]; then
                yum install -y nodejs npm
            elif command -v sudo >/dev/null 2>&1; then
                sudo yum install -y nodejs npm
            fi
        elif command -v pacman >/dev/null 2>&1; then
            echo "Installing Node.js & npm via pacman..."
            if [ "$(id -u)" -eq 0 ]; then
                pacman -Sy --noconfirm nodejs npm
            elif command -v sudo >/dev/null 2>&1; then
                sudo pacman -Sy --noconfirm nodejs npm
            fi
        elif command -v apk >/dev/null 2>&1; then
            echo "Installing Node.js & npm via apk..."
            if [ "$(id -u)" -eq 0 ]; then
                apk add --no-cache nodejs npm
            elif command -v sudo >/dev/null 2>&1; then
                sudo apk add --no-cache nodejs npm
            fi
        else
            echo "Error: Unsupported Linux package manager. Please install Node.js manually." >&2
            exit 1
        fi
    elif [ "$OS_TYPE" = "Darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            echo "Installing Node.js via Homebrew..."
            brew install node
        else
            echo "Error: Homebrew is required to auto-install Node.js on macOS. Please install Homebrew or Node.js from https://nodejs.org." >&2
            exit 1
        fi
    else
        echo "Error: Unsupported operating system ($OS_TYPE). Please install Node.js manually." >&2
        exit 1
    fi

    # Verify installation
    if ! command -v npm >/dev/null 2>&1; then
        echo "Error: Node.js / npm installation failed. Please install Node.js manually from https://nodejs.org." >&2
        exit 1
    fi
    echo "Node.js and npm installed successfully!"
fi

# 3. Setup Python Virtual Environment and Backend Dependencies
echo "[4/5] Setting up backend dependencies and CLI launcher..."
cd "$SCRIPT_DIR"
if command -v uv >/dev/null 2>&1; then
    uv sync --extra dev
else
    if [ ! -d ".venv" ]; then
        python3 -m venv .venv
    fi
    .venv/bin/pip install -e .
fi

# 4. Build Frontend Production Bundle
echo "[5/5] Building frontend production bundle..."
cd "$SCRIPT_DIR/frontend"
if [ ! -d "node_modules" ]; then
    echo "Installing frontend npm packages..."
    npm install
fi
echo "Compiling Vite production bundle..."
npm run build

# 5. Configure Global Launcher Shim
GLOBAL_BIN_DIR="${HOME}/.local/bin"
mkdir -p "$GLOBAL_BIN_DIR"
LAUNCHER_SCRIPT="$GLOBAL_BIN_DIR/igris"

cat <<EOF > "$LAUNCHER_SCRIPT"
#!/usr/bin/env bash
export IGRIS_HOME="$SCRIPT_DIR"
if [ -f "\$IGRIS_HOME/.venv/bin/python" ]; then
    exec "\$IGRIS_HOME/.venv/bin/python" -m igris.cli.launcher "\$@"
else
    echo "Error: Igris Python virtual environment not found at \$IGRIS_HOME/.venv/bin/python." >&2
    echo "Run ./install.sh to repair the environment." >&2
    exit 1
fi
EOF

chmod +x "$LAUNCHER_SCRIPT"

echo ""
echo "===================================================================="
echo "            Igris has been installed successfully!                  "
echo "===================================================================="
echo ""
echo "You can now run 'igris' from your terminal."
if [[ ":$PATH:" != *":$GLOBAL_BIN_DIR:"* ]]; then
    echo ""
    echo "Note: Ensure '$GLOBAL_BIN_DIR' is in your PATH."
    echo "Add the following to your ~/.bashrc or ~/.zshrc:"
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
fi
echo ""
echo "Available commands:"
echo "    igris             # Start Igris & open GUI in your browser"
echo "    igris --status    # Check running server status"
echo "    igris --stop      # Stop background server instance"
echo "    igris --repair    # Rebuild frontend and verify dependencies"
echo "    igris --version   # Display installed version"
echo "    igris --help      # Show all options"
echo "===================================================================="
