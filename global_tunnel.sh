#!/bin/bash
# ==============================================================================
# Global Public Access Launcher (Cloudflare Tunnel)
# Makes your local cybersecurity server accessible from ANY device in the world!
# ==============================================================================

cd "$(dirname "$0")"

if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
fi

echo "================================================================================"
echo " 🌐 Launching Global Public Tunnel for Any Device Anywhere"
echo "================================================================================"

# Start server in background if not running
if ! lsof -i :8000 > /dev/null 2>&1; then
    echo "🚀 Starting backend server on port 8000..."
    python3 main.py server --port 8000 &
    sleep 2
fi

echo "🌍 Connecting to Cloudflare Global Edge Network..."
./bin/cloudflared tunnel --url http://localhost:8000
