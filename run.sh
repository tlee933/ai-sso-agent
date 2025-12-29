#!/bin/bash
# AI SSO Agent - Quick Start Script

echo "🔐 AI SSO Agent - Starting..."

# Check if virtual environment exists
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
source venv/bin/activate

# Install dependencies if needed
if [ ! -f "venv/.installed" ]; then
    echo "Installing dependencies..."
    pip install -r requirements.txt
    touch venv/.installed
fi

# Check if .env exists
if [ ! -f ".env" ]; then
    echo "⚠️  No .env file found!"
    echo "Creating .env from .env.example..."
    cp .env.example .env

    # Generate secrets
    SECRET_KEY=$(openssl rand -hex 32)
    FERNET_KEY=$(python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())")

    # Update .env
    sed -i "s/your-secret-key-here-generate-with-openssl-rand-hex-32/$SECRET_KEY/" .env
    sed -i "s/your-fernet-key-here/$FERNET_KEY/" .env

    echo "✅ Generated .env file with secure keys"
    echo "⚠️  Please review .env and update any other settings"
fi

# Run the application
cd src/api
echo "🚀 Starting AI SSO Agent on http://localhost:8000"
echo "📖 API docs available at http://localhost:8000/docs"
python main.py
