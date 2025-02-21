#!/bin/bash

# Setup script for Honeypot Detection Project
echo "Starting setup..."

# Update system packages (optional, uncomment if needed)
# sudo apt update && sudo apt upgrade -y  # For Linux (Ubuntu/Debian)
# brew update  # For macOS

# Create and activate virtual environment
echo "Setting up Python virtual environment..."
python3 -m venv cowrie-env
source cowrie-env/bin/activate

# Install dependencies
echo "Installing dependencies..."
pip install --upgrade pip
pip install -r requirements-dev.txt

# Configure Cowrie (Ensure cowrie.cfg exists)
if [ -f "cowrie.cfg" ]; then
    echo "Cowrie configuration found!"
else
    echo "cowrie.cfg not found! Please check your configuration."
    exit 1
fi

# Setup complete
echo "Setup complete! To activate the environment, run:"
echo "source cowrie-env/bin/activate"
